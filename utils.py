"""Shared utility functions for hermes-agent."""

import contextlib
import errno
import hashlib
import json
import logging
import os
import shutil
import stat
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Optional, Union
from urllib.parse import urlparse

import yaml

logger = logging.getLogger(__name__)


TRUTHY_STRINGS = frozenset({"1", "true", "yes", "on"})


def is_truthy_value(value: Any, default: bool = False) -> bool:
    """Coerce bool-ish values using the project's shared truthy string set."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in TRUTHY_STRINGS
    return bool(value)


def env_var_enabled(name: str, default: str = "") -> bool:
    """Return True when an environment variable is set to a truthy value."""
    return is_truthy_value(os.getenv(name, default), default=False)


def _preserve_file_mode(path: Path) -> "int | None":
    """Capture the permission bits of *path* if it exists, else ``None``."""
    try:
        return stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    except OSError:
        return None


def _restore_file_mode(path: Path, mode: "int | None") -> None:
    """Re-apply *mode* to *path* after an atomic replace.

    ``tempfile.mkstemp`` creates files with 0o600 (owner-only).  After
    ``os.replace`` swaps the temp file into place the target inherits
    those restrictive permissions, breaking Docker / NAS volume mounts
    that rely on broader permissions set by the user.  Calling this
    right after ``os.replace`` restores the original permissions.
    """
    if mode is None:
        return
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def atomic_replace(tmp_path: Union[str, Path], target: Union[str, Path]) -> str:
    """Atomically move *tmp_path* onto *target*, preserving symlinks.

    ``os.replace(tmp, target)`` atomically swaps ``tmp`` into place at
    ``target``.  When ``target`` is a symlink, the symlink itself is
    replaced with a regular file — silently detaching managed deployments
    that symlink ``config.yaml`` / ``SOUL.md`` / ``auth.json`` etc. from
    ``~/.hermes/`` to a git-tracked profile package or dotfiles repo
    (GitHub #16743).

    This helper resolves the symlink first so ``os.replace`` writes to
    the real file in-place while the symlink survives.  For non-symlink
    and non-existent paths the behavior is identical to a plain
    ``os.replace`` call unless the rename fails with ``EXDEV`` or ``EBUSY``;
    those cases fall back to copy/fsync/unlink for cross-device, bind-mount,
    and busy-file deployments.

    Returns the resolved real path used for the replace, so callers that
    need to re-apply permissions can target it instead of the symlink.
    """
    target_str = str(target)
    real_path = os.path.realpath(target_str) if os.path.islink(target_str) else target_str
    tmp_str = str(tmp_path)
    try:
        os.replace(tmp_str, real_path)
    except OSError as exc:
        if exc.errno not in (errno.EXDEV, errno.EBUSY):
            raise
        logger.debug(
            "atomic_replace: %s -> %s failed with %s; falling back to copy",
            tmp_str,
            real_path,
            errno.errorcode.get(exc.errno, exc.errno),
        )
        shutil.copyfile(tmp_str, real_path)
        try:
            shutil.copystat(tmp_str, real_path)
        except OSError:
            pass
        try:
            with open(real_path, "rb") as f:
                os.fsync(f.fileno())
        except OSError:
            pass
        os.unlink(tmp_str)
    return real_path


# ─── Config Write Locking ─────────────────────────────────────────────────────
#
# atomic_yaml_write makes individual writes crash-safe, but two concurrent
# read-modify-write cycles still race last-writer-wins: both read the same
# config.yaml, each applies its own edit, and whichever os.replace lands
# second silently drops the other's change.  The helpers below add the
# missing serialization, mirroring the kanban _cross_process_init_lock
# pattern (hermes_cli/kanban_db.py): an advisory lock on a sidecar file
# (flock on POSIX, msvcrt byte-range on Windows) held across the FULL
# read→edit→os.replace cycle, plus an mtime+hash stale-write guard as a
# backstop against writers that don't take the lock (older binaries,
# manual edits mid-cycle).

_IS_WINDOWS = sys.platform == "win32"

# Sentinel distinguishing "no stale check requested" from "file was absent
# at read time" (where the snapshot itself is None).
_STATE_UNCHECKED = object()

# Returned by a locked_yaml_mutate() mutate callback to skip the write
# entirely (e.g. the value is already set).
SKIP_WRITE = object()


class ConfigWriteConflictError(RuntimeError):
    """Config file changed on disk between read and write.

    Raised by the stale-write guard when a concurrent writer (one not
    holding the config lock) modified the file mid read-modify-write
    cycle.  Persisting anyway would silently revert that writer's change.
    """


def file_write_state(path: Union[str, Path]) -> "tuple | None":
    """Snapshot (mtime_ns, size, sha256) of *path*, or ``None`` if absent.

    Capture this at read time and pass it as ``expected_state`` to
    :func:`atomic_yaml_write` to detect writes that raced the cycle.
    Follows symlinks, matching :func:`atomic_replace` semantics.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, digest.hexdigest())


def config_lock_path(path: Union[str, Path]) -> Path:
    """Sidecar lock file guarding read-modify-write cycles on *path*.

    For ``~/.hermes/config.yaml`` this is ``~/.hermes/.config.lock``; for a
    profile's ``~/.hermes/profiles/<p>/config.yaml`` it is
    ``~/.hermes/profiles/<p>/.config.lock`` — one lock per config file, so
    profiles don't serialize against each other or against global config.
    """
    path = Path(path)
    return path.parent / f".{path.stem}.lock"


class _ConfigLockState:
    """Per-lock-path state: thread gate + re-entrancy depth + OS handle."""

    __slots__ = ("thread_lock", "depth", "handle")

    def __init__(self) -> None:
        self.thread_lock = threading.RLock()
        self.depth = 0
        self.handle = None


_CONFIG_LOCK_STATES: "dict[str, _ConfigLockState]" = {}
_CONFIG_LOCK_REGISTRY_GUARD = threading.Lock()


def _reset_config_locks_after_fork() -> None:
    """Drop inherited lock state in a forked child.

    A child forked while the parent holds a config lock inherits a registry
    whose depth>0 entry would make the child skip the flock and write inside
    the parent's critical section.  Resetting forces the child to acquire
    fresh (it blocks until the parent releases).  The inherited handle is
    abandoned, not closed here — the parent's fd keeps the flock alive, and
    closing one duplicate of a shared open-file description doesn't release
    it anyway.
    """
    global _CONFIG_LOCK_STATES, _CONFIG_LOCK_REGISTRY_GUARD
    _CONFIG_LOCK_REGISTRY_GUARD = threading.Lock()
    _CONFIG_LOCK_STATES = {}


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_config_locks_after_fork)


@contextlib.contextmanager
def config_file_lock(path: Union[str, Path]):
    """Advisory cross-process lock for a config read-modify-write cycle.

    Hold this across the FULL cycle (read → edit → os.replace), not just
    the write — locking only the write still loses updates because both
    writers read the same starting state.

    Re-entrant within a thread (``save_config`` may run inside a caller's
    locked cycle); distinct threads in one process serialize on a per-path
    RLock, and distinct processes serialize on the sidecar file lock.
    """
    lock_path = config_lock_path(path)
    key = str(lock_path)
    with _CONFIG_LOCK_REGISTRY_GUARD:
        state = _CONFIG_LOCK_STATES.setdefault(key, _ConfigLockState())
    with state.thread_lock:
        if state.depth == 0:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("a+b")
            try:
                if _IS_WINDOWS:
                    import msvcrt

                    # Byte-range lock on the first byte; seek explicitly
                    # because msvcrt.locking starts at the file position.
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            except BaseException:
                handle.close()
                raise
            state.handle = handle
        state.depth += 1
        try:
            yield
        finally:
            state.depth -= 1
            if state.depth == 0:
                handle = state.handle
                state.handle = None
                try:
                    if _IS_WINDOWS:
                        import msvcrt

                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                finally:
                    handle.close()


def _replace_with_guard(tmp_path: str, path: Path, expected_state: Any) -> str:
    """Atomically swap *tmp_path* onto *path*, enforcing the stale guard.

    The re-stat happens immediately before ``os.replace``; the residual
    window is closed by callers holding :func:`config_file_lock` — the
    guard exists to catch writers that bypass the lock.
    """
    if expected_state is not _STATE_UNCHECKED:
        current = file_write_state(path)
        if current != expected_state:
            raise ConfigWriteConflictError(
                f"{path} changed on disk since it was read; aborting write to "
                f"avoid reverting the concurrent change (re-read and retry)"
            )
    return atomic_replace(tmp_path, path)


def atomic_json_write(
    path: Union[str, Path],
    data: Any,
    *,
    indent: int = 2,
    mode: int | None = None,
    **dump_kwargs: Any,
) -> None:
    """Write JSON data to a file atomically.

    Uses temp file + fsync + os.replace to ensure the target file is never
    left in a partially-written state. If the process crashes mid-write,
    the previous version of the file remains intact.

    Args:
        path: Target file path (will be created or overwritten).
        data: JSON-serializable data to write.
        indent: JSON indentation (default 2).
        mode: Optional final permission mode. When set, the temp file is
            created and replaced with this mode, avoiding chmod-after-write
            TOCTOU exposure for secret-bearing files.
        **dump_kwargs: Additional keyword args forwarded to json.dump(), such
            as default=str for non-native types.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    original_mode = None if mode is not None else _preserve_file_mode(path)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.stem}_",
        suffix=".tmp",
    )
    try:
        if mode is not None and hasattr(os, "fchmod"):
            # fchmod is Unix-only; Windows' os module has no fchmod. Skipping it
            # here is safe — mkstemp already created the temp file as 0o600, and
            # the post-replace os.chmod below applies the final mode durably.
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                data,
                f,
                indent=indent,
                ensure_ascii=False,
                **dump_kwargs,
            )
            f.flush()
            os.fsync(f.fileno())
        # Preserve symlinks — swap in-place on the real file (GitHub #16743).
        real_path = atomic_replace(tmp_path, path)
        if mode is not None:
            try:
                os.chmod(real_path, mode)
            except OSError:
                pass
        else:
            _restore_file_mode(Path(real_path), original_mode)
    except BaseException:
        # Intentionally catch BaseException so temp-file cleanup still runs for
        # KeyboardInterrupt/SystemExit before re-raising the original signal.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


class IndentDumper(yaml.SafeDumper):
    """PyYAML dumper that indents list items under mapping keys (2-space).

    Default PyYAML emits "indentless" sequences — list items start at the
    same column as their parent mapping key.  ``ruamel.yaml`` (used by
    :func:`atomic_roundtrip_yaml_update`) emits 2-space-indented sequences.
    Mixing both styles in the same ``config.yaml`` produces a file that
    stricter parsers like ``js-yaml`` reject with ``bad indentation of a
    mapping entry``.  Forcing ``indentless=False`` aligns the two
    serializers so all write paths emit byte-identical layouts (#31999).
    """

    def increase_indent(self, flow=False, indentless=False):  # noqa: ARG002
        return super().increase_indent(flow, False)


def atomic_yaml_write(
    path: Union[str, Path],
    data: Any,
    *,
    default_flow_style: bool = False,
    sort_keys: bool = False,
    extra_content: str | None = None,
    expected_state: Any = _STATE_UNCHECKED,
) -> None:
    """Write YAML data to a file atomically.

    Uses temp file + fsync + os.replace to ensure the target file is never
    left in a partially-written state.  If the process crashes mid-write,
    the previous version of the file remains intact.

    Args:
        path: Target file path (will be created or overwritten).
        data: YAML-serializable data to write.
        default_flow_style: YAML flow style (default False).
        sort_keys: Whether to sort dict keys (default False).
        extra_content: Optional string to append after the YAML dump
            (e.g. commented-out sections for user reference).
        expected_state: Stale-write guard for read-modify-write callers —
            pass the :func:`file_write_state` snapshot captured when the
            file was read (``None`` if it was absent).  If the file
            changed since, raises :class:`ConfigWriteConflictError`
            instead of replacing.  Omit for plain overwrites.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    original_mode = _preserve_file_mode(path)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.stem}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            # allow_unicode=True writes emoji/kaomoji (e.g. personalities, skin
            # cursors) as real UTF-8 instead of fragile escape sequences. Without
            # it, PyYAML emits astral-plane chars as `\UXXXXXXXX` (8-digit) escapes
            # inside multi-line double-quoted strings wrapped with `\`
            # continuations — a structure that stricter/non-PyYAML parsers and
            # hand-edits routinely break into unclosed quotes, corrupting the whole
            # config (GitHub #51356).
            yaml.dump(
                data,
                f,
                Dumper=IndentDumper,
                default_flow_style=default_flow_style,
                sort_keys=sort_keys,
                allow_unicode=True,
            )
            if extra_content:
                f.write(extra_content)
            f.flush()
            os.fsync(f.fileno())
        # Preserve symlinks — swap in-place on the real file (GitHub #16743).
        real_path = _replace_with_guard(tmp_path, path, expected_state)
        _restore_file_mode(real_path, original_mode)
    except BaseException:
        # Match atomic_json_write: cleanup must also happen for process-level
        # interruptions before we re-raise them.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def atomic_roundtrip_yaml_update(
    path: Union[str, Path],
    key_path: str,
    value: Any,
    *,
    max_attempts: int = 3,
) -> None:
    """Update one dotted YAML key while preserving comments and readable text.

    This is intentionally narrower than :func:`atomic_yaml_write`: it is for
    user-edited config files where comments, ordering, quoting, and Unicode
    should survive a single setting mutation.  Writes still use the same temp
    file + fsync + atomic replace pattern.

    The full read-modify-write cycle runs under :func:`config_file_lock`,
    so concurrent updaters serialize instead of losing each other's keys.
    If a non-locking writer still lands mid-cycle (stale-write guard), the
    cycle re-reads and re-applies up to *max_attempts* times — safe because
    setting one dotted key is idempotent — then raises
    :class:`ConfigWriteConflictError`.
    """
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    yaml_rt = YAML(typ="rt")
    yaml_rt.preserve_quotes = True
    yaml_rt.allow_unicode = True
    yaml_rt.default_flow_style = False
    yaml_rt.indent(mapping=2, sequence=4, offset=2)

    with config_file_lock(path):
        for attempt in range(max_attempts):
            snapshot = file_write_state(path)
            if path.exists():
                with path.open("r", encoding="utf-8") as f:
                    config = yaml_rt.load(f) or CommentedMap()
            else:
                config = CommentedMap()

            if not isinstance(config, CommentedMap):
                config = CommentedMap(config)

            current = config
            keys = key_path.split(".")
            for key in keys[:-1]:
                next_value = current.get(key)
                if not isinstance(next_value, CommentedMap):
                    next_value = CommentedMap()
                    current[key] = next_value
                current = next_value
            current[keys[-1]] = value

            original_mode = _preserve_file_mode(path)
            fd, tmp_path = tempfile.mkstemp(
                dir=str(path.parent),
                prefix=f".{path.stem}_",
                suffix=".tmp",
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    yaml_rt.dump(config, f)
                    f.flush()
                    os.fsync(f.fileno())
                real_path = _replace_with_guard(tmp_path, path, snapshot)
                _restore_file_mode(real_path, original_mode)
                return
            except BaseException as exc:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                if (
                    isinstance(exc, ConfigWriteConflictError)
                    and attempt < max_attempts - 1
                ):
                    continue
                raise


def locked_yaml_mutate(
    path: Union[str, Path],
    mutate: Callable[[dict], Any],
    *,
    sort_keys: bool = False,
    default_flow_style: bool = False,
    extra_content: "str | None" = None,
    max_attempts: int = 3,
) -> Optional[dict]:
    """Run a full read→modify→write cycle on a YAML mapping file, safely.

    Serializes the WHOLE cycle under :func:`config_file_lock` (not just the
    write) so two concurrent updates compose instead of last-writer-wins,
    and verifies the stale-write guard before replacing in case a
    non-locking writer raced anyway — in which case the cycle re-reads and
    re-applies *mutate*, up to *max_attempts* times.

    *mutate* receives the parsed dict (``{}`` if the file is absent or
    unparseable, matching the raw-read behavior of the call sites this
    replaces).  It edits in place, or returns a replacement dict, or
    returns :data:`SKIP_WRITE` to abort without writing (e.g. the value is
    already set).  Because of the retry loop it must be safe to call more
    than once.

    Returns the dict that was written, or ``None`` when skipped.
    """
    path = Path(path)
    with config_file_lock(path):
        for attempt in range(max_attempts):
            snapshot = file_write_state(path)
            data: dict = {}
            if path.exists():
                try:
                    with path.open(encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                except Exception:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
            result = mutate(data)
            if result is SKIP_WRITE:
                return None
            if result is not None:
                data = result
            try:
                atomic_yaml_write(
                    path,
                    data,
                    sort_keys=sort_keys,
                    default_flow_style=default_flow_style,
                    extra_content=extra_content,
                    expected_state=snapshot,
                )
                return data
            except ConfigWriteConflictError:
                if attempt == max_attempts - 1:
                    raise
    return None


# ─── JSON Helpers ─────────────────────────────────────────────────────────────


def safe_json_loads(text: str, default: Any = None) -> Any:
    """Parse JSON, returning *default* on any parse error.

    Replaces the ``try: json.loads(x) except (JSONDecodeError, TypeError)``
    pattern duplicated across display.py, anthropic_adapter.py,
    auxiliary_client.py, and others.
    """
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return default


# ── Fast YAML loading ────────────────────────────────────────────────────
#
# PyYAML's pure-Python SafeLoader is ~8x slower than the libyaml-backed
# ``CSafeLoader`` C extension. Startup parses config.yaml and every plugin
# manifest with the slow path, costing ~0.9s of cold-start time. The C loader
# is a true drop-in for ``safe_load`` (same restricted tag set), so prefer it
# and fall back to the pure-Python loader only when libyaml isn't compiled in.
_fast_yaml_loader = None


def _get_fast_yaml_loader():
    global _fast_yaml_loader
    if _fast_yaml_loader is None:
        _fast_yaml_loader = getattr(yaml, "CSafeLoader", None) or yaml.SafeLoader
    return _fast_yaml_loader


def fast_safe_load(stream: Any) -> Any:
    """``yaml.safe_load`` using the libyaml C loader when available.

    Accepts the same inputs as ``yaml.safe_load`` (a ``str``/``bytes`` document
    or a readable file object) and returns the same parsed structure. Falls
    back to PyYAML's pure-Python ``SafeLoader`` when ``CSafeLoader`` isn't
    available, so behavior is identical everywhere — only the speed differs.
    """
    return yaml.load(stream, Loader=_get_fast_yaml_loader())


# ─── Environment Variable Helpers ─────────────────────────────────────────────


def env_int(key: str, default: int = 0) -> int:
    """Read an environment variable as an integer, with fallback."""
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except (ValueError, TypeError):
        return default


def env_float(key: str, default: float = 0.0) -> float:
    """Read an environment variable as a float, with fallback."""
    raw = os.getenv(key, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except (ValueError, TypeError):
        return default


def env_bool(key: str, default: bool = False) -> bool:
    """Read an environment variable as a boolean."""
    return is_truthy_value(os.getenv(key, ""), default=default)


# ─── Proxy Helpers ────────────────────────────────────────────────────────────


_PROXY_ENV_KEYS = (
    "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY",
    "https_proxy", "http_proxy", "all_proxy",
)


def normalize_proxy_url(proxy_url: str | None) -> str | None:
    """Normalize proxy URLs for httpx/aiohttp compatibility.

    WSL/Clash-style environments often export SOCKS proxies as
    ``socks://127.0.0.1:PORT``. httpx rejects that alias and expects the
    explicit ``socks5://`` scheme instead.
    """
    candidate = str(proxy_url or "").strip()
    if not candidate:
        return None
    if candidate.lower().startswith("socks://"):
        return f"socks5://{candidate[len('socks://'):]}"
    return candidate


def normalize_proxy_env_vars() -> None:
    """Rewrite supported proxy env vars to canonical URL forms in-place."""
    for key in _PROXY_ENV_KEYS:
        value = os.getenv(key, "")
        normalized = normalize_proxy_url(value)
        if normalized and normalized != value:
            os.environ[key] = normalized


# ─── URL Parsing Helpers ──────────────────────────────────────────────────────


def base_url_hostname(base_url: str) -> str:
    """Return the lowercased hostname for a base URL, or ``""`` if absent.

    Use exact-hostname comparisons against known provider hosts
    (``api.openai.com``, ``api.x.ai``, ``api.anthropic.com``) instead of
    substring matches on the raw URL. Substring checks treat attacker- or
    proxy-controlled paths/hosts like ``https://api.openai.com.example/v1``
    or ``https://proxy.test/api.openai.com/v1`` as native endpoints, which
    leads to wrong api_mode / auth routing.
    """
    raw = (base_url or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").lower().rstrip(".")


# ─── Model Capability Detection ──────────────────────────────────────────────


def model_forces_max_completion_tokens(model: str) -> bool:
    """Return True for model families that require ``max_completion_tokens``.

    OpenAI's newer families reject ``max_tokens`` on /v1/chat/completions with
    HTTP 400 ``unsupported_parameter`` — the caller must send
    ``max_completion_tokens`` instead. This covers:

    - ``gpt-4o`` / ``gpt-4o-mini`` / ``gpt-4o-*``
    - ``gpt-4.1`` / ``gpt-4.1-*``
    - ``gpt-5`` / ``gpt-5.x`` / ``gpt-5-*``
    - ``o1`` / ``o1-*``
    - ``o3`` / ``o3-*``
    - ``o4`` / ``o4-*``

    Handles vendor prefixes like ``openai/gpt-5.4`` by stripping to the tail.
    The URL-based check (``base_url_hostname == "api.openai.com"``) misses
    third-party OpenAI-compatible endpoints (custom OpenAI gateways,
    OpenRouter) that front these models and enforce the same parameter
    constraint, so name-based detection is required as a fallback.
    """
    m = (model or "").strip().lower()
    if not m:
        return False
    if "/" in m:
        m = m.rsplit("/", 1)[-1]
    return (
        m.startswith("gpt-4o")
        or m.startswith("gpt-4.1")
        or m.startswith("gpt-5")
        or m.startswith("o1")
        or m.startswith("o3")
        or m.startswith("o4")
    )


def base_url_host_matches(base_url: str, domain: str) -> bool:
    """Return True when the base URL's hostname is ``domain`` or a subdomain.

    Safer counterpart to ``domain in base_url``, which is the substring
    false-positive class documented on ``base_url_hostname``. Accepts bare
    hosts, full URLs, and URLs with paths.

        base_url_host_matches("https://api.moonshot.ai/v1", "moonshot.ai") == True
        base_url_host_matches("https://moonshot.ai", "moonshot.ai")        == True
        base_url_host_matches("https://evil.com/moonshot.ai/v1", "moonshot.ai") == False
        base_url_host_matches("https://moonshot.ai.evil/v1", "moonshot.ai")     == False
    """
    hostname = base_url_hostname(base_url)
    if not hostname:
        return False
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return False
    return hostname == domain or hostname.endswith("." + domain)

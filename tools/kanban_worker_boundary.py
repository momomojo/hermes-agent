"""Fail-closed filesystem boundary for dispatcher-owned model tool calls."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from agent.delegation_context import is_dispatcher_owned_worker_context


WORKER_GIT_SECURITY_BOUNDARY = "hermes.worker_git_isolation.v1"


_LOCAL_SANDBOX_WORKSPACE: ContextVar[Path | None] = ContextVar(
    "hermes_kanban_local_sandbox_workspace",
    default=None,
)


class WorkerSandboxUnavailable(RuntimeError):
    """Raised when the host cannot provide a real filesystem boundary."""


def _boundary_expected() -> bool:
    return (
        is_dispatcher_owned_worker_context()
        and os.environ.get("HERMES_SESSION_SOURCE") == "kanban"
        and bool(str(os.environ.get("HERMES_KANBAN_TASK") or "").strip())
    )


def dispatcher_worker_boundary_expected() -> bool:
    """Return whether this execution must stay inside the worker boundary."""
    return _boundary_expected()


@dataclass(frozen=True)
class _LiveAssignment:
    workspace: Path
    workspace_kind: str


def _live_assignment(
    *,
    task_id: str,
    run_id: int,
    claim_lock: str,
    env_workspace: Path,
) -> _LiveAssignment | None:
    """Read back the durable claim so a reclaimed process loses authority."""
    raw_db = str(os.environ.get("HERMES_KANBAN_DB") or "").strip()
    board = str(os.environ.get("HERMES_KANBAN_BOARD") or "").strip()
    if not raw_db or not board:
        return None
    db_path = Path(raw_db).expanduser()
    if not db_path.is_absolute():
        return None
    try:
        db_path = db_path.resolve(strict=True)
        conn = sqlite3.connect(
            f"{db_path.as_uri()}?mode=ro",
            uri=True,
            timeout=1.0,
        )
        try:
            row = conn.execute(
                "SELECT status, current_run_id, claim_lock, workspace_kind, "
                "workspace_path, branch_name, project_id FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
        finally:
            conn.close()
    except (OSError, RuntimeError, sqlite3.Error):
        return None
    if row is None:
        return None
    (
        status,
        current_run_id,
        durable_claim,
        workspace_kind,
        durable_workspace,
        durable_branch,
        durable_project,
    ) = row
    try:
        stored_workspace = Path(str(durable_workspace)).expanduser().resolve(
            strict=True
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if not (
        status == "running"
        and current_run_id == run_id
        and durable_claim == claim_lock
        and stored_workspace == env_workspace
    ):
        return None

    # Durable ``dir`` and legacy explicit ``scratch`` paths are supported, but
    # a board row must never turn its own database or a known credential store
    # into the model's writable workspace.  This is host-state validation, not
    # trust in a worker-provided path: ``stored_workspace`` and ``db_path`` were
    # both read back from the exact live board claim above.
    try:
        if stored_workspace == Path("/"):
            return None
        db_path.relative_to(stored_workspace)
    except ValueError:
        pass
    else:
        return None
    try:
        sensitive_paths = _credential_read_paths(stored_workspace)
    except (OSError, RuntimeError, WorkerSandboxUnavailable):
        return None
    for sensitive in sensitive_paths:
        try:
            sensitive.relative_to(stored_workspace)
        except ValueError:
            continue
        return None

    branch = str(os.environ.get("HERMES_KANBAN_BRANCH") or "").strip()
    sealed_repo = str(
        os.environ.get("HERMES_KANBAN_TRUSTED_REPO_ROOT") or ""
    ).strip()
    if workspace_kind == "worktree":
        if (
            not branch
            or not sealed_repo
            or "HERMES_KANBAN_PROJECT_ID" not in os.environ
        ):
            return None
        try:
            repo = Path(sealed_repo).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            return None
        expected = (repo / ".worktrees" / task_id).resolve(strict=False)
        leaf = branch.rsplit("/", 1)[-1]
        if not (
            stored_workspace == expected
            and durable_branch == branch
            and str(durable_project or "")
            == str(os.environ.get("HERMES_KANBAN_PROJECT_ID") or "")
            and (
                branch == f"wt/{task_id}"
                or leaf == task_id
                or leaf.startswith(f"{task_id}-")
            )
        ):
            return None
        return _LiveAssignment(stored_workspace, "worktree")

    if workspace_kind in {"scratch", "dir"}:
        # Non-Git tasks deliberately have no Git/project authority. A stale
        # worktree seal inherited into one is a confused-deputy condition.
        if branch or sealed_repo or "HERMES_KANBAN_PROJECT_ID" in os.environ:
            return None
        if durable_branch:
            return None
        if workspace_kind == "dir":
            return _LiveAssignment(stored_workspace, "dir")

        # The current scratch layout is exactly <managed-root>/<task-id>. Keep
        # that sibling isolation. Older durable tasks may carry an explicit
        # absolute path outside the managed root; resolve_workspace() preserves
        # those by design, so the exact live DB path is their authority.
        raw_root = str(
            os.environ.get("HERMES_KANBAN_WORKSPACES_ROOT") or ""
        ).strip()
        if not raw_root:
            return None
        try:
            root = Path(raw_root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            return None
        try:
            relative = stored_workspace.relative_to(root)
        except ValueError:
            relative = None
        if relative is not None and relative.parts != (task_id,):
            return None
        return _LiveAssignment(stored_workspace, "scratch")
    return None


def _assigned_live_assignment() -> _LiveAssignment | None:
    """Return the durable dispatcher assignment for the owning execution."""
    if not _boundary_expected():
        return None
    task_id = str(os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    run_id = str(os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    claim_lock = str(os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or "").strip()
    if not all((task_id, run_id, claim_lock)):
        return None
    try:
        exact_run_id = int(run_id)
    except ValueError:
        return None
    raw = str(os.environ.get("HERMES_KANBAN_WORKSPACE") or "").strip()
    if not raw:
        return None
    workspace = Path(raw).expanduser()
    if not workspace.is_absolute():
        return None
    try:
        workspace = workspace.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    assignment = _live_assignment(
        task_id=task_id,
        run_id=exact_run_id,
        claim_lock=claim_lock,
        env_workspace=workspace,
    )
    if assignment is None:
        return None
    return assignment


def assigned_workspace() -> Path | None:
    """Return the exact dispatcher workspace that requires the OS sandbox."""
    assignment = _assigned_live_assignment()
    return assignment.workspace if assignment is not None else None


def current_local_sandbox_workspace() -> Path | None:
    """Return the task workspace whose local subprocess is being sandboxed."""
    return _LOCAL_SANDBOX_WORKSPACE.get()


@contextmanager
def local_worker_sandbox(workspace: Path) -> Iterator[None]:
    """Scope one local environment execution to the exact task workspace."""
    token = _LOCAL_SANDBOX_WORKSPACE.set(workspace.resolve(strict=True))
    try:
        yield
    finally:
        _LOCAL_SANDBOX_WORKSPACE.reset(token)


def _worker_temp_root(workspace: Path) -> Path:
    """Return a private, task/run-bound temp root outside the commit tree."""
    import hashlib

    identity = "\0".join(
        (
            str(workspace),
            str(os.environ.get("HERMES_KANBAN_TASK") or ""),
            str(os.environ.get("HERMES_KANBAN_RUN_ID") or ""),
            str(os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or ""),
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    parent = Path(tempfile.gettempdir()).resolve() / "hermes-kanban-worker"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink():
        raise WorkerSandboxUnavailable("worker sandbox temp root is a symlink")
    root = parent / digest
    root.mkdir(mode=0o700, exist_ok=True)
    if root.is_symlink() or root.resolve(strict=True).parent != parent:
        raise WorkerSandboxUnavailable("worker sandbox temp identity is unsafe")
    try:
        root.chmod(0o700)
    except OSError as exc:
        raise WorkerSandboxUnavailable(
            "worker sandbox temp permissions could not be enforced"
        ) from exc
    return root.resolve(strict=True)


def _credential_read_paths(workspace: Path | None = None) -> tuple[Path, ...]:
    """Return host credential locations that model subprocesses must not read."""
    candidates: list[Path] = []
    try:
        from agent.file_safety import _hermes_home_path, _hermes_root_path

        active_home = _hermes_home_path()
        hermes_root = _hermes_root_path()
    except Exception:
        active_home = Path(
            str(os.environ.get("HERMES_HOME") or "~/.hermes")
        ).expanduser()
        hermes_root = Path.home() / ".hermes"

    hermes_bases = [active_home, hermes_root]
    profiles_dir = hermes_root / "profiles"
    try:
        hermes_bases.extend(path for path in profiles_dir.iterdir() if path.is_dir())
    except OSError:
        pass
    credential_files = (
        "auth.json",
        "auth.lock",
        ".anthropic_oauth.json",
        ".env",
        "webhook_subscriptions.json",
        "auth/google_oauth.json",
        "cache/bws_cache.json",
        "cache/bws_cache.enc.json",
    )
    for base in hermes_bases:
        candidates.extend(base / relative for relative in credential_files)
        candidates.extend((base / "mcp-tokens", base / "skills" / ".hub"))
    candidates.append(hermes_root / "shared" / "nous_auth.json")
    shared_auth_dir = str(os.environ.get("HERMES_SHARED_AUTH_DIR") or "").strip()
    if shared_auth_dir:
        candidates.append(Path(shared_auth_dir).expanduser() / "nous_auth.json")

    home = Path.home()
    candidates.extend(
        (
            home / ".ssh",
            home / ".gnupg",
            home / ".aws",
            home / ".kube",
            home / ".config" / "gh",
            home / ".config" / "gcloud",
            home / ".git-credentials",
            home / ".netrc",
            home / "Library" / "Keychains",
        )
    )
    unique: list[Path] = []
    seen: set[Path] = set()
    exact_workspace = workspace.resolve(strict=True) if workspace is not None else None
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_absolute() or resolved in seen:
            continue
        if exact_workspace is not None:
            try:
                exact_workspace.relative_to(resolved)
            except ValueError:
                pass
            else:
                raise WorkerSandboxUnavailable(
                    "assigned workspace overlaps a host credential location"
                )
        seen.add(resolved)
        unique.append(resolved)
    return tuple(unique)


def _seatbelt_profile(workspace: Path, temp_root: Path) -> str:
    """Build the macOS Seatbelt profile for one worker execution."""
    quoted_workspace = json.dumps(str(workspace))
    quoted_temp = json.dumps(str(temp_root))
    quoted_gitfile = json.dumps(str(workspace / ".git"))
    rules = [
        "(version 1)",
        "(deny default)",
        "(allow process*)",
        "(allow file-read*)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow ipc-posix-shm)",
        "(allow ipc-posix-sem)",
        f"(allow file-write* (subpath {quoted_workspace}) "
        f"(subpath {quoted_temp}) (literal \"/dev/null\"))",
        f"(deny file-write* (literal {quoted_gitfile}) "
        f"(subpath {quoted_gitfile}))",
        "(deny network*)",
    ]
    for sensitive in _credential_read_paths(workspace):
        quoted = json.dumps(str(sensitive))
        rules.append(
            f"(deny file-read* (literal {quoted}) (subpath {quoted}))"
        )
    return " ".join(rules)


def _bubblewrap_read_masks(workspace: Path) -> list[str]:
    """Mask exact host credential paths that lie in an exposed system tree."""
    args: list[str] = []
    for sensitive in _credential_read_paths(workspace):
        try:
            if sensitive.is_dir():
                args.extend(("--tmpfs", str(sensitive)))
            elif sensitive.exists():
                args.extend(("--ro-bind", "/dev/null", str(sensitive)))
            else:
                continue
        except OSError:
            continue
    return args


def _bubblewrap_system_roots() -> tuple[tuple[Path, Path], ...]:
    """Return the small immutable host view needed to execute local tools."""
    candidates = (
        Path("/usr"),
        Path("/bin"),
        Path("/sbin"),
        Path("/lib"),
        Path("/lib64"),
        Path("/usr/local"),
        Path("/opt"),
        Path("/etc"),
        Path("/nix/store"),
        Path(sys.prefix),
        Path(sys.base_prefix),
    )
    roots: list[tuple[Path, Path]] = []
    seen: set[tuple[Path, Path]] = set()
    for candidate in candidates:
        try:
            if not candidate.exists():
                continue
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        destination = candidate
        pair = (resolved, destination)
        if resolved == Path("/") or pair in seen:
            continue
        # Avoid redundant identity mounts below an already exposed immutable
        # tree, but preserve merged-/usr aliases such as /bin -> /usr/bin: the
        # empty sandbox root does not otherwise contain the alias path.
        if destination == resolved and any(
            resolved == source or resolved.is_relative_to(source)
            for source, _target in roots
        ):
            continue
        seen.add(pair)
        roots.append(pair)
    return tuple(roots)


def local_sandbox_argv(argv: Sequence[str], workspace: Path) -> list[str]:
    """Wrap argv in a real local filesystem+network sandbox.

    macOS uses Seatbelt. Linux uses bubblewrap with a minimal immutable system
    view and only the exact task workspace plus private task temp writable.
    Unsupported hosts fail closed instead of falling back to command parsing.
    """
    exact_workspace = workspace.expanduser().resolve(strict=True)
    temp_root = _worker_temp_root(exact_workspace)
    system = platform.system()
    if system == "Darwin":
        sandbox_exec = shutil.which("sandbox-exec")
        if not sandbox_exec:
            raise WorkerSandboxUnavailable("macOS sandbox-exec is unavailable")
        return [
            sandbox_exec,
            "-p",
            _seatbelt_profile(exact_workspace, temp_root),
            "/usr/bin/env",
            f"HOME={temp_root}",
            f"TMPDIR={temp_root}",
            *argv,
        ]
    if system == "Linux":
        bubblewrap = shutil.which("bwrap")
        if not bubblewrap:
            raise WorkerSandboxUnavailable(
                "Linux bubblewrap (bwrap) is required for Kanban workers"
            )
        args = [
            bubblewrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
        ]
        # Do not bind host /. AF_UNIX ignores network namespaces, so a
        # read-only full-root view still exposes control sockets anywhere on
        # the host. Bind only immutable executable/runtime trees; /run, /tmp,
        # /var/tmp, and the user's home are private empty mounts.
        private_roots = (Path("/run"), Path("/tmp"), Path("/var/tmp"), Path.home())
        seen_private: set[Path] = set()
        for private_root in private_roots:
            if private_root == Path("/") or private_root in seen_private:
                continue
            try:
                private_root.relative_to(exact_workspace)
            except ValueError:
                pass
            else:
                raise WorkerSandboxUnavailable(
                    "assigned workspace is too broad for private runtime isolation"
                )
            seen_private.add(private_root)
            args.extend(("--tmpfs", str(private_root)))
        for system_source, system_target in _bubblewrap_system_roots():
            args.extend(("--ro-bind", str(system_source), str(system_target)))
        args.extend([
            "--bind",
            str(exact_workspace),
            str(exact_workspace),
        ])
        git_metadata = exact_workspace / ".git"
        if git_metadata.exists():
            args.extend(("--ro-bind", str(git_metadata), str(git_metadata)))
        args.extend([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            *_bubblewrap_read_masks(exact_workspace),
            "--bind",
            str(temp_root),
            str(temp_root),
            "--setenv",
            "HOME",
            str(temp_root),
            "--setenv",
            "TMPDIR",
            str(temp_root),
            *argv,
        ])
        return args
    raise WorkerSandboxUnavailable(
        f"{system or 'unknown'} has no supported Kanban worker filesystem sandbox"
    )


def terminal_backend_violation(env_type: str, *, background: bool) -> str | None:
    """Fail closed unless this worker command can use a verified OS sandbox."""
    assignment = _assigned_live_assignment()
    if assignment is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy terminal run."
            )
        return None
    workspace = assignment.workspace
    if background:
        return (
            "Blocked: dispatcher-owned Kanban workers cannot start background "
            "commands outside the trusted broker lifecycle. Run bounded tests "
            "in the foreground."
        )
    if env_type != "local":
        return (
            "Blocked: dispatcher-owned Kanban workers require the verified local "
            "filesystem sandbox; remote/container/SSH terminal backends are not "
            "part of the trusted Git handoff boundary."
        )
    try:
        # Preflight the exact platform boundary without executing anything.
        local_sandbox_argv(["/usr/bin/true"], workspace)
    except (OSError, RuntimeError) as exc:
        return f"Blocked: verified local filesystem sandbox unavailable: {exc}"
    return None


def execute_code_violation() -> str | None:
    """Disable the unsandboxed sibling arbitrary-code path for workers."""
    assignment = _assigned_live_assignment()
    if assignment is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing stale/confused-deputy execute_code."
            )
        return None
    return (
        "Blocked: execute_code is disabled for dispatcher-owned Kanban workers. "
        "Run bounded tests through the verified local terminal sandbox; Git "
        "commit and publishing remain host-broker-only."
    )


def terminal_violation(command: str, cwd: str | None) -> str | None:
    """Return an unoverrideable denial for a model shell boundary crossing."""
    assignment = _assigned_live_assignment()
    if assignment is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy terminal run."
            )
        return None
    workspace = assignment.workspace
    try:
        command_cwd = Path(cwd or os.getcwd()).expanduser().resolve(strict=True)
        command_cwd.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        return (
            "Blocked: dispatcher-owned Kanban terminal commands must run inside "
            f"the assigned workspace ({workspace})."
        )
    if any(
        marker in command
        for marker in (
            "HERMES_KANBAN_DB",
            "HERMES_KANBAN_WORKSPACES_ROOT",
            "HERMES_KANBAN_ROOT",
        )
    ):
        return (
            "Blocked: Kanban board/database paths are host-tool-only; model-facing "
            "workers must use the kanban_* lifecycle tools."
        )
    return _command_git_violation(command, command_cwd, depth=0, visited=set())


def _command_git_violation(
    command: str,
    cwd: Path,
    *,
    depth: int,
    visited: set[Path],
) -> str | None:
    """Scan a command plus bounded referenced shell scripts."""
    from tools.self_repo_guard import detect_kanban_worker_git_violation

    hit, message = detect_kanban_worker_git_violation(command, str(cwd))
    if hit:
        return message
    if depth >= 4:
        return (
            "Blocked: referenced shell-script nesting exceeded the Kanban Git "
            "boundary's safe scan depth."
        )
    # Reuse the hardened bounded regular-file reader already used by the
    # gateway lifecycle guard (binary skip, oversized fail-closed, no device or
    # cloud-placeholder reads). This closes `bash mutate.sh` indirection.
    from cron.lifecycle_guard import (
        _iter_referenced_shell_scripts,
        _read_referenced_script,
    )

    for raw_path in _iter_referenced_shell_scripts(command, cwd=str(cwd)):
        try:
            script_path = raw_path.resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            return "Blocked: referenced shell script path could not be validated."
        if script_path in visited:
            continue
        visited.add(script_path)
        script, unsafe = _read_referenced_script(raw_path)
        if unsafe:
            return "Blocked: referenced shell script could not be safely inspected."
        if not script:
            continue
        violation = _command_git_violation(
            script,
            script_path.parent,
            depth=depth + 1,
            visited=visited,
        )
        if violation:
            return violation
    return None


def write_path_violation(path: str | Path) -> str | None:
    """Return a denial when a model file tool targets control-plane state."""
    assignment = _assigned_live_assignment()
    if assignment is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy file write."
            )
        return None
    workspace = assignment.workspace
    try:
        target = Path(path).expanduser().resolve(strict=False)
        relative = target.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        return (
            f"Blocked: {path} is outside the assigned Kanban workspace "
            f"({workspace}); board lifecycle state is host-tool-only."
        )
    if ".git" in relative.parts:
        return (
            "Blocked: Git metadata is host-broker-only for dispatcher-owned "
            "Kanban workers. Edit normal task files instead."
        )
    return None

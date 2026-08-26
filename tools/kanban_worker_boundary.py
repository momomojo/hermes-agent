"""Fail-closed filesystem boundary for dispatcher-owned model tool calls."""

from __future__ import annotations

import json
import os
import platform
import shutil
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
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


def assigned_workspace() -> Path | None:
    """Return the exact dispatcher workspace only for the owning execution."""
    if not _boundary_expected():
        return None
    task_id = str(os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    run_id = str(os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    claim_lock = str(os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or "").strip()
    branch = str(os.environ.get("HERMES_KANBAN_BRANCH") or "").strip()
    sealed_repo = str(
        os.environ.get("HERMES_KANBAN_TRUSTED_REPO_ROOT") or ""
    ).strip()
    if not all((task_id, run_id, claim_lock, branch, sealed_repo)):
        return None
    try:
        int(run_id)
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
        repo = Path(sealed_repo).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    expected = (repo / ".worktrees" / task_id).resolve(strict=False)
    if workspace != expected:
        return None
    leaf = branch.rsplit("/", 1)[-1]
    if not (branch == f"wt/{task_id}" or leaf == task_id or leaf.startswith(f"{task_id}-")):
        return None
    return workspace


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


def _credential_read_paths() -> tuple[Path, ...]:
    """Return host credential locations that model subprocesses must not read."""
    candidates: list[Path] = []
    raw_hermes_home = str(os.environ.get("HERMES_HOME") or "").strip()
    if raw_hermes_home:
        candidates.append(Path(raw_hermes_home).expanduser())
    home = Path.home()
    candidates.extend(
        (
            home / ".hermes",
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
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if not resolved.is_absolute() or resolved in seen:
            continue
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
    for sensitive in _credential_read_paths():
        quoted = json.dumps(str(sensitive))
        rules.append(
            f"(deny file-read* (literal {quoted}) (subpath {quoted}))"
        )
    return " ".join(rules)


def _bubblewrap_read_masks(temp_root: Path) -> list[str]:
    """Mask existing host credential paths inside a read-only root bind."""
    empty_dir = temp_root / ".masked-credential-dir"
    empty_file = temp_root / ".masked-credential-file"
    empty_dir.mkdir(mode=0o700, exist_ok=True)
    empty_file.touch(mode=0o600, exist_ok=True)
    args: list[str] = []
    for sensitive in _credential_read_paths():
        try:
            if sensitive.is_dir():
                source = empty_dir
            elif sensitive.exists():
                source = empty_file
            else:
                continue
        except OSError:
            continue
        args.extend(("--ro-bind", str(source), str(sensitive)))
    return args


def local_sandbox_argv(argv: Sequence[str], workspace: Path) -> list[str]:
    """Wrap argv in a real local filesystem+network sandbox.

    macOS uses Seatbelt. Linux uses bubblewrap with a read-only host root and
    only the exact task workspace plus private task temp rebound writable.
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
        return [
            bubblewrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-net",
            "--unshare-pid",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            str(exact_workspace),
            str(exact_workspace),
            "--ro-bind",
            str(exact_workspace / ".git"),
            str(exact_workspace / ".git"),
            *_bubblewrap_read_masks(temp_root),
            "--bind",
            str(temp_root),
            str(temp_root),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--setenv",
            "HOME",
            str(temp_root),
            "--setenv",
            "TMPDIR",
            str(temp_root),
            *argv,
        ]
    raise WorkerSandboxUnavailable(
        f"{system or 'unknown'} has no supported Kanban worker filesystem sandbox"
    )


def terminal_backend_violation(env_type: str, *, background: bool) -> str | None:
    """Fail closed unless this worker command can use a verified OS sandbox."""
    workspace = assigned_workspace()
    if workspace is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy terminal run."
            )
        return None
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
    """Disable the sibling arbitrary-code path for dispatcher workers."""
    workspace = assigned_workspace()
    if workspace is None:
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
    workspace = assigned_workspace()
    if workspace is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy terminal run."
            )
        return None
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
    workspace = assigned_workspace()
    if workspace is None:
        if _boundary_expected():
            return (
                "Blocked: dispatcher-owned Kanban workspace authority is missing "
                "or inconsistent; refusing a stale/confused-deputy file write."
            )
        return None
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

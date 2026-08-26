"""Fail-closed filesystem boundary for dispatcher-owned model tool calls."""

from __future__ import annotations

import os
from pathlib import Path

from agent.delegation_context import is_dispatcher_owned_worker_context


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

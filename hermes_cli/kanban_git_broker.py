"""Trusted post-turn Git broker for dispatcher-owned Kanban workers.

Model-facing workers may edit and test their assigned checkout, but cannot
write shared Git metadata. This module runs only after the model turn returns
to the unsandboxed Hermes worker host. It derives authority from the active
claim plus board/project metadata, never from a worker-supplied Git path.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any

from agent.delegation_context import is_dispatcher_owned_worker_context
from hermes_cli import kanban_db as kb

PUBLISH_CONTRACT = "hermes.trusted_local_commit.v1"
PUBLISH_MARKER = "AWAITING_TRUSTED_PUBLISHER v1"
FAILURE_MARKER = "TRUSTED_LOCAL_COMMIT_FAILED v1"
_BROKER_AUTHOR_EMAIL = "hermes-kanban@localhost.invalid"

_PROTECTED_BRANCHES = frozenset({
    "main",
    "master",
    "develop",
    "development",
    "production",
})
_UNSAFE_CONFIG = re.compile(
    r"^(?:core\.hooksPath|core\.fsmonitor|credential\.helper|"
    r"filter\..+\.(?:clean|process)|diff\..+\.(?:command|textconv)|"
    r"merge\..+\.driver|alias\..+|include(?:If)?\..+)$",
    re.IGNORECASE,
)


class BrokerRejected(RuntimeError):
    """Raised when durable worker identity does not match the trusted checkout."""


def _base_git_env() -> dict[str, str]:
    # Git is strictly local here. Build a small allowlist instead of copying
    # the long-lived Hermes process env: stale worker GIT_* overrides,
    # provider/GitHub credentials, SSH agents, and dynamic-loader injection
    # variables must never cross this privileged broker boundary.
    env = {
        key: value
        for key in (
            "PATH",
            "HOME",
            "TMPDIR",
            "TEMP",
            "TMP",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "SYSTEMROOT",
            "COMSPEC",
            "PATHEXT",
        )
        if (value := os.environ.get(key)) is not None
    }
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
        "GIT_AUTHOR_NAME": "Hermes Trusted Kanban Broker",
        "GIT_AUTHOR_EMAIL": _BROKER_AUTHOR_EMAIL,
        "GIT_COMMITTER_NAME": "Hermes Trusted Kanban Broker",
        "GIT_COMMITTER_EMAIL": _BROKER_AUTHOR_EMAIL,
    })
    return env


def _git(
    args: list[str],
    *,
    git_dir: Path | None = None,
    work_tree: Path | None = None,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    cmd = [
        "git",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "tag.gpgSign=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
    ]
    if git_dir is not None:
        cmd.append(f"--git-dir={git_dir}")
    if work_tree is not None:
        cmd.append(f"--work-tree={work_tree}")
    cmd.extend(args)
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        env=_base_git_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "git command failed").strip()
        raise BrokerRejected(detail[:500])
    return result


def _trusted_repo_root(board: str, sealed_repo: str) -> tuple[Path, dict[str, Any]]:
    metadata = kb.read_board_metadata(board)
    raw = str(metadata.get("default_workdir") or "").strip()
    if not raw:
        raise BrokerRejected("board has no trusted default_workdir")
    configured = Path(raw).expanduser()
    if not configured.is_absolute():
        raise BrokerRejected("trusted board checkout is not absolute")
    repo = Path(sealed_repo).expanduser()
    if not repo.is_absolute():
        raise BrokerRejected("dispatcher-sealed repository is not absolute")
    repo = repo.resolve(strict=True)
    if configured.resolve(strict=True) != repo:
        raise BrokerRejected(
            "board checkout does not match dispatcher-sealed repository"
        )
    if not (repo / ".git").is_dir():
        raise BrokerRejected(
            "dispatcher-sealed repository is not a normal Git checkout"
        )
    result = _git(
        ["rev-parse", "--show-toplevel"],
        git_dir=repo / ".git",
        work_tree=repo,
    )
    if Path(result.stdout.strip()).resolve(strict=True) != repo:
        raise BrokerRejected("dispatcher-sealed repository identity is inconsistent")
    return repo, metadata


def _trusted_worktree_git_dir(common_dir: Path, workspace: Path) -> Path:
    registry = common_dir / "worktrees"
    expected_gitfile = (workspace / ".git").resolve(strict=False)
    matches: list[Path] = []
    if registry.is_dir():
        for entry in registry.iterdir():
            gitdir_file = entry / "gitdir"
            if not gitdir_file.is_file():
                continue
            try:
                registered = Path(gitdir_file.read_text(encoding="utf-8").strip())
            except OSError:
                continue
            if registered.resolve(strict=False) == expected_gitfile:
                matches.append(entry.resolve(strict=True))
    if len(matches) != 1:
        raise BrokerRejected("workspace is not the exact trusted linked worktree")
    return matches[0]


def _validate_branch(task_id: str, branch: str) -> None:
    leaf = branch.rsplit("/", 1)[-1]
    if (
        branch.casefold() in _PROTECTED_BRANCHES
        or leaf.casefold() in _PROTECTED_BRANCHES
    ):
        raise BrokerRejected("protected branch is never worker-committable")
    if not (
        branch == f"wt/{task_id}" or leaf == task_id or leaf.startswith(f"{task_id}-")
    ):
        raise BrokerRejected("branch is not bound to the exact task id")
    if _git(["check-ref-format", "--branch", branch], check=False).returncode != 0:
        raise BrokerRejected("branch name is not a valid Git branch")


def _reject_and_block(conn, task, run_id: int, reason: str) -> dict[str, Any]:
    safe_reason = " ".join(str(reason).split())[:500]
    kb.block_task(
        conn,
        task.id,
        reason=f"{FAILURE_MARKER}: {safe_reason}",
        kind="capability",
        expected_run_id=run_id,
    )
    return {"outcome": "rejected", "reason": safe_reason, "task_id": task.id}


def _pending_request(conn, task_id: str, run_id: int) -> dict[str, Any] | None:
    for event in reversed(kb.list_events(conn, task_id)):
        if (
            event.kind != kb.TRUSTED_GIT_COMPLETION_REQUEST_EVENT
            or event.run_id != run_id
        ):
            continue
        payload = event.payload
        if (
            isinstance(payload, dict)
            and payload.get("contract") == "hermes.trusted_git_completion_request.v1"
        ):
            return payload
    return None


def _recover_exact_broker_commit(
    *,
    git_dir: Path,
    workspace: Path,
    task_id: str,
    run_id: int,
) -> tuple[str, str] | None:
    """Return ``(base, head)`` for this exact run's interrupted broker commit."""
    head_sha = _git(
        ["rev-parse", "HEAD"], git_dir=git_dir, work_tree=workspace
    ).stdout.strip()
    message = _git(
        ["show", "-s", "--format=%ae%n%B", head_sha],
        git_dir=git_dir,
        work_tree=workspace,
    ).stdout.splitlines()
    if not message or message[0].strip() != _BROKER_AUTHOR_EMAIL:
        return None
    expected = {
        "Hermes-Kanban-Task": task_id,
        "Hermes-Kanban-Run": str(run_id),
    }
    trailers: dict[str, str] = {}
    for line in message[1:]:
        key, separator, value = line.partition(":")
        if separator and key in {
            "Hermes-Kanban-Task",
            "Hermes-Kanban-Run",
            "Hermes-Kanban-Base",
        }:
            trailers[key] = value.strip()
    if any(trailers.get(key) != value for key, value in expected.items()):
        return None
    base_sha = trailers.get("Hermes-Kanban-Base", "")
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        return None
    actual_parent = _git(
        ["rev-parse", f"{head_sha}^"], git_dir=git_dir, work_tree=workspace
    ).stdout.strip()
    if actual_parent != base_sha:
        return None
    return base_sha, head_sha


def _recover_reclaimed_broker_commit(
    conn,
    *,
    git_dir: Path,
    workspace: Path,
    task_id: str,
    current_run_id: int,
) -> tuple[str, str, int] | None:
    """Recover a journaled broker commit whose original run was reclaimed.

    The staged completion event is the durable pre-commit journal. The commit
    must be the exact broker-authored single child of its recorded base, its
    trailer run must be an earlier reclaimed run for this task, and that run
    must have a matching request with no publisher event. A successor claim can
    therefore finish the SQLite handoff without trusting successor prose or
    accepting an arbitrary pre-existing commit.
    """
    head_sha = _git(
        ["rev-parse", "HEAD"], git_dir=git_dir, work_tree=workspace
    ).stdout.strip()
    message = _git(
        ["show", "-s", "--format=%ae%n%B", head_sha],
        git_dir=git_dir,
        work_tree=workspace,
    ).stdout.splitlines()
    if not message or message[0].strip() != _BROKER_AUTHOR_EMAIL:
        return None
    trailers: dict[str, str] = {}
    for line in message[1:]:
        key, separator, value = line.partition(":")
        if separator and key in {
            "Hermes-Kanban-Task",
            "Hermes-Kanban-Run",
            "Hermes-Kanban-Base",
        }:
            trailers[key] = value.strip()
    if trailers.get("Hermes-Kanban-Task") != task_id:
        return None
    try:
        prior_run_id = int(trailers.get("Hermes-Kanban-Run", ""))
    except ValueError:
        return None
    if prior_run_id >= current_run_id:
        return None
    base_sha = trailers.get("Hermes-Kanban-Base", "")
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        return None
    actual_parent = _git(
        ["rev-parse", f"{head_sha}^"], git_dir=git_dir, work_tree=workspace
    ).stdout.strip()
    if actual_parent != base_sha:
        return None
    run = conn.execute(
        "SELECT status, outcome FROM task_runs WHERE id = ? AND task_id = ?",
        (prior_run_id, task_id),
    ).fetchone()
    if run is None or run["status"] != "reclaimed" or run["outcome"] != "reclaimed":
        return None
    if _pending_request(conn, task_id, prior_run_id) is None:
        return None
    for event in kb.list_events(conn, task_id):
        if event.kind == "trusted_local_commit" and event.run_id == prior_run_id:
            return None
    return base_sha, head_sha, prior_run_id


def finalize_current_worker_git_handoff() -> dict[str, Any]:
    """Commit one staged worktree handoff and park it for trusted publishing.

    Safe to call more than once. When no exact staged request exists it is a
    no-op. Rejections from an actual dispatcher-owned worker block the task with
    a deterministic failure marker; inherited cron/delegation contexts receive
    no mutation at all.
    """
    if not is_dispatcher_owned_worker_context():
        return {"outcome": "not_dispatcher_worker"}
    if os.environ.get("HERMES_SESSION_SOURCE") != "kanban":
        return {"outcome": "not_dispatcher_worker"}

    task_id = str(os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    raw_run_id = str(os.environ.get("HERMES_KANBAN_RUN_ID") or "").strip()
    claim_lock = str(os.environ.get("HERMES_KANBAN_CLAIM_LOCK") or "").strip()
    env_workspace = str(os.environ.get("HERMES_KANBAN_WORKSPACE") or "").strip()
    env_branch = str(os.environ.get("HERMES_KANBAN_BRANCH") or "").strip()
    board = str(os.environ.get("HERMES_KANBAN_BOARD") or "").strip()
    sealed_repo = str(os.environ.get("HERMES_KANBAN_TRUSTED_REPO_ROOT") or "").strip()
    sealed_project_raw = os.environ.get("HERMES_KANBAN_PROJECT_ID")
    if not all((task_id, raw_run_id, claim_lock, env_workspace, env_branch, board)):
        return {"outcome": "not_dispatcher_worker"}
    try:
        run_id = int(raw_run_id)
    except ValueError:
        return {"outcome": "not_dispatcher_worker"}

    conn = kb.connect()
    try:
        task = kb.get_task(conn, task_id)
        if task is None or task.status != "running" or task.current_run_id != run_id:
            return {"outcome": "no_pending_handoff", "task_id": task_id}
        request = _pending_request(conn, task_id, run_id)
        if request is None:
            return {"outcome": "no_pending_handoff", "task_id": task_id}

        try:
            if task.claim_lock != claim_lock:
                raise BrokerRejected("claim lock mismatch")
            if task.workspace_kind != "worktree" or not task.workspace_path:
                raise BrokerRejected("task is not an exact worktree assignment")
            if not task.branch_name or task.branch_name != env_branch:
                raise BrokerRejected("branch mismatch")
            _validate_branch(task_id, env_branch)
            if not sealed_repo or sealed_project_raw is None:
                raise BrokerRejected("dispatcher-sealed repository identity is missing")
            sealed_project = sealed_project_raw.strip() or None
            if task.project_id != sealed_project:
                raise BrokerRejected(
                    "task project does not match dispatcher-sealed project"
                )

            workspace = Path(task.workspace_path).expanduser().resolve(strict=True)
            if Path(env_workspace).expanduser().resolve(strict=False) != workspace:
                raise BrokerRejected("workspace mismatch")
            repo, board_metadata = _trusted_repo_root(board, sealed_repo)
            if (
                workspace.parent.resolve(strict=False)
                != (repo / ".worktrees").resolve(strict=False)
                or workspace.name != task_id
            ):
                raise BrokerRejected("workspace is outside the trusted board checkout")
            board_project = str(board_metadata.get("project_id") or "").strip() or None
            if board_project != sealed_project:
                raise BrokerRejected(
                    "board project does not match dispatcher-sealed project"
                )

            common_dir = (repo / ".git").resolve(strict=True)
            git_dir = _trusted_worktree_git_dir(common_dir, workspace)
            head_ref = _git(
                ["symbolic-ref", "HEAD"], git_dir=git_dir, work_tree=workspace
            ).stdout.strip()
            if head_ref != f"refs/heads/{env_branch}":
                raise BrokerRejected("worktree HEAD does not match the assigned branch")

            config = _git(
                ["config", "--local", "--name-only", "--list"],
                git_dir=git_dir,
                work_tree=workspace,
            )
            worktree_config_enabled = _git(
                [
                    "config",
                    "--local",
                    "--type=bool",
                    "--get",
                    "extensions.worktreeConfig",
                ],
                git_dir=git_dir,
                work_tree=workspace,
                check=False,
            )
            worktree_config_output = ""
            if worktree_config_enabled.stdout.strip().casefold() == "true":
                worktree_config_output = _git(
                    ["config", "--worktree", "--name-only", "--list"],
                    git_dir=git_dir,
                    work_tree=workspace,
                ).stdout
            unsafe_keys = sorted(
                key.strip()
                for key in (config.stdout + "\n" + worktree_config_output).splitlines()
                if _UNSAFE_CONFIG.match(key.strip())
            )
            if unsafe_keys:
                raise BrokerRejected(
                    "trusted repository has executable Git config: "
                    + ", ".join(unsafe_keys)
                )

            status = _git(
                ["status", "--porcelain=v1", "--untracked-files=all"],
                git_dir=git_dir,
                work_tree=workspace,
            ).stdout
            recovered_from_run_id = None
            if status.strip():
                base_sha = _git(
                    ["rev-parse", "HEAD"], git_dir=git_dir, work_tree=workspace
                ).stdout.strip()
                _git(
                    ["add", "-A", "--", "."],
                    git_dir=git_dir,
                    work_tree=workspace,
                    cwd=workspace,
                )
                title = " ".join((task.title or "task change").split())[:72]
                _git(
                    [
                        "commit",
                        "--no-gpg-sign",
                        "-m",
                        f"kanban({task_id}): {title}",
                        "-m",
                        f"Hermes-Kanban-Task: {task_id}\n"
                        f"Hermes-Kanban-Run: {run_id}\n"
                        f"Hermes-Kanban-Base: {base_sha}",
                    ],
                    git_dir=git_dir,
                    work_tree=workspace,
                    cwd=workspace,
                )
                head_sha = _git(
                    ["rev-parse", "HEAD"], git_dir=git_dir, work_tree=workspace
                ).stdout.strip()
            else:
                recovered = _recover_exact_broker_commit(
                    git_dir=git_dir,
                    workspace=workspace,
                    task_id=task_id,
                    run_id=run_id,
                )
                if recovered is None:
                    reclaimed = _recover_reclaimed_broker_commit(
                        conn,
                        git_dir=git_dir,
                        workspace=workspace,
                        task_id=task_id,
                        current_run_id=run_id,
                    )
                    if reclaimed is None:
                        raise BrokerRejected("worker produced no file changes to commit")
                    base_sha, head_sha, recovered_from_run_id = reclaimed
                else:
                    base_sha, head_sha = recovered
            changed_raw = _git(
                ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", head_sha],
                git_dir=git_dir,
                work_tree=workspace,
            ).stdout
            changed_paths = sorted(path for path in changed_raw.split("\0") if path)

            contract: dict[str, Any] = {
                "contract": PUBLISH_CONTRACT,
                "task_id": task_id,
                "project_id": task.project_id,
                "board": board,
                "workspace": str(workspace),
                "branch": env_branch,
                "base_sha": base_sha,
                "head_sha": head_sha,
                "changed_paths": changed_paths,
                "publisher_state": "awaiting",
            }
            if recovered_from_run_id is not None:
                contract["recovered_from_run_id"] = recovered_from_run_id
            blocked = kb.park_trusted_git_commit(
                conn,
                task_id,
                contract=contract,
                reason=PUBLISH_MARKER,
                expected_run_id=run_id,
                expected_claim_lock=claim_lock,
            )
            if not blocked:
                raise BrokerRejected("task changed state before publisher handoff")
            return {
                "outcome": "awaiting_trusted_publisher",
                "task_id": task_id,
                "head_sha": head_sha,
                "branch": env_branch,
            }
        except (BrokerRejected, OSError) as exc:
            return _reject_and_block(conn, task, run_id, str(exc))
    finally:
        conn.close()

"""Security-contract tests for the trusted Kanban Git commit broker."""

from __future__ import annotations

import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from agent.delegation_context import non_dispatcher_owned_context
from hermes_cli import kanban_db as kb


def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(path: Path) -> str:
    path.mkdir(parents=True)
    _git("init", "-b", "main", str(path))
    _git("config", "user.email", "broker@example.invalid", cwd=path)
    _git("config", "user.name", "Trusted Broker Test", cwd=path)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git("add", "README.md", cwd=path)
    _git("commit", "-m", "base", cwd=path)
    return _git("rev-parse", "HEAD", cwd=path)


@pytest.fixture
def broker_task(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    repo = tmp_path / "trusted-repo"
    base_sha = _init_repo(repo)
    kb.init_db()
    kb.write_board_metadata(
        "default",
        default_workdir=str(repo),
        project_id="p_radulator",
    )
    conn = kb.connect()
    tid = kb.create_task(
        conn,
        title="Implement safe worker change",
        workspace_kind="worktree",
        workspace_path=str(repo),
    )
    branch = f"radulator/{tid}-safe-worker-change"
    workspace = repo / ".worktrees" / tid
    _git("worktree", "add", "-b", branch, str(workspace), cwd=repo)
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET workspace_path = ?, branch_name = ?, project_id = ? WHERE id = ?",
            (str(workspace), branch, "p_radulator", tid),
        )
    claimed = kb.claim_task(conn, tid)
    assert claimed is not None

    monkeypatch.setenv("HERMES_SESSION_SOURCE", "kanban")
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(claimed.claim_lock))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", branch)
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    monkeypatch.setenv("HERMES_KANBAN_DB", str(kb.kanban_db_path(board="default")))
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(repo))
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "p_radulator")

    yield conn, tid, repo, workspace, branch, base_sha, claimed
    conn.close()


def _stage(conn, tid: str, run_id: int) -> None:
    assert kb.stage_trusted_git_completion(
        conn,
        tid,
        summary="implementation and tests complete",
        metadata={"tests_run": ["focused"]},
        expected_run_id=run_id,
    )


def test_broker_git_environment_scrubs_credentials_and_worker_git_overrides(
    monkeypatch,
):
    monkeypatch.setenv("GITHUB_TOKEN", "worker-token-must-not-reach-git")
    monkeypatch.setenv("OPENAI_API_KEY", "provider-secret-must-not-reach-git")
    monkeypatch.setenv("GIT_DIR", "/attacker/repository.git")
    monkeypatch.setenv("GIT_INDEX_FILE", "/attacker/index")
    monkeypatch.setenv("GIT_SSH_COMMAND", "attacker-controlled-command")
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", "/attacker/inject.dylib")

    from hermes_cli.kanban_git_broker import _base_git_env

    env = _base_git_env()

    assert "GITHUB_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env
    assert "GIT_DIR" not in env
    assert "GIT_INDEX_FILE" not in env
    assert "GIT_SSH_COMMAND" not in env
    assert "DYLD_INSERT_LIBRARIES" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"


def test_broker_commits_only_exact_task_branch_and_emits_publish_contract(
    broker_task, monkeypatch
):
    conn, tid, repo, workspace, branch, base_sha, claimed = broker_task
    sibling = f"radulator/{tid}-sibling"
    _git("branch", sibling, base_sha, cwd=repo)
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    # The visible .git file is inside the model-writable cwd. Corrupting it
    # must not redirect the broker, which resolves the worktree registry only
    # from the trusted checkout's read-only shared metadata.
    (workspace / ".git").write_text(
        "gitdir: /attacker/controlled.git\n", encoding="utf-8"
    )
    # An obsolete worker-supplied authority pin must be ignored completely.
    monkeypatch.setenv("HERMES_KANBAN_GIT_COMMON_DIR", "/attacker/repo/.git")
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "awaiting_trusted_publisher"
    head_sha = _git("rev-parse", branch, cwd=repo)
    assert head_sha != base_sha
    assert _git("rev-parse", "main", cwd=repo) == base_sha
    assert _git("rev-parse", sibling, cwd=repo) == base_sha
    assert _git("show", f"{head_sha}:feature.txt", cwd=repo) == "worker output"
    task = kb.get_task(conn, tid)
    assert task is not None
    assert task.status == "blocked"
    assert task.block_kind == "capability"
    events = kb.list_events(conn, task_id=tid)
    payload = next(
        event.payload for event in events if event.kind == "trusted_local_commit"
    )
    assert payload == {
        "contract": "hermes.trusted_local_commit.v1",
        "task_id": tid,
        "project_id": "p_radulator",
        "board": "default",
        "workspace": str(workspace.resolve()),
        "branch": branch,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "changed_paths": ["feature.txt"],
        "publisher_state": "awaiting",
    }


def test_broker_rejects_workspace_from_repo_outside_board_project(
    broker_task, tmp_path, monkeypatch
):
    conn, tid, _repo, _workspace, branch, _base_sha, claimed = broker_task
    attacker_repo = tmp_path / "attacker-repo"
    attacker_base = _init_repo(attacker_repo)
    attacker_workspace = attacker_repo / ".worktrees" / tid
    _git("worktree", "add", "-b", branch, str(attacker_workspace), cwd=attacker_repo)
    (attacker_workspace / "attack.txt").write_text("do not commit\n", encoding="utf-8")
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET workspace_path = ? WHERE id = ?",
            (str(attacker_workspace), tid),
        )
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(attacker_workspace))
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "rejected"
    assert "trusted board checkout" in result["reason"]
    assert _git("rev-parse", branch, cwd=attacker_repo) == attacker_base
    assert kb.get_task(conn, tid).status == "blocked"


def test_broker_rejects_worker_rewriting_board_and_task_to_attacker_repo(
    broker_task, tmp_path, monkeypatch
):
    conn, tid, trusted_repo, _workspace, branch, trusted_base, claimed = broker_task
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(trusted_repo))
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "p_radulator")
    attacker_repo = tmp_path / "attacker-repo"
    attacker_base = _init_repo(attacker_repo)
    attacker_workspace = attacker_repo / ".worktrees" / tid
    _git("worktree", "add", "-b", branch, str(attacker_workspace), cwd=attacker_repo)
    (attacker_workspace / "attack.txt").write_text("do not commit\n", encoding="utf-8")
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET workspace_path = ? WHERE id = ?",
            (str(attacker_workspace), tid),
        )
    kb.write_board_metadata(
        "default",
        default_workdir=str(attacker_repo),
        project_id="p_radulator",
    )
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(attacker_workspace))
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "rejected"
    assert "dispatcher-sealed repository" in result["reason"]
    assert _git("rev-parse", branch, cwd=attacker_repo) == attacker_base
    assert _git("rev-parse", "main", cwd=trusted_repo) == trusted_base


def test_broker_rejects_protected_branch_even_when_env_and_task_match(
    broker_task, monkeypatch
):
    conn, tid, repo, workspace, _branch, base_sha, claimed = broker_task
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET branch_name='main' WHERE id=?", (tid,))
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", "main")
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "rejected"
    assert "protected branch" in result["reason"]
    assert _git("rev-parse", "main", cwd=repo) == base_sha
    assert kb.get_task(conn, tid).status == "blocked"


def test_broker_rejects_executable_worktree_git_config_before_commit(broker_task):
    conn, tid, repo, workspace, branch, base_sha, claimed = broker_task
    _git("config", "extensions.worktreeConfig", "true", cwd=repo)
    _git(
        "config",
        "--worktree",
        "filter.attacker.process",
        "attacker-controlled-command",
        cwd=workspace,
    )
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "rejected"
    assert "executable Git config" in result["reason"]
    assert _git("rev-parse", branch, cwd=repo) == base_sha


def test_broker_rejects_stale_workspace_env_without_touching_task(
    broker_task, monkeypatch
):
    conn, tid, _repo, workspace, _branch, _base_sha, claimed = broker_task
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    _stage(conn, tid, claimed.current_run_id)
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace.parent / "sibling"))

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "rejected"
    assert "workspace mismatch" in result["reason"]
    assert kb.get_task(conn, tid).status == "blocked"


def test_broker_refuses_inherited_cron_context(broker_task):
    conn, tid, _repo, workspace, _branch, _base_sha, claimed = broker_task
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli.kanban_git_broker import finalize_current_worker_git_handoff

    with non_dispatcher_owned_context():
        result = finalize_current_worker_git_handoff()

    assert result["outcome"] == "not_dispatcher_worker"
    assert kb.get_task(conn, tid).status == "running"
    assert _git("status", "--porcelain", cwd=workspace) == "?? feature.txt"


def test_broker_recovers_exact_commit_after_board_transaction_crash(
    broker_task, monkeypatch
):
    conn, tid, repo, workspace, branch, base_sha, claimed = broker_task
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    _stage(conn, tid, claimed.current_run_id)

    from hermes_cli import kanban_git_broker as broker

    real_write_txn = kb.write_txn

    @contextmanager
    def crash_before_board_commit(_conn):
        raise RuntimeError("simulated host crash after git commit")
        yield  # pragma: no cover

    monkeypatch.setattr(kb, "write_txn", crash_before_board_commit)
    with pytest.raises(RuntimeError, match="simulated host crash"):
        broker.finalize_current_worker_git_handoff()

    committed_sha = _git("rev-parse", branch, cwd=repo)
    assert committed_sha != base_sha
    assert kb.get_task(conn, tid).status == "running"

    monkeypatch.setattr(kb, "write_txn", real_write_txn)
    result = broker.finalize_current_worker_git_handoff()

    assert result == {
        "outcome": "awaiting_trusted_publisher",
        "task_id": tid,
        "head_sha": committed_sha,
        "branch": branch,
    }
    assert kb.get_task(conn, tid).status == "blocked"
    publish_events = [
        event
        for event in kb.list_events(conn, tid)
        if event.kind == "trusted_local_commit"
    ]
    assert len(publish_events) == 1


def test_broker_recovers_exact_commit_after_run_was_reclaimed(
    broker_task, monkeypatch
):
    """A successor claim must not strand a commit made for the crashed run."""
    conn, tid, repo, workspace, branch, base_sha, first = broker_task
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    _stage(conn, tid, first.current_run_id)

    from hermes_cli import kanban_git_broker as broker

    real_write_txn = kb.write_txn

    @contextmanager
    def crash_before_board_commit(_conn):
        raise RuntimeError("simulated host crash after git commit")
        yield  # pragma: no cover

    monkeypatch.setattr(kb, "write_txn", crash_before_board_commit)
    with pytest.raises(RuntimeError, match="simulated host crash"):
        broker.finalize_current_worker_git_handoff()
    committed_sha = _git("rev-parse", branch, cwd=repo)
    assert committed_sha != base_sha

    monkeypatch.setattr(kb, "write_txn", real_write_txn)
    assert kb.reclaim_task(conn, tid, reason="worker crashed", signal_fn=lambda *_: None)
    second = kb.claim_task(conn, tid)
    assert second is not None
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(second.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(second.claim_lock))
    _stage(conn, tid, second.current_run_id)

    result = broker.finalize_current_worker_git_handoff()

    assert result == {
        "outcome": "awaiting_trusted_publisher",
        "task_id": tid,
        "head_sha": committed_sha,
        "branch": branch,
    }
    task = kb.get_task(conn, tid)
    assert task is not None and task.status == "blocked"
    publish = [
        event.payload
        for event in kb.list_events(conn, tid)
        if event.kind == "trusted_local_commit"
    ]
    assert len(publish) == 1
    assert publish[0]["recovered_from_run_id"] == first.current_run_id
    assert publish[0]["base_sha"] == base_sha
    assert publish[0]["head_sha"] == committed_sha

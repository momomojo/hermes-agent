"""Regression tests for incident t_db349b2a: first-claim worktree workers were
spawned from the pre-resolution Task snapshot, so HERMES_KANBAN_BRANCH was
missing and the worker boundary refused every command.

The dispatcher must spawn (and fire the spawn hook) with the resolved,
persisted workspace and branch in both the ready and review lanes, fail closed
when the claimed row drifts before spawn, and never let a branchless worker
inherit a stale branch pin from the parent process.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    for args in (["add", "README.md"], ["commit", "-m", "init"]):
        subprocess.run(
            ["git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=t@example.com",
             "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True,
        )
    return repo


def _first_claim_worktree_task(conn, repo: Path, *, status: str = "ready") -> str:
    tid = kb.create_task(
        conn,
        title="first-claim worktree task",
        assignee="coder",
        workspace_kind="worktree",
        workspace_path=str(repo),
    )
    assert kb.get_task(conn, tid).branch_name is None  # the shape that broke
    conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, tid))
    conn.commit()
    return tid


def _capturing_spawn(captured: list):
    def spawn(task, workspace):
        captured.append((task, workspace))
        return None

    return spawn


@pytest.mark.parametrize("status", ["ready", "review"])
def test_first_claim_worktree_worker_gets_resolved_branch(
    kanban_home, all_assignees_spawnable, tmp_path, status,
):
    repo = _make_repo(tmp_path)
    captured: list = []
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo, status=status)
        kb.dispatch_once(conn, spawn_fn=_capturing_spawn(captured))
        persisted = kb.get_task(conn, tid)

    assert len(captured) == 1, f"{status} lane did not spawn exactly once"
    spawned, workspace = captured[0]
    assert persisted.branch_name == f"wt/{tid}"
    assert spawned.branch_name == persisted.branch_name
    assert spawned.workspace_path == persisted.workspace_path == workspace
    assert Path(workspace) == (repo / ".worktrees" / tid).resolve()
    # The claim identity is the one this tick took, not a re-read of anything newer.
    assert spawned.current_run_id == persisted.current_run_id
    assert spawned.claim_lock == persisted.claim_lock
    if status == "review":
        assert "sdlc-review" in (spawned.skills or [])


def test_spawn_hook_receives_resolved_identity(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch,
):
    repo = _make_repo(tmp_path)
    hooked: list = []
    monkeypatch.setattr(
        kb, "_fire_worker_spawned_hook",
        lambda conn, task, workspace, pid, board=None: hooked.append(task),
    )
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo)
        kb.dispatch_once(conn, spawn_fn=_capturing_spawn([]))
    assert [t.branch_name for t in hooked] == [f"wt/{tid}"]


def test_claim_drift_before_spawn_fails_closed(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch,
):
    repo = _make_repo(tmp_path)
    captured: list = []
    real_tip = kb._maybe_emit_scratch_tip

    def reclaim_then_tip(conn, task_id, kind):
        # Another dispatcher reclaims the row after resolution, before spawn.
        conn.execute("UPDATE tasks SET claim_lock = 'someone-else' WHERE id = ?", (task_id,))
        conn.commit()
        return real_tip(conn, task_id, kind)

    monkeypatch.setattr(kb, "_maybe_emit_scratch_tip", reclaim_then_tip)
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo)
        kb.dispatch_once(conn, spawn_fn=_capturing_spawn(captured))
        kinds = [
            r["kind"] for r in conn.execute(
                "SELECT kind FROM task_events WHERE task_id = ? ORDER BY id", (tid,),
            )
        ]
    assert captured == [], "no worker may launch after identity drift"
    assert "spawn_identity_drift" in kinds


def test_default_spawn_does_not_inherit_a_stale_branch_pin(kanban_home, tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", "wt/stale-from-parent")
    captured = {}

    class _FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["env"] = kwargs.get("env", {})
            self.pid = 4242

    monkeypatch.setattr("subprocess.Popen", _FakePopen)
    ws = tmp_path / "ws"
    ws.mkdir()
    task = kb.Task(
        id="t_branchless",
        title="x",
        body=None,
        assignee="coder",
        status="ready",
        priority=0,
        created_by=None,
        created_at=0,
        started_at=None,
        completed_at=None,
        workspace_kind="scratch",
        workspace_path=str(ws),
        claim_lock=None,
        claim_expires=None,
        tenant=None,
        branch_name=None,
    )
    kb._default_spawn(task, str(ws))
    assert "HERMES_KANBAN_BRANCH" not in captured["env"]

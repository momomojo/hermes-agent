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


# field -> (mutation applied after resolution but before spawn, claim still ours?)
_DRIFTS = {
    "assignee": ("UPDATE tasks SET assignee = 'someone-else' WHERE id = ?", True),
    "project_id": ("UPDATE tasks SET project_id = 'other-project' WHERE id = ?", True),
    "workspace_path": ("UPDATE tasks SET workspace_path = '/elsewhere' WHERE id = ?", True),
    "branch_name": ("UPDATE tasks SET branch_name = 'wt/elsewhere' WHERE id = ?", True),
    "workspace_kind": ("UPDATE tasks SET workspace_kind = 'scratch' WHERE id = ?", True),
    "claim_lock": ("UPDATE tasks SET claim_lock = 'someone-else' WHERE id = ?", False),
    "current_run_id": ("UPDATE tasks SET current_run_id = current_run_id + 1000 WHERE id = ?", False),
    "status": ("UPDATE tasks SET status = 'blocked' WHERE id = ?", False),
}


def _kinds(conn, tid):
    return [
        r["kind"] for r in conn.execute(
            "SELECT kind FROM task_events WHERE task_id = ? ORDER BY id", (tid,),
        )
    ]


@pytest.mark.parametrize("lane", ["ready", "review"])
@pytest.mark.parametrize("field", sorted(_DRIFTS))
def test_drift_before_spawn_fails_closed(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch, lane, field,
):
    sql, still_ours = _DRIFTS[field]
    repo = _make_repo(tmp_path)
    captured: list = []
    seen = {}
    real_tip = kb._maybe_emit_scratch_tip

    def drift_then_tip(conn, task_id, kind):
        row = conn.execute(
            "SELECT current_run_id, claim_lock FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        seen["run_id"], seen["claim_lock"] = row["current_run_id"], row["claim_lock"]
        conn.execute(sql, (task_id,))
        conn.commit()
        seen["after"] = dict(conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone())
        return real_tip(conn, task_id, kind)

    monkeypatch.setattr(kb, "_maybe_emit_scratch_tip", drift_then_tip)
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo, status=lane)
        res = kb.dispatch_once(conn, spawn_fn=_capturing_spawn(captured))
        task = dict(conn.execute("SELECT * FROM tasks WHERE id = ?", (tid,)).fetchone())
        run = conn.execute(
            "SELECT outcome, ended_at FROM task_runs WHERE id = ?", (seen["run_id"],)
        ).fetchone()
        kinds = _kinds(conn, tid)

    assert captured == [], f"{field} drift in the {lane} lane must launch nothing"
    assert "spawn_identity_drift" in kinds
    # One drift is below the default breaker limit, so nothing is auto-blocked.
    assert res.auto_blocked == []
    if still_ours:
        # Our own claim is released at once (not left to the TTL) and counted.
        assert task["status"] == lane
        assert task["claim_lock"] is None
        assert task["consecutive_failures"] == 1
        assert run["outcome"] == "spawn_failed" and run["ended_at"] is not None
    else:
        # Someone else's claim, run or deliberate status is left untouched.
        for name in ("status", "claim_lock", "current_run_id"):
            assert task[name] == seen["after"][name]
        assert task["consecutive_failures"] == 0
        assert "spawn_failed" not in kinds


@pytest.mark.parametrize("lane", ["ready", "review"])
@pytest.mark.parametrize("field", ["workspace_path", "claim_lock"])
def test_drift_that_trips_the_breaker_is_reported(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch, lane, field,
):
    """A drift that trips the breaker must reach DispatchResult.auto_blocked,
    like every other spawn failure; a drift on someone else's claim never
    counts against the task."""
    sql, still_ours = _DRIFTS[field]
    repo = _make_repo(tmp_path)
    captured: list = []
    real_tip = kb._maybe_emit_scratch_tip

    def drift_then_tip(conn, task_id, kind):
        conn.execute(sql, (task_id,))
        conn.commit()
        return real_tip(conn, task_id, kind)

    monkeypatch.setattr(kb, "_maybe_emit_scratch_tip", drift_then_tip)
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo, status=lane)
        res = kb.dispatch_once(
            conn, spawn_fn=_capturing_spawn(captured), failure_limit=1,
        )
        task = kb.get_task(conn, tid)

    assert captured == []
    if still_ours:
        assert res.auto_blocked == [tid]
        assert task.status == "blocked"
        assert task.claim_lock is None
    else:
        assert res.auto_blocked == []
        assert task.status != "blocked"
        assert task.consecutive_failures == 0


def test_real_reclaim_before_spawn_leaves_the_new_owner_alone(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch,
):
    repo = _make_repo(tmp_path)
    captured: list = []
    new_owner = {}
    real_tip = kb._maybe_emit_scratch_tip

    def reclaim_then_tip(conn, task_id, kind):
        # Our claim expires, the reaper resets it, and another worker claims it.
        conn.execute("UPDATE tasks SET claim_expires = 0 WHERE id = ?", (task_id,))
        conn.commit()
        kb.release_stale_claims(conn)
        other = kb.claim_task(conn, task_id, claimer="other:1")
        assert other is not None
        new_owner["claim_lock"], new_owner["run_id"] = other.claim_lock, other.current_run_id
        return real_tip(conn, task_id, kind)

    monkeypatch.setattr(kb, "_maybe_emit_scratch_tip", reclaim_then_tip)
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo)
        kb.dispatch_once(conn, spawn_fn=_capturing_spawn(captured))
        task = kb.get_task(conn, tid)
        new_run = conn.execute(
            "SELECT ended_at FROM task_runs WHERE id = ?", (new_owner["run_id"],)
        ).fetchone()
        kinds = _kinds(conn, tid)

    assert captured == []
    assert "spawn_identity_drift" in kinds
    assert task.status == "running"
    assert task.claim_lock == new_owner["claim_lock"]
    assert task.current_run_id == new_owner["run_id"]
    assert new_run["ended_at"] is None, "the new owner's run must stay open"


def test_first_claim_worker_env_passes_the_worker_boundary(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch,
):
    """End to end: the environment the real _default_spawn gives a first-claim
    worktree worker must satisfy the worker boundary that refused it before."""
    import os

    from tools import kanban_worker_boundary as boundary

    import subprocess

    repo = _make_repo(tmp_path)
    captured = {}
    real_popen = subprocess.Popen

    class _WorkerLaunch:
        pid = 4242

    def fake_popen(cmd, *args, **kwargs):
        # Intercept only the worker launch; let git (worktree creation) run.
        env = kwargs.get("env")
        if env and "HERMES_KANBAN_TASK" in env:
            captured["env"] = dict(env)
            return _WorkerLaunch()
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with kb.connect() as conn:
        tid = _first_claim_worktree_task(conn, repo)
        kb.dispatch_once(conn, spawn_fn=kb._default_spawn)
        task = kb.get_task(conn, tid)

    env = captured["env"]
    assert env.get("HERMES_KANBAN_BRANCH") == f"wt/{tid}"
    for key in [k for k in os.environ if k.startswith("HERMES_KANBAN_") or k == "TERMINAL_CWD"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        if key.startswith("HERMES_KANBAN_") or key == "TERMINAL_CWD":
            monkeypatch.setenv(key, value)
    live = boundary._live_assignment(
        task_id=tid,
        run_id=task.current_run_id,
        claim_lock=task.claim_lock,
        env_workspace=Path(env["HERMES_KANBAN_WORKSPACE"]).resolve(),
    )
    assert live is not None, "the worker boundary must accept the spawned identity"


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


@pytest.mark.parametrize("with_project", [False, True])
@pytest.mark.parametrize("lane", ["ready", "review"])
def test_first_claim_env_passes_boundary_with_and_without_project(
    kanban_home, all_assignees_spawnable, tmp_path, monkeypatch, with_project, lane,
):
    """A plain first-claim worktree task (no project, branch still None) and a
    project-linked one (deterministic branch set at creation) both get a
    worker environment the unchanged boundary accepts, in both lanes; a wrong
    project pin is still refused."""
    import os
    import subprocess
    from hermes_cli import projects_db as pdb
    from tools import kanban_worker_boundary as boundary

    repo = _make_repo(tmp_path)
    captured = {}
    real_popen = subprocess.Popen

    class _WorkerLaunch:
        pid = 4242

    def fake_popen(cmd, *args, **kwargs):
        env = kwargs.get("env")
        if env and "HERMES_KANBAN_TASK" in env:
            captured["env"] = dict(env)
            return _WorkerLaunch()
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    project_id = None
    if with_project:
        with pdb.connect_closing() as pconn:
            project_id = pdb.create_project(pconn, name="Probe Project", primary_path=str(repo))
    with kb.connect() as conn:
        if with_project:
            tid = kb.create_task(conn, title="first-claim project task", assignee="coder",
                                 workspace_kind="worktree", project_id=project_id)
        else:
            tid = kb.create_task(conn, title="first-claim task", assignee="coder",
                                 workspace_kind="worktree", workspace_path=str(repo))
        created = kb.get_task(conn, tid)
        assert created.project_id == project_id
        # Project-linked tasks get a deterministic branch at creation; plain
        # worktree tasks start branchless (the shape that broke in t_db349b2a).
        assert (created.branch_name is None) == (not with_project)
        conn.execute("UPDATE tasks SET status = ? WHERE id = ?", (lane, tid))
        conn.commit()
        kb.dispatch_once(conn, spawn_fn=kb._default_spawn)
        task = kb.get_task(conn, tid)

    env = captured["env"]
    assert task.branch_name and env.get("HERMES_KANBAN_BRANCH") == task.branch_name
    assert env.get("HERMES_KANBAN_PROJECT_ID") == (project_id or "")
    for key in [k for k in os.environ if k.startswith("HERMES_KANBAN_") or k == "TERMINAL_CWD"]:
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        if key.startswith("HERMES_KANBAN_") or key == "TERMINAL_CWD":
            monkeypatch.setenv(key, value)
    ws = Path(env["HERMES_KANBAN_WORKSPACE"]).resolve()
    assert boundary._live_assignment(task_id=tid, run_id=task.current_run_id,
                                     claim_lock=task.claim_lock, env_workspace=ws) is not None
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "someone-else")
    assert boundary._live_assignment(task_id=tid, run_id=task.current_run_id,
                                     claim_lock=task.claim_lock, env_workspace=ws) is None

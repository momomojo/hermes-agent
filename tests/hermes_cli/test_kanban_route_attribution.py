import json
import sqlite3
from types import SimpleNamespace

import pytest

from hermes_cli import kanban_db as kb


def test_worker_route_snapshot_uses_profile_default_and_task_override(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "model:\n  provider: openai-codex\n  default: gpt-5.6-terra\nagent:\n  reasoning_effort: medium\n"
    )
    task = SimpleNamespace(current_run_id=7, model_override=None)
    snap = kb._worker_route_snapshot(task, str(tmp_path))
    assert snap == {
        "provider": "openai-codex",
        "model": "gpt-5.6-terra",
        "reasoning_effort": "medium",
        "attribution": "dispatcher_pre_spawn",
    }
    task.model_override = "gpt-5.6-sol"
    assert kb._worker_route_snapshot(task, str(tmp_path))["model"] == "gpt-5.6-sol"


def test_worker_route_snapshot_fails_closed_when_incomplete(tmp_path):
    (tmp_path / "config.yaml").write_text("model:\n  default: gpt-5.6-terra\n")
    with pytest.raises(RuntimeError, match="cannot capture exact route"):
        kb._worker_route_snapshot(SimpleNamespace(current_run_id=9, model_override=None), str(tmp_path))


def test_persist_worker_route_snapshot_merges_metadata_transactionally(tmp_path):
    db = tmp_path / "kanban.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE task_runs (id INTEGER PRIMARY KEY, status TEXT, metadata TEXT)")
    conn.execute("INSERT INTO task_runs VALUES (1, 'running', ?)", (json.dumps({"existing": True}),))
    conn.commit(); conn.close()
    snap = {"provider": "openai-codex", "model": "gpt-5.6-terra", "reasoning_effort": "medium", "attribution": "dispatcher_pre_spawn"}
    kb._persist_worker_route_snapshot(db, 1, snap)
    conn = sqlite3.connect(db)
    payload = json.loads(conn.execute("SELECT metadata FROM task_runs WHERE id=1").fetchone()[0])
    conn.close()
    assert payload == {"existing": True, "route_snapshot": snap}


def test_persist_worker_route_snapshot_refuses_nonrunning_run(tmp_path):
    db = tmp_path / "kanban.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE task_runs (id INTEGER PRIMARY KEY, status TEXT, metadata TEXT)")
    conn.execute("INSERT INTO task_runs VALUES (1, 'completed', NULL)")
    conn.commit(); conn.close()
    with pytest.raises(RuntimeError, match="not running"):
        kb._persist_worker_route_snapshot(db, 1, {"model": "x"})

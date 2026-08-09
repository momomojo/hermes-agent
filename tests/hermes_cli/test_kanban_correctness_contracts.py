"""Focused state-safety contracts for the Kanban lifecycle kernel."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from unittest import mock

import pytest

from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def test_initial_block_is_sticky_until_explicit_unblock(kanban_home: Path) -> None:
    with kb.connect() as conn:
        task_id = kb.create_task(
            conn,
            title="operator gate",
            initial_status="blocked",
        )

        for _ in range(3):
            assert kb.recompute_ready(conn) == 0
            assert kb.get_task(conn, task_id).status == "blocked"

        events = kb.list_events(conn, task_id)
        assert [event.kind for event in events[:2]] == ["created", "blocked"]
        assert events[1].payload["source"] == "creation"

        assert kb.unblock_task(conn, task_id)
        assert kb.get_task(conn, task_id).status == "ready"


def test_initial_block_stays_sticky_after_all_parents_finish(
    kanban_home: Path,
) -> None:
    with kb.connect() as conn:
        parent_id = kb.create_task(conn, title="parent")
        child_id = kb.create_task(
            conn,
            title="gated child",
            parents=[parent_id],
            initial_status="blocked",
        )
        assert kb.complete_task(conn, parent_id, summary="done")

        assert kb.recompute_ready(conn) == 0
        assert kb.get_task(conn, child_id).status == "blocked"


def test_running_completion_requires_exact_current_run_token(
    kanban_home: Path,
) -> None:
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="owned run", assignee="worker")
        claimed = kb.claim_task(conn, task_id)
        assert claimed is not None
        run_id = claimed.current_run_id
        assert run_id is not None

        assert kb.complete_task(conn, task_id, summary="missing token") is False
        assert kb.complete_task(
            conn,
            task_id,
            summary="stale token",
            expected_run_id=run_id + 1,
        ) is False

        still_running = kb.get_task(conn, task_id)
        assert still_running.status == "running"
        assert still_running.current_run_id == run_id
        assert kb.get_run(conn, run_id).ended_at is None

        assert kb.complete_task(
            conn,
            task_id,
            summary="current owner completed",
            expected_run_id=run_id,
        )
        assert kb.get_task(conn, task_id).status == "done"
        assert kb.get_run(conn, run_id).outcome == "completed"


def test_manual_completion_of_unclaimed_ready_and_blocked_tasks_is_preserved(
    kanban_home: Path,
) -> None:
    with kb.connect() as conn:
        ready_id = kb.create_task(conn, title="ready manual")
        blocked_id = kb.create_task(
            conn,
            title="blocked manual",
            initial_status="blocked",
        )

        assert kb.complete_task(conn, ready_id, summary="verified ready")
        assert kb.complete_task(conn, blocked_id, summary="verified blocked")
        assert kb.get_task(conn, ready_id).status == "done"
        assert kb.get_task(conn, blocked_id).status == "done"


def test_admin_running_override_requires_reason_and_is_fully_audited(
    kanban_home: Path,
) -> None:
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="orphaned worker", assignee="worker")
        claimed = kb.claim_task(conn, task_id)
        assert claimed is not None
        run_id = claimed.current_run_id
        assert run_id is not None

        with pytest.raises(ValueError, match="non-empty actor"):
            kb.admin_complete_running_task(
                conn, task_id, actor="", reason="verified externally",
            )
        with pytest.raises(ValueError, match="non-empty reason"):
            kb.admin_complete_running_task(
                conn, task_id, actor="operator", reason="",
            )

        assert kb.admin_complete_running_task(
            conn,
            task_id,
            actor="operator",
            reason="worker exited after result was independently verified",
            summary="verified output",
        )

        task = kb.get_task(conn, task_id)
        assert task.status == "done"
        assert task.current_run_id is None
        run = kb.get_run(conn, run_id)
        assert run.outcome == "completed"
        assert run.ended_at is not None

        events = kb.list_events(conn, task_id)
        override = next(
            event for event in events if event.kind == "admin_completion_override"
        )
        assert override.run_id == run_id
        assert override.payload == {
            "actor": "operator",
            "reason": "worker exited after result was independently verified",
            "overridden_run_id": run_id,
            "completion_source": "admin_override",
        }
        completed = next(event for event in events if event.kind == "completed")
        assert completed.payload["admin_override"] is True
        assert completed.payload["completed_by"] == "operator"


def test_wal_commit_does_not_compare_logical_pages_to_main_file(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "wal.db"
    conn = kb.connect(db_path=db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        # A zero-byte main-file report would always look truncated if logical
        # WAL pages were compared to the main database after COMMIT.
        with mock.patch.object(os.path, "getsize", return_value=0):
            with kb.write_txn(conn):
                conn.execute(
                    "INSERT INTO tasks "
                    "(id, title, assignee, status, priority, created_at) "
                    "VALUES ('t_wal_safe', 'wal-safe', 'worker', 'ready', 0, 1)"
                )
        assert conn.execute(
            "SELECT title FROM tasks WHERE id='t_wal_safe'"
        ).fetchone()[0] == "wal-safe"
    finally:
        conn.close()


def test_rollback_journal_still_detects_a_short_main_file(tmp_path: Path) -> None:
    db_path = tmp_path / "rollback.db"
    conn = kb.connect(db_path=db_path)
    try:
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() is not None
        assert conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0].lower() == "delete"
        with mock.patch.object(os.path, "getsize", return_value=0):
            with pytest.raises(sqlite3.DatabaseError, match="torn-extend"):
                kb._check_file_length_invariant(conn)
    finally:
        conn.close()


def test_clean_exit_is_finalized_and_reported_as_protocol_violation(
    kanban_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with kb.connect() as conn:
        task_id = kb.create_task(conn, title="missing terminal call", assignee="worker")
        claimed = kb.claim_task(conn, task_id, claimer=f"{kb._claimer_id().split(':', 1)[0]}:test")
        assert claimed is not None
        run_id = claimed.current_run_id
        assert run_id is not None
        fake_pid = 987654
        kb._set_worker_pid(conn, task_id, fake_pid)
        kb._record_worker_exit(fake_pid, 0)
        monkeypatch.setattr(kb, "_pid_alive", lambda _pid: False)
        monkeypatch.setattr(kb, "_resolve_crash_grace_seconds", lambda: 0)

        result = kb.dispatch_once(conn, dry_run=True)

        assert result.protocol_violations == [task_id]
        assert result.crashed == []
        task = kb.get_task(conn, task_id)
        assert task.status in {"ready", "blocked"}
        assert task.status != "running"
        assert task.current_run_id is None
        run = kb.get_run(conn, run_id)
        assert run.status == "failed"
        assert run.outcome == "protocol_violation"
        assert run.ended_at is not None
        event = next(
            event for event in kb.list_events(conn, task_id)
            if event.kind == "protocol_violation"
        )
        assert event.run_id == run_id
        assert event.payload["exit_code"] == 0

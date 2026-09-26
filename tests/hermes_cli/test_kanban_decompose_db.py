"""Tests for kb.decompose_triage_task — the DB-layer atomic fan-out
from the triage column. LLM-free by design.
"""

from __future__ import annotations

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


def _create_triage(conn, title="rough idea", body=None, assignee=None, tenant=None):
    return kb.create_task(
        conn,
        title=title,
        body=body,
        assignee=assignee,
        tenant=tenant,
        triage=True,
    )


def test_decompose_creates_children_and_promotes_root(kanban_home):
    with kb.connect() as conn:
        tid = _create_triage(conn, title="ship a feature")
        assert kb.get_task(conn, tid).status == "triage"

    children = [
        {"title": "research", "body": "look at prior art", "assignee": "researcher", "parents": []},
        {"title": "build it", "body": "write code", "assignee": "engineer", "parents": [0]},
    ]
    with kb.connect() as conn:
        child_ids = kb.decompose_triage_task(
            conn,
            tid,
            root_assignee="orchestrator",
            children=children,
            author="decomposer",
        )
    assert child_ids is not None
    assert len(child_ids) == 2

    with kb.connect() as conn:
        root = kb.get_task(conn, tid)
        c0 = kb.get_task(conn, child_ids[0])
        c1 = kb.get_task(conn, child_ids[1])

    # Root flipped to todo with orchestrator assignee, gated by children.
    assert root.status == "todo"
    assert root.assignee == "orchestrator"
    # First child has no internal parents → ready on recompute_ready.
    assert c0.status == "ready"
    assert c0.assignee == "researcher"
    # Second child has parents=[0] → stays in todo until c0 completes.
    assert c1.status == "todo"
    assert c1.assignee == "engineer"


def test_decompose_records_audit_comment_and_event(kanban_home):
    with kb.connect() as conn:
        tid = _create_triage(conn)
        child_ids = kb.decompose_triage_task(
            conn,
            tid,
            root_assignee="orch",
            children=[{"title": "task A", "assignee": "researcher"}],
            author="alice",
        )
    assert child_ids is not None

    with kb.connect() as conn:
        comments = kb.list_comments(conn, tid)
        events = kb.list_events(conn, tid)

    assert any("Decomposed into" in (c.body or "") for c in comments)
    assert any(ev.kind == "decomposed" for ev in events)






# ---------------------------------------------------------------------------
# Loop-breaker triage is left for a human by the automatic path
# ---------------------------------------------------------------------------

def _loop_broken_task(conn, title="loops"):
    """Drive a task through two same-cause blocks so the loop breaker routes it to triage."""
    tid = kb.create_task(conn, title=title, assignee="worker")
    for _ in range(kb.BLOCK_RECURRENCE_LIMIT):
        with kb.write_txn(conn):
            conn.execute("UPDATE tasks SET status='ready' WHERE id=?", (tid,))
        assert kb.claim_task(conn, tid, claimer="worker") is not None
        kb.block_task(conn, tid, reason="same cause", kind="capability")
        if kb.get_task(conn, tid).status == "blocked":
            kb.unblock_task(conn, tid)
    assert kb.get_task(conn, tid).status == "triage"
    return tid


def test_auto_path_skips_loop_breaker_triage(kanban_home):
    from hermes_cli import kanban_decompose as decomp
    with kb.connect_closing() as conn:
        fresh = _create_triage(conn, title="fresh idea")
        looped = _loop_broken_task(conn)
    assert decomp.list_triage_ids(include_loop_breaker=False) == [fresh]
    assert looped not in decomp.list_triage_ids(include_loop_breaker=False)


def test_explicit_listing_still_includes_loop_breaker_triage(kanban_home):
    from hermes_cli import kanban_decompose as decomp
    with kb.connect_closing() as conn:
        fresh = _create_triage(conn, title="fresh idea")
        looped = _loop_broken_task(conn)
    assert set(decomp.list_triage_ids()) == {fresh, looped}


def test_plain_triage_task_is_auto_eligible(kanban_home):
    from hermes_cli import kanban_decompose as decomp
    with kb.connect_closing() as conn:
        tid = _create_triage(conn)
    assert decomp.list_triage_ids(include_loop_breaker=False) == [tid]


def test_loop_breaker_filter_applies_before_row_cap(kanban_home):
    with kb.connect_closing() as conn:
        _loop_broken_task(conn, title="loops 1")
        _loop_broken_task(conn, title="loops 2")
        fresh = _create_triage(conn, title="fresh idea")
        capped = kb.list_tasks(conn, status="triage", limit=1)
        eligible = kb.list_tasks(
            conn, status="triage", limit=1, block_recurrences_below=kb.BLOCK_RECURRENCE_LIMIT,
        )
    assert [t.id for t in capped] != [fresh]  # older loop-broken rows fill an unfiltered cap
    assert [t.id for t in eligible] == [fresh]


def test_specify_rechecks_loop_breaker_inside_write_txn(kanban_home):
    with kb.connect_closing() as conn:
        looped = _loop_broken_task(conn)
        assert kb.specify_triage_task(conn, looped, title="auto", skip_loop_breaker=True) is False
        assert kb.get_task(conn, looped).status == "triage"
        assert kb.specify_triage_task(conn, looped, title="by hand") is True  # explicit path unchanged
        assert kb.get_task(conn, looped).status in ("todo", "ready")  # left triage


def test_decompose_db_rechecks_loop_breaker_inside_write_txn(kanban_home):
    children = [{"title": "child", "body": "b", "assignee": "engineer", "parents": []}]
    with kb.connect_closing() as conn:
        looped = _loop_broken_task(conn)
        before = len(kb.list_tasks(conn))
        assert kb.decompose_triage_task(
            conn, looped, root_assignee="orchestrator", children=children, skip_loop_breaker=True,
        ) is None
        assert len(kb.list_tasks(conn)) == before
        assert kb.get_task(conn, looped).status == "triage"


def test_decompose_task_leaves_loop_breaker_triage_on_the_automatic_path(kanban_home):
    from hermes_cli import kanban_decompose as decomp
    with kb.connect_closing() as conn:
        looped = _loop_broken_task(conn)
    outcome = decomp.decompose_task(looped, author="auto-decomposer", skip_loop_breaker=True)
    assert outcome.ok is False
    assert "loop-breaker" in outcome.reason

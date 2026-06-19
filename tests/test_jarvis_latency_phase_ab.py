#!/usr/bin/env python3
"""Jarvis Phase A/B regression tests for t_ec7fb229.

These tests exercise the managed-layer scripts changed by the Jarvis latency
fix without calling external services or printing credentials.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


HERMES = Path("/Users/agent/.hermes")
SCRIPTS = HERMES / "scripts"


def load_script(name: str):
    path = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader, path
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_session_stats_bucket_classification_and_alert_scope():
    stats_mod = load_script("jarvis_session_stats.py")
    now = 1_781_500_000.0
    rows = [
        {"id": 1, "sid": "jarvis-human", "role": "user", "text": "what is next", "ts": now},
        {"id": 2, "sid": "jarvis-human", "role": "assistant", "text": "next thing", "ts": now + 4},
        {"id": 3, "sid": "jarvis-tool", "role": "user", "text": "check calendar", "ts": now + 10},
        {"id": 4, "sid": "jarvis-tool", "role": "tool", "text": "calendar", "ts": now + 11},
        {"id": 5, "sid": "jarvis-tool", "role": "assistant", "text": "calendar done", "ts": now + 25},
        {"id": 6, "sid": "jarvis-briefing-real", "role": "user", "text": "BRIEFING", "ts": now + 30},
        {"id": 7, "sid": "jarvis-briefing-real", "role": "assistant", "text": "one item", "ts": now + 130},
        {"id": 8, "sid": "jarvis-latency-smoke", "role": "user", "text": "Reply exactly: OK", "ts": now + 140},
        {"id": 9, "sid": "jarvis-latency-smoke", "role": "assistant", "text": "OK", "ts": now + 160},
    ]

    result = stats_mod.parse_turns(rows, now=now + 200)
    buckets = result["latency_buckets"]

    assert buckets["simple_no_tool"]["n"] == 1
    assert buckets["simple_no_tool"]["p90_s"] == 4.0
    assert buckets["ordinary_tool"]["n"] == 1
    assert buckets["ordinary_tool"]["p90_s"] == 15.0
    assert buckets["briefing"]["n"] == 1
    assert buckets["briefing"]["p90_s"] == 100.0
    assert buckets["test_session"]["n"] == 1
    assert result["headline_latency_alerts"] == []


def test_briefing_queue_bounded_registry_only(monkeypatch):
    helper = load_script("jarvis_briefing_queue.py")
    monkeypatch.setattr(helper, "load_registry", lambda: [
        {
            "kind": "registry",
            "id": "late",
            "title": "Late escalated item",
            "profile": "job-medical",
            "due": "2026-06-12",
            "escalate": True,
            "source": "kanban:t_demo0001",
            "context": "test registry item",
        }
    ])

    queue = helper.build_queue(include_kanban=False)
    assert queue["count"] == 1
    assert queue["sources"] == {"registry_pending": 1, "blocked_on_mohib_cards": 0}
    assert queue["item"]["title"] == "Late escalated item"
    spoken = helper.spoken(queue)
    assert "First item: Late escalated item" in spoken
    assert "Your call." in spoken


def test_action_registry_delegate_marks_in_flight_and_reuses_existing_task(tmp_path):
    delegate = load_script("action_registry_delegate.py")
    data = {"items": [{"id": "abc", "title": "Review one thing", "status": "pending"}]}
    item, _ = delegate.find_item(data, "abc")

    changed = delegate.mark_delegated(item, item_id="abc", task_id="t_11111111", timestamp="2026-06-18T12:00:00+00:00")

    assert changed is True
    assert item["status"] == "in-flight"
    assert item["delegated_task_id"] == "t_11111111"
    assert item["delegated_at"] == "2026-06-18T12:00:00+00:00"
    assert "hide from Jarvis BRIEFING" in item["notes"]

    registry_path = tmp_path / "registry.json"
    registry_path.write_text(json.dumps(data), encoding="utf-8")
    result = delegate.delegate_item("abc", registry_path=registry_path, task_id="t_22222222", dry_run=True)

    # Existing delegated_task_id wins: repeated delegation cannot overwrite the
    # original worker card or create a duplicate queue item.
    assert result["reused_existing"] is True
    assert result["delegated_task_id"] == "t_11111111"


def test_action_registry_delegate_cli_dry_run_does_not_write_and_real_run_suppresses_briefing(tmp_path):
    root = tmp_path / "hermes"
    state = root / "state"
    state.mkdir(parents=True)
    db = root / "kanban.db"
    import sqlite3
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO tasks VALUES (?, ?)", ("t_33333333", "ready"))
    conn.commit()
    conn.close()
    registry = state / "mohib-action-registry.json"
    registry.write_text(
        json.dumps({"items": [{"id": "x", "title": "Delegate me", "status": "pending"}]}),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["HERMES_ROOT"] = str(root)

    dry = subprocess.run(
        [sys.executable, str(SCRIPTS / "action_registry_delegate.py"), "x", "--task-id", "t_33333333", "--registry", str(registry), "--dry-run"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env=env,
    )
    assert json.loads(dry.stdout)["dry_run"] is True
    assert json.loads(registry.read_text())["items"][0]["status"] == "pending"

    subprocess.run(
        [sys.executable, str(SCRIPTS / "action_registry_delegate.py"), "x", "--task-id", "t_33333333", "--registry", str(registry)],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env=env,
    )
    item = json.loads(registry.read_text())["items"][0]
    assert item["status"] == "in-flight"
    assert item["delegated_task_id"] == "t_33333333"

    queue = subprocess.run(
        [sys.executable, str(SCRIPTS / "jarvis_briefing_queue.py"), "--json", "--no-kanban"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env=env,
    )
    payload = json.loads(queue.stdout)
    assert payload["count"] == 0
    assert payload["sources"]["registry_pending"] == 0


def test_briefing_queue_suppresses_pending_item_with_active_delegated_task(tmp_path):
    helper = load_script("jarvis_briefing_queue.py")
    import sqlite3
    db = tmp_path / "kanban.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, status TEXT)")
    conn.execute("INSERT INTO tasks VALUES (?, ?)", ("t_44444444", "ready"))
    conn.commit()
    conn.close()
    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps({
            "items": [
                {"id": "delegated", "title": "Worker has it", "status": "pending", "delegated_task_id": "t_44444444"},
                {"id": "plain", "title": "Still needs Mohib", "status": "pending"},
            ]
        }),
        encoding="utf-8",
    )

    items = helper.load_registry(path=registry, kanban_db=db)
    titles = {item["title"] for item in items}

    assert "Worker has it" not in titles
    assert "Still needs Mohib" in titles


def test_action_board_render_places_in_flight_items_in_delegated_section():
    board = load_script("mohib_action_board.py")
    text = board.render([
        {"id": "pending", "title": "Needs Mohib", "profile": "default", "status": "pending"},
        {"id": "delegated", "title": "Worker has it", "profile": "default", "status": "in-flight", "delegated_task_id": "t_44444444"},
    ])

    assert "== WAITING ON YOU (undated) ==" in text
    assert "☐ Needs Mohib" in text
    assert "== IN PROCESS / DELEGATED ==" in text
    assert "🔄 Worker has it  [default] → t_44444444" in text


def test_briefing_helper_cli_no_kanban_outputs_one_spoken_line(tmp_path):
    root = tmp_path / "hermes"
    state = root / "state"
    state.mkdir(parents=True)
    (state / "mohib-action-registry.json").write_text(
        json.dumps({"items": [{"id": "x", "title": "One item", "status": "pending", "due": "2026-06-20"}]}),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["HERMES_ROOT"] = str(root)
    proc = subprocess.run(
        [sys.executable, str(SCRIPTS / "jarvis_briefing_queue.py"), "--spoken", "--no-kanban"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env=env,
    )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "First item: One item" in lines[0]
    assert "Your call." in lines[0]

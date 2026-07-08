from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "open_loop_consolidator.py"


def load_module():
    spec = importlib.util.spec_from_file_location("open_loop_consolidator", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def make_kanban_db(path: Path, rows: list[tuple[str, str, str, str, str]]) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE tasks (id TEXT PRIMARY KEY, title TEXT, body TEXT, assignee TEXT, status TEXT)")
    conn.executemany("INSERT INTO tasks VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()


def test_consolidator_throttles_duplicate_open_loop_actions(tmp_path):
    mod = load_module()
    state_path = tmp_path / "state.json"
    records_path = tmp_path / "records.json"
    records_path.write_text(json.dumps({
        "records": [
            {
                "source": "watchdog",
                "source_id": "daily-health",
                "title": "Daily health page still failing",
                "detail": "last_status=error",
                "gate": "internal",
            }
        ]
    }))

    first = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--records-json",
            str(records_path),
            "--state",
            str(state_path),
            "--apply",
            "--now",
            "2026-06-18T12:00:00+00:00",
            "--throttle-seconds",
            "3600",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    first_payload = json.loads(first.stdout)
    assert first_payload["summary"]["emit_count"] == 1
    assert first_payload["actions"][0]["action"] == "kanban:create"
    assert state_path.exists()

    second = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--records-json",
            str(records_path),
            "--state",
            str(state_path),
            "--dry-run",
            "--now",
            "2026-06-18T12:30:00+00:00",
            "--throttle-seconds",
            "3600",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    second_payload = json.loads(second.stdout)
    assert second_payload["summary"]["emit_count"] == 0
    assert second_payload["summary"]["throttled_count"] == 1
    assert second_payload["throttled"][0]["throttled"] is True

    state_after_dry_run = json.loads(state_path.read_text())
    assert state_after_dry_run["updated_at"] == "2026-06-18T12:00:00+00:00"
    assert mod.SCHEMA_VERSION == 1


def test_consolidator_closes_absent_records_and_suppresses_delegated_registry_items(tmp_path):
    mod = load_module()
    state = {
        "schema_version": 1,
        "records": {
            "ol_old": {
                "key": "ol_old",
                "status": "open",
                "source": "kanban",
                "source_id": "t_old",
                "title": "Old blocked thing",
                "fingerprint": "old",
                "first_seen_at": "2026-06-17T12:00:00+00:00",
                "last_emitted_at": "2026-06-17T12:00:00+00:00",
            }
        },
    }
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({
        "items": [
            {
                "id": "delegated-item",
                "title": "Worker already has this",
                "status": "pending",
                "delegated_task_id": "t_active",
                "profile": "default",
            }
        ]
    }))
    kanban = tmp_path / "kanban.db"
    make_kanban_db(kanban, [("t_active", "Active task", "", "default", "running")])

    records = mod.collect_from_action_registry(registry, kanban_db=kanban, now_iso="2026-06-18T12:00:00+00:00")
    assert records[0].state == "suppressed"

    result = mod.consolidate(records, state, now_iso="2026-06-18T12:00:00+00:00", throttle_seconds=3600)
    assert result["summary"] == {
        "records_seen": 1,
        "emit_count": 0,
        "throttled_count": 0,
        "suppressed_count": 1,
        "closed_count": 1,
    }
    assert result["suppressed"][0]["action"] == "suppress"
    assert result["closed"][0]["key"] == "ol_old"
    closed_state = result["state"]["records"]["ol_old"]
    assert closed_state["status"] == "closed"
    assert closed_state["closure"]["reason"] == "source_absent_or_terminal"


def test_collectors_classify_kanban_and_hindsight_fixture_records(tmp_path):
    mod = load_module()
    kanban = tmp_path / "kanban.db"
    make_kanban_db(
        kanban,
        [
            ("t_mohib", "Need Mohib approval", "credential choice", "default", "blocked"),
            ("t_internal", "review-required cron fix", "tests pass", "default", "blocked"),
            ("t_done", "Done", "", "default", "done"),
        ],
    )
    hindsight = tmp_path / "hindsight.jsonl"
    hindsight.write_text(
        json.dumps({"id": "h1", "title": "Fleet cron still failing", "unresolved": True}) + "\n" +
        json.dumps({"id": "h2", "title": "Resolved item", "resolved": True}) + "\n"
    )

    records = mod.collect_from_kanban(kanban, now_iso="2026-06-18T12:00:00+00:00")
    gates = {record.source_id: record.gate for record in records}
    assert gates == {"t_mohib": "mohib", "t_internal": "internal"}

    hindsight_records = mod.collect_from_hindsight_json(hindsight, now_iso="2026-06-18T12:00:00+00:00")
    assert [record.source_id for record in hindsight_records] == ["h1"]
    assert hindsight_records[0].gate == "internal"

    result = mod.consolidate(records + hindsight_records, {"schema_version": 1, "records": {}}, now_iso="2026-06-18T12:00:00+00:00", throttle_seconds=3600)
    actions = {(action["record"]["source_id"], action["action"]) for action in result["actions"]}
    assert ("t_mohib", "action_board:add") in actions
    assert ("t_internal", "kanban:create") in actions
    assert ("h1", "kanban:create") in actions

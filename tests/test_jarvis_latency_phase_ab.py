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

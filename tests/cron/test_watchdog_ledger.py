"""Tests for cron watchdog result ledger persistence."""
from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest


@pytest.fixture
def hermes_env(tmp_path, monkeypatch):
    """Isolate HERMES_HOME and reload modules that resolve it at import time."""
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "cron").mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))

    import hermes_constants
    importlib.reload(hermes_constants)
    import cron.watchdog_ledger
    importlib.reload(cron.watchdog_ledger)

    return home


def _ts(second: int = 0) -> datetime:
    return datetime(2026, 1, 1, 12, 0, second, tzinfo=timezone.utc)


def test_record_watchdog_result_first_seen_then_unchanged(hermes_env):
    from cron.watchdog_ledger import load_watchdog_record, record_watchdog_result

    job = {"id": "job_1", "name": "Memory watchdog"}

    first = record_watchdog_result(job, status="ok", output="disk 80%", now=_ts(0))
    assert first["changed"] is True
    assert first["reason"] == "first_seen"
    assert first["previous_hash"] is None

    second = record_watchdog_result(job, status="ok", output="disk 80%", now=_ts(1))
    assert second["changed"] is False
    assert second["reason"] == "unchanged"
    assert second["previous_hash"] == first["current_hash"]

    record = load_watchdog_record("job_1")
    assert record is not None
    assert record["run_count"] == 2
    assert record["changed_count"] == 1
    assert record["last_status"] == "ok"
    assert record["last_reason"] == "unchanged"
    assert len(record["history"]) == 2


def test_record_watchdog_result_changed_output_and_recovered(hermes_env):
    from cron.watchdog_ledger import record_watchdog_result

    job = {"id": "job_2", "name": "API watchdog"}

    record_watchdog_result(job, status="ok", output="healthy", now=_ts(0))
    changed = record_watchdog_result(job, status="ok", output="latency high", now=_ts(1))
    assert changed["changed"] is True
    assert changed["reason"] == "output_changed"

    failed = record_watchdog_result(
        job, status="error", output="exit 2", error="exit 2", now=_ts(2)
    )
    assert failed["changed"] is True
    assert failed["reason"] == "status_changed"

    recovered = record_watchdog_result(job, status="silent", output="", now=_ts(3))
    assert recovered["changed"] is True
    assert recovered["reason"] == "recovered"


def test_record_watchdog_result_rejects_unsafe_job_ids(hermes_env):
    from cron.watchdog_ledger import record_watchdog_result, watchdog_ledger_path

    for bad_id in ("", ".", "..", "../escape", "nested/job", "nested\\job", "/tmp/job"):
        with pytest.raises(ValueError):
            watchdog_ledger_path(bad_id)
        with pytest.raises(ValueError):
            record_watchdog_result({"id": bad_id}, status="ok", output="x")


def test_record_watchdog_result_bounds_history_and_preview(hermes_env):
    from cron.watchdog_ledger import load_watchdog_record, record_watchdog_result

    job = {"id": "job_3"}
    for i in range(5):
        record_watchdog_result(
            job,
            status="ok",
            output=f"payload {i} " + ("x" * 100),
            now=_ts(i),
            max_history=3,
            max_preview_chars=20,
        )

    record = load_watchdog_record("job_3")
    assert record is not None
    assert record["run_count"] == 5
    assert len(record["history"]) == 3
    assert record["history"][0]["preview"].startswith("payload 2")
    assert len(record["last_preview"]) <= 20


def test_load_watchdog_record_corrupt_json_is_recoverable(hermes_env):
    from cron.watchdog_ledger import load_watchdog_record, record_watchdog_result, watchdog_ledger_path

    path = watchdog_ledger_path("job_4")
    path.write_text("{not-json", encoding="utf-8")

    assert load_watchdog_record("job_4") is None

    result = record_watchdog_result({"id": "job_4"}, status="ok", output="fresh", now=_ts())
    assert result["changed"] is True
    assert result["reason"] == "first_seen"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["last_status"] == "ok"


def test_format_watchdog_metadata_is_archive_friendly(hermes_env):
    from cron.watchdog_ledger import format_watchdog_metadata, record_watchdog_result

    result = record_watchdog_result({"id": "job_5"}, status="silent", output="", now=_ts())
    metadata = format_watchdog_metadata(result)

    assert "**Watchdog Changed:** true" in metadata
    assert "**Watchdog Reason:** first_seen" in metadata
    assert "**Watchdog Result SHA256:**" in metadata
    assert "watchdog-ledger/job_5.json" in metadata


def test_silent_results_store_hashes_without_payload_preview(hermes_env):
    from cron.watchdog_ledger import load_watchdog_record, record_watchdog_result

    secretish_payload = '{"wakeAgent": false, "diagnostic": "token-like-value"}'
    record_watchdog_result(
        {"id": "job_silent"},
        status="silent",
        output=secretish_payload,
        now=_ts(),
    )

    record = load_watchdog_record("job_silent")
    assert record is not None
    assert record["last_preview"] == ""
    assert "preview" not in record["history"][-1]
    assert record["last_output_sha256"]
    assert "token-like-value" not in json.dumps(record)


def test_record_watchdog_result_cross_process_updates_are_serialized(hermes_env):
    from cron.watchdog_ledger import load_watchdog_record

    repo_root = str(Path(__file__).resolve().parents[2])
    worker_code = """
import os
import sys
sys.path.insert(0, os.environ['REPO_ROOT'])
from cron.watchdog_ledger import record_watchdog_result
worker = os.environ['WORKER_ID']
for i in range(25):
    record_watchdog_result(
        {'id': 'job_concurrent', 'name': 'Concurrent watchdog'},
        status='ok',
        output=f'worker={worker} i={i}',
        max_history=200,
    )
"""
    env_base = os.environ.copy()
    env_base["HERMES_HOME"] = str(hermes_env)
    env_base["REPO_ROOT"] = repo_root

    procs = []
    for worker_id in range(4):
        env = dict(env_base)
        env["WORKER_ID"] = str(worker_id)
        procs.append(
            subprocess.Popen(
                [sys.executable, "-c", worker_code],
                cwd=repo_root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

    failures = []
    for proc in procs:
        stdout, stderr = proc.communicate(timeout=20)
        if proc.returncode != 0:
            failures.append((proc.returncode, stdout, stderr))
    assert failures == []

    record = load_watchdog_record("job_concurrent")
    assert record is not None
    assert record["run_count"] == 100
    assert len(record["history"]) == 100

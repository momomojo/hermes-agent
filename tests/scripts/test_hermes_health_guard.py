"""Tests for scripts/hermes_health_guard.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path


def _load_health_guard_module():
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "hermes_health_guard.py"
    spec = importlib.util.spec_from_file_location("hermes_health_guard_for_test", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_ensure_venv_python_reexecs_when_launched_with_system_python(monkeypatch, tmp_path):
    guard = _load_health_guard_module()
    desired = tmp_path / "venv" / "bin" / "python"
    desired.parent.mkdir(parents=True)
    desired.write_text("#!/bin/sh\n", encoding="utf-8")
    desired.chmod(0o755)

    calls = []
    monkeypatch.setattr(guard, "PYTHON", desired)
    monkeypatch.setattr(guard.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(guard, "__file__", str(tmp_path / "hermes_health_guard.py"))
    monkeypatch.delenv("HERMES_HEALTH_GUARD_REEXECED", raising=False)
    monkeypatch.setattr(
        guard.os,
        "execve",
        lambda exe, argv, env: calls.append((exe, argv, env)),
    )

    guard._ensure_venv_python()

    assert len(calls) == 1
    exe, argv, env = calls[0]
    assert exe == str(desired.resolve())
    assert argv[0] == str(desired.resolve())
    assert argv[1].endswith("hermes_health_guard.py")
    assert env["HERMES_HEALTH_GUARD_REEXECED"] == "1"


def test_ensure_venv_python_noops_when_already_in_venv(monkeypatch, tmp_path):
    guard = _load_health_guard_module()
    desired = tmp_path / "venv" / "bin" / "python"
    desired.parent.mkdir(parents=True)
    desired.write_text("#!/bin/sh\n", encoding="utf-8")
    desired.chmod(0o755)

    monkeypatch.setattr(guard, "PYTHON", desired)
    monkeypatch.setattr(guard.sys, "executable", str(desired))
    monkeypatch.setattr(
        guard.os,
        "execve",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected execve")),
    )

    guard._ensure_venv_python()


# ── provider-health sentinel integration ───────────────────────────────────
#
# The autouse _hermetic_environment fixture points HERMES_HOME at a per-test
# tempdir before the module loads, so guard.HOME (and the derived
# PROVIDER_HEALTH_STATE_PATH) already target the fake home.


def _register_sentinel(home: Path, *, enabled: bool = True, paused: bool = False) -> None:
    (home / "cron").mkdir(exist_ok=True)
    job = {"name": "provider-health-sentinel", "enabled": enabled}
    if paused:
        job["paused_at"] = "2026-06-12T00:00:00+00:00"
    (home / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": [job]}), encoding="utf-8"
    )


def _write_provider_state(home: Path, payload) -> None:
    state_dir = home / "state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "provider-health-state.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )


def test_provider_health_skipped_when_sentinel_not_registered():
    guard = _load_health_guard_module()
    # No cron/jobs.json at all → portability guard keeps us silent even
    # though the state file is also missing.
    assert guard._check_provider_health() == []
    assert guard._provider_health_summary() == {}


def test_provider_health_skipped_when_sentinel_disabled_or_paused():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME, enabled=False)
    assert guard._check_provider_health() == []
    _register_sentinel(guard.HOME, paused=True)
    assert guard._check_provider_health() == []


def test_provider_health_missing_state_pages_once():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME)
    failures = guard._check_provider_health()
    assert failures == [
        "provider-health: state file missing/unreadable "
        "(sentinel cron registered but no output)"
    ]
    assert guard._provider_health_summary() == {}


def test_provider_health_stale_state_pages():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME)
    stale = (datetime.now().astimezone() - timedelta(minutes=120)).isoformat()
    _write_provider_state(guard.HOME, {"updated": stale, "lanes": {}})
    failures = guard._check_provider_health()
    assert len(failures) == 1
    assert "provider-health: state stale" in failures[0]
    assert "sentinel dead?" in failures[0]


def test_provider_health_fresh_state_no_failures():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME)
    fresh = datetime.now().astimezone().isoformat()
    _write_provider_state(
        guard.HOME,
        {"updated": fresh, "lanes": {"anthropic": {"status": "ok", "detail": ""}}},
    )
    assert guard._check_provider_health() == []
    assert guard._provider_health_summary() == {"anthropic": "ok"}


def test_provider_health_down_lane_pages_and_warn_lane_does_not():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME)
    fresh = datetime.now().astimezone().isoformat()
    _write_provider_state(
        guard.HOME,
        {
            "updated": fresh,
            "lanes": {
                "codex-provider@radulator": {"status": "down", "detail": "x" * 500},
                "anthropic": {"status": "warn", "detail": "slow"},
                "openrouter": {"status": "degraded", "detail": "flaky"},
            },
        },
    )
    failures = guard._check_provider_health()
    assert len(failures) == 1
    assert failures[0].startswith("provider-health: lane codex-provider@radulator down: ")
    detail = failures[0].split("down: ", 1)[1]
    assert detail == "x" * 160  # truncated to 160 chars
    summary = guard._provider_health_summary()
    assert summary == {
        "anthropic": "warn",
        "codex-provider@radulator": "down",
        "openrouter": "degraded",
    }


def test_provider_health_unparseable_updated_treated_as_no_output():
    guard = _load_health_guard_module()
    _register_sentinel(guard.HOME)
    _write_provider_state(guard.HOME, {"updated": "not-a-date", "lanes": {}})
    failures = guard._check_provider_health()
    assert len(failures) == 1
    assert "state file missing/unreadable" in failures[0]


def test_runtime_compile_success_is_silent(monkeypatch):
    guard = _load_health_guard_module()
    seen = []

    def fake_run(cmd, *, timeout=20.0):
        seen.append((cmd, timeout))
        return {"ok": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(guard, "_run", fake_run)
    assert guard._check_runtime_compile() == []
    assert seen == [
        (
            [str(guard.PYTHON), "-m", "compileall", "-q", *guard.COMPILEALL_TARGETS],
            guard.COMPILEALL_TIMEOUT_SECONDS,
        )
    ]


def test_runtime_compile_failure_pages_concisely(monkeypatch):
    guard = _load_health_guard_module()

    def fake_run(cmd, *, timeout=20.0):
        return {"ok": False, "stdout": "", "stderr": "IndentationError: unexpected indent"}

    monkeypatch.setattr(guard, "_run", fake_run)
    failures = guard._check_runtime_compile()
    assert failures == [
        "runtime compile gate failed: python -m compileall hermes_cli agent gateway plugins: "
        "IndentationError: unexpected indent"
    ]


# ── profile cron ownership / duplicate-registry quarantine ─────────────────


def _write_cron_jobs(home: Path, jobs: list[dict]) -> None:
    (home / "cron").mkdir(parents=True, exist_ok=True)
    (home / "cron" / "jobs.json").write_text(
        json.dumps({"jobs": jobs}), encoding="utf-8"
    )


def test_exact_default_cron_clone_is_flagged_before_jobs_error():
    guard = _load_health_guard_module()
    jobs = [
        {
            "id": "a",
            "name": "owner job",
            "prompt": "",
            "script": "owner.sh",
            "no_agent": True,
            "schedule": {"kind": "interval", "minutes": 5},
            "enabled": True,
            "last_status": "ok",
        },
        {
            "id": "b",
            "name": "second owner job",
            "prompt": "reason",
            "script": None,
            "no_agent": False,
            "schedule": {"kind": "cron", "expr": "0 9 * * *"},
            "enabled": True,
            "last_status": "ok",
        },
    ]
    _write_cron_jobs(guard.HOME, jobs)
    clone_home = guard.HOME / "profiles" / "coder"
    clone_jobs = json.loads(json.dumps(jobs))
    clone_jobs[0]["last_status"] = "error"
    clone_jobs[0]["last_error"] = "profile-local script missing"
    _write_cron_jobs(clone_home, clone_jobs)
    (clone_home / "config.yaml").write_text("cron:\n  enabled: true\n", encoding="utf-8")

    failures = guard._check_duplicate_cron_registries(["coder"])

    assert len(failures) == 1
    assert "cron registry duplicated from default for coder" in failures[0]
    assert "2 exact job definition(s)" in failures[0]


def test_profile_with_owned_cron_job_is_not_misclassified_as_clone():
    guard = _load_health_guard_module()
    _write_cron_jobs(
        guard.HOME,
        [{"id": "a", "name": "default", "script": "a.sh", "enabled": True}],
    )
    profile_home = guard.HOME / "profiles" / "coder"
    _write_cron_jobs(
        profile_home,
        [{"id": "owned", "name": "owned", "script": "owned.sh", "enabled": True}],
    )
    (profile_home / "config.yaml").write_text("cron:\n  enabled: true\n", encoding="utf-8")

    assert guard._check_duplicate_cron_registries(["coder"]) == []


def test_disabled_profile_cron_errors_are_quarantined_from_health_pages():
    guard = _load_health_guard_module()
    profile_home = guard.HOME / "profiles" / "coder"
    _write_cron_jobs(
        profile_home,
        [
            {
                "id": "a",
                "name": "stale cloned failure",
                "enabled": True,
                "last_status": "error",
                "last_error": "Script not found",
            }
        ],
    )
    (profile_home / "config.yaml").write_text("cron:\n  enabled: false\n", encoding="utf-8")

    assert guard._check_cron_failures(["coder"]) == []


def test_html_table_stringifies_structured_missing_entries():
    guard = _load_health_guard_module()

    table = guard._html_table(
        [
            {
                "profile": "default",
                "ok": False,
                "missing": [{"missing": ["task-a"], "reason": "not runnable"}],
            }
        ],
        "preflight",
    )

    assert (
        "{&quot;missing&quot;:[&quot;task-a&quot;],&quot;reason&quot;:&quot;not runnable&quot;}"
        in table
    )


# ── managed-layer drift ─────────────────────────────────────────────────────


def test_managed_layer_drift_skipped_without_git(monkeypatch):
    guard = _load_health_guard_module()
    monkeypatch.setattr(guard, "REPO", guard.HOME)  # _run cwd must exist
    assert not (guard.HOME / ".git").exists()
    assert guard._check_managed_layer_drift() == []


def test_managed_layer_drift_fresh_vs_old_dirty_paths(monkeypatch):
    guard = _load_health_guard_module()
    monkeypatch.setattr(guard, "REPO", guard.HOME)  # _run cwd must exist
    subprocess.run(
        ["git", "init", "-q", str(guard.HOME)], check=True, capture_output=True
    )

    dirty = guard.HOME / "config-drift.json"
    dirty.write_text("{}\n", encoding="utf-8")

    # Fresh dirty file: survived no autocommit yet → silent.
    assert guard._check_managed_layer_drift() == []

    # Same file with mtime pushed past the threshold → one consolidated page.
    old = datetime.now() - timedelta(hours=guard.MANAGED_DRIFT_MAX_AGE_H + 1)
    os.utime(dirty, (old.timestamp(), old.timestamp()))
    failures = guard._check_managed_layer_drift()
    assert len(failures) == 1
    assert failures[0].startswith("managed-layer drift: 1 uncommitted path(s) older than ")
    assert "config-drift.json" in failures[0]
    assert "autocommit aborted/failing?" in failures[0]


def _backup_timestamp(*, hours_ago: float) -> str:
    return (datetime.now() - timedelta(hours=hours_ago)).strftime("%Y-%m-%d %H:%M:%S")


def test_backup_freshness_accepts_clean_zero_exit(monkeypatch, tmp_path):
    guard = _load_health_guard_module()
    log = tmp_path / "home-backup.log"
    stamp = _backup_timestamp(hours_ago=1)
    log.write_text(
        f"=== hermes home backup started {stamp} ===\n"
        f"=== finished {stamp} rsync_rc=0/0 ===\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(guard, "BACKUP_LOG", log)

    assert guard._check_backup_freshness() == []


def test_backup_freshness_accepts_wrapper_classified_vanished_source_race(
    monkeypatch, tmp_path
):
    guard = _load_health_guard_module()
    log = tmp_path / "home-backup.log"
    stamp = _backup_timestamp(hours_ago=1)
    log.write_text(
        f"=== hermes home backup started {stamp} ===\n"
        "rsync(42): error: /tmp/source: open (2): No such file or directory\n"
        f"=== finished {stamp} rsync_rc=23/0 ===\n"
        "BACKUP OK with benign vanished-source warning rc=23/0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(guard, "BACKUP_LOG", log)

    assert guard._check_backup_freshness() == []


def test_backup_freshness_rejects_unclassified_or_mismatched_nonzero_run(
    monkeypatch, tmp_path
):
    guard = _load_health_guard_module()
    log = tmp_path / "home-backup.log"
    old_stamp = _backup_timestamp(hours_ago=48)
    new_stamp = _backup_timestamp(hours_ago=1)
    log.write_text(
        f"=== hermes home backup started {old_stamp} ===\n"
        f"=== finished {old_stamp} rsync_rc=0/0 ===\n"
        f"=== hermes home backup started {new_stamp} ===\n"
        f"=== finished {new_stamp} rsync_rc=23/0 ===\n"
        "BACKUP OK with benign vanished-source warning rc=24/0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(guard, "BACKUP_LOG", log)

    failures = guard._check_backup_freshness()
    assert len(failures) == 1
    assert f"home-backup stale: last success {old_stamp}" in failures[0]


def test_gateway_restart_not_required_for_health_scripts_and_tests(monkeypatch):
    guard = _load_health_guard_module()
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, stdout="baseline-sha\n", stderr=""),
            subprocess.CompletedProcess(
                [],
                0,
                stdout="scripts/hermes_health_guard.py\ntests/scripts/test_hermes_health_guard.py\n",
                stderr="",
            ),
        ]
    )
    monkeypatch.setattr(guard.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert guard._gateway_restart_required_since(12345) is False


def test_gateway_restart_required_for_runtime_change(monkeypatch):
    guard = _load_health_guard_module()
    responses = iter(
        [
            subprocess.CompletedProcess([], 0, stdout="baseline-sha\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="gateway/run.py\n", stderr=""),
        ]
    )
    monkeypatch.setattr(guard.subprocess, "run", lambda *_args, **_kwargs: next(responses))

    assert guard._gateway_restart_required_since(12345) is True


def test_gateway_restart_required_when_git_baseline_is_ambiguous(monkeypatch):
    guard = _load_health_guard_module()
    monkeypatch.setattr(
        guard.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            [], 1, stdout="", stderr="git failed"
        ),
    )

    assert guard._gateway_restart_required_since(12345) is True


def test_hindsight_recall_types_observation_only_is_healthy(monkeypatch):
    guard = _load_health_guard_module()
    (guard.HOME / "hindsight").mkdir(exist_ok=True)
    (guard.HOME / "config.yaml").write_text("memory:\n  provider: hindsight\n", encoding="utf-8")
    (guard.HOME / "hindsight" / "config.json").write_text(
        json.dumps({
            "api_url": "http://truenas-scale.tail1339c4.ts.net:8890",
            "bank_id": "hermes-owner",
            "recall_types": ["observation"],
        }),
        encoding="utf-8",
    )

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return json.dumps({"banks": [{"bank_id": "hermes-owner"}]}).encode()

    monkeypatch.setattr(guard.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())

    assert guard._check_hindsight_config(None) == []


def test_hindsight_recall_types_mixed_is_flagged(monkeypatch):
    guard = _load_health_guard_module()
    (guard.HOME / "hindsight").mkdir(exist_ok=True)
    (guard.HOME / "config.yaml").write_text("memory:\n  provider: hindsight\n", encoding="utf-8")
    (guard.HOME / "hindsight" / "config.json").write_text(
        json.dumps({
            "api_url": "http://truenas-scale.tail1339c4.ts.net:8890",
            "bank_id": "hermes-owner",
            "recall_types": ["observation", "world", "experience"],
        }),
        encoding="utf-8",
    )

    class FakeResponse:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def read(self):
            return json.dumps({"banks": [{"bank_id": "hermes-owner"}]}).encode()

    monkeypatch.setattr(guard.urllib.request, "urlopen", lambda *_args, **_kwargs: FakeResponse())

    failures = guard._check_hindsight_config(None)
    assert len(failures) == 1
    assert "should be ['observation']" in failures[0]

import json
from pathlib import Path

import pytest
import yaml

from hermes_cli.config_apply_gate import apply_gated_config_value
from hermes_cli.config import (
    LiveConfigApplyGateError,
    authorized_live_config_apply,
    save_config,
    set_config_value,
)
from hermes_cli.judge_gate import JudgeGateError, resolve_judge_verdict


def _write_ledger(path: Path, entries: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(json.dumps(entry, sort_keys=True) for entry in entries) + "\n",
        encoding="utf-8",
    )
    return path


def test_resolve_judge_verdict_accepts_matching_approve(tmp_path):
    ledger = _write_ledger(
        tmp_path / "judge-ledger.jsonl",
        [
            {
                "ts": 100,
                "title": "Pin fall-through auxiliary tasks to flash",
                "verdict": "APPROVE",
                "detail": "GATE-VERDICT: APPROVE\nLooks good.",
            }
        ],
    )

    verdict = resolve_judge_verdict(
        "100",
        expected_title="Pin fall-through auxiliary tasks to flash",
        ledger_path=ledger,
    )

    assert verdict.id == "100"
    assert verdict.verdict == "APPROVE"
    assert verdict.future_conditions == ()


def test_resolve_judge_verdict_refuses_missing_verdict(tmp_path):
    ledger = _write_ledger(tmp_path / "judge-ledger.jsonl", [])

    with pytest.raises(JudgeGateError, match="not found"):
        resolve_judge_verdict(
            "404",
            expected_title="Pin fall-through auxiliary tasks to flash",
            ledger_path=ledger,
        )


def test_resolve_judge_verdict_refuses_empty_verdict_id(tmp_path):
    ledger = _write_ledger(tmp_path / "judge-ledger.jsonl", [])

    with pytest.raises(JudgeGateError, match="missing judge verdict id"):
        resolve_judge_verdict(
            "",
            expected_title="Pin fall-through auxiliary tasks to flash",
            ledger_path=ledger,
        )


def test_resolve_judge_verdict_refuses_non_approve(tmp_path):
    ledger = _write_ledger(
        tmp_path / "judge-ledger.jsonl",
        [
            {
                "ts": 101,
                "title": "Pin fall-through auxiliary tasks to flash",
                "verdict": "REJECT",
                "detail": "GATE-VERDICT: REJECT\nNot this.",
            }
        ],
    )

    with pytest.raises(JudgeGateError, match="not APPROVE"):
        resolve_judge_verdict(
            "101",
            expected_title="Pin fall-through auxiliary tasks to flash",
            ledger_path=ledger,
        )


def test_resolve_judge_verdict_refuses_title_mismatch(tmp_path):
    ledger = _write_ledger(
        tmp_path / "judge-ledger.jsonl",
        [
            {
                "ts": 102,
                "title": "Unrelated production restart",
                "verdict": "APPROVE",
                "detail": "GATE-VERDICT: APPROVE\nDifferent scope.",
            }
        ],
    )

    with pytest.raises(JudgeGateError, match="title mismatch"):
        resolve_judge_verdict(
            "102",
            expected_title="Pin fall-through auxiliary tasks to flash",
            ledger_path=ledger,
        )


def test_gated_config_apply_creates_verdict_bound_backup(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")
    ledger = _write_ledger(
        tmp_path / "state" / "judge-ledger.jsonl",
        [
            {
                "ts": 200,
                "title": "Pin fall-through auxiliary tasks to flash",
                "verdict": "APPROVE",
                "detail": "GATE-VERDICT: APPROVE\nConfig-only change.",
            }
        ],
    )

    result = apply_gated_config_value(
        "model.default",
        "new-model",
        verdict_id="200",
        change="aux-pin",
        expected_title="Pin fall-through auxiliary tasks to flash",
        ledger_path=ledger,
    )

    assert result.backup_dir.parent == home / "backups"
    assert result.backup_dir.name.startswith("aux-pin-200-")
    assert (result.backup_dir / "config.yaml").read_text(encoding="utf-8") == (
        "model:\n  default: old-model\n"
    )
    manifest = json.loads((result.backup_dir / "manifest.json").read_text())
    assert manifest["verdict_id"] == "200"
    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["model"]["default"] == "new-model"


def test_future_condition_apply_creates_idempotent_verification_card(
    monkeypatch, tmp_path
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_KANBAN_HOME", str(home))
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")
    ledger = _write_ledger(
        tmp_path / "state" / "judge-ledger.jsonl",
        [
            {
                "ts": 201,
                "title": "Pin fall-through auxiliary tasks to flash",
                "verdict": "APPROVE",
                "detail": (
                    "GATE-VERDICT: APPROVE\n"
                    "Condition: after the 03:30 restart, verify aux routing "
                    "on all profiles."
                ),
            }
        ],
    )

    first = apply_gated_config_value(
        "model.default",
        "new-model",
        verdict_id="201",
        change="aux-pin",
        expected_title="Pin fall-through auxiliary tasks to flash",
        ledger_path=ledger,
    )
    second = apply_gated_config_value(
        "model.default",
        "new-model",
        verdict_id="201",
        change="aux-pin",
        expected_title="Pin fall-through auxiliary tasks to flash",
        ledger_path=ledger,
    )

    assert first.future_verification_task_id
    assert first.future_verification_task_id == second.future_verification_task_id

    from hermes_cli import kanban_db as kb

    conn = kb.connect()
    try:
        rows = conn.execute(
            "SELECT id, title, status, idempotency_key FROM tasks "
            "WHERE idempotency_key LIKE 'config-apply-future:201:%'"
        ).fetchall()
    finally:
        conn.close()

    assert len(rows) == 1
    assert rows[0]["id"] == first.future_verification_task_id
    assert rows[0]["status"] == "blocked"
    assert "Verify future condition" in rows[0]["title"]


def test_config_set_refuses_guarded_live_fleet_key_on_default_root(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".hermes"
    (home / "state").mkdir(parents=True)
    (home / "state" / "judge-ledger.jsonl").write_text("", encoding="utf-8")
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        set_config_value("model.default", "new-model")

    assert exc.value.code == 2
    assert config_path.read_text(encoding="utf-8") == (
        "model:\n  default: old-model\n"
    )
    assert "judge-gated apply" in capsys.readouterr().err


def test_config_set_allows_unguarded_live_fleet_key_on_default_root(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".hermes"
    (home / "state").mkdir(parents=True)
    (home / "state" / "judge-ledger.jsonl").write_text("", encoding="utf-8")
    config_path = home / "config.yaml"
    config_path.write_text("display:\n  inline_diffs: false\n", encoding="utf-8")

    set_config_value("display.inline_diffs", "true")

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["display"]["inline_diffs"] is True


def test_config_set_allows_guarded_key_under_non_live_temp_home(
    monkeypatch, tmp_path
):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")

    set_config_value("model.default", "new-model")

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["model"]["default"] == "new-model"


def test_save_config_refuses_guarded_live_fleet_change(monkeypatch, tmp_path):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".hermes"
    (home / "state").mkdir(parents=True)
    (home / "state" / "judge-ledger.jsonl").write_text("", encoding="utf-8")
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")

    with pytest.raises(LiveConfigApplyGateError, match="model"):
        save_config({"model": {"default": "new-model"}})

    assert config_path.read_text(encoding="utf-8") == (
        "model:\n  default: old-model\n"
    )


def test_save_config_allows_guarded_live_fleet_change_inside_apply_context(
    monkeypatch, tmp_path
):
    monkeypatch.delenv("HERMES_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".hermes"
    (home / "state").mkdir(parents=True)
    (home / "state" / "judge-ledger.jsonl").write_text("", encoding="utf-8")
    config_path = home / "config.yaml"
    config_path.write_text("model:\n  default: old-model\n", encoding="utf-8")

    with authorized_live_config_apply():
        save_config({"model": {"default": "new-model"}})

    saved = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert saved["model"]["default"] == "new-model"

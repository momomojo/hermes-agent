"""Judge-gated config apply helpers."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hermes_cli.judge_gate import JudgeVerdict, resolve_judge_verdict


@dataclass(frozen=True)
class ConfigApplyResult:
    config_path: Path
    backup_dir: Path
    verdict: JudgeVerdict
    future_verification_task_id: str | None = None


_SAFE_PART_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_name_part(value: str, *, fallback: str) -> str:
    cleaned = _SAFE_PART_RE.sub("-", str(value or "").strip()).strip("-._")
    return cleaned[:80] or fallback


def create_verdict_config_backup(
    config_path: str | Path,
    *,
    change: str,
    verdict: JudgeVerdict,
    future_verification_task_id: str | None = None,
) -> Path:
    """Create a verdict-bound backup directory under ``<root>/backups``."""
    from hermes_constants import get_default_hermes_root
    from utils import atomic_json_write

    config_path = Path(config_path)
    backup_root = get_default_hermes_root() / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    change_part = _safe_name_part(change, fallback="config-apply")
    verdict_part = _safe_name_part(verdict.id, fallback="verdict")
    base_name = f"{change_part}-{verdict_part}-{stamp}"
    backup_dir = backup_root / base_name
    suffix = 1
    while backup_dir.exists():
        backup_dir = backup_root / f"{base_name}-{suffix}"
        suffix += 1
    backup_dir.mkdir(mode=0o700)

    copied_config = None
    if config_path.exists():
        copied_config = backup_dir / config_path.name
        shutil.copy2(config_path, copied_config)

    manifest = {
        "change": change,
        "verdict_id": verdict.id,
        "verdict_ts": verdict.ts,
        "verdict_title": verdict.title,
        "config_path": str(config_path),
        "copied_config": str(copied_config) if copied_config else None,
        "created_at": int(time.time()),
        "future_conditions": list(verdict.future_conditions),
        "future_verification_task_id": future_verification_task_id,
    }
    atomic_json_write(backup_dir / "manifest.json", manifest, indent=2, sort_keys=True)
    return backup_dir


def ensure_future_condition_verification_card(
    *,
    verdict: JudgeVerdict,
    change: str,
    config_path: str | Path,
    board: str | None = None,
) -> str | None:
    """Create an idempotent blocked Kanban card for future verdict conditions."""
    if not verdict.future_conditions:
        return None

    from hermes_cli import kanban_db as kb

    key_material = "\n".join([verdict.id, change, *verdict.future_conditions])
    key_hash = hashlib.sha256(key_material.encode("utf-8")).hexdigest()[:16]
    idempotency_key = f"config-apply-future:{verdict.id}:{key_hash}"
    title = (
        f"Verify future condition for {change} "
        f"(judge verdict {verdict.id})"
    )
    body = "\n".join(
        [
            "A judge-approved config apply included future-looking condition(s).",
            "",
            f"Change: {change}",
            f"Verdict id: {verdict.id}",
            f"Verdict title: {verdict.title}",
            f"Config path: {Path(config_path)}",
            "",
            "Conditions:",
            *[f"- {line}" for line in verdict.future_conditions],
            "",
            "Verify the condition evidence and comment the result before closing.",
        ]
    )
    conn = kb.connect(board=board)
    try:
        return kb.create_task(
            conn,
            title=title,
            body=body,
            created_by="config-apply-gate",
            workspace_kind="scratch",
            priority=50,
            idempotency_key=idempotency_key,
            initial_status="blocked",
            board=board,
        )
    finally:
        conn.close()


def apply_gated_config_value(
    key: str,
    value: Any,
    *,
    verdict_id: str,
    change: str,
    expected_title: str | None = None,
    expected_scope: str | None = None,
    ledger_path: str | Path | None = None,
    board: str | None = None,
) -> ConfigApplyResult:
    """Apply one config key after a matching APPROVE verdict is validated."""
    from hermes_cli.config import (
        _set_nested,
        _terminal_env_value,
        authorized_live_config_apply,
        ensure_hermes_home,
        get_config_path,
        require_live_config_apply_authorized_for_key,
        save_env_value,
        terminal_config_env_var_for_key,
    )
    from utils import locked_yaml_mutate

    if not str(change or "").strip():
        raise ValueError("--change is required for verdict-bound backup naming")

    verdict = resolve_judge_verdict(
        verdict_id,
        expected_title=expected_title,
        expected_scope=expected_scope,
        ledger_path=ledger_path,
    )

    ensure_hermes_home()
    config_path = get_config_path()
    with authorized_live_config_apply():
        require_live_config_apply_authorized_for_key(key, config_path=config_path)

    future_task_id = ensure_future_condition_verification_card(
        verdict=verdict,
        change=change,
        config_path=config_path,
        board=board,
    )
    backup_dir = create_verdict_config_backup(
        config_path,
        change=change,
        verdict=verdict,
        future_verification_task_id=future_task_id,
    )
    with authorized_live_config_apply():
        locked_yaml_mutate(
            config_path,
            lambda cfg: _set_nested(cfg, key, value),
            sort_keys=False,
        )

    env_var = terminal_config_env_var_for_key(key)
    if env_var and key != "terminal.cwd":
        save_env_value(env_var, _terminal_env_value(value))

    try:
        os.chmod(config_path, 0o600)
    except (OSError, NotImplementedError):
        pass

    return ConfigApplyResult(
        config_path=config_path,
        backup_dir=backup_dir,
        verdict=verdict,
        future_verification_task_id=future_task_id,
    )

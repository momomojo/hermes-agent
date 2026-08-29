"""Host-sealed Kanban dispatch authority cannot be minted by model workers."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import stat
from pathlib import Path

import pytest

from hermes_cli import kanban as kc
from hermes_cli import kanban_db as kb


@pytest.fixture
def kanban_home(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    return home


def _host_cli(*tokens: str) -> tuple[int, str, str]:
    parser = argparse.ArgumentParser(prog="hermes")
    sub = parser.add_subparsers(dest="command")
    kc.build_parser(sub, include_host_authority=True)
    args = parser.parse_args(["kanban", *tokens])
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        rc = kc.kanban_command(args)
    return int(rc or 0), stdout.getvalue(), stderr.getvalue()


def _init_authority() -> dict:
    rc, stdout, stderr = _host_cli("authority", "init", "--json")
    assert rc == 0, stderr
    return json.loads(stdout)


def _trusted_create(*extra: str) -> tuple[int, dict | None, str]:
    tokens = (
        "trusted-create",
        "publisher prerequisite",
        "--body",
        "Pinned Radulator publisher prerequisite v1",
        "--assignee",
        "radulator",
        "--created-by",
        "radulator-no-agent-installer",
        "--idempotency-key",
        "radulator:publisher-prerequisite:v1",
        "--priority",
        "17",
        "--max-runtime",
        "45m",
        "--skill",
        "sdlc-review",
        "--skill",
        "github-code-review",
        "--max-retries",
        "2",
        "--model",
        "qwen-local",
        "--provider",
        "custom",
        "--reasoning",
        "high",
        "--goal",
        "--goal-max-turns",
        "7",
        "--session-id",
        "publisher-install-session",
        "--workflow-template-id",
        "publisher-install-v1",
        "--current-step-key",
        "preflight",
        "--initial-status",
        "blocked",
        *extra,
        "--json",
    )
    rc, stdout, stderr = _host_cli(*tokens)
    return rc, json.loads(stdout) if stdout.strip() else None, stderr


def test_authority_key_is_board_local_private_and_not_returned(kanban_home):
    result = _init_authority()

    key_path = kb.board_dir() / ".trusted-dispatch-authority.key"
    key_stat = key_path.lstat()
    assert stat.S_ISREG(key_stat.st_mode)
    assert stat.S_IMODE(key_stat.st_mode) == 0o600
    assert key_stat.st_uid == os.geteuid()
    assert key_stat.st_nlink == 1
    assert key_path.read_bytes()
    assert "key" not in json.dumps(result).lower().replace("key_id", "")
    assert result["contract"] == "hermes.kanban_dispatch_authority.v1"
    assert result["initialized"] is True


def test_ai_slash_surface_cannot_reach_host_authority_commands(kanban_home):
    _init_authority()

    output = kc.run_slash(
        "trusted-create forged --idempotency-key radulator:forged:v1 --json"
    )

    assert "usage error" in output.lower()
    with kb.connect_closing() as conn:
        assert kb.list_tasks(conn, limit=100) == []


def test_trusted_create_receipt_covers_full_dispatch_definition(kanban_home):
    _init_authority()
    rc, created, stderr = _trusted_create()
    assert rc == 0, stderr

    rc, stdout, stderr = _host_cli("show", created["id"], "--json")
    assert rc == 0, stderr
    shown = json.loads(stdout)
    task = shown["task"]
    receipt = shown["dispatch_authority"]

    assert task["goal_mode"] is True
    assert task["goal_max_turns"] == 7
    assert task["skills"] == ["sdlc-review", "github-code-review"]
    assert task["max_retries"] == 2
    assert task["session_id"] == "publisher-install-session"
    assert task["workflow_template_id"] == "publisher-install-v1"
    assert task["current_step_key"] == "preflight"
    assert receipt["contract"] == "hermes.kanban_dispatch_authority.v1"
    assert receipt["signature_valid"] is True
    assert receipt["row_matches_payload"] is True
    assert receipt["verified"] is True
    assert "signature" not in receipt
    assert "mac" not in receipt
    payload = receipt["payload"]
    assert payload == {
        "contract": "hermes.kanban_dispatch_authority.v1",
        "board": "default",
        "task_id": created["id"],
        "title": "publisher prerequisite",
        "body": "Pinned Radulator publisher prerequisite v1",
        "body_sha256": task["body_sha256"],
        "assignee": "radulator",
        "profile": "radulator",
        "created_by": "radulator-no-agent-installer",
        "creation_origin": "host_sealed",
        "created_at": task["created_at"],
        "idempotency_key": "radulator:publisher-prerequisite:v1",
        "tenant": None,
        "priority": 17,
        "requested_initial_status": "blocked",
        "requested_workspace_kind": "scratch",
        "requested_workspace_path": None,
        "requested_branch_name": None,
        "requested_project_id": None,
        "requested_triage": False,
        "pre_dispatch_status": "blocked",
        "workspace_kind": "scratch",
        "workspace_path": None,
        "branch_name": None,
        "project_id": None,
        "parent_ids": [],
        "max_runtime_seconds": 45 * 60,
        "skills": ["sdlc-review", "github-code-review"],
        "max_retries": 2,
        "model_override": "qwen-local",
        "provider_override": "custom",
        "reasoning_effort": "high",
        "goal_mode": True,
        "goal_max_turns": 7,
        "session_id": "publisher-install-session",
        "workflow_template_id": "publisher-install-v1",
        "current_step_key": "preflight",
    }
    assert shown["idempotency_readback"] == {
        "key": "radulator:publisher-prerequisite:v1",
        "active_match_count": 1,
        "active_task_ids": [created["id"]],
    }


def test_trusted_create_rejects_unsealed_idempotency_collision(kanban_home):
    _init_authority()
    with kb.connect_closing() as conn:
        attacker = kb.create_task(
            conn,
            title="publisher prerequisite",
            body="Pinned Radulator publisher prerequisite v1",
            assignee="radulator",
            created_by="radulator-no-agent-installer",
            creation_origin="trusted_cli",
            idempotency_key="radulator:publisher-prerequisite:v1",
            priority=17,
            max_runtime_seconds=45 * 60,
            skills=["sdlc-review", "github-code-review"],
            max_retries=2,
            model_override="qwen-local",
            provider_override="custom",
            reasoning_effort="high",
            goal_mode=True,
            goal_max_turns=7,
            session_id="publisher-install-session",
            workflow_template_id="publisher-install-v1",
            current_step_key="preflight",
            initial_status="blocked",
        )

    rc, created, stderr = _trusted_create()

    assert rc == 1
    assert created is None
    assert "unsealed idempotency collision" in stderr.lower()
    with kb.connect_closing() as conn:
        assert kb.get_task(conn, attacker).creation_origin == "trusted_cli"
        assert conn.execute(
            "SELECT COUNT(*) FROM task_dispatch_authorities"
        ).fetchone()[0] == 0


def test_trusted_create_reuses_only_same_verified_receipt(kanban_home):
    _init_authority()
    rc, first, stderr = _trusted_create()
    assert rc == 0, stderr

    rc, second, stderr = _trusted_create()

    assert rc == 0, stderr
    assert second["id"] == first["id"]
    assert second["reused"] is True
    with kb.connect_closing() as conn:
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1


@pytest.mark.parametrize(
    "changed",
    [
        ("--skill", "attacker-skill"),
        ("--workspace", "dir:/tmp/attacker"),
        ("--session-id", "attacker-session"),
        ("--max-retries", "9"),
    ],
)
def test_trusted_create_rejects_changed_request_against_valid_receipt(
    kanban_home, changed
):
    _init_authority()
    rc, first, stderr = _trusted_create()
    assert rc == 0, stderr

    rc, second, stderr = _trusted_create(*changed)

    assert rc == 1
    assert second is None
    assert "sealed collision differs" in stderr
    with kb.connect_closing() as conn:
        assert conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert kb.get_task(conn, first["id"]) is not None


def test_verified_authority_is_cas_consumed_before_worker_claim(kanban_home):
    _init_authority()
    rc, created, stderr = _trusted_create("--initial-status", "running")
    assert rc == 0, stderr

    with kb.connect_closing() as conn:
        claimed = kb.claim_task(conn, created["id"], claimer="host:authority-test")
        assert claimed is not None
        from hermes_cli.kanban_authority import verify_task_authority

        receipt = verify_task_authority(conn, created["id"])

    assert claimed.status == "running"
    assert receipt["verified"] is True
    assert receipt["row_matches_payload"] is True
    assert receipt["claim_generation"] == 1
    assert receipt["last_claimed_run_id"] == claimed.current_run_id
    assert receipt["payload"]["pre_dispatch_status"] == "ready"


def test_post_seal_duplicate_idempotency_row_revokes_authority(kanban_home):
    _init_authority()
    rc, created, stderr = _trusted_create("--initial-status", "running")
    assert rc == 0, stderr
    with kb.connect_closing() as conn:
        duplicate = kb.create_task(conn, title="attacker duplicate")
        with kb.write_txn(conn):
            conn.execute(
                "UPDATE tasks SET idempotency_key = ? WHERE id = ?",
                ("radulator:publisher-prerequisite:v1", duplicate),
            )
        assert kb.claim_task(conn, created["id"], claimer="host:test") is None

    rc, stdout, stderr = _host_cli("show", created["id"], "--json")
    assert rc == 0, stderr
    shown = json.loads(stdout)
    assert shown["dispatch_authority"]["verified"] is False
    assert "idempotency_key" in shown["dispatch_authority"]["mismatch_fields"]
    assert shown["idempotency_readback"]["active_match_count"] == 2


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("skills", '["attacker-skill"]'),
        ("max_retries", 99),
        ("session_id", "attacker-session"),
        ("goal_max_turns", 999),
        ("current_step_key", "attacker-step"),
        ("workspace_path", "/tmp/attacker"),
    ],
)
def test_tampered_dispatch_definition_invalidates_receipt_and_claim(
    kanban_home, column, value
):
    _init_authority()
    rc, created, stderr = _trusted_create("--initial-status", "running")
    assert rc == 0, stderr
    with kb.connect_closing() as conn:
        with kb.write_txn(conn):
            conn.execute(
                f"UPDATE tasks SET {column} = ? WHERE id = ?",
                (value, created["id"]),
            )

        assert kb.claim_task(conn, created["id"], claimer="host:test") is None

    rc, stdout, stderr = _host_cli("show", created["id"], "--json")
    assert rc == 0, stderr
    receipt = json.loads(stdout)["dispatch_authority"]
    assert receipt["signature_valid"] is True
    assert receipt["row_matches_payload"] is False
    assert receipt["verified"] is False
    assert column in receipt["mismatch_fields"]


def test_authority_key_symlink_or_loose_mode_fails_closed(kanban_home, tmp_path):
    key_path = kb.board_dir() / ".trusted-dispatch-authority.key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    target = tmp_path / "attacker-key"
    target.write_bytes(os.urandom(32))
    key_path.symlink_to(target)

    rc, _stdout, stderr = _host_cli("authority", "init", "--json")
    assert rc == 1
    assert "symlink" in stderr.lower()

    key_path.unlink()
    key_path.write_bytes(os.urandom(32))
    key_path.chmod(0o644)
    rc, _stdout, stderr = _host_cli("trusted-create", "x", "--idempotency-key", "x", "--json")
    assert rc == 1
    assert "0600" in stderr

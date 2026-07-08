from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from hermes_cli import artifact_registry as ar
from hermes_cli.artifacts import artifacts_command
from hermes_cli.subcommands.artifacts import build_artifacts_parser


def _home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def test_cleanup_deletes_only_registry_owned_blob(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    live = tmp_path / "live.txt"
    live.write_text("keep me", encoding="utf-8")

    external = ar.register_artifact(
        live,
        source="test",
        ttl_seconds=1,
        now=100,
    )
    owned = ar.register_artifact(
        live,
        source="test",
        ttl_seconds=1,
        copy_into_store=True,
        now=100,
    )

    result = ar.cleanup_expired(now=102)

    assert result["checked"] == 2
    assert live.exists()
    assert ar.get_artifact(external.id).cleanup_state == "expired"
    assert ar.get_artifact(owned.id).cleanup_state == "removed"
    assert not Path(owned.path).exists()


def test_promote_extends_ttl_and_can_make_permanent(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    source = tmp_path / "report.pdf"
    source.write_bytes(b"%PDF-1.7")
    record = ar.register_artifact(source, source="telegram", ttl_seconds=10, now=100)

    promoted = ar.promote_artifact(record.id, ttl_seconds=50, now=120)
    assert promoted.expires_at == 170
    assert promoted.promoted_at == 120

    permanent = ar.promote_artifact(record.id, permanent=True, now=130)
    assert permanent.expires_at is None


def test_metadata_source_mime_sensitivity_and_links(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    source = tmp_path / "image.png"
    source.write_bytes(b"png")

    record = ar.register_artifact(
        source,
        source="gateway_inbound",
        source_id="telegram:99:0",
        mime_type="image/png",
        sensitivity="user-provided",
        task_id="t_abc12345",
        session_id="20260618_abc",
        board="default",
        metadata={"chat_id": "42"},
        ttl_seconds=60,
        now=100,
    )
    updated = ar.update_metadata(record.id, {"thread_id": "7"}, now=101)

    assert updated.source == "gateway_inbound"
    assert updated.source_id == "telegram:99:0"
    assert updated.mime_type == "image/png"
    assert updated.sensitivity == "user-provided"
    assert updated.task_id == "t_abc12345"
    assert updated.session_id == "20260618_abc"
    assert updated.metadata == {"chat_id": "42", "thread_id": "7"}
    assert ar.list_artifacts(task_id="t_abc12345") == [updated]


def test_gateway_inbound_helper_records_session_and_source(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    source = tmp_path / "telegram.pdf"
    source.write_bytes(b"%PDF")
    event = SimpleNamespace(
        media_urls=[str(source)],
        media_types=["application/pdf"],
        source=SimpleNamespace(
            platform=SimpleNamespace(value="telegram"),
            chat_id="42",
            thread_id="99",
        ),
        message_id="777",
        message_type=SimpleNamespace(value="document"),
    )

    records = ar.record_gateway_inbound_files(event, session_id="sid_1", ttl_seconds=60)

    assert len(records) == 1
    record = records[0]
    assert record.source == "gateway_inbound"
    assert record.source_id == "telegram:777:0"
    assert record.session_id == "sid_1"
    assert record.mime_type == "application/pdf"
    assert record.sensitivity == "user-provided"
    assert record.metadata["platform"] == "telegram"
    assert record.metadata["chat_id"] == "42"
    assert record.metadata["thread_id"] == "99"


def test_artifacts_cli_register_json(tmp_path, monkeypatch, capsys):
    _home(tmp_path, monkeypatch)
    payload = tmp_path / "payload.txt"
    payload.write_text("hello", encoding="utf-8")
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    build_artifacts_parser(sub, cmd_artifacts=artifacts_command)

    args = parser.parse_args(
        [
            "artifacts",
            "register",
            str(payload),
            "--source",
            "unit",
            "--ttl",
            "5m",
            "--metadata",
            '{"kind":"fixture"}',
            "--json",
        ]
    )
    args.func(args)

    out = json.loads(capsys.readouterr().out)
    assert out["source"] == "unit"
    assert out["metadata"] == {"kind": "fixture"}
    assert out["expires_at"] - out["created_at"] == 300


def test_kanban_dashboard_upload_registers_artifact(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)
    from hermes_cli import kanban_db as kb
    from plugins.kanban.dashboard import plugin_api

    kb.init_db()
    conn = kb.connect()
    try:
        task_id = kb.create_task(conn, title="inspect", body="", assignee="codex")
    finally:
        conn.close()

    app = FastAPI()
    app.include_router(plugin_api.router, prefix="/api/plugins/kanban")
    client = TestClient(app)

    response = client.post(
        f"/api/plugins/kanban/tasks/{task_id}/attachments",
        files={"file": ("notes.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 200, response.text
    records = ar.list_artifacts(source="kanban_attachment", task_id=task_id)
    assert len(records) == 1
    assert records[0].mime_type == "text/plain"
    assert records[0].sensitivity == "user-provided"
    assert records[0].metadata["uploaded_by"] == "dashboard"

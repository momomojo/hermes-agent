"""End-to-end contract tests for the dedicated-identity Kanban broker."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from hermes_cli.config_defaults import DEFAULT_CONFIG


pytestmark = pytest.mark.macos_only


def _git(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(path: Path) -> str:
    path.mkdir()
    _git("init", "-b", "main", str(path))
    _git("config", "user.name", "Broker Test", cwd=path)
    _git("config", "user.email", "broker@example.invalid", cwd=path)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    (path / "bin").mkdir()
    script = path / "bin" / "tool.sh"
    script.write_text("#!/bin/sh\necho base\n", encoding="utf-8")
    script.chmod(0o755)
    _git("add", ".", cwd=path)
    _git("commit", "-m", "base", cwd=path)
    return _git("rev-parse", "HEAD", cwd=path)


def _secure_socket_parent(path: Path) -> Path:
    os.chown(path, -1, os.getegid())
    path.chmod(0o710)
    return path


def _remote_repository() -> dict:
    return {
        "contract": "hermes.github_repository.v1",
        "host": "github.com",
        "owner": "momomojo",
        "name": "Radulator",
        "full_name": "momomojo/Radulator",
        "repository_id": 987654321,
        "canonical_url": "https://github.com/momomojo/Radulator",
        "is_fork": False,
        "publication_policy": {
            "pull_request_base": "main",
            "workflow_id": 101,
            "workflow_name": "E2E",
            "workflow_path": ".github/workflows/e2e.yml",
            "workflow_event": "pull_request",
            "required_job_names": ["E2E / exact-head"],
            "required_app": {"id": 15368, "slug": "github-actions"},
            "ready_label_actor": {
                "id": 24681012,
                "login": "hermes-publisher",
                "type": "User",
            },
            "ready_label": "ready-for-gate",
        },
    }


@pytest.fixture
def broker_fixture(tmp_path):
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    base_sha = _init_repo(source)
    state = tmp_path / "private-broker-state"
    workspace_root = tmp_path / "worker-spaces"
    broker = DedicatedKanbanBroker(
        state_dir=state,
        workspace_root=workspace_root,
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
        trusted_publisher_enabled=True,
    )
    broker.initialize()
    broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    yield broker, source, base_sha
    broker.close()


def _request(**overrides):
    request = {
        "contract": "hermes.kanban_trusted_create_request.v1",
        "request_id": "create-radulator-1",
        "board": "default",
        "repository_id": "radulator",
        "idempotency_key": "radulator:feedback:birads-2025:v1",
        "title": "Implement BI-RADS feedback",
        "body": "Implement the exact reviewed feedback.",
        "assignee": "radulator",
        "created_by": "radulator-no-agent-controller",
        "tenant": None,
        "priority": 17,
        "requested_initial_status": "ready",
        "requested_workspace_kind": "broker_workspace",
        "requested_workspace_path": None,
        "requested_branch_name": None,
        "requested_project_id": None,
        "requested_triage": False,
        "parent_ids": [],
        "max_runtime_seconds": 2700,
        "skills": ["sdlc-review", "github-code-review"],
        "max_retries": 2,
        "model_override": "qwen-local",
        "provider_override": "custom",
        "reasoning_effort": "high",
        "goal_mode": True,
        "goal_max_turns": 7,
        "session_id": "feedback-intake-v1",
        "workflow_template_id": "radulator-feedback-v1",
        "current_step_key": "implementation",
    }
    request.update(overrides)
    return request


def _publish_ack(event: dict, handoff: dict, **overrides) -> dict:
    observed_at = int(time.time())
    workflow_completed_at = observed_at - 2
    label_created_at = observed_at - 1
    job = {
        "job_id": 44001,
        "check_run_id": 55001,
        "workflow_id": 101,
        "workflow_run_id": 202,
        "run_attempt": 1,
        "check_suite_id": 303,
        "name": "E2E / exact-head",
        "status": "completed",
        "conclusion": "success",
        "head_sha": event["head_sha"],
        "app": {
            "id": 15368,
            "slug": "github-actions",
        },
    }
    remote_readback = {
        "contract": "hermes.github_publish_readback.v1",
        "repository": _remote_repository(),
        "pull_request": {
            "number": 28,
            "url": "https://github.com/momomojo/Radulator/pull/28",
            "state": "open",
            "is_draft": False,
            "head_repository_full_name": "momomojo/Radulator",
            "head_repository_is_fork": False,
            "head_ref": event["branch"],
            "head_ref_full": f"refs/heads/{event['branch']}",
            "base_ref": event["base_branch"],
            "base_ref_full": f"refs/heads/{event['base_branch']}",
            "base_sha": event["target_base_sha"],
            "head_sha": event["head_sha"],
        },
        "workflow": {
            "workflow_id": 101,
            "workflow_name": "E2E",
            "workflow_path": ".github/workflows/e2e.yml",
            "run_id": 202,
            "newest_run_id_for_workflow_and_head": 202,
            "run_attempt": 1,
            "check_suite_id": 303,
            "event": "pull_request",
            "head_sha": event["head_sha"],
            "status": "completed",
            "conclusion": "success",
            "completed_at": workflow_completed_at,
            "required_job_ids": [job["job_id"]],
            "required_jobs": [job],
        },
        "ready_label": {
            "name": "ready-for-gate",
            "present": True,
            "label_event_id": 66001,
            "actor": {
                "id": 24681012,
                "login": "hermes-publisher",
                "type": "User",
            },
            "pull_request_number": 28,
            "head_sha": event["head_sha"],
            "workflow_run_id": 202,
            "check_suite_id": 303,
            "event_created_at": label_created_at,
            "readback_at": observed_at,
        },
    }
    acknowledgement = {
        "contract": "hermes.publisher_ack.v1",
        "receipt_id": event["receipt_id"],
        "receipt_payload_sha256": event["payload_sha256"],
        "bundle_sha256": handoff["bundle_sha256"],
        "repository_id": event["repository_id"],
        "task_id": event["task_id"],
        "run_id": event["run_id"],
        "branch": event["branch"],
        "base_branch": event["base_branch"],
        "base_sha": event["base_sha"],
        "target_base_sha": event["target_base_sha"],
        "head_sha": event["head_sha"],
        "published_head_sha": event["head_sha"],
        "publish_outcome": "fast_forwarded",
        "readback_complete": True,
        "remote_readback": remote_readback,
    }
    acknowledgement.update(overrides)
    return acknowledgement


def _complete_published_task(broker, *, key: str) -> tuple[dict, dict, dict, dict]:
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key=f"radulator:completion:{key}:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], f"{key}.txt").write_text(f"{key}\n", encoding="utf-8")
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id=f"completion-{key}-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    acknowledgement = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=_publish_ack(event, handoff),
    )
    return created, claim, event, acknowledgement


def test_dedicated_broker_is_default_off_and_contract_is_pinned():
    from hermes_cli.kanban_dedicated_broker import KANBAN_BROKER_SECURITY_BOUNDARY

    assert DEFAULT_CONFIG["kanban"]["dedicated_broker_enabled"] is False
    assert DEFAULT_CONFIG["kanban"]["trusted_publisher_enabled"] is False
    assert KANBAN_BROKER_SECURITY_BOUNDARY == "hermes.dedicated_broker_identity.v1"


def test_broker_database_schema_version_is_exact_and_drift_fails_closed(tmp_path):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    kwargs = {
        "state_dir": tmp_path / "state",
        "workspace_root": tmp_path / "workspaces",
        "broker_uid": os.geteuid(),
        "controller_uid": os.geteuid(),
        "publisher_uid": os.geteuid(),
        "operator_uid": os.geteuid(),
        "worker_uid": os.geteuid(),
        "workspace_gid": os.getegid(),
        "trusted_publisher_enabled": True,
    }
    broker = DedicatedKanbanBroker(**kwargs)
    broker.initialize()
    assert broker.conn.execute(
        "SELECT schema_version FROM broker_schema WHERE singleton=1"
    ).fetchone()[0] == 1
    broker.close()

    database = sqlite3.connect(Path(kwargs["state_dir"]) / "broker.sqlite3")
    database.execute("UPDATE broker_schema SET schema_version=0 WHERE singleton=1")
    database.commit()
    database.close()

    reopened = DedicatedKanbanBroker(**kwargs)
    with pytest.raises(BrokerSecurityError, match="schema version"):
        reopened.initialize()
    reopened.close()


def test_dedicated_route_fails_closed_without_exact_surface_config(monkeypatch):
    from hermes_cli import config
    from hermes_cli.kanban_broker_routing import DedicatedBrokerRouteError
    from hermes_cli.kanban_broker_routing import trusted_create

    monkeypatch.setattr(
        config,
        "load_config_readonly",
        lambda: {"kanban": {"dedicated_broker_enabled": True}},
    )
    with pytest.raises(DedicatedBrokerRouteError, match="trusted publisher opt-in"):
        trusted_create(_request())
    monkeypatch.setattr(
        config,
        "load_config_readonly",
        lambda: {
            "kanban": {
                "dedicated_broker_enabled": True,
                "trusted_publisher_enabled": True,
            }
        },
    )
    with pytest.raises(DedicatedBrokerRouteError, match="controller client config"):
        trusted_create(_request())


def test_broker_serializes_rollback_before_another_authority_commit(
    broker_fixture,
):
    """A rollback in one thread must never commit another thread's row."""
    broker, _source, _base = broker_fixture
    transaction_open = threading.Event()
    allow_rollback = threading.Event()
    second_finished = threading.Event()
    errors: list[BaseException] = []

    def rollback_thread() -> None:
        try:
            with pytest.raises(RuntimeError, match="forced rollback"):
                with broker.serialized_transaction():
                    with broker.conn:
                        broker.conn.execute(
                            "INSERT INTO rpc_sequences VALUES ('rollback-probe', 1)"
                        )
                        transaction_open.set()
                        assert allow_rollback.wait(timeout=5)
                        raise RuntimeError("forced rollback")
        except BaseException as exc:  # pragma: no cover - thread transport
            errors.append(exc)

    def commit_thread() -> None:
        try:
            assert transaction_open.wait(timeout=5)
            broker.consume_rpc_request(
                surface="controller",
                sequence=1,
                nonce="serialized-commit",
                request_sha256="a" * 64,
            )
            second_finished.set()
        except BaseException as exc:  # pragma: no cover - thread transport
            errors.append(exc)

    first = threading.Thread(target=rollback_thread)
    second = threading.Thread(target=commit_thread)
    first.start()
    second.start()
    assert transaction_open.wait(timeout=5)
    assert not second_finished.wait(timeout=0.1)
    allow_rollback.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert (
        broker.conn.execute(
            "SELECT 1 FROM rpc_sequences WHERE surface='rollback-probe'"
        ).fetchone()
        is None
    )
    assert (
        broker.conn.execute(
            "SELECT last_sequence FROM rpc_sequences WHERE surface='controller'"
        ).fetchone()["last_sequence"]
        == 1
    )


def test_rpc_replay_window_accepts_out_of_order_and_remains_bounded(broker_fixture):
    broker, _source, _base = broker_fixture
    broker.consume_rpc_request(
        surface="controller",
        sequence=2,
        nonce="sequence-two",
        request_sha256="2" * 64,
    )
    broker.consume_rpc_request(
        surface="controller",
        sequence=1,
        nonce="sequence-one",
        request_sha256="1" * 64,
    )
    for sequence in range(3, 2505):
        broker.consume_rpc_request(
            surface="controller",
            sequence=sequence,
            nonce=f"nonce-{sequence}",
            request_sha256=f"{sequence:064x}"[-64:],
        )
    count = broker.conn.execute(
        "SELECT COUNT(*) AS count FROM rpc_nonces WHERE surface='controller'"
    ).fetchone()["count"]
    assert count <= 2048

    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    with pytest.raises(BrokerConflict, match="replay"):
        broker.consume_rpc_request(
            surface="controller",
            sequence=1,
            nonce="sequence-one",
            request_sha256="1" * 64,
        )


def test_host_cli_routes_dedicated_trusted_create_without_legacy_db(
    monkeypatch,
    capsys,
):
    from hermes_cli import kanban
    from hermes_cli import kanban_broker_routing as routing

    parser = argparse.ArgumentParser()
    top = parser.add_subparsers(dest="command")
    kanban.build_parser(top, include_host_authority=True)
    regular_create = parser.parse_args(["kanban", "create", "Ordinary task"])
    assert regular_create.initial_status == "running"
    args = parser.parse_args([
        "kanban",
        "trusted-create",
        "Brokered task",
        "--broker-repository",
        "radulator",
        "--assignee",
        "radulator",
        "--idempotency-key",
        "radulator:cli-route:v1",
        "--json",
    ])
    seen: dict[str, object] = {}
    monkeypatch.setattr(routing, "dedicated_broker_enabled", lambda: True)
    monkeypatch.setattr(
        routing,
        "trusted_create",
        lambda request: (
            seen.update(request)
            or {
                "task_id": "t_brokered",
                "receipt_id": "ka_brokered",
                "reused": False,
            }
        ),
    )
    monkeypatch.setattr(
        kanban.kb,
        "init_db",
        lambda: pytest.fail("legacy Kanban DB must not be opened"),
    )
    assert kanban.kanban_command(args) == 0
    assert seen["contract"] == "hermes.kanban_trusted_create_request.v1"
    assert seen["repository_id"] == "radulator"
    assert seen["requested_workspace_path"] is None
    assert seen["requested_initial_status"] == "ready"
    output = json.loads(capsys.readouterr().out)
    assert output["task_id"] == "t_brokered"


@pytest.mark.parametrize(
    ("argv", "route_name"),
    [
        (
            ["broker-dispatch", "t_exact", "--operation-id", "op_exact", "--json"],
            "dispatch_task",
        ),
        (
            [
                "broker-export",
                "--receipt-id",
                "klc_exact",
                "--payload-sha256",
                "a" * 64,
                "--json",
            ],
            "export_bundle",
        ),
        (
            [
                "broker-refresh",
                "--repository-id",
                "radulator",
                "--expected-old-base-sha",
                "b" * 40,
                "--json",
            ],
            "refresh_repository_base",
        ),
    ],
)
def test_host_cli_routes_controller_publisher_and_operator_without_legacy_db(
    monkeypatch,
    capsys,
    argv,
    route_name,
):
    from hermes_cli import kanban
    from hermes_cli import kanban_broker_routing as routing

    parser = argparse.ArgumentParser()
    top = parser.add_subparsers(dest="command")
    kanban.build_parser(top, include_host_authority=True)
    args = parser.parse_args(["kanban", *argv])
    seen: dict[str, object] = {}
    monkeypatch.setattr(routing, "dedicated_broker_enabled", lambda: True)

    def called(**kwargs):
        seen.update(kwargs)
        return {"route": route_name}

    monkeypatch.setattr(routing, route_name, called)
    monkeypatch.setattr(
        kanban.kb,
        "init_db",
        lambda: pytest.fail("legacy Kanban DB must not be opened"),
    )
    assert kanban.kanban_command(args) == 0
    assert seen
    assert json.loads(capsys.readouterr().out)["route"] == route_name


def test_private_state_is_owner_only_and_wrong_broker_uid_fails(tmp_path):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    state = tmp_path / "private"
    broker = DedicatedKanbanBroker(
        state_dir=state,
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "authority.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((state / "broker.sqlite3").stat().st_mode) == 0o600
    broker.close()

    wrong = DedicatedKanbanBroker(
        state_dir=state,
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid() + 1,
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    with pytest.raises(BrokerSecurityError, match="owner"):
        wrong.initialize()


def test_private_workspace_and_publisher_roots_must_be_disjoint(tmp_path):
    """Catch a config that places publisher objects in a model-traversable root."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    with pytest.raises(BrokerSecurityError, match="disjoint"):
        DedicatedKanbanBroker(
            state_dir=tmp_path / "state",
            workspace_root=tmp_path / "workspaces",
            publisher_handoff_root=tmp_path / "workspaces" / "publisher",
            broker_uid=os.geteuid(),
            controller_uid=os.geteuid(),
            publisher_uid=os.geteuid(),
            workspace_gid=os.getegid(),
            publisher_gid=os.getegid(),
        )
    with pytest.raises(BrokerSecurityError, match="disjoint"):
        DedicatedKanbanBroker(
            state_dir=tmp_path / "workspaces" / "state",
            workspace_root=tmp_path / "workspaces",
            publisher_handoff_root=tmp_path / "publisher",
            broker_uid=os.geteuid(),
            controller_uid=os.geteuid(),
            publisher_uid=os.geteuid(),
            workspace_gid=os.getegid(),
            publisher_gid=os.getegid(),
        )


def test_controller_only_trusted_create_is_exact_and_receipt_hides_mac(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerAuthorizationError
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    with pytest.raises(BrokerAuthorizationError):
        broker.trusted_create(peer_uid=os.geteuid() + 1, request=_request())

    first = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    second = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    assert first["reused"] is False
    assert second["reused"] is True
    assert second["task_id"] == first["task_id"]
    assert first["status"] == second["status"] == "ready"

    receipt = broker.verify_dispatch_authority(first["receipt_id"])
    assert receipt["verified"] is True
    assert receipt["contract"] == "hermes.kanban_dispatch_authority.v1"
    assert receipt["payload"]["broker_boundary"] == (
        "hermes.dedicated_broker_identity.v1"
    )
    assert receipt["payload"]["requested_project_id"] is None
    assert receipt["payload"]["project_id"] is None
    assert receipt["payload"]["workspace_kind"] == "broker_workspace"
    assert receipt["payload"]["requested_workspace_path"] is None
    assert "hmac" not in json.dumps(receipt).lower()

    changed = _request(max_retries=3)
    with pytest.raises(BrokerConflict, match="max_retries"):
        broker.trusted_create(peer_uid=os.geteuid(), request=changed)


def test_trusted_create_rejects_extra_schema_and_nonready_status(broker_fixture):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    extra = _request(attacker_dispatch_field="minted")
    with pytest.raises(BrokerSecurityError, match="fields"):
        broker.trusted_create(peer_uid=os.geteuid(), request=extra)
    with pytest.raises(BrokerSecurityError, match="ready"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(
                request_id="blocked-request",
                idempotency_key="radulator:blocked-create:v1",
                requested_initial_status="blocked",
            ),
        )
    with pytest.raises(BrokerSecurityError, match="provider.*model"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(
                request_id="provider-without-model",
                idempotency_key="radulator:provider-without-model:v1",
                model_override=None,
                provider_override="custom",
            ),
        )
    with pytest.raises(BrokerSecurityError, match="reasoning"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(
                request_id="bad-reasoning",
                idempotency_key="radulator:bad-reasoning:v1",
                reasoning_effort="unbounded",
            ),
        )
    with pytest.raises(BrokerSecurityError, match="list fields"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(
                request_id="bad-skills",
                idempotency_key="radulator:bad-skills:v1",
                skills=[{"not": "a skill"}],
            ),
        )


def test_dispatch_receipt_detects_private_row_confused_deputy_tampering(broker_fixture):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    with broker.conn:
        broker.conn.execute(
            "UPDATE tasks SET branch='wt/t_confused_deputy' WHERE task_id=?",
            (created["task_id"],),
        )
    receipt = broker.verify_dispatch_authority(created["receipt_id"])
    assert receipt["verified"] is False
    assert receipt["row_matches_payload"] is False
    assert "branch_name" in receipt["mismatch_fields"]
    with pytest.raises(BrokerConflict, match="authority"):
        broker.claim_for_dispatch(created["task_id"])


def test_controller_cannot_choose_even_nonprotected_raw_branch(broker_fixture):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    with pytest.raises(BrokerSecurityError, match="branch"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(
                idempotency_key="radulator:raw-branch:v1",
                requested_branch_name="feature/attacker-selected",
            ),
        )


def test_reverse_worker_workspace_has_no_git_and_broker_commits_exact_snapshot(
    broker_fixture,
):
    broker, _source, base_sha = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    assert not (workspace / ".git").exists()
    assert (workspace / "README.md").read_text(encoding="utf-8") == "base\n"

    (workspace / "README.md").write_text("updated\n", encoding="utf-8")
    (workspace / "feature.txt").write_text("worker output\n", encoding="utf-8")
    (workspace / "bin" / "tool.sh").unlink()

    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="commit-operation-1",
        untrusted_worker_result={"summary": "done", "tests": ["pytest"]},
    )

    assert event["contract"] == "hermes.trusted_local_commit.v1"
    assert event["broker_boundary"] == "hermes.dedicated_broker_identity.v1"
    assert event["base_sha"] == base_sha
    assert event["head_sha"] != base_sha
    assert event["changed_paths"] == ["README.md", "bin/tool.sh", "feature.txt"]
    assert [entry["operation"] for entry in event["changed_entries"]] == [
        "modify",
        "delete",
        "add",
    ]
    assert event["project_id"] is None
    assert event["publisher_state"] == "awaiting"
    assert event["reason"] == "AWAITING_TRUSTED_PUBLISHER v1"
    assert "untrusted_worker_result" not in event

    private_repo = broker.private_repository_path("radulator")
    assert _git("rev-parse", event["branch"], cwd=private_repo) == event["head_sha"]
    assert _git("rev-parse", "main", cwd=private_repo) == base_sha
    assert _git("show", f"{event['head_sha']}:feature.txt", cwd=private_repo) == (
        "worker output"
    )
    with pytest.raises(subprocess.CalledProcessError):
        _git("show", f"{event['head_sha']}:bin/tool.sh", cwd=private_repo)

    verified = broker.verify_publish_receipt(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    assert verified["verified"] is True
    assert verified["canonical_payload"] == event
    assert "hmac" not in json.dumps(verified).lower()


def test_materialized_workspace_is_group_editable_without_git_control_state(
    broker_fixture,
):
    """Catch broker materialization that a distinct worker UID cannot edit."""
    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:cross-uid-modes:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])

    assert workspace.stat().st_gid == os.getegid()
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o2770
    assert stat.S_IMODE((workspace / "bin").stat().st_mode) == 0o2770
    assert stat.S_IMODE((workspace / "README.md").stat().st_mode) == 0o660
    assert stat.S_IMODE((workspace / "bin" / "tool.sh").stat().st_mode) == 0o770
    assert (workspace / "README.md").stat().st_gid == os.getegid()
    assert (workspace / "bin" / "tool.sh").stat().st_gid == os.getegid()
    assert not (workspace / ".git").exists()


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a root-owned staging host")
def test_distinct_worker_uid_can_edit_materialized_files_but_not_broker_state(
    tmp_path,
):
    """Catch mode-only tests that never exercise the actual cross-UID write."""
    from hermes_cli.kanban_broker_canary import cross_uid_workspace_edit_proof

    del tmp_path
    staging = Path(tempfile.mkdtemp(prefix="hkb-cross-uid-", dir="/tmp"))
    try:
        staging.chmod(0o711)
        workspace = staging / "task"
        workspace.mkdir(mode=0o770)
        os.chown(workspace, 1, 2)
        workspace.chmod(0o2770)
        tracked = workspace / "README.md"
        tracked.write_text("base\n", encoding="utf-8")
        os.chown(tracked, 1, 2)
        tracked.chmod(0o660)
        secret = staging / "authority.key"
        secret.write_bytes(b"never visible")
        os.chown(secret, 1, 1)
        secret.chmod(0o600)
        assert cross_uid_workspace_edit_proof(
            workspace=workspace,
            broker_secret=secret,
            model_uid=2,
            model_gid=2,
        )
        assert tracked.read_text(encoding="utf-8") == "base\nmodel edit\n"
        assert (workspace / "model-created.txt").read_text(encoding="utf-8") == (
            "model bytes\n"
        )
    finally:
        shutil.rmtree(staging)


def test_broker_initiates_worker_socket_and_worker_sends_only_untrusted_result(
    broker_fixture, tmp_path
):
    from hermes_cli.kanban_broker_protocol import receive_frame, send_frame

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    short_socket_dir = Path(tempfile.mkdtemp(prefix="hkb-worker-", dir="/tmp"))
    worker_socket = short_socket_dir / "worker.sock"
    ready = threading.Event()
    seen: dict[str, object] = {}

    def worker() -> None:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(worker_socket))
        os.chmod(worker_socket, 0o600)
        server.listen(1)
        ready.set()
        conn, _ = server.accept()
        with conn:
            envelope = receive_frame(conn)
            seen.update(envelope)
            workspace = Path(envelope["workspace_path"])
            assert not (workspace / ".git").exists()
            (workspace / "reverse-worker.txt").write_text(
                "untrusted worker bytes\n", encoding="utf-8"
            )
            send_frame(
                conn,
                {
                    "contract": "hermes.worker_turn_complete.v1",
                    "summary": "untrusted",
                    "repository_id": "attacker",
                    "branch": "main",
                    "workspace_path": "/tmp/attacker",
                },
            )
        server.close()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    assert ready.wait(5)
    event = broker.dispatch_to_worker(
        task_id=created["task_id"],
        worker_socket=worker_socket,
        operation_id="reverse-worker-operation",
    )
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert seen["contract"] == "hermes.broker_reverse_worker_dispatch.v1"
    assert event["repository_id"] == "radulator"
    assert event["branch"].startswith("wt/")
    assert event["changed_paths"] == ["reverse-worker.txt"]
    shutil.rmtree(short_socket_dir)


def test_production_worker_socket_accepts_only_broker_envelope_and_edits_workspace(
    broker_fixture, monkeypatch
):
    from hermes_cli.kanban_broker_worker import WorkerSocketService
    from hermes_cli.kanban_broker_worker import _safe_worker_env
    from tools.kanban_worker_boundary import assigned_workspace
    from tools.kanban_worker_boundary import execute_code_violation
    from tools.kanban_worker_boundary import write_path_violation

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:production-worker:v1"),
    )
    socket_root = Path(tempfile.mkdtemp(prefix="hkb-real-worker-", dir="/tmp"))
    _secure_socket_parent(socket_root)
    endpoint = socket_root / "worker.sock"
    seen: dict[str, object] = {}
    monkeypatch.setenv("GH_TOKEN", "must-not-enter-dedicated-worker")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-dedicated-worker")
    monkeypatch.setenv("COPILOT_TOKEN", "must-not-enter-dedicated-worker")
    monkeypatch.setenv("SSH_ASKPASS", "/tmp/attacker-askpass")
    monkeypatch.setenv("GIT_SSH_COMMAND", "/tmp/attacker-ssh")
    monkeypatch.setenv("MODEL_PARENT_SENTINEL", "must-not-be-inherited")
    monkeypatch.setenv("HERMES_KANBAN_DB", "/tmp/stale-attacker-board.db")

    def handler(envelope):
        seen.update(envelope)
        worker_env = _safe_worker_env(
            envelope, worker_hermes_root=socket_root / "worker-home"
        )
        assert worker_env["HERMES_SESSION_SOURCE"] == "kanban"
        assert worker_env["HERMES_KANBAN_DEDICATED_BOUNDARY"] == (
            "hermes.dedicated_broker_identity.v1"
        )
        assert worker_env["HERMES_KANBAN_CLAIM_LOCK"].startswith("dedicated:")
        assert "GH_TOKEN" not in worker_env
        assert "GITHUB_TOKEN" not in worker_env
        assert "COPILOT_TOKEN" not in worker_env
        assert "SSH_ASKPASS" not in worker_env
        assert worker_env["GIT_SSH_COMMAND"] == "/usr/bin/false"
        assert "MODEL_PARENT_SENTINEL" not in worker_env
        assert worker_env["XDG_CONFIG_HOME"] == str(
            socket_root / "worker-home/.config"
        )
        assert "HERMES_KANBAN_DB" not in worker_env
        with monkeypatch.context() as context:
            for name, value in worker_env.items():
                context.setenv(name, value)
            assert assigned_workspace() == Path(envelope["workspace_path"])
            assert execute_code_violation() is not None
            assert (
                write_path_violation(Path.home() / ".config/gh/hosts.yml") is not None
            )
        Path(envelope["workspace_path"], "production-worker.txt").write_text(
            "production worker bytes\n", encoding="utf-8"
        )
        return {"contract": "hermes.worker_turn_complete.v1", "outcome": "done"}

    worker = WorkerSocketService(
        socket_path=endpoint,
        workspace_root=broker.workspace_root,
        broker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
        handler=handler,
    )
    worker.start()
    thread = threading.Thread(target=worker.serve_once, daemon=True)
    thread.start()
    try:
        event = broker.dispatch_to_worker(
            task_id=created["task_id"],
            worker_socket=endpoint,
            operation_id="production-worker-operation",
        )
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert seen["repository_id"] == "radulator"
        assert event["changed_paths"] == ["production-worker.txt"]
    finally:
        worker.close()
        shutil.rmtree(socket_root)


def test_worker_credential_home_rejects_github_and_ssh_authority(tmp_path):
    from hermes_cli.kanban_broker_worker import WorkerServiceError
    from hermes_cli.kanban_broker_worker import validate_worker_credential_home

    worker_home = tmp_path / "worker-home"
    profile_home = worker_home / "profiles/radulator"
    profile_home.mkdir(parents=True)
    worker_home.chmod(0o700)
    (worker_home / "profiles").chmod(0o700)
    profile_home.chmod(0o700)
    (profile_home / ".env").write_text(
        "OPENAI_API_KEY=provider-only\n", encoding="utf-8"
    )
    assert validate_worker_credential_home(
        worker_home,
        profile="radulator",
        expected_owner_uid=os.geteuid(),
    )["profile_home"] == str(profile_home)

    forbidden = [
        (worker_home / ".config/gh/hosts.yml", "oauth_token: dummy\n"),
        (profile_home / ".config/gh/hosts.yml", "oauth_token: dummy\n"),
        (worker_home / ".git-credentials", "https://dummy@example.invalid\n"),
        (worker_home / ".gitconfig", "[credential]\nhelper = osxkeychain\n"),
        (profile_home / ".npmrc", "//npm.pkg.github.com/:_authToken=dummy\n"),
        (worker_home / ".ssh/id_ed25519", "dummy\n"),
        (
            worker_home / "Library/Application Support/gh/hosts.yml",
            "oauth_token: dummy\n",
        ),
    ]
    for path, content in forbidden:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        with pytest.raises(WorkerServiceError, match="credential authority"):
            validate_worker_credential_home(
                worker_home,
                profile="radulator",
                expected_owner_uid=os.geteuid(),
            )
        path.unlink()
        parent = path.parent
        while parent != worker_home:
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent

    (profile_home / ".env").write_text("GH_TOKEN=dummy\n", encoding="utf-8")
    with pytest.raises(WorkerServiceError, match="GitHub credential key"):
        validate_worker_credential_home(
            worker_home,
            profile="radulator",
            expected_owner_uid=os.geteuid(),
        )
    (profile_home / ".env").write_text(
        "PROVIDER_TOKEN=github_pat_dummy\n", encoding="utf-8"
    )
    with pytest.raises(WorkerServiceError, match="GitHub credential material"):
        validate_worker_credential_home(
            worker_home,
            profile="radulator",
            expected_owner_uid=os.geteuid(),
        )


def test_dedicated_worker_dotenv_policy_cannot_import_github_credentials(
    tmp_path, monkeypatch
):
    from hermes_cli.env_loader import load_hermes_dotenv

    profile_home = tmp_path / "worker-home/profiles/radulator"
    profile_home.mkdir(parents=True)
    (profile_home / ".env").write_text(
        "OPENAI_API_KEY=provider-only\n",
        encoding="utf-8",
    )
    (profile_home / ".op.env").write_text(
        "OP_SERVICE_ACCOUNT_TOKEN=must-not-load\n", encoding="utf-8"
    )
    project_env = tmp_path / "project.env"
    project_env.write_text(
        "GITHUB_TOKEN=project-github\nPROJECT_ENV_SENTINEL=must-not-load\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_KANBAN_CREDENTIAL_POLICY", "github-denied-v1")
    monkeypatch.setenv("GITHUB_PAT", "inherited-github")
    monkeypatch.setenv("PARENT_NEUTRAL_TOKEN", "github_pat_inherited")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/inherited-agent.sock")
    monkeypatch.setattr(
        "hermes_cli.env_loader._apply_external_secret_sources",
        lambda _home: pytest.fail("dedicated worker contacted an external secret source"),
    )
    monkeypatch.setattr(
        "hermes_cli.env_loader._apply_managed_env",
        lambda: pytest.fail("dedicated worker imported the machine managed env"),
    )
    changed = {
        "OPENAI_API_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_PAT",
        "SSH_AUTH_SOCK",
        "OP_SERVICE_ACCOUNT_TOKEN",
        "PROJECT_ENV_SENTINEL",
        "PARENT_NEUTRAL_TOKEN",
    }
    prior = {name: os.environ.get(name) for name in changed}
    try:
        loaded = load_hermes_dotenv(
            hermes_home=profile_home,
            project_env=project_env,
        )
        assert loaded == [profile_home / ".env"]
        assert os.environ["OPENAI_API_KEY"] == "provider-only"
        for name in changed - {"OPENAI_API_KEY"}:
            assert name not in os.environ
        (profile_home / ".env").write_text("GH_TOKEN=dummy\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="GitHub credential key"):
            load_hermes_dotenv(hermes_home=profile_home, project_env=project_env)
        (profile_home / ".env").write_text(
            "PROVIDER_TOKEN=github_pat_dummy\n", encoding="utf-8"
        )
        with pytest.raises(RuntimeError, match="GitHub credential material"):
            load_hermes_dotenv(hermes_home=profile_home, project_env=project_env)
    finally:
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_worker_service_reports_retryable_turn_failure_and_keeps_listening(
    broker_fixture,
):
    from hermes_cli.kanban_broker_worker import WorkerServiceError
    from hermes_cli.kanban_broker_worker import WorkerSocketService

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(
            idempotency_key="radulator:worker-service-retry:v1",
            max_retries=2,
        ),
    )
    socket_root = Path(tempfile.mkdtemp(prefix="hkb-worker-retry-", dir="/tmp"))
    _secure_socket_parent(socket_root)
    endpoint = socket_root / "worker.sock"
    calls = 0

    def handler(envelope):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise WorkerServiceError("model process failed")
        Path(envelope["workspace_path"], "retry-success.txt").write_text(
            "success\n", encoding="utf-8"
        )
        return {"contract": "hermes.worker_turn_complete.v1", "outcome": "done"}

    worker = WorkerSocketService(
        socket_path=endpoint,
        workspace_root=broker.workspace_root,
        broker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
        handler=handler,
    )
    worker.start()
    thread = threading.Thread(
        target=lambda: [worker.serve_once() for _ in range(2)], daemon=True
    )
    thread.start()
    try:
        with pytest.raises(Exception, match="worker turn failed"):
            broker.dispatch_to_worker(
                task_id=created["task_id"],
                worker_socket=endpoint,
                operation_id="worker-service-failure",
            )
        failed = broker.conn.execute(
            "SELECT state, failure_code FROM dispatch_attempts WHERE operation_id=?",
            ("worker-service-failure",),
        ).fetchone()
        assert (failed["state"], failed["failure_code"]) == (
            "FAILED",
            "worker_failed",
        )
        assert broker.task_status(created["task_id"]) == "ready"
        event = broker.dispatch_to_worker(
            task_id=created["task_id"],
            worker_socket=endpoint,
            operation_id="worker-service-success",
        )
        assert event["changed_paths"] == ["retry-success.txt"]
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        worker.close()
        shutil.rmtree(socket_root)


def test_production_worker_applies_every_sealed_execution_override(
    broker_fixture, monkeypatch
):
    from hermes_cli.kanban_broker_worker import run_hermes_worker

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(
            idempotency_key="radulator:worker-overrides:v1",
            skills=["github-code-review", "sdlc-review"],
            model_override="qwen-local",
            provider_override="custom",
            reasoning_effort="high",
            goal_mode=True,
            goal_max_turns=7,
        ),
    )
    envelope = broker.claim_for_dispatch(created["task_id"])
    worker_home = Path(tempfile.mkdtemp(prefix="hkb-worker-home-", dir="/tmp"))
    (worker_home / "profiles/radulator").mkdir(parents=True)
    worker_home.chmod(0o700)
    (worker_home / "profiles").chmod(0o700)
    (worker_home / "profiles/radulator").chmod(0o700)
    seen: dict[str, object] = {}

    def fake_run(command, **kwargs):
        seen["command"] = list(command)
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(command, 0, "completed", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_worker.subprocess.run", fake_run)
    try:
        result = run_hermes_worker(
            envelope,
            python_executable=Path("/usr/bin/python3"),
            worker_hermes_root=worker_home,
        )
    finally:
        shutil.rmtree(worker_home)
    command = seen["command"]
    assert command[:7] == [
        "/usr/bin/python3",
        "-m",
        "hermes_cli.main",
        "-p",
        "radulator",
        "--cli",
        "--skills",
    ]
    assert command.count("--skills") == 2
    assert ["-m", "qwen-local"] == command[
        command.index("-m", 3) : command.index("-m", 3) + 2
    ]
    assert ["--provider", "custom"] == command[
        command.index("--provider") : command.index("--provider") + 2
    ]
    assert ["--reasoning", "high"] == command[
        command.index("--reasoning") : command.index("--reasoning") + 2
    ]
    assert command[-1] == "-Q"
    worker_env = seen["kwargs"]["env"]
    assert worker_env["HOME"] == str(worker_home)
    assert worker_env["HERMES_HOME"] == str(worker_home)
    assert worker_env["HERMES_KANBAN_CREDENTIAL_POLICY"] == "github-denied-v1"
    assert worker_env["HERMES_KANBAN_GOAL_MODE"] == "1"
    assert worker_env["HERMES_KANBAN_GOAL_MAX_TURNS"] == "7"
    assert seen["kwargs"]["cwd"] == envelope["workspace_path"]
    assert result == {
        "contract": "hermes.worker_turn_complete.v1",
        "outcome": "completed",
        "exit_code": 0,
    }


def test_dispatch_missing_endpoint_fails_run_and_applies_bounded_retry(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerError

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(
            idempotency_key="radulator:dispatch-missing:v1",
            max_retries=2,
        ),
    )
    missing = Path("/tmp/hermes-broker-missing-worker.sock")
    missing.unlink(missing_ok=True)

    with pytest.raises((BrokerError, OSError)):
        broker.dispatch_to_worker(
            task_id=created["task_id"],
            worker_socket=missing,
            operation_id="missing-worker-attempt-1",
        )
    first = broker.conn.execute(
        "SELECT status FROM runs WHERE task_id=? ORDER BY run_id DESC LIMIT 1",
        (created["task_id"],),
    ).fetchone()
    assert first["status"] == "failed"
    assert broker.task_status(created["task_id"]) == "ready"

    with pytest.raises((BrokerError, OSError)):
        broker.dispatch_to_worker(
            task_id=created["task_id"],
            worker_socket=missing,
            operation_id="missing-worker-attempt-2",
        )
    assert broker.task_status(created["task_id"]) == "blocked"
    attempts = broker.conn.execute(
        "SELECT state, failure_code FROM dispatch_attempts "
        "WHERE task_id=? ORDER BY run_id",
        (created["task_id"],),
    ).fetchall()
    assert [(row["state"], row["failure_code"]) for row in attempts] == [
        ("FAILED", "endpoint_missing"),
        ("FAILED", "endpoint_missing"),
    ]


@pytest.mark.parametrize("failure", ["refused", "timeout", "malformed", "no_change"])
def test_dispatch_terminal_failures_never_orphan_running_state(
    broker_fixture,
    failure,
):
    from hermes_cli.kanban_broker_protocol import receive_frame, send_frame
    from hermes_cli.kanban_dedicated_broker import BrokerError

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(
            idempotency_key=f"radulator:dispatch-{failure}:v1",
            max_retries=0,
        ),
    )
    socket_root = Path(tempfile.mkdtemp(prefix="hkb-failure-", dir="/tmp"))
    endpoint = socket_root / "worker.sock"
    ready = threading.Event()

    if failure == "refused":
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(endpoint))
        stale.close()
        thread = None
    else:

        def worker() -> None:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(endpoint))
            server.listen(1)
            ready.set()
            conn, _address = server.accept()
            with conn:
                receive_frame(conn)
                if failure == "timeout":
                    threading.Event().wait(0.2)
                elif failure == "malformed":
                    send_frame(conn, {"contract": "attacker.turn.v1"})
                else:
                    send_frame(
                        conn,
                        {"contract": "hermes.worker_turn_complete.v1"},
                    )
            server.close()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert ready.wait(5)

    with pytest.raises((BrokerError, OSError, TimeoutError)):
        broker.dispatch_to_worker(
            task_id=created["task_id"],
            worker_socket=endpoint,
            operation_id=f"dispatch-{failure}-operation",
            timeout_seconds=0.05,
        )
    if thread is not None:
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert broker.task_status(created["task_id"]) == "blocked"
    run = broker.conn.execute(
        "SELECT status FROM runs WHERE task_id=?",
        (created["task_id"],),
    ).fetchone()
    assert run["status"] == "failed"
    dispatch = broker.conn.execute(
        "SELECT state, failure_code FROM dispatch_attempts WHERE task_id=?",
        (created["task_id"],),
    ).fetchone()
    assert dispatch["state"] == "FAILED"
    assert dispatch["failure_code"] == failure
    shutil.rmtree(socket_root)


def test_broker_restart_sweeps_post_claim_orphan_to_retryable_state(tmp_path):
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    kwargs = {
        "state_dir": tmp_path / "state",
        "workspace_root": tmp_path / "workspaces",
        "publisher_handoff_root": tmp_path / "handoffs",
        "broker_uid": os.geteuid(),
        "controller_uid": os.geteuid(),
        "publisher_uid": os.geteuid(),
        "operator_uid": os.geteuid(),
        "worker_uid": os.geteuid(),
        "workspace_gid": os.getegid(),
        "trusted_publisher_enabled": True,
    }
    broker = DedicatedKanbanBroker(**kwargs)
    broker.initialize()
    broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(
            idempotency_key="radulator:restart-orphan:v1",
            max_retries=2,
        ),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    assert Path(claim["workspace_path"]).exists()
    broker.close()

    recovered = DedicatedKanbanBroker(**kwargs)
    recovered.initialize()
    assert recovered.task_status(created["task_id"]) == "ready"
    run = recovered.conn.execute(
        "SELECT status FROM runs WHERE task_id=?",
        (created["task_id"],),
    ).fetchone()
    assert run["status"] == "failed"
    assert not Path(claim["workspace_path"]).exists()
    recovered.close()


def test_commit_rejects_symlink_arbitrary_workspace_and_protected_refs(
    broker_fixture, tmp_path
):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "escape").symlink_to(tmp_path / "outside")

    with pytest.raises(BrokerSecurityError, match="symlink"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="bad-symlink",
            untrusted_worker_result={
                "workspace_path": str(tmp_path),
                "branch": "main",
                "repository_id": "attacker",
            },
        )
    assert broker.task_status(created["task_id"]) == "blocked"


def test_snapshot_rejects_replaced_workspace_root_and_hardlinks(
    broker_fixture, tmp_path
):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    moved = workspace.with_name(workspace.name + "-moved")
    workspace.rename(moved)
    workspace.mkdir()
    with pytest.raises(BrokerSecurityError, match="identity"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="replaced-root",
            untrusted_worker_result={},
        )

    request = _request(
        request_id="create-radulator-2",
        idempotency_key="radulator:hardlink:v1",
    )
    created = broker.trusted_create(peer_uid=os.geteuid(), request=request)
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    outside = tmp_path / "outside-secret"
    outside.write_text("do not import\n", encoding="utf-8")
    os.link(outside, workspace / "hardlink")
    with pytest.raises(BrokerSecurityError, match="hard-linked"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="hardlink-operation",
            untrusted_worker_result={},
        )


def test_snapshot_rejects_filesystem_equivalent_git_metadata_aliases(
    broker_fixture,
):
    """APFS aliases such as .GIT must never enter a brokered commit."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:git-alias:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    alias = workspace / ".GIT"
    alias.mkdir()
    (alias / "config").write_text("[core]\n", encoding="utf-8")

    with pytest.raises(BrokerSecurityError, match="Git metadata"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="git-alias-operation",
            untrusted_worker_result={},
        )
    assert broker.task_status(created["task_id"]) == "blocked"


def test_path_validation_rejects_unicode_git_aliases_and_normalized_collisions():
    """Reject conservative HFS/APFS-equivalent names before filesystem writes."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import (
        _assert_no_filesystem_path_collisions,
        _safe_relative_path,
    )

    for alias in (".GIT/config", ".g\u200cit/config", ".gi\ufefft/config"):
        with pytest.raises(BrokerSecurityError, match="Git metadata"):
            _safe_relative_path(alias)

    with pytest.raises(BrokerSecurityError, match="filesystem-equivalent"):
        _assert_no_filesystem_path_collisions(["Docs/Readme.md", "docs/README.md"])
    with pytest.raises(BrokerSecurityError, match="filesystem-equivalent"):
        _assert_no_filesystem_path_collisions(["caf\u00e9.txt", "cafe\u0301.txt"])


def test_commit_replay_uses_immutable_journal_after_workspace_mutation(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "feature.txt").write_text("one\n", encoding="utf-8")
    first = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="replay-operation",
        untrusted_worker_result={},
    )
    second = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="replay-operation",
        untrusted_worker_result={},
    )
    assert second == first

    (workspace / "feature.txt").write_text("two\n", encoding="utf-8")
    assert (
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="replay-operation",
            untrusted_worker_result={},
        )
        == first
    )

    second_task = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:other-operation-owner:v1"),
    )
    second_claim = broker.claim_for_dispatch(second_task["task_id"])
    Path(second_claim["workspace_path"], "other.txt").write_text(
        "other\n", encoding="utf-8"
    )
    with pytest.raises(BrokerConflict, match="belongs to another run"):
        broker.commit_run(
            task_id=second_task["task_id"],
            run_id=second_claim["run_id"],
            operation_id="replay-operation",
            untrusted_worker_result={},
        )


def test_crash_after_ref_recovers_same_commit_and_receipt(broker_fixture):
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "feature.txt").write_text("recover me\n", encoding="utf-8")

    with pytest.raises(BrokerInjectedCrash, match="REF_UPDATED"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="crash-operation",
            untrusted_worker_result={},
            inject_crash_after="REF_UPDATED",
        )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="crash-operation",
        untrusted_worker_result={},
    )
    assert event["changed_paths"] == ["feature.txt"]
    assert broker.operation_state("crash-operation") == "EMITTED"


def test_receipt_emission_cas_rejects_stale_task_after_ref_recovery(broker_fixture):
    """Catch receipt emission that parks an operation after task authority changed."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:emit-cas:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "feature.txt").write_text(
        "stale task\n", encoding="utf-8"
    )
    with pytest.raises(BrokerInjectedCrash, match="REF_UPDATED"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="emit-cas-operation",
            untrusted_worker_result={},
            inject_crash_after="REF_UPDATED",
        )
    with broker.conn:
        broker.conn.execute(
            "UPDATE tasks SET status='blocked' WHERE task_id=?",
            (created["task_id"],),
        )
    with pytest.raises(BrokerConflict, match="emission compare-and-swap"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="emit-cas-operation",
            untrusted_worker_result={},
        )
    assert broker.operation_state("emit-cas-operation") == "REF_UPDATED"
    assert (
        broker.conn.execute(
            "SELECT 1 FROM publish_receipts WHERE operation_id='emit-cas-operation'"
        ).fetchone()
        is None
    )


def test_crash_between_git_ref_and_journal_recovers_without_second_commit(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "feature.txt").write_text(
        "recover ref gap\n", encoding="utf-8"
    )
    with pytest.raises(BrokerInjectedCrash, match="REF_BEFORE_JOURNAL"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="ref-gap-operation",
            untrusted_worker_result={},
            inject_crash_after="REF_BEFORE_JOURNAL",
        )
    assert broker.operation_state("ref-gap-operation") == "OBJECT_WRITTEN"
    Path(claim["workspace_path"], "feature.txt").write_text(
        "attacker mutation after crash\n", encoding="utf-8"
    )
    recovered = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="ref-gap-operation",
        untrusted_worker_result={},
    )
    assert broker.operation_state("ref-gap-operation") == "EMITTED"
    private_repo = broker.private_repository_path("radulator")
    assert _git("rev-list", "--count", recovered["branch"], cwd=private_repo) == "2"
    assert (
        _git(
            "show",
            f"{recovered['head_sha']}:feature.txt",
            cwd=private_repo,
        )
        == "recover ref gap"
    )


def test_restart_recovers_journaled_commit_without_mutable_workspace(tmp_path):
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    kwargs = {
        "state_dir": tmp_path / "state",
        "workspace_root": tmp_path / "workspaces",
        "publisher_handoff_root": tmp_path / "handoffs",
        "broker_uid": os.geteuid(),
        "controller_uid": os.geteuid(),
        "publisher_uid": os.geteuid(),
        "operator_uid": os.geteuid(),
        "worker_uid": os.geteuid(),
        "workspace_gid": os.getegid(),
        "trusted_publisher_enabled": True,
    }
    broker = DedicatedKanbanBroker(**kwargs)
    broker.initialize()
    broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:restart-commit:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "feature.txt").write_text("sealed bytes\n", encoding="utf-8")
    with pytest.raises(BrokerInjectedCrash, match="REF_BEFORE_JOURNAL"):
        broker.commit_run(
            task_id=created["task_id"],
            run_id=claim["run_id"],
            operation_id="restart-commit-operation",
            untrusted_worker_result={},
            inject_crash_after="REF_BEFORE_JOURNAL",
        )
    (workspace / "feature.txt").write_text("mutated bytes\n", encoding="utf-8")
    broker.close()

    recovered = DedicatedKanbanBroker(**kwargs)
    recovered.initialize()
    assert recovered.operation_state("restart-commit-operation") == "EMITTED"
    receipt = recovered.conn.execute(
        "SELECT payload_json FROM publish_receipts WHERE operation_id=?",
        ("restart-commit-operation",),
    ).fetchone()
    assert receipt is not None
    event = json.loads(receipt["payload_json"])
    private = recovered.private_repository_path("radulator")
    assert _git("show", f"{event['head_sha']}:feature.txt", cwd=private) == (
        "sealed bytes"
    )
    recovered.close()


def test_git_plumbing_ignores_worker_hooks_config_and_credentials(
    broker_fixture, monkeypatch, tmp_path
):
    broker, _source, _base = broker_fixture
    marker = tmp_path / "hook-executed"
    fsmonitor_marker = tmp_path / "fsmonitor-executed"
    path_git_marker = tmp_path / "path-git-executed"
    hostile_bin = tmp_path / "hostile-bin"
    hostile_bin.mkdir()
    hostile_git = hostile_bin / "git"
    hostile_git.write_text(
        f'#!/bin/sh\ntouch {path_git_marker}\nexec /usr/bin/git "$@"\n',
        encoding="utf-8",
    )
    hostile_git.chmod(0o755)
    hostile_home = tmp_path / "hostile-home"
    hostile_home.mkdir()
    (hostile_home / ".gitconfig").write_text(
        "[core]\n\thooksPath = " + str(tmp_path / "hooks") + "\n",
        encoding="utf-8",
    )
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    hook = hooks / "pre-commit"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    fsmonitor = tmp_path / "hostile-fsmonitor"
    fsmonitor.write_text(
        f"#!/bin/sh\ntouch {fsmonitor_marker}\nprintf '\\0'\n", encoding="utf-8"
    )
    fsmonitor.chmod(0o755)
    private_repo = broker.private_repository_path("radulator")
    _git("config", "core.fsmonitor", str(fsmonitor), cwd=private_repo)
    _git("config", "core.fsmonitorHookVersion", "2", cwd=private_repo)
    monkeypatch.setenv("HOME", str(hostile_home))
    monkeypatch.setenv("GH_TOKEN", "must-not-cross-boundary")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross-boundary")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.hooksPath")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(hooks))
    monkeypatch.setenv("PATH", str(hostile_bin))

    created = broker.trusted_create(peer_uid=os.geteuid(), request=_request())
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "feature.txt").write_text("safe\n", encoding="utf-8")
    broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="hostile-config-operation",
        untrusted_worker_result={},
    )
    assert not marker.exists()
    assert not fsmonitor_marker.exists()
    assert not path_git_marker.exists()
    env = broker.git_environment_for_test()
    assert env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin"
    assert "GH_TOKEN" not in env
    assert "GITHUB_TOKEN" not in env
    assert "GIT_CONFIG_COUNT" not in env


def test_repository_registration_rejects_replace_refs_before_materialization(
    tmp_path,
):
    """Catch nominal base SHAs whose bytes are silently rewritten by replace refs."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    base_sha = _init_repo(source)
    (source / "README.md").write_text("replacement bytes\n", encoding="utf-8")
    _git("add", "README.md", cwd=source)
    _git("commit", "-m", "replacement", cwd=source)
    replacement_sha = _git("rev-parse", "HEAD", cwd=source)
    _git("replace", base_sha, replacement_sha, cwd=source)

    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    with pytest.raises(BrokerSecurityError, match="replace"):
        broker.register_repository(
            peer_uid=os.geteuid(),
            repository_id="radulator",
            source_path=source,
            default_branch="main",
            project_id=None,
            remote_repository=_remote_repository(),
        )
    assert not (tmp_path / "state" / "repositories" / "radulator.git").exists()
    broker.close()


def test_repository_registration_replays_exact_result_after_response_loss(
    broker_fixture,
):
    broker, source, base = broker_fixture
    replay = broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    assert replay["repository_id"] == "radulator"
    assert replay["base_sha"] == base
    assert replay["source_path"] == str(source.resolve())
    assert replay["remote_repository"] == _remote_repository()


def test_repository_registration_rejects_model_mutable_trusted_checkout(tmp_path):
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    mutable = source / ".git" / "config"
    mutable.chmod(0o666)
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid() + 10,
        publisher_uid=os.geteuid() + 11,
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid() + 12,
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    try:
        with pytest.raises(BrokerSecurityError, match="trusted checkout.*mutable"):
            broker.register_repository(
                peer_uid=os.geteuid(),
                repository_id="radulator",
                source_path=source,
                default_branch="main",
                project_id=None,
                remote_repository=_remote_repository(),
            )
    finally:
        broker.close()


def test_repository_registration_neutralizes_source_pack_objects_hook(tmp_path):
    """A model-writable checkout config must not execute as the broker UID."""
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    marker = tmp_path / "source-hook-executed-as-broker"
    hook = tmp_path / "hostile-pack-objects"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\nexit 97\n", encoding="utf-8")
    hook.chmod(0o755)
    _git("config", "uploadpack.packObjectsHook", str(hook), cwd=source)
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    registered = broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    assert registered["base_sha"] == _git("rev-parse", "HEAD", cwd=source)
    assert not marker.exists()
    broker.close()


def test_repository_registration_rejects_grafts_and_object_alternates(tmp_path):
    """Catch local rewrite/borrowing mechanisms before a private mirror is trusted."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    base_sha = _init_repo(source)
    git_dir = source / ".git"
    (git_dir / "info" / "grafts").write_text(f"{base_sha}\n", encoding="ascii")
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    with pytest.raises(BrokerSecurityError, match="graft"):
        broker.register_repository(
            peer_uid=os.geteuid(),
            repository_id="radulator",
            source_path=source,
            default_branch="main",
            project_id=None,
            remote_repository=_remote_repository(),
        )
    (git_dir / "info" / "grafts").unlink()
    (git_dir / "objects" / "info" / "alternates").write_text(
        str(tmp_path / "borrowed-objects") + "\n", encoding="utf-8"
    )
    with pytest.raises(BrokerSecurityError, match="alternate"):
        broker.register_repository(
            peer_uid=os.geteuid(),
            repository_id="radulator",
            source_path=source,
            default_branch="main",
            project_id=None,
            remote_repository=_remote_repository(),
        )
    broker.close()


def test_private_repository_rewrites_are_rechecked_at_every_authority_boundary(
    broker_fixture,
):
    """Catch post-registration private-state corruption before trusted-create."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, source, base_sha = broker_fixture
    (source / "README.md").write_text("other bytes\n", encoding="utf-8")
    _git("add", "README.md", cwd=source)
    _git("commit", "-m", "other", cwd=source)
    replacement_sha = _git("rev-parse", "HEAD", cwd=source)
    private = broker.private_repository_path("radulator")
    # Import the replacement commit as an object, then add the forbidden ref.
    packed = subprocess.run(
        ["git", "-C", str(source), "format-patch", "-1", "--stdout"],
        check=True,
        capture_output=True,
    ).stdout
    assert packed
    _git("fetch", str(source), replacement_sha, cwd=private)
    _git(
        f"--git-dir={private}",
        "update-ref",
        f"refs/replace/{base_sha}",
        replacement_sha,
    )
    with pytest.raises(BrokerSecurityError, match="replace"):
        broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(idempotency_key="radulator:private-rewrite:v1"),
        )


@pytest.mark.parametrize("boundary", ["materialize", "commit"])
def test_private_replace_ref_added_after_seal_is_rejected_before_git_plumbing(
    broker_fixture, boundary
):
    """Catch a private replace ref introduced after authority was sealed."""
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, source, base_sha = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key=f"radulator:rewrite-{boundary}:v1"),
    )
    claim = None
    if boundary == "commit":
        claim = broker.claim_for_dispatch(created["task_id"])
        Path(claim["workspace_path"], "feature.txt").write_text(
            "changed\n", encoding="utf-8"
        )
    (source / "README.md").write_text("replacement\n", encoding="utf-8")
    _git("add", "README.md", cwd=source)
    _git("commit", "-m", "replacement", cwd=source)
    replacement_sha = _git("rev-parse", "HEAD", cwd=source)
    private = broker.private_repository_path("radulator")
    _git("fetch", str(source), replacement_sha, cwd=private)
    _git(
        f"--git-dir={private}",
        "update-ref",
        f"refs/replace/{base_sha}",
        replacement_sha,
    )

    if boundary == "materialize":
        with pytest.raises(BrokerSecurityError, match="replace"):
            broker.claim_for_dispatch(created["task_id"])
    else:
        with pytest.raises(BrokerSecurityError, match="replace"):
            broker.commit_run(
                task_id=created["task_id"],
                run_id=claim["run_id"],
                operation_id="rewrite-after-claim",
                untrusted_worker_result={},
            )


def test_publisher_receives_receipt_bound_read_only_bundle_not_private_git(
    tmp_path,
):
    """Catch a receipt API that leaves the separate publisher unable to get objects."""
    from hermes_cli.kanban_dedicated_broker import BrokerAuthorizationError
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    handoff_root = tmp_path / "publisher-handoffs"
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "private-state",
        workspace_root=tmp_path / "workspaces",
        publisher_handoff_root=handoff_root,
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
        publisher_gid=os.getegid(),
        trusted_publisher_enabled=True,
    )
    broker.initialize()
    broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
    )
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:bundle:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "published.txt").write_text(
        "exact brokered bytes\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="bundle-operation",
        untrusted_worker_result={},
    )

    with pytest.raises(BrokerAuthorizationError):
        broker.export_publish_bundle(
            peer_uid=os.geteuid() + 1,
            receipt_id=event["receipt_id"],
            payload_sha256=event["payload_sha256"],
        )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    assert handoff["contract"] == "hermes.publisher_object_handoff.v1"
    assert handoff["receipt_id"] == event["receipt_id"]
    assert handoff["receipt_payload_sha256"] == event["payload_sha256"]
    assert handoff["branch"] == event["branch"]
    assert handoff["base_sha"] == event["base_sha"]
    assert handoff["head_sha"] == event["head_sha"]
    bundle = Path(handoff["bundle_path"])
    assert bundle.parent == handoff_root
    assert tmp_path / "private-state" not in bundle.parents
    assert stat.S_IMODE(handoff_root.stat().st_mode) == 0o710
    assert stat.S_IMODE(bundle.stat().st_mode) == 0o640
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() == handoff["bundle_sha256"]
    assert str(broker.private_repository_path("radulator")) not in json.dumps(handoff)

    consumer = tmp_path / "publisher-repository"
    _git("init", "-b", "main", str(consumer))
    _git(
        "fetch",
        str(bundle),
        f"refs/heads/{event['branch']}:refs/heads/imported",
        cwd=consumer,
    )
    assert _git("rev-parse", "imported", cwd=consumer) == event["head_sha"]
    assert _git("show", "imported:published.txt", cwd=consumer) == (
        "exact brokered bytes"
    )
    assert (
        broker.export_publish_bundle(
            peer_uid=os.geteuid(),
            receipt_id=event["receipt_id"],
            payload_sha256=event["payload_sha256"],
        )
        == handoff
    )
    broker.close()


def test_publisher_bundle_recovers_idempotently_after_rename_before_journal(
    broker_fixture,
):
    """Catch bundle replay that rewrites objects or loses a crash-orphaned handoff."""
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:bundle-crash:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "recover.txt").write_text(
        "recover exact bundle\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="bundle-crash-operation",
        untrusted_worker_result={},
    )
    with pytest.raises(BrokerInjectedCrash, match="BUNDLE_RENAMED"):
        broker.export_publish_bundle(
            peer_uid=os.geteuid(),
            receipt_id=event["receipt_id"],
            payload_sha256=event["payload_sha256"],
            inject_crash_after="BUNDLE_RENAMED",
        )
    assert (
        broker.conn.execute(
            "SELECT 1 FROM publish_exports WHERE receipt_id=?", (event["receipt_id"],)
        ).fetchone()
        is None
    )
    recovered = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    replay = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    assert replay == recovered
    assert recovered["head_sha"] == event["head_sha"]
    assert (
        hashlib.sha256(Path(recovered["bundle_path"]).read_bytes()).hexdigest()
        == (recovered["bundle_sha256"])
    )


def test_publisher_ack_finalizes_branch_without_advancing_unmerged_protected_base(
    broker_fixture,
):
    broker, _source, base_sha = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:publish-ack:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "published.txt").write_text("published\n", encoding="utf-8")
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="publish-ack-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    bundle = Path(handoff["bundle_path"])

    acknowledgement = _publish_ack(event, handoff)
    acknowledged = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=acknowledgement,
    )
    assert acknowledged["contract"] == "hermes.publisher_ack.v1"
    assert acknowledged["branch_published_from"] == base_sha
    assert acknowledged["branch_published_to"] == event["head_sha"]
    assert acknowledged["repository_base_sha"] == base_sha
    assert acknowledged["cleanup_state"] == "cleaned"
    assert broker.task_status(created["task_id"]) == "done"
    assert broker.operation_state("publish-ack-operation") == "PUBLISHED"
    run = broker.conn.execute(
        "SELECT status FROM runs WHERE run_id=?", (claim["run_id"],)
    ).fetchone()
    assert run["status"] == "done"
    repository = broker.conn.execute(
        "SELECT base_sha FROM repositories WHERE repository_id='radulator'"
    ).fetchone()
    assert repository["base_sha"] == base_sha
    private = broker.private_repository_path("radulator")
    assert _git("rev-parse", "main", cwd=private) == base_sha
    with pytest.raises(subprocess.CalledProcessError):
        _git("rev-parse", event["branch"], cwd=private)
    assert not workspace.exists()
    assert not bundle.exists()

    replay = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=acknowledgement,
    )
    assert replay == acknowledged
    verified = broker.verify_publish_receipt(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    assert verified["verified"] is True
    assert verified["operation_state"] == "PUBLISHED"

    next_task = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:after-publish:v1"),
    )
    next_claim = broker.claim_for_dispatch(next_task["task_id"])
    assert next_claim["base_sha"] == base_sha


def test_publisher_ack_rejects_stale_or_non_fast_forward_authority(broker_fixture):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:publish-ack-stale:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "stale.txt").write_text("stale\n", encoding="utf-8")
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="publish-ack-stale-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    with pytest.raises(BrokerConflict, match="acknowledgement"):
        broker.acknowledge_publish(
            peer_uid=os.geteuid(),
            acknowledgement=_publish_ack(
                event,
                handoff,
                published_head_sha="f" * 40,
            ),
        )
    assert broker.task_status(created["task_id"]) == "blocked"

    private = broker.private_repository_path("radulator")
    # Simulate an independently advanced protected base without trusting an
    # arbitrary publisher-supplied SHA.  The exact base CAS must reject it.
    _git(
        f"--git-dir={private}",
        "update-ref",
        "refs/heads/main",
        event["head_sha"],
        event["base_sha"],
    )
    with broker.conn:
        broker.conn.execute(
            "UPDATE repositories SET base_sha=? WHERE repository_id='radulator'",
            (event["head_sha"],),
        )
    with pytest.raises(BrokerConflict, match="base"):
        broker.acknowledge_publish(
            peer_uid=os.geteuid(),
            acknowledgement=_publish_ack(event, handoff),
        )


def test_controller_supersedes_failed_ci_receipt_and_reseals_same_branch_correction(
    broker_fixture,
):
    broker, _source, protected_base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:correction:v1"),
    )
    first_claim = broker.claim_for_dispatch(created["task_id"])
    first_workspace = Path(first_claim["workspace_path"])
    (first_workspace / "correction.txt").write_text("first\n", encoding="utf-8")
    first_event = broker.commit_run(
        task_id=created["task_id"],
        run_id=first_claim["run_id"],
        operation_id="correction-first-operation",
        untrusted_worker_result={},
    )

    correction = broker.request_publish_correction(
        peer_uid=os.geteuid(),
        request={
            "contract": "hermes.publisher_correction_request.v1",
            "receipt_id": first_event["receipt_id"],
            "receipt_payload_sha256": first_event["payload_sha256"],
            "reason_code": "ci_failed",
        },
    )

    assert correction["status"] == "ready"
    assert correction["superseded_head_sha"] == first_event["head_sha"]
    verified_old = broker.verify_publish_receipt(
        peer_uid=os.geteuid(),
        receipt_id=first_event["receipt_id"],
        payload_sha256=first_event["payload_sha256"],
    )
    assert verified_old["verified"] is False
    assert verified_old["revoked"] is True
    assert broker.operation_state("correction-first-operation") == "SUPERSEDED"

    second_claim = broker.claim_for_dispatch(created["task_id"])
    assert second_claim["branch"] == first_event["branch"]
    assert second_claim["base_sha"] == first_event["head_sha"]
    assert second_claim["target_base_sha"] == protected_base
    second_workspace = Path(second_claim["workspace_path"])
    assert (second_workspace / "correction.txt").read_text(encoding="utf-8") == "first\n"
    (second_workspace / "correction.txt").write_text("second\n", encoding="utf-8")
    second_event = broker.commit_run(
        task_id=created["task_id"],
        run_id=second_claim["run_id"],
        operation_id="correction-second-operation",
        untrusted_worker_result={},
    )
    assert second_event["base_sha"] == first_event["head_sha"]
    assert second_event["target_base_sha"] == protected_base
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=second_event["receipt_id"],
        payload_sha256=second_event["payload_sha256"],
    )
    acknowledged = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=_publish_ack(second_event, handoff),
    )
    assert acknowledged["branch_published_from"] == first_event["head_sha"]
    assert acknowledged["repository_base_sha"] == protected_base


def test_publisher_ack_requires_exact_remote_pr_ci_and_ready_label_readback(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:remote-readback:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "remote.txt").write_text(
        "remote evidence\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="remote-readback-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )

    invalid: list[dict] = []
    missing = _publish_ack(event, handoff)
    missing.pop("remote_readback")
    invalid.append(missing)
    wrong_owner = _publish_ack(event, handoff)
    wrong_owner["remote_readback"]["repository"]["owner"] = "attacker"
    invalid.append(wrong_owner)
    fork = _publish_ack(event, handoff)
    fork["remote_readback"]["pull_request"]["head_repository_is_fork"] = True
    invalid.append(fork)
    stale_head = _publish_ack(event, handoff)
    stale_head["remote_readback"]["workflow"]["head_sha"] = "f" * 40
    invalid.append(stale_head)
    not_newest = _publish_ack(event, handoff)
    not_newest["remote_readback"]["workflow"]["newest_run_id_for_workflow_and_head"] = (
        999
    )
    invalid.append(not_newest)
    wrong_jobs = _publish_ack(event, handoff)
    wrong_jobs["remote_readback"]["workflow"]["required_job_ids"] = [999]
    invalid.append(wrong_jobs)
    label_before_ci = _publish_ack(event, handoff)
    label_before_ci["remote_readback"]["ready_label"]["event_created_at"] = (
        label_before_ci["remote_readback"]["workflow"]["completed_at"] - 1
    )
    invalid.append(label_before_ci)
    wrong_label_actor = _publish_ack(event, handoff)
    wrong_label_actor["remote_readback"]["ready_label"]["actor"]["id"] = 15368
    invalid.append(wrong_label_actor)
    for acknowledgement in invalid:
        with pytest.raises(BrokerConflict):
            broker.acknowledge_publish(
                peer_uid=os.geteuid(), acknowledgement=acknowledgement
            )
        assert broker.task_status(created["task_id"]) == "blocked"

    acknowledged = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=_publish_ack(event, handoff),
    )
    completion = broker.verify_publish_completion(
        peer_uid=os.geteuid(),
        completion_id=acknowledged["completion_id"],
        payload_sha256=acknowledged["completion_payload_sha256"],
    )
    assert completion["verified"] is True
    payload = completion["canonical_payload"]
    assert payload["remote_readback"]["pull_request"]["head_sha"] == event["head_sha"]
    assert payload["remote_readback"]["workflow"]["run_id"] == 202
    assert payload["remote_readback"]["ready_label"]["name"] == "ready-for-gate"
    assert payload["remote_readback"]["ready_label"]["actor"] == {
        "id": 24681012,
        "login": "hermes-publisher",
        "type": "User",
    }


def test_publisher_ack_binds_every_required_job_to_one_run_attempt_and_suite(
    broker_fixture,
):
    """Catch required check rows mixed in from another workflow run or attempt."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:job-run-binding:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "job-binding.txt").write_text(
        "job binding\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="job-run-binding-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    acknowledgement = _publish_ack(event, handoff)
    job = acknowledgement["remote_readback"]["workflow"]["required_jobs"][0]
    job.update({
        "workflow_id": 101,
        "workflow_run_id": 202,
        "run_attempt": 1,
        "check_suite_id": 303,
    })

    mixed = json.loads(json.dumps(acknowledgement))
    mixed["remote_readback"]["workflow"]["required_jobs"][0][
        "workflow_run_id"
    ] = 999
    with pytest.raises(BrokerConflict, match="required job"):
        broker.acknowledge_publish(
            peer_uid=os.geteuid(), acknowledgement=mixed
        )
    assert broker.task_status(created["task_id"]) == "blocked"

    result = broker.acknowledge_publish(
        peer_uid=os.geteuid(), acknowledgement=acknowledgement
    )
    assert result["publish_outcome"] == "fast_forwarded"


def test_publisher_obligation_query_is_authenticated_bounded_and_pending_only(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerAuthorizationError
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    events = []
    for key in ("pending-one", "pending-two"):
        created = broker.trusted_create(
            peer_uid=os.geteuid(),
            request=_request(idempotency_key=f"radulator:{key}:v1"),
        )
        claim = broker.claim_for_dispatch(created["task_id"])
        Path(claim["workspace_path"], f"{key}.txt").write_text(
            f"{key}\n", encoding="utf-8"
        )
        events.append(
            broker.commit_run(
                task_id=created["task_id"],
                run_id=claim["run_id"],
                operation_id=f"{key}-operation",
                untrusted_worker_result={},
            )
        )

    first = broker.list_publish_obligations(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_obligation_query.v1",
            "repository_id": "radulator",
            "after_created_at": 0,
            "after_receipt_id": "",
            "limit": 1,
        },
    )
    assert first["contract"] == "hermes.publisher_obligation_query.v1"
    assert first["has_more"] is True
    assert len(first["items"]) == 1
    assert first["items"][0]["verified"] is True
    second = broker.list_publish_obligations(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_obligation_query.v1",
            "repository_id": "radulator",
            "after_created_at": first["next_cursor"]["created_at"],
            "after_receipt_id": first["next_cursor"]["receipt_id"],
            "limit": 1,
        },
    )
    assert second["has_more"] is False
    assert {
        item["canonical_payload"]["receipt_id"]
        for item in [*first["items"], *second["items"]]
    } == {event["receipt_id"] for event in events}

    published = events[0]
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=published["receipt_id"],
        payload_sha256=published["payload_sha256"],
    )
    broker.acknowledge_publish(
        peer_uid=os.geteuid(), acknowledgement=_publish_ack(published, handoff)
    )
    remaining = broker.list_publish_obligations(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_obligation_query.v1",
            "repository_id": "radulator",
            "after_created_at": 0,
            "after_receipt_id": "",
            "limit": 10,
        },
    )
    assert [
        item["canonical_payload"]["receipt_id"] for item in remaining["items"]
    ] == [events[1]["receipt_id"]]
    with pytest.raises(BrokerConflict, match="limit"):
        broker.list_publish_obligations(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 101,
            },
        )
    with pytest.raises(BrokerAuthorizationError, match="not authorized"):
        broker.list_publish_obligations(
            peer_uid=os.geteuid() + 1,
            query={
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 1,
            },
        )


def test_publisher_completion_receipts_are_tamper_evident_bounded_and_paginated(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict
    from hermes_cli.kanban_dedicated_broker import BrokerSecurityError

    broker, _source, _base = broker_fixture
    _created_one, claim_one, event_one, acknowledged_one = _complete_published_task(
        broker, key="one"
    )
    _created_two, claim_two, event_two, acknowledged_two = _complete_published_task(
        broker, key="two"
    )
    assert acknowledged_one["completion_id"].startswith("kpc_")
    verified = broker.verify_publish_completion(
        peer_uid=os.geteuid(),
        completion_id=acknowledged_one["completion_id"],
        payload_sha256=acknowledged_one["completion_payload_sha256"],
    )
    assert verified["verified"] is True
    payload = verified["canonical_payload"]
    assert payload["receipt_id"] == event_one["receipt_id"]
    assert payload["task_id"] == event_one["task_id"]
    assert payload["run_id"] == claim_one["run_id"]
    assert payload["claim_generation"] == claim_one["claim_generation"]
    assert payload["repository_id"] == event_one["repository_id"]
    assert payload["branch"] == event_one["branch"]
    assert payload["base_sha"] == event_one["base_sha"]
    assert payload["head_sha"] == event_one["head_sha"]

    first = broker.list_publish_completions(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_completion_query.v1",
            "repository_id": "radulator",
            "after_created_at": 0,
            "after_completion_id": "",
            "limit": 1,
        },
    )
    assert first["has_more"] is True
    assert len(first["items"]) == 1
    second = broker.list_publish_completions(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_completion_query.v1",
            "repository_id": "radulator",
            "after_created_at": first["next_cursor"]["created_at"],
            "after_completion_id": first["next_cursor"]["completion_id"],
            "limit": 1,
        },
    )
    assert second["has_more"] is False
    assert {
        item["canonical_payload"]["receipt_id"]
        for item in [*first["items"], *second["items"]]
    } == {event_one["receipt_id"], event_two["receipt_id"]}
    assert second["items"][0]["canonical_payload"]["run_id"] in {
        claim_one["run_id"],
        claim_two["run_id"],
    }
    with pytest.raises(BrokerConflict, match="limit"):
        broker.list_publish_completions(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_completion_query.v1",
                "repository_id": None,
                "after_created_at": 0,
                "after_completion_id": "",
                "limit": 101,
            },
        )

    with broker.conn:
        broker.conn.execute(
            "UPDATE publisher_completions SET completion_json='{}' "
            "WHERE completion_id=?",
            (acknowledged_two["completion_id"],),
        )
    tampered = broker.verify_publish_completion(
        peer_uid=os.geteuid(),
        completion_id=acknowledged_two["completion_id"],
        payload_sha256=acknowledged_two["completion_payload_sha256"],
    )
    assert tampered["verified"] is False
    with pytest.raises(BrokerSecurityError, match="completion"):
        broker.list_publish_completions(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_completion_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_completion_id": "",
                "limit": 10,
            },
        )


def test_publisher_ack_recovers_after_base_ref_update_before_db_cas(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:publish-ack-crash:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "crash.txt").write_text(
        "crash safe\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="publish-ack-crash-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    acknowledgement = _publish_ack(event, handoff)
    with pytest.raises(BrokerInjectedCrash, match="BASE_REF_UPDATED"):
        broker.acknowledge_publish(
            peer_uid=os.geteuid(),
            acknowledgement=acknowledgement,
            inject_crash_after="BASE_REF_UPDATED",
        )
    assert broker.operation_state("publish-ack-crash-operation") == "EMITTED"
    recovered = broker.acknowledge_publish(
        peer_uid=os.geteuid(),
        acknowledgement=acknowledgement,
    )
    assert recovered["cleanup_state"] == "cleaned"
    assert broker.operation_state("publish-ack-crash-operation") == "PUBLISHED"


def test_publisher_ack_replay_recovers_after_completion_cas(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerInjectedCrash
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:completion-cas-crash:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    workspace = Path(claim["workspace_path"])
    (workspace / "completion-cas.txt").write_text(
        "durable completion\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="completion-cas-crash-operation",
        untrusted_worker_result={},
    )
    handoff = broker.export_publish_bundle(
        peer_uid=os.geteuid(),
        receipt_id=event["receipt_id"],
        payload_sha256=event["payload_sha256"],
    )
    acknowledgement = _publish_ack(event, handoff)

    with pytest.raises(BrokerInjectedCrash, match="COMPLETION_CAS"):
        broker.acknowledge_publish(
            peer_uid=os.geteuid(),
            acknowledgement=acknowledgement,
            inject_crash_after="COMPLETION_CAS",
        )

    assert broker.task_status(created["task_id"]) == "done"
    assert broker.operation_state("completion-cas-crash-operation") == "PUBLISHED"
    row = broker.conn.execute(
        "SELECT completion_id, payload_sha256 FROM publisher_completions "
        "WHERE receipt_id=?",
        (event["receipt_id"],),
    ).fetchone()
    assert row is not None

    restart_kwargs = {
        "state_dir": broker.state_dir,
        "workspace_root": broker.workspace_root,
        "publisher_handoff_root": broker.publisher_handoff_root,
        "broker_uid": broker.broker_uid,
        "controller_uid": broker.controller_uid,
        "publisher_uid": broker.publisher_uid,
        "operator_uid": broker.operator_uid,
        "worker_uid": broker.worker_uid,
        "workspace_gid": broker.workspace_gid,
        "publisher_gid": broker.publisher_gid,
        "trusted_publisher_enabled": True,
    }
    broker.close()
    recovered = DedicatedKanbanBroker(**restart_kwargs)
    recovered.initialize()
    try:
        replay = recovered.acknowledge_publish(
            peer_uid=os.geteuid(),
            acknowledgement=acknowledgement,
        )
        assert replay["cleanup_state"] == "cleaned"
        assert replay["completion_id"] == row["completion_id"]
        verified = recovered.verify_publish_completion(
            peer_uid=os.geteuid(),
            completion_id=row["completion_id"],
            payload_sha256=row["payload_sha256"],
        )
        assert verified["verified"] is True
        assert verified["canonical_payload"]["task_id"] == created["task_id"]
        assert not workspace.exists()
        assert not Path(handoff["bundle_path"]).exists()
    finally:
        recovered.close()


def test_operator_refresh_requires_fast_forward_and_new_tasks_use_new_base(
    broker_fixture,
):
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, source, old_base = broker_fixture
    (source / "upstream.txt").write_text("upstream\n", encoding="utf-8")
    _git("add", "upstream.txt", cwd=source)
    _git("commit", "-m", "upstream", cwd=source)
    new_base = _git("rev-parse", "HEAD", cwd=source)
    refreshed = broker.refresh_repository_base(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        expected_old_base_sha=old_base,
    )
    assert refreshed["base_advanced_from"] == old_base
    assert refreshed["base_advanced_to"] == new_base
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:after-refresh:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    assert claim["base_sha"] == new_base
    assert (
        Path(claim["workspace_path"], "upstream.txt").read_text(encoding="utf-8")
        == "upstream\n"
    )

    _git("reset", "--hard", old_base, cwd=source)
    with pytest.raises(BrokerConflict, match="fast-forward"):
        broker.refresh_repository_base(
            peer_uid=os.geteuid(),
            repository_id="radulator",
            expected_old_base_sha=new_base,
        )


def test_real_publisher_rpc_exports_only_exact_receipt_bound_bundle(broker_fixture):
    """Catch publisher RPCs that accept worker paths or private-ref authority."""
    from hermes_cli.kanban_broker_client import BrokerRPCClient
    from hermes_cli.kanban_broker_client import BrokerRPCError
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerSocketService

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:publisher-rpc:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "rpc-publish.txt").write_text(
        "publisher rpc\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="publisher-rpc-operation",
        untrusted_worker_result={},
    )
    socket_root = _secure_socket_parent(
        Path(tempfile.mkdtemp(prefix="hkb-publisher-", dir="/tmp"))
    )
    endpoint = socket_root / "publisher.sock"
    key = b"p" * 32
    service = BrokerSocketService(
        surfaces={
            "publisher": {
                "path": endpoint,
                "gid": os.getegid(),
                "server": BrokerRPCServer(
                    broker=broker,
                    surface="publisher",
                    allowed_uid=os.geteuid(),
                    client_key=key,
                ),
            }
        },
        broker_uid=os.geteuid(),
    )
    service.start()
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        client = BrokerRPCClient(
            socket_path=endpoint,
            expected_broker_uid=os.geteuid(),
            client_key=key,
            sequence_path=socket_root / "publisher.sequence",
        )
        pending = client.call(
            "list_publish_obligations",
            {
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 10,
            },
        )
        assert [item["receipt_id"] for item in pending["items"]] == [
            event["receipt_id"]
        ]
        handoff = client.call(
            "export_bundle",
            {
                "receipt_id": event["receipt_id"],
                "payload_sha256": event["payload_sha256"],
            },
        )
        assert handoff["head_sha"] == event["head_sha"]
        acknowledged = client.call(
            "ack_publish",
            _publish_ack(event, handoff),
        )
        assert acknowledged["cleanup_state"] == "cleaned"
        completion = client.call(
            "verify_completion",
            {
                "completion_id": acknowledged["completion_id"],
                "payload_sha256": acknowledged["completion_payload_sha256"],
            },
        )
        assert completion["verified"] is True
        obligations = client.call(
            "list_completion_obligations",
            {
                "contract": "hermes.publisher_completion_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_completion_id": "",
                "limit": 10,
            },
        )
        assert [item["completion_id"] for item in obligations["items"]] == [
            acknowledged["completion_id"]
        ]
        assert broker.task_status(created["task_id"]) == "done"
        drained = client.call(
            "list_publish_obligations",
            {
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 10,
            },
        )
        assert drained["items"] == []
        with pytest.raises(BrokerRPCError, match="fields"):
            client.call(
                "export_bundle",
                {
                    "receipt_id": event["receipt_id"],
                    "payload_sha256": event["payload_sha256"],
                    "private_repository": "/tmp/attacker.git",
                },
            )
    finally:
        service.stop()
        thread.join(timeout=5)
        service.close()
        shutil.rmtree(socket_root)


def test_launchd_plan_uses_dedicated_identity_and_separate_sockets(tmp_path):
    import plistlib

    from hermes_cli.kanban_broker_install import render_broker_seatbelt_profile
    from hermes_cli.kanban_broker_install import render_launchd_plist
    from hermes_cli.kanban_broker_install import validate_group_separation
    from hermes_cli.kanban_broker_install import validate_identity_separation
    from hermes_cli.kanban_broker_install import render_worker_launchd_plist

    rendered = render_launchd_plist(
        python_executable=Path("/usr/bin/python3"),
        config_path=tmp_path / "broker-service.json",
        state_dir=tmp_path / "state",
        broker_user="_hermesbroker",
        package_root=tmp_path / "runtime/hermes_cli",
    )
    assert "<string>_hermesbroker</string>" in rendered
    assert "ai.hermes.kanban-broker" in rendered
    assert "hermes_cli.kanban_broker_service" in rendered
    assert "broker-service.json" in rendered
    assert "/usr/bin/sandbox-exec" in rendered
    assert "broker.sb" in rendered
    assert "GH_TOKEN" not in rendered
    assert "GITHUB_TOKEN" not in rendered
    worker_rendered = render_worker_launchd_plist(
        python_executable=Path("/usr/bin/python3"),
        python_sha256="1" * 64,
        package_root=tmp_path / "runtime/hermes_cli",
        package_manifest_sha256="2" * 64,
        worker_socket=tmp_path / "worker/worker.sock",
        workspace_root=tmp_path / "workspaces",
        broker_uid=401,
        workspace_gid=704,
        model_user="_hermesmodel",
        worker_hermes_root=tmp_path / "worker-home",
    )
    worker_payload = plistlib.loads(worker_rendered.encode("utf-8"))
    assert worker_payload["Label"] == "ai.hermes.kanban-worker"
    assert worker_payload["UserName"] == "_hermesmodel"
    assert worker_payload["RunAtLoad"] is True
    assert worker_payload["KeepAlive"] is True
    assert worker_payload["ProgramArguments"][
        worker_payload["ProgramArguments"].index("--package-root") + 1
    ] == str(tmp_path / "runtime/hermes_cli")
    assert (
        worker_payload["ProgramArguments"][
            worker_payload["ProgramArguments"].index("--package-manifest-sha256") + 1
        ]
        == "2" * 64
    )
    assert (
        worker_payload["ProgramArguments"][
            worker_payload["ProgramArguments"].index("--python-sha256") + 1
        ]
        == "1" * 64
    )
    assert worker_payload["ProgramArguments"][
        worker_payload["ProgramArguments"].index("--worker-hermes-root") + 1
    ] == str(tmp_path / "worker-home")
    assert worker_payload["EnvironmentVariables"]["HOME"] == str(
        tmp_path / "worker-home"
    )
    assert worker_payload["EnvironmentVariables"]["HERMES_HOME"] == str(
        tmp_path / "worker-home"
    )
    assert worker_payload["EnvironmentVariables"]["XDG_CONFIG_HOME"] == str(
        tmp_path / "worker-home/.config"
    )
    assert worker_payload["EnvironmentVariables"]["GNUPGHOME"] == str(
        tmp_path / "worker-home/.gnupg"
    )
    assert worker_payload["EnvironmentVariables"][
        "HERMES_KANBAN_CREDENTIAL_POLICY"
    ] == "github-denied-v1"
    assert "GH_TOKEN" not in worker_rendered
    profile = render_broker_seatbelt_profile(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        socket_dir=tmp_path,
    )
    assert '(deny network-outbound (remote ip "*:*"))' in profile
    assert '(deny network-bind (local ip "*:*"))' in profile
    assert str(tmp_path / "state") in profile
    validate_identity_separation(
        broker_uid=401,
        model_uid=501,
        controller_uid=402,
        publisher_uid=403,
    )
    with pytest.raises(ValueError, match="distinct"):
        validate_identity_separation(
            broker_uid=501,
            model_uid=501,
            controller_uid=402,
            publisher_uid=403,
        )

    validate_group_separation(
        broker_uid=401,
        model_uid=501,
        controller_uid=402,
        controller_gid=702,
        publisher_uid=403,
        publisher_gid=703,
        operator_uid=0,
        operator_gid=0,
        workspace_gid=701,
        memberships={
            401: {0, 701, 702, 703},
            501: {701},
            402: {702},
            403: {703},
            0: {0},
        },
    )
    with pytest.raises(ValueError, match="model.*publisher"):
        validate_group_separation(
            broker_uid=401,
            model_uid=501,
            controller_uid=402,
            controller_gid=702,
            publisher_uid=403,
            publisher_gid=703,
            operator_uid=0,
            operator_gid=0,
            workspace_gid=701,
            memberships={
                401: {0, 701, 702, 703},
                501: {701, 703},
                402: {702},
                403: {703},
                0: {0},
            },
        )
    with pytest.raises(ValueError, match="broker.*required group"):
        validate_group_separation(
            broker_uid=401,
            model_uid=501,
            controller_uid=402,
            controller_gid=702,
            publisher_uid=403,
            publisher_gid=703,
            operator_uid=404,
            operator_gid=704,
            workspace_gid=701,
            memberships={
                401: {701, 702, 704},
                501: {701},
                402: {702},
                403: {703},
                404: {704},
            },
        )


def test_worker_startup_binds_exact_installed_python_and_package():
    from hermes_cli.kanban_broker_install import runtime_package_manifest
    from hermes_cli.kanban_broker_worker import validate_worker_runtime

    package_root = Path(__file__).parents[2] / "hermes_cli"
    manifest = runtime_package_manifest(
        package_root,
        expected_owner_uid=os.getuid(),
    )
    python = Path(sys.executable).resolve(strict=True)
    python_sha = hashlib.sha256(python.read_bytes()).hexdigest()
    identity = validate_worker_runtime(
        python_executable=python,
        python_sha256=python_sha,
        package_root=package_root,
        package_manifest_sha256=manifest["sha256"],
        expected_package_owner_uid=os.getuid(),
        expected_python_owner_uid=python.stat().st_uid,
    )
    assert identity["package_manifest_sha256"] == manifest["sha256"]
    with pytest.raises(Exception, match="manifest"):
        validate_worker_runtime(
            python_executable=python,
            python_sha256=python_sha,
            package_root=package_root,
            package_manifest_sha256="0" * 64,
            expected_package_owner_uid=os.getuid(),
            expected_python_owner_uid=python.stat().st_uid,
        )


def test_socket_service_requires_client_group_traversable_dedicated_parents():
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerServiceError
    from hermes_cli.kanban_broker_service import BrokerSocketService

    class NoopBroker:
        def consume_rpc_request(self, **_kwargs):
            return None

    socket_root = Path(tempfile.mkdtemp(prefix="hkb-parent-", dir="/tmp"))
    unsafe_parent = socket_root / "unsafe"
    try:
        unsafe_parent.mkdir(mode=0o700)
        service = BrokerSocketService(
            surfaces={
                "operator": {
                    "path": unsafe_parent / "operator.sock",
                    "gid": os.getegid(),
                    "server": BrokerRPCServer(
                        broker=NoopBroker(),
                        surface="operator",
                        allowed_uid=os.geteuid(),
                        client_key=b"o" * 32,
                    ),
                }
            },
            broker_uid=os.geteuid(),
        )
        with pytest.raises(BrokerServiceError, match="socket parent"):
            service.start()
        service.close()

        _secure_socket_parent(unsafe_parent)
        working = BrokerSocketService(
            surfaces={
                "operator": {
                    "path": unsafe_parent / "operator.sock",
                    "gid": os.getegid(),
                    "server": BrokerRPCServer(
                        broker=NoopBroker(),
                        surface="operator",
                        allowed_uid=os.geteuid(),
                        client_key=b"o" * 32,
                    ),
                }
            },
            broker_uid=os.geteuid(),
        )
        working.start()
        working.close()
    finally:
        shutil.rmtree(socket_root)


def test_controller_rpc_requires_peer_uid_mac_and_rejects_nonce_replay(broker_fixture):
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_protocol import ProtocolError
    from hermes_cli.kanban_broker_protocol import signed_request

    broker, _source, _base = broker_fixture
    client_key = b"c" * 32
    server = BrokerRPCServer(
        broker=broker,
        surface="controller",
        allowed_uid=os.geteuid(),
        client_key=client_key,
    )
    request = signed_request(
        client_key,
        sequence=1,
        nonce="nonce-one",
        method="trusted_create",
        body=_request(idempotency_key="radulator:rpc:v1"),
    )
    response = server.dispatch(peer_uid=os.geteuid(), message=request)
    assert response["ok"] is True
    with pytest.raises(ProtocolError, match="replay"):
        server.dispatch(peer_uid=os.geteuid(), message=request)
    wrong = signed_request(
        b"x" * 32,
        sequence=2,
        nonce="nonce-two",
        method="trusted_create",
        body=_request(idempotency_key="radulator:rpc-wrong:v1"),
    )
    with pytest.raises(ProtocolError, match="authentication"):
        server.dispatch(peer_uid=os.geteuid(), message=wrong)
    fresh = signed_request(
        client_key,
        sequence=3,
        nonce="nonce-three",
        method="trusted_create",
        body=_request(idempotency_key="radulator:rpc-peer:v1"),
    )
    with pytest.raises(ProtocolError, match="peer"):
        server.dispatch(peer_uid=os.geteuid() + 1, message=fresh)
    malformed = signed_request(
        client_key,
        sequence=4,
        nonce="nonce-four",
        method="trusted_create",
        body=["not", "an", "object"],
    )
    with pytest.raises(ProtocolError, match="body"):
        server.dispatch(peer_uid=os.geteuid(), message=malformed)


def test_publish_correction_rpc_is_controller_only_and_reseals_exact_task(
    broker_fixture,
):
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_protocol import ProtocolError
    from hermes_cli.kanban_broker_protocol import signed_request

    broker, _source, _base = broker_fixture
    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_request(idempotency_key="radulator:correction-rpc:v1"),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    Path(claim["workspace_path"], "rpc-correction.txt").write_text(
        "first\n", encoding="utf-8"
    )
    event = broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id="correction-rpc-operation",
        untrusted_worker_result={},
    )
    body = {
        "contract": "hermes.publisher_correction_request.v1",
        "receipt_id": event["receipt_id"],
        "receipt_payload_sha256": event["payload_sha256"],
        "reason_code": "ci_failed",
    }
    controller_key = b"c" * 32
    controller = BrokerRPCServer(
        broker=broker,
        surface="controller",
        allowed_uid=os.geteuid(),
        client_key=controller_key,
    )
    response = controller.dispatch(
        peer_uid=os.geteuid(),
        message=signed_request(
            controller_key,
            sequence=1,
            nonce="correction-controller",
            method="request_publish_correction",
            body=body,
        ),
    )
    assert response["ok"] is True
    assert response["result"]["task_id"] == created["task_id"]
    assert response["result"]["status"] == "ready"

    publisher_key = b"p" * 32
    publisher = BrokerRPCServer(
        broker=broker,
        surface="publisher",
        allowed_uid=os.geteuid(),
        client_key=publisher_key,
    )
    with pytest.raises(ProtocolError, match="unavailable"):
        publisher.dispatch(
            peer_uid=os.geteuid(),
            message=signed_request(
                publisher_key,
                sequence=1,
                nonce="correction-publisher",
                method="request_publish_correction",
                body=body,
            ),
        )


def test_real_unix_service_and_persistent_client_execute_reviewed_rpc_surface(
    broker_fixture,
):
    """Catch an RPC dispatcher that has no real accept loop or usable client."""
    from hermes_cli.kanban_broker_client import BrokerRPCClient
    from hermes_cli.kanban_broker_client import BrokerRPCError
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerSocketService

    broker, _source, _base = broker_fixture
    socket_root = _secure_socket_parent(
        Path(tempfile.mkdtemp(prefix="hkb-rpc-", dir="/tmp"))
    )
    controller_socket = socket_root / "controller.sock"
    worker_socket = socket_root / "worker.sock"
    client_key = b"r" * 32
    server = BrokerRPCServer(
        broker=broker,
        surface="controller",
        allowed_uid=os.geteuid(),
        client_key=client_key,
        worker_socket=worker_socket,
    )
    service = BrokerSocketService(
        surfaces={
            "controller": {
                "path": controller_socket,
                "server": server,
                "gid": os.getegid(),
            }
        },
        broker_uid=os.geteuid(),
    )
    service.start()
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        sequence_path = socket_root / "controller.sequence"
        client = BrokerRPCClient(
            socket_path=controller_socket,
            expected_broker_uid=os.geteuid(),
            client_key=client_key,
            sequence_path=sequence_path,
        )
        result = client.call(
            "trusted_create",
            _request(idempotency_key="radulator:real-rpc:v1"),
        )
        assert result["task_id"].startswith("t_")
        assert stat.S_IMODE(sequence_path.stat().st_mode) == 0o600

        restarted_client = BrokerRPCClient(
            socket_path=controller_socket,
            expected_broker_uid=os.geteuid(),
            client_key=client_key,
            sequence_path=sequence_path,
        )
        reused = restarted_client.call(
            "trusted_create",
            _request(idempotency_key="radulator:real-rpc:v1"),
        )
        assert reused["task_id"] == result["task_id"]
        assert reused["reused"] is True

        worker_ready = threading.Event()

        def worker() -> None:
            from hermes_cli.kanban_broker_protocol import receive_frame, send_frame

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(worker_socket))
            os.chmod(worker_socket, 0o600)
            listener.listen(1)
            worker_ready.set()
            conn, _ = listener.accept()
            with conn:
                envelope = receive_frame(conn)
                assert not Path(envelope["workspace_path"], ".git").exists()
                Path(envelope["workspace_path"], "service-worker.txt").write_text(
                    "service worker bytes\n", encoding="utf-8"
                )
                send_frame(
                    conn,
                    {
                        "contract": "hermes.worker_turn_complete.v1",
                        "summary": "untrusted",
                    },
                )
            listener.close()

        worker_thread = threading.Thread(target=worker, daemon=True)
        worker_thread.start()
        assert worker_ready.wait(5)
        accepted = restarted_client.call(
            "dispatch_task",
            {
                "task_id": result["task_id"],
                "operation_id": "real-service-operation",
            },
        )
        assert accepted["contract"] == "hermes.broker_dispatch_operation.v1"
        assert accepted["state"] == "CLAIMED"
        assert accepted["terminal"] is False
        assert accepted["timeout_seconds"] == 2700
        replay = restarted_client.call(
            "dispatch_task",
            {
                "task_id": result["task_id"],
                "operation_id": "real-service-operation",
            },
        )
        assert replay["operation_id"] == accepted["operation_id"]
        worker_thread.join(timeout=5)
        assert not worker_thread.is_alive()
        deadline = time.monotonic() + 5
        while True:
            status = restarted_client.call(
                "dispatch_status", {"operation_id": "real-service-operation"}
            )
            if status["terminal"]:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status["state"] == "SUCCEEDED"
        event = status["event"]
        assert event["contract"] == "hermes.trusted_local_commit.v1"
        assert event["changed_paths"] == ["service-worker.txt"]
        terminal_replay = restarted_client.call(
            "dispatch_task",
            {
                "task_id": result["task_id"],
                "operation_id": "real-service-operation",
            },
        )
        assert terminal_replay == {
            key: value for key, value in status.items() if key != "verified"
        }
        with pytest.raises(BrokerRPCError, match="fields"):
            restarted_client.call(
                "dispatch_task",
                {
                    "task_id": result["task_id"],
                    "operation_id": "attacker-operation",
                    "worker_socket": "/tmp/attacker.sock",
                },
            )
    finally:
        service.stop()
        thread.join(timeout=5)
        service.close()
        shutil.rmtree(socket_root)
    assert not thread.is_alive()


def test_rpc_disconnect_during_error_response_does_not_crash_service_handler(
    broker_fixture,
):
    """An authenticated surface must survive a client that resets mid-response."""
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer

    broker, _source, _base = broker_fixture
    server = BrokerRPCServer(
        broker=broker,
        surface="controller",
        allowed_uid=os.geteuid(),
        client_key=b"d" * 32,
    )
    service_side, client_side = socket.socketpair()
    try:
        client_side.sendall(b"\x00\x00\x00\x02{}")
        client_side.shutdown(socket.SHUT_RDWR)
        client_side.close()
        server.handle_connection(service_side)
    finally:
        service_side.close()
        client_side.close()


def test_operator_client_quiesces_real_service_before_rollback(broker_fixture):
    """Catch rollback plans that stop launchd without broker protocol quiescence."""
    from hermes_cli.kanban_broker_client import main as broker_client_main
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerSocketService

    broker, _source, _base = broker_fixture
    socket_root = _secure_socket_parent(
        Path(tempfile.mkdtemp(prefix="hkb-quiesce-", dir="/tmp"))
    )
    operator_socket = socket_root / "operator.sock"
    operator_key = b"q" * 32
    service = BrokerSocketService(
        surfaces={
            "operator": {
                "path": operator_socket,
                "server": BrokerRPCServer(
                    broker=broker,
                    surface="operator",
                    allowed_uid=os.geteuid(),
                    client_key=operator_key,
                ),
                "gid": os.getegid(),
            }
        },
        broker_uid=os.geteuid(),
    )
    service.start()
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        key_path = socket_root / "operator.key"
        key_path.write_bytes(operator_key)
        key_path.chmod(0o640)
        config_path = socket_root / "operator-client.json"
        config_path.write_text(
            json.dumps({
                "contract": "hermes.kanban_broker_client_config.v1",
                "surface": "operator",
                "socket_path": str(operator_socket),
                "expected_broker_uid": os.geteuid(),
                "key_path": str(key_path),
                "sequence_path": str(socket_root / "operator.sequence"),
            }),
            encoding="utf-8",
        )
        config_path.chmod(0o600)
        assert broker_client_main(["quiesce", "--config", str(config_path)]) == 0
        assert thread.is_alive()
        service.stop()
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        service.stop()
        thread.join(timeout=5)
        service.close()
        shutil.rmtree(socket_root)


def test_quiesce_is_responsive_rejects_new_dispatch_and_reports_inflight(tmp_path):
    from hermes_cli.kanban_broker_client import BrokerRPCClient
    from hermes_cli.kanban_broker_client import BrokerRPCError
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerSocketService

    class BlockingBroker:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()

        def consume_rpc_request(self, **_kwargs):
            return None

        def begin_dispatch(self, *, task_id, operation_id):
            return {
                "contract": "hermes.broker_dispatch_operation.v1",
                "operation_id": operation_id,
                "task_id": task_id,
                "run_id": 1,
                "state": "CLAIMED",
                "terminal": False,
                "start_required": True,
            }

        def perform_dispatch(self, **_kwargs):
            self.started.set()
            assert self.release.wait(5)
            return {
                "contract": "hermes.broker_dispatch_operation.v1",
                "state": "SUCCEEDED",
                "terminal": True,
            }

        def trusted_create(self, **_kwargs):
            return {"task_id": "unexpected"}

        def request_publish_correction(self, **_kwargs):
            return {"outcome": "unexpected"}

        def export_publish_bundle(self, **_kwargs):
            return {"outcome": "unexpected"}

        def refresh_repository_base(self, **_kwargs):
            return {"outcome": "unexpected"}

    broker = BlockingBroker()
    socket_root = Path(tempfile.mkdtemp(prefix="hkb-quiesce-long-", dir="/tmp"))
    controller_root = socket_root / "controller"
    operator_root = socket_root / "operator"
    publisher_root = socket_root / "publisher"
    controller_root.mkdir()
    operator_root.mkdir()
    publisher_root.mkdir()
    _secure_socket_parent(controller_root)
    _secure_socket_parent(operator_root)
    _secure_socket_parent(publisher_root)
    controller_socket = controller_root / "controller.sock"
    operator_socket = operator_root / "operator.sock"
    publisher_socket = publisher_root / "publisher.sock"
    controller_key = b"c" * 32
    operator_key = b"o" * 32
    publisher_key = b"p" * 32
    service = BrokerSocketService(
        surfaces={
            "controller": {
                "path": controller_socket,
                "gid": os.getegid(),
                "server": BrokerRPCServer(
                    broker=broker,
                    surface="controller",
                    allowed_uid=os.geteuid(),
                    client_key=controller_key,
                    worker_socket=socket_root / "worker.sock",
                ),
            },
            "operator": {
                "path": operator_socket,
                "gid": os.getegid(),
                "server": BrokerRPCServer(
                    broker=broker,
                    surface="operator",
                    allowed_uid=os.geteuid(),
                    client_key=operator_key,
                ),
            },
            "publisher": {
                "path": publisher_socket,
                "gid": os.getegid(),
                "server": BrokerRPCServer(
                    broker=broker,
                    surface="publisher",
                    allowed_uid=os.geteuid(),
                    client_key=publisher_key,
                ),
            },
        },
        broker_uid=os.geteuid(),
        max_inflight=4,
    )
    service.start()
    serving = threading.Thread(target=service.serve_forever, daemon=True)
    serving.start()
    controller = BrokerRPCClient(
        socket_path=controller_socket,
        expected_broker_uid=os.geteuid(),
        client_key=controller_key,
        sequence_path=socket_root / "controller.sequence",
        timeout_seconds=2,
    )
    operator = BrokerRPCClient(
        socket_path=operator_socket,
        expected_broker_uid=os.geteuid(),
        client_key=operator_key,
        sequence_path=socket_root / "operator.sequence",
        timeout_seconds=0.5,
    )
    publisher = BrokerRPCClient(
        socket_path=publisher_socket,
        expected_broker_uid=os.geteuid(),
        client_key=publisher_key,
        sequence_path=socket_root / "publisher.sequence",
        timeout_seconds=0.5,
    )
    result: dict[str, object] = {}

    def dispatch() -> None:
        result.update(
            controller.call(
                "dispatch_task",
                {"task_id": "t_exact", "operation_id": "op_exact"},
            )
        )

    dispatch_thread = threading.Thread(target=dispatch, daemon=True)
    dispatch_thread.start()
    try:
        assert broker.started.wait(2)
        started = time.monotonic()
        quiesce = operator.call(
            "quiesce",
            {
                "contract": "hermes.kanban_broker_quiesce.v1",
                "reason": "test",
            },
        )
        assert time.monotonic() - started < 0.5
        assert quiesce["quiescing"] is True
        status = operator.call(
            "quiesce_status",
            {"contract": "hermes.kanban_broker_quiesce_status.v1"},
        )
        assert status["inflight"] >= 1
        with pytest.raises(BrokerRPCError, match="quiescing"):
            controller.call("trusted_create", _request())
        with pytest.raises(BrokerRPCError, match="quiescing"):
            controller.call(
                "request_publish_correction",
                {
                    "contract": "hermes.publisher_correction_request.v1",
                    "receipt_id": "receipt",
                    "receipt_payload_sha256": "0" * 64,
                    "reason_code": "ci_failed",
                },
            )
        with pytest.raises(BrokerRPCError, match="quiescing"):
            publisher.call(
                "export_bundle",
                {"receipt_id": "receipt", "payload_sha256": "0" * 64},
            )
        with pytest.raises(BrokerRPCError, match="quiescing"):
            operator.call(
                "refresh_repository_base",
                {"repository_id": "radulator", "expected_old_base_sha": "0" * 40},
            )
    finally:
        broker.release.set()
        dispatch_thread.join(timeout=3)
        service.stop()
        serving.join(timeout=3)
        service.close()
        shutil.rmtree(socket_root)
    assert result["contract"] == "hermes.broker_dispatch_operation.v1"
    assert result["state"] == "CLAIMED"


def test_operator_quiesce_waits_for_zero_inflight_and_times_out(monkeypatch, tmp_path):
    from hermes_cli.kanban_broker_client import BrokerRPCError
    from hermes_cli.kanban_broker_client import quiesce_and_wait

    class FakeClient:
        def __init__(self, statuses):
            self.statuses = iter(statuses)
            self.methods = []

        def call(self, method, body):
            self.methods.append((method, body))
            if method == "quiesce":
                return {"quiescing": True, "inflight": 1}
            return next(self.statuses)

    client = FakeClient([
        {"quiescing": True, "inflight": 1},
        {"quiescing": True, "inflight": 0},
    ])
    monkeypatch.setattr("hermes_cli.kanban_broker_client.time.sleep", lambda _s: None)
    result = quiesce_and_wait(client, wait_seconds=2, poll_seconds=0.01)
    assert result == {"quiescing": True, "inflight": 0}
    assert [method for method, _body in client.methods] == [
        "quiesce",
        "quiesce_status",
        "quiesce_status",
    ]

    timed_out = FakeClient([{"quiescing": True, "inflight": 1}] * 20)
    ticks = iter([0.0, 0.0, 2.0])
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.time.monotonic", lambda: next(ticks)
    )
    with pytest.raises(BrokerRPCError, match="in-flight"):
        quiesce_and_wait(timed_out, wait_seconds=1, poll_seconds=0)


def test_install_assets_are_disabled_first_and_rollback_uses_reviewed_modules(
    tmp_path,
):
    """Catch activation by rendering and rollback through ad-hoc shell surfaces."""
    from hermes_cli.kanban_broker_install import render_broker_service_config
    from hermes_cli.kanban_broker_install import render_rollback_plan
    from hermes_cli.kanban_broker_install import disable_service_config
    from hermes_cli.kanban_broker_install import verify_service_disabled
    from hermes_cli.kanban_broker_service import BrokerServiceDisabled
    from hermes_cli.kanban_broker_service import require_enabled_service_config

    config_path = tmp_path / "broker-service.json"
    rendered = render_broker_service_config(
        install_root=tmp_path,
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        worker_hermes_root=tmp_path / "worker-home",
        publisher_handoff_root=tmp_path / "publisher-handoffs",
        controller_socket=tmp_path / "controller.sock",
        publisher_socket=tmp_path / "publisher.sock",
        operator_socket=tmp_path / "operator.sock",
        worker_socket=tmp_path / "worker.sock",
        controller_key_path=tmp_path / "controller.key",
        publisher_key_path=tmp_path / "publisher.key",
        operator_key_path=tmp_path / "operator.key",
        broker_uid=os.geteuid(),
        broker_gid=os.getegid(),
        model_uid=os.geteuid() + 1,
        controller_uid=os.geteuid() + 2,
        controller_gid=402,
        publisher_uid=os.geteuid() + 3,
        publisher_gid=403,
        operator_uid=0,
        operator_gid=0,
        workspace_gid=501,
        trusted_publisher_enabled=False,
        package_root=tmp_path / "installed-runtime/hermes_cli",
        package_manifest_sha256="a" * 64,
        canary_key_path=tmp_path / "canary/canary.key",
        seatbelt_profile_path=tmp_path / "state/broker.sb",
        launchd_plist_path=tmp_path / "launchd/ai.hermes.kanban-broker.plist",
        worker_launchd_plist_path=tmp_path / "launchd/ai.hermes.kanban-worker.plist",
    )
    config = json.loads(rendered)
    assert config["contract"] == "hermes.kanban_broker_service_config.v1"
    assert config["broker_boundary"] == "hermes.dedicated_broker_identity.v1"
    assert config["enabled"] is False
    assert config["trusted_publisher_enabled"] is False
    assert config["worker_hermes_root"] == str(tmp_path / "worker-home")
    with pytest.raises(BrokerServiceDisabled):
        require_enabled_service_config(config)

    activated = dict(config)
    activated["enabled"] = True
    activated["trusted_publisher_enabled"] = True
    config_path.write_text(json.dumps(activated), encoding="utf-8")
    config_path.chmod(0o600)
    disabled = disable_service_config(
        config_path,
        expected_owner_uid=os.geteuid(),
    )
    assert disabled["enabled"] is False
    assert disabled["trusted_publisher_enabled"] is False
    assert (
        verify_service_disabled(
            config_path,
            expected_owner_uid=os.geteuid(),
        )
        is True
    )
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    symlink = tmp_path / "config-link.json"
    symlink.symlink_to(config_path)
    with pytest.raises(ValueError, match="real file"):
        disable_service_config(symlink, expected_owner_uid=os.geteuid())

    rollback = render_rollback_plan(
        python_executable=Path("/usr/bin/python3"),
        operator_client_config=tmp_path / "operator-client.json",
        service_config=config_path,
    )
    assert rollback == {
        "quiesce": [
            "/usr/bin/python3",
            "-m",
            "hermes_cli.kanban_broker_client",
            "quiesce",
            "--config",
            str(tmp_path / "operator-client.json"),
        ],
        "bootout": [
            "/bin/launchctl",
            "bootout",
            "system/ai.hermes.kanban-broker",
        ],
        "disable_config": [
            "/usr/bin/python3",
            "-m",
            "hermes_cli.kanban_broker_install",
            "disable",
            "--config",
            str(config_path),
        ],
        "assert_disabled": [
            "/usr/bin/python3",
            "-m",
            "hermes_cli.kanban_broker_install",
            "verify-disabled",
            "--config",
            str(config_path),
        ],
    }


def test_identity_and_filesystem_provision_plans_include_broker_groups_and_assets(
    tmp_path,
):
    from hermes_cli.kanban_broker_install import render_filesystem_provision_plan
    from hermes_cli.kanban_broker_install import render_runtime_package_assets
    from hermes_cli.kanban_broker_install import render_identity_provision_commands
    from hermes_cli.kanban_broker_install import render_identity_provision_plan

    identities = render_identity_provision_plan(
        broker_user="_hermesbroker",
        broker_uid=401,
        broker_gid=701,
        controller_user="_hermescontroller",
        controller_uid=402,
        controller_group="_hermescontroller",
        controller_gid=702,
        publisher_user="_hermespublisher",
        publisher_uid=403,
        publisher_group="_hermespublisher",
        publisher_gid=703,
        operator_user="root",
        operator_uid=0,
        operator_group="wheel",
        operator_gid=0,
        model_user="_hermesmodel",
        model_uid=501,
        workspace_group="_hermesworkspace",
        workspace_gid=704,
    )
    assert identities["contract"] == "hermes.kanban_broker_identity_plan.v1"
    memberships = {tuple(item) for item in identities["memberships"]}
    assert ("_hermesbroker", "_hermescontroller") in memberships
    assert ("_hermesbroker", "_hermespublisher") in memberships
    assert ("_hermesbroker", "wheel") in memberships
    assert ("_hermesbroker", "_hermesworkspace") in memberships
    assert ("_hermesmodel", "_hermesworkspace") in memberships
    assert ["_hermesmodel", 501, 704] in identities["users"]
    commands = render_identity_provision_commands(identities)
    assert ["/usr/bin/dscl", ".", "-create", "/Groups/_hermesbroker"] in commands
    assert [
        "/usr/sbin/dseditgroup",
        "-o",
        "edit",
        "-a",
        "_hermesbroker",
        "-t",
        "user",
        "_hermesworkspace",
    ] in commands
    assert all(isinstance(command, list) for command in commands)

    runtime_assets = render_runtime_package_assets(
        source_root=Path(__file__).parents[2] / "hermes_cli",
        destination_root=tmp_path / "runtime/hermes_cli",
    )
    config = {
        "install_root": str(tmp_path),
        "state_dir": str(tmp_path / "state"),
        "workspace_root": str(tmp_path / "workspaces"),
        "worker_hermes_root": str(tmp_path / "worker-home"),
        "publisher_handoff_root": str(tmp_path / "handoff"),
        "controller_socket": str(tmp_path / "sockets/controller/controller.sock"),
        "publisher_socket": str(tmp_path / "sockets/publisher/publisher.sock"),
        "operator_socket": str(tmp_path / "sockets/operator/operator.sock"),
        "worker_socket": str(tmp_path / "sockets/worker/worker.sock"),
        "controller_key_path": str(tmp_path / "keys/controller/controller.key"),
        "publisher_key_path": str(tmp_path / "keys/publisher/publisher.key"),
        "operator_key_path": str(tmp_path / "keys/operator/operator.key"),
        "broker_uid": 401,
        "broker_gid": 701,
        "model_uid": 501,
        "controller_uid": 402,
        "controller_gid": 702,
        "publisher_uid": 403,
        "publisher_gid": 703,
        "operator_uid": 0,
        "operator_gid": 0,
        "workspace_gid": 704,
        "canary_key_path": str(tmp_path / "canary/canary.key"),
        "package_root": str(tmp_path / "runtime/hermes_cli"),
        "package_manifest_sha256": runtime_assets["package_manifest_sha256"],
    }
    assets = render_filesystem_provision_plan(
        config=config,
        service_config_path=tmp_path / "config/service.json",
        seatbelt_profile_path=tmp_path / "config/broker.sb",
        launchd_plist_path=tmp_path / "launchd/ai.hermes.kanban-broker.plist",
        worker_launchd_plist_path=tmp_path / "launchd/ai.hermes.kanban-worker.plist",
        client_config_paths={
            "controller": tmp_path / "clients/controller/client.json",
            "publisher": tmp_path / "clients/publisher/client.json",
            "operator": tmp_path / "clients/operator/client.json",
        },
        sequence_paths={
            "controller": tmp_path / "sequences/controller/client.sequence",
            "publisher": tmp_path / "sequences/publisher/client.sequence",
            "operator": tmp_path / "sequences/operator/client.sequence",
        },
        runtime_assets=runtime_assets,
    )
    by_path = {item["path"]: item for item in assets["directories"]}
    assert by_path[str(tmp_path)] == {
        "path": str(tmp_path),
        "uid": 0,
        "gid": 0,
        "mode": 0o711,
    }
    for root_parent in (tmp_path / "runtime", tmp_path / "sockets", tmp_path / "keys"):
        assert by_path[str(root_parent)] == {
            "path": str(root_parent),
            "uid": 0,
            "gid": 0,
            "mode": 0o711,
        }
    for surface, gid in (("controller", 702), ("publisher", 703), ("operator", 0)):
        item = by_path[str(tmp_path / f"sockets/{surface}")]
        assert item == {
            "path": str(tmp_path / f"sockets/{surface}"),
            "uid": 401,
            "gid": gid,
            "mode": 0o710,
        }
        assert by_path[str(tmp_path / f"keys/{surface}")] == {
            "path": str(tmp_path / f"keys/{surface}"),
            "uid": 401,
            "gid": gid,
            "mode": 0o710,
        }
    worker = by_path[str(tmp_path / "sockets/worker")]
    assert worker == {
        "path": str(tmp_path / "sockets/worker"),
        "uid": 501,
        "gid": 704,
        "mode": 0o710,
    }
    assert by_path[str(tmp_path / "worker-home")] == {
        "path": str(tmp_path / "worker-home"),
        "uid": 501,
        "gid": 704,
        "mode": 0o700,
    }


def test_activation_is_bound_to_fresh_complete_root_canary_attestation(
    monkeypatch, tmp_path
):
    from hermes_cli.kanban_broker_install import ACTIVATION_CANARY_CHECKS
    from hermes_cli.kanban_broker_install import activate_service_config
    from hermes_cli.kanban_broker_install import generate_activation_attestation

    config_path = tmp_path / "broker.json"
    config = {
        "contract": "hermes.kanban_broker_service_config.v1",
        "broker_boundary": "hermes.dedicated_broker_identity.v1",
        "enabled": True,
        "trusted_publisher_enabled": False,
        "install_nonce": "install-nonce-exact",
        "broker_uid": os.geteuid(),
        "canary_key_path": str(tmp_path / "canary.key"),
        "package_root": str(Path(__file__).parents[2] / "hermes_cli"),
    }
    config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    now = 1_800_000_000
    runtime_identity = {
        "python_executable": "/usr/bin/python3",
        "python_sha256": "1" * 64,
        "git_executable": "/usr/bin/git",
        "git_sha256": "2" * 64,
        "package_root": "/Library/HermesBroker/hermes_cli",
        "package_manifest_sha256": "3" * 64,
    }
    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_install.validate_runtime_identity",
        lambda *_args, **_kwargs: runtime_identity,
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_install._read_canary_key",
        lambda _path: b"k" * 32,
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_canary.run_activation_canaries",
        lambda _config: {
            name: {"outcome": "PASS", "detail": "observed"}
            for name in ACTIVATION_CANARY_CHECKS
        },
    )
    attestation = generate_activation_attestation(
        service_config_path=config_path,
        expected_owner_uid=os.getuid(),
        now=now,
    )
    assert attestation["runner_path"] == str(
        Path(config["package_root"]) / "kanban_broker_canary.py"
    )
    activated = activate_service_config(
        config_path,
        expected_owner_uid=os.getuid(),
        attestation=attestation,
        now=now + 5,
    )
    assert activated["enabled"] is True
    assert activated["trusted_publisher_enabled"] is True

    disabled = dict(config)
    disabled["enabled"] = True
    config_path.write_text(
        json.dumps(disabled, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    incomplete = {
        "contract": "hermes.kanban_broker_activation_canary.v1",
        "broker_boundary": "hermes.dedicated_broker_identity.v1",
        "service_config_sha256": "0" * 64,
        "install_nonce": "install-nonce-exact",
        "issued_at": now,
        "checks": {name: True for name in ACTIVATION_CANARY_CHECKS},
    }
    with pytest.raises(ValueError, match="canary"):
        activate_service_config(
            config_path,
            expected_owner_uid=os.getuid(),
            attestation=incomplete,
            now=now + 5,
        )
    stale = dict(attestation)
    with pytest.raises(ValueError, match="stale"):
        activate_service_config(
            config_path,
            expected_owner_uid=os.getuid(),
            attestation=stale,
            now=now + 3600,
        )
    forged_runner = tmp_path / "forged-canary.py"
    forged_runner.write_text("# not the installed runner\n", encoding="utf-8")
    outside = dict(attestation)
    outside["runner_path"] = str(forged_runner)
    outside["runner_sha256"] = hashlib.sha256(forged_runner.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="runner.*installed package"):
        activate_service_config(
            config_path,
            expected_owner_uid=os.getuid(),
            attestation=outside,
            now=now + 5,
        )
    assert (
        json.loads(config_path.read_text(encoding="utf-8"))["trusted_publisher_enabled"]
        is False
    )


def test_root_canary_distinguishes_missing_and_error_from_permission_denial(
    monkeypatch, tmp_path
):
    from hermes_cli.kanban_broker_canary import cross_uid_read_denied

    monkeypatch.setattr("hermes_cli.kanban_broker_canary.os.geteuid", lambda: 0)
    with pytest.raises(RuntimeError, match="MISSING"):
        cross_uid_read_denied(
            tmp_path / "missing-authority-key",
            model_uid=os.getuid(),
            model_gid=os.getgid(),
        )


def test_credential_scrub_canary_uses_a_complete_sealed_worker_envelope(tmp_path):
    import plistlib

    from hermes_cli.kanban_broker_canary import _credential_scrub_check

    plist = tmp_path / "worker.plist"
    plist.write_bytes(
        plistlib.dumps(
            {"EnvironmentVariables": {"PATH": "/usr/bin:/bin"}},
            fmt=plistlib.FMT_XML,
        )
    )
    workspace = tmp_path / "workspaces" / "canary"
    workspace.mkdir(parents=True)
    worker_home = tmp_path / "worker-home"
    worker_home.mkdir(mode=0o700)
    assert (
        _credential_scrub_check({
            "launchd_plist_path": str(plist),
            "worker_launchd_plist_path": str(plist),
            "workspace_root": str(workspace.parent),
            "worker_hermes_root": str(worker_home),
            "model_uid": os.geteuid(),
        })
        is True
    )


def test_runtime_identity_rejects_mutable_package_even_with_matching_digest(tmp_path):
    from hermes_cli.kanban_broker_install import runtime_package_manifest

    package = tmp_path / "hermes_cli"
    package.mkdir(mode=0o755)
    module = package / "broker.py"
    module.write_text("BOUNDARY = 1\n", encoding="utf-8")
    module.chmod(0o664)
    with pytest.raises(ValueError, match="mutable"):
        runtime_package_manifest(package, expected_owner_uid=os.getuid())


def test_runtime_package_manifest_excludes_interpreter_bytecode_caches(tmp_path):
    from hermes_cli.kanban_broker_install import runtime_package_manifest

    package = tmp_path / "hermes_cli"
    package.mkdir(mode=0o755)
    (package / "broker.py").write_text("BOUNDARY = 1\n", encoding="utf-8")
    before = runtime_package_manifest(package, expected_owner_uid=os.getuid())

    cache = package / "__pycache__"
    cache.mkdir(mode=0o755)
    (cache / "broker.cpython-311.pyc").write_bytes(b"volatile bytecode")
    after = runtime_package_manifest(package, expected_owner_uid=os.getuid())

    assert after == before


def test_disabled_asset_provision_is_idempotent_and_symlink_safe(monkeypatch, tmp_path):
    from hermes_cli.kanban_broker_install import provision_filesystem_plan
    from hermes_cli.kanban_broker_install import render_broker_client_config

    owner = os.getuid()
    group = os.getgid()
    parent = tmp_path / "private"
    target = parent / "controller.json"
    plan = {
        "contract": "hermes.kanban_broker_filesystem_plan.v1",
        "directories": [
            {"path": str(parent), "uid": owner, "gid": group, "mode": 0o700}
        ],
        "files": [
            {
                "path": str(target),
                "uid": owner,
                "gid": group,
                "mode": 0o600,
                "kind": "controller_client_config",
            }
        ],
    }
    payload = render_broker_client_config(
        surface="controller",
        socket_path=tmp_path / "controller.sock",
        expected_broker_uid=401,
        key_path=tmp_path / "controller.key",
        sequence_path=tmp_path / "controller.sequence",
    ).encode("utf-8")
    assert b"client_key" not in payload
    assert b"GH_TOKEN" not in payload
    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    provision_filesystem_plan(plan, payloads={str(target): payload})
    provision_filesystem_plan(plan, payloads={str(target): payload})
    assert target.read_bytes() == payload
    assert stat.S_IMODE(target.stat().st_mode) == 0o600

    target.unlink()
    target.symlink_to(tmp_path / "attacker")
    with pytest.raises(ValueError, match="real file"):
        provision_filesystem_plan(plan, payloads={str(target): payload})


def test_disabled_install_transaction_proves_both_launchd_labels_disabled(
    monkeypatch, tmp_path
):
    from hermes_cli.kanban_broker_install import provision_disabled_install

    owner = os.getuid()
    group = os.getgid()
    config_path = tmp_path / "private" / "service.json"
    config = {
        "contract": "hermes.kanban_broker_service_config.v1",
        "broker_boundary": "hermes.dedicated_broker_identity.v1",
        "enabled": False,
        "trusted_publisher_enabled": False,
        "broker_uid": owner,
    }
    payload = (json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    plan = {
        "contract": "hermes.kanban_broker_filesystem_plan.v1",
        "directories": [
            {
                "path": str(config_path.parent),
                "uid": owner,
                "gid": group,
                "mode": 0o700,
            }
        ],
        "files": [
            {
                "path": str(config_path),
                "uid": owner,
                "gid": group,
                "mode": 0o600,
                "kind": "service_config",
            }
        ],
    }
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["print", "system/ai.hermes.kanban-broker"] or argv[1:3] == [
            "print",
            "system/ai.hermes.kanban-worker",
        ]:
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                'disabled services = {\n\t"ai.hermes.kanban-broker" => true\n'
                '\t"ai.hermes.kanban-worker" => true\n}\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    provision_disabled_install(
        plan,
        payloads={str(config_path): payload},
        service_config_path=config_path,
        runner=runner,
    )
    assert json.loads(config_path.read_text(encoding="utf-8"))["enabled"] is False
    assert [
        "/bin/launchctl",
        "disable",
        "system/ai.hermes.kanban-broker",
    ] in calls
    assert [
        "/bin/launchctl",
        "disable",
        "system/ai.hermes.kanban-worker",
    ] in calls
    assert ["/bin/launchctl", "print-disabled", "system"] in calls

    loaded_calls: list[list[str]] = []

    def loaded_runner(argv, **kwargs):
        loaded_calls.append(list(argv))
        if argv[1:3] == ["print", "system/ai.hermes.kanban-broker"]:
            return subprocess.CompletedProcess(argv, 0, "loaded", "")
        return subprocess.CompletedProcess(argv, 113, "", "not found")

    with pytest.raises(ValueError, match="already loaded"):
        provision_disabled_install(
            plan,
            payloads={str(config_path): payload},
            service_config_path=config_path,
            runner=loaded_runner,
        )
    assert not any("disable" in item for call in loaded_calls for item in call)


def test_activation_bootstrap_failure_restores_exact_disabled_state(
    monkeypatch, tmp_path
):
    from hermes_cli.kanban_broker_install import activate_installation

    owner = os.getuid()
    config_path = tmp_path / "service.json"
    config = {
        "contract": "hermes.kanban_broker_service_config.v1",
        "broker_boundary": "hermes.dedicated_broker_identity.v1",
        "enabled": False,
        "trusted_publisher_enabled": False,
        "install_nonce": "bootstrap-failure",
        "broker_uid": owner,
        "operator_uid": 0,
    }
    config_path.write_text(
        json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    calls = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if "bootstrap" in argv:
            raise subprocess.CalledProcessError(1, argv)
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    with pytest.raises(subprocess.CalledProcessError):
        activate_installation(
            service_config_path=config_path,
            expected_owner_uid=owner,
            launchd_plist_path=tmp_path / "ai.hermes.kanban-broker.plist",
            worker_launchd_plist_path=tmp_path / "ai.hermes.kanban-worker.plist",
            operator_client_config=tmp_path / "operator.json",
            now=1_800_000_005,
            runner=runner,
        )
    reread = json.loads(config_path.read_text(encoding="utf-8"))
    assert reread["enabled"] is False
    assert reread["trusted_publisher_enabled"] is False
    assert any("bootout" in argv for argv in calls)


def test_activation_failure_disables_before_bootout_and_proves_safe_state(
    monkeypatch, tmp_path
):
    """Catch KeepAlive races and unverified best-effort activation cleanup."""
    from hermes_cli.kanban_broker_install import activate_installation

    owner = os.getuid()
    config_path = tmp_path / "service.json"
    config_path.write_text(
        json.dumps({
            "contract": "hermes.kanban_broker_service_config.v1",
            "broker_boundary": "hermes.dedicated_broker_identity.v1",
            "enabled": False,
            "trusted_publisher_enabled": False,
            "install_nonce": "verified-activation-rollback",
            "broker_uid": owner,
            "operator_uid": 0,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    calls: list[list[str]] = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if "bootstrap" in argv:
            raise subprocess.CalledProcessError(1, argv)
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    with pytest.raises(subprocess.CalledProcessError):
        activate_installation(
            service_config_path=config_path,
            expected_owner_uid=owner,
            launchd_plist_path=tmp_path / "ai.hermes.kanban-broker.plist",
            worker_launchd_plist_path=tmp_path / "ai.hermes.kanban-worker.plist",
            operator_client_config=tmp_path / "operator.json",
            runner=runner,
        )

    first_bootout = next(i for i, call in enumerate(calls) if "bootout" in call)
    disable_calls = [i for i, call in enumerate(calls) if "disable" in call]
    assert max(disable_calls) < first_bootout
    for label in ("ai.hermes.kanban-broker", "ai.hermes.kanban-worker"):
        assert ["/bin/launchctl", "print", f"system/{label}"] in calls
    assert ["/bin/launchctl", "print-disabled", "system"] in calls
    assert json.loads(config_path.read_text(encoding="utf-8"))["enabled"] is False


def test_activation_failure_rejects_rollback_when_service_remains_loaded(
    monkeypatch, tmp_path
):
    """Catch cleanup that reports the original error while authority stays live."""
    from hermes_cli.kanban_broker_install import activate_installation

    owner = os.getuid()
    config_path = tmp_path / "service.json"
    config_path.write_text(
        json.dumps({
            "contract": "hermes.kanban_broker_service_config.v1",
            "broker_boundary": "hermes.dedicated_broker_identity.v1",
            "enabled": False,
            "trusted_publisher_enabled": False,
            "install_nonce": "unsafe-activation-rollback",
            "broker_uid": owner,
            "operator_uid": 0,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    def runner(argv, **_kwargs):
        if "bootstrap" in argv:
            raise subprocess.CalledProcessError(1, argv)
        if argv[1:3] == ["print", "system/ai.hermes.kanban-broker"]:
            return subprocess.CompletedProcess(argv, 0, "still loaded", "")
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    with pytest.raises(ValueError, match="activation rollback failed closed"):
        activate_installation(
            service_config_path=config_path,
            expected_owner_uid=owner,
            launchd_plist_path=tmp_path / "ai.hermes.kanban-broker.plist",
            worker_launchd_plist_path=tmp_path / "ai.hermes.kanban-worker.plist",
            operator_client_config=tmp_path / "operator.json",
            runner=runner,
        )


def test_activation_stage_write_failure_still_restores_disabled_state(
    monkeypatch, tmp_path
):
    """Catch a staged config write that raises before the caller marks it staged."""
    from hermes_cli.kanban_broker_install import activate_installation

    owner = os.getuid()
    config_path = tmp_path / "service.json"
    config = {
        "contract": "hermes.kanban_broker_service_config.v1",
        "broker_boundary": "hermes.dedicated_broker_identity.v1",
        "enabled": False,
        "trusted_publisher_enabled": False,
        "install_nonce": "stage-write-failure",
        "broker_uid": owner,
        "operator_uid": 0,
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")
    config_path.chmod(0o600)
    calls: list[list[str]] = []

    def partial_stage(path, **_kwargs):
        staged = dict(config)
        staged["enabled"] = True
        Path(path).write_text(json.dumps(staged), encoding="utf-8")
        Path(path).chmod(0o600)
        raise RuntimeError("stage readback failed")

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_install.stage_service_config", partial_stage
    )
    with pytest.raises(RuntimeError, match="stage readback failed"):
        activate_installation(
            service_config_path=config_path,
            expected_owner_uid=owner,
            launchd_plist_path=tmp_path / "ai.hermes.kanban-broker.plist",
            worker_launchd_plist_path=tmp_path / "ai.hermes.kanban-worker.plist",
            operator_client_config=tmp_path / "operator.json",
            runner=runner,
        )

    reread = json.loads(config_path.read_text(encoding="utf-8"))
    assert reread["enabled"] is False
    assert reread["trusted_publisher_enabled"] is False
    assert any("disable" in call for call in calls)


def test_rollback_disables_before_bootout_and_positively_proves_both_unloaded(
    monkeypatch, tmp_path
):
    from hermes_cli.kanban_broker_install import rollback_installation

    config_path = tmp_path / "service.json"
    config_path.write_text(
        json.dumps({
            "contract": "hermes.kanban_broker_service_config.v1",
            "broker_boundary": "hermes.dedicated_broker_identity.v1",
            "broker_uid": os.getuid(),
            "enabled": True,
            "trusted_publisher_enabled": True,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    class Client:
        pass

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.load_broker_client",
        lambda *_args, **_kwargs: Client(),
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.quiesce_and_wait",
        lambda _client, **_kwargs: {"quiescing": True, "inflight": 0},
    )
    calls: list[list[str]] = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if argv[1] == "bootout" and argv[-1].endswith("kanban-worker"):
            return subprocess.CompletedProcess(argv, 113, "", "not loaded")
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = rollback_installation(
        service_config_path=config_path,
        expected_owner_uid=os.getuid(),
        operator_client_config=tmp_path / "operator.json",
        runner=runner,
    )
    assert result["enabled"] is False
    assert result["trusted_publisher_enabled"] is False
    first_bootout = next(i for i, call in enumerate(calls) if "bootout" in call)
    disable_calls = [i for i, call in enumerate(calls) if "disable" in call]
    assert max(disable_calls) < first_bootout
    assert ["/bin/launchctl", "print-disabled", "system"] in calls
    assert [
        "/bin/launchctl",
        "print",
        "system/ai.hermes.kanban-broker",
    ] in calls
    assert [
        "/bin/launchctl",
        "print",
        "system/ai.hermes.kanban-worker",
    ] in calls


def test_rollback_bootout_transport_failure_still_proves_safe_state(
    monkeypatch, tmp_path
):
    """Catch one bootout exception suppressing later compensation and readback."""
    from hermes_cli.kanban_broker_install import rollback_installation

    config_path = tmp_path / "service.json"
    config_path.write_text(
        json.dumps({
            "contract": "hermes.kanban_broker_service_config.v1",
            "broker_boundary": "hermes.dedicated_broker_identity.v1",
            "broker_uid": os.getuid(),
            "enabled": True,
            "trusted_publisher_enabled": True,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    class Client:
        pass

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.load_broker_client",
        lambda *_args, **_kwargs: Client(),
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.quiesce_and_wait",
        lambda _client, **_kwargs: {"quiescing": True, "inflight": 0},
    )
    calls: list[list[str]] = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if argv[1:3] == ["bootout", "system/ai.hermes.kanban-broker"]:
            raise OSError("launchctl transport failed")
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = rollback_installation(
        service_config_path=config_path,
        expected_owner_uid=os.getuid(),
        operator_client_config=tmp_path / "operator.json",
        runner=runner,
    )
    assert result["enabled"] is False
    assert result["trusted_publisher_enabled"] is False
    assert [
        "/bin/launchctl",
        "bootout",
        "system/ai.hermes.kanban-worker",
    ] in calls
    assert [
        "/bin/launchctl",
        "print",
        "system/ai.hermes.kanban-broker",
    ] in calls
    assert ["/bin/launchctl", "print-disabled", "system"] in calls


def test_rollback_config_disable_failure_still_attempts_service_compensation(
    monkeypatch, tmp_path
):
    """Catch a config-write exception aborting service bootout and readback."""
    from hermes_cli.kanban_broker_install import rollback_installation

    config_path = tmp_path / "service.json"
    config_path.write_text(
        json.dumps({
            "contract": "hermes.kanban_broker_service_config.v1",
            "broker_boundary": "hermes.dedicated_broker_identity.v1",
            "broker_uid": os.getuid(),
            "enabled": True,
            "trusted_publisher_enabled": True,
        }),
        encoding="utf-8",
    )
    config_path.chmod(0o600)

    class Client:
        pass

    monkeypatch.setattr("hermes_cli.kanban_broker_install.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.load_broker_client",
        lambda *_args, **_kwargs: Client(),
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_client.quiesce_and_wait",
        lambda _client, **_kwargs: {"quiescing": True, "inflight": 0},
    )
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_install.disable_service_config",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("disk failure")),
    )
    calls: list[list[str]] = []

    def runner(argv, **_kwargs):
        calls.append(list(argv))
        if argv[1] == "print":
            return subprocess.CompletedProcess(argv, 113, "", "not found")
        if argv[1:] == ["print-disabled", "system"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                '"ai.hermes.kanban-broker" => true\n'
                '"ai.hermes.kanban-worker" => true\n',
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(ValueError, match="broker rollback failed closed"):
        rollback_installation(
            service_config_path=config_path,
            expected_owner_uid=os.getuid(),
            operator_client_config=tmp_path / "operator.json",
            runner=runner,
        )
    for label in ("ai.hermes.kanban-broker", "ai.hermes.kanban-worker"):
        assert ["/bin/launchctl", "bootout", f"system/{label}"] in calls
        assert ["/bin/launchctl", "print", f"system/{label}"] in calls
    assert ["/bin/launchctl", "print-disabled", "system"] in calls


def test_default_false_config_never_attempts_service_or_legacy_fallback(
    monkeypatch,
):
    """Catch a false/malformed opt-in that activates or falls back to same-UID Git."""
    from hermes_cli.kanban_broker_service import BrokerServiceDisabled
    from hermes_cli.kanban_broker_service import dedicated_broker_enabled
    from hermes_cli.kanban_broker_service import require_enabled_service_config
    from hermes_cli import kanban_git_broker

    assert dedicated_broker_enabled({}) is False
    assert (
        dedicated_broker_enabled({"kanban": {"dedicated_broker_enabled": False}})
        is False
    )
    assert (
        dedicated_broker_enabled({"kanban": {"dedicated_broker_enabled": 1}}) is False
    )
    assert (
        dedicated_broker_enabled({"kanban": {"dedicated_broker_enabled": "true"}})
        is False
    )
    assert (
        dedicated_broker_enabled({"kanban": {"dedicated_broker_enabled": True}}) is True
    )
    with pytest.raises(BrokerServiceDisabled):
        require_enabled_service_config({"enabled": False})

    monkeypatch.setattr(
        kanban_git_broker,
        "_dedicated_broker_enabled",
        lambda: True,
    )
    monkeypatch.setattr(
        kanban_git_broker.kb,
        "connect",
        lambda: pytest.fail("legacy same-UID DB path must not be reached"),
    )
    assert kanban_git_broker.finalize_current_worker_git_handoff() == {
        "outcome": "dedicated_broker_owned"
    }


def test_launchd_invokes_existing_service_module_with_one_validated_config(tmp_path):
    """Catch install plans that invoke a nonexistent generic `serve` surface."""
    import plistlib

    from hermes_cli.kanban_broker_install import render_launchd_plist

    rendered = render_launchd_plist(
        python_executable=Path("/usr/bin/python3"),
        config_path=tmp_path / "broker-service.json",
        state_dir=tmp_path / "state",
        broker_user="_hermesbroker",
        package_root=tmp_path / "runtime/hermes_cli",
    )
    payload = plistlib.loads(rendered.encode("utf-8"))
    arguments = payload["ProgramArguments"]
    assert arguments == [
        "/usr/bin/sandbox-exec",
        "-f",
        str(tmp_path / "state" / "broker.sb"),
        "/usr/bin/python3",
        "-m",
        "hermes_cli.kanban_broker_service",
        "serve",
        "--config",
        str(tmp_path / "broker-service.json"),
    ]
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True


def test_operator_rpc_is_separate_from_controller_surface(tmp_path):
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_protocol import ProtocolError
    from hermes_cli.kanban_broker_protocol import signed_request
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid() + 10,
        publisher_uid=os.geteuid() + 11,
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid() + 12,
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    key = b"o" * 32
    body = {
        "repository_id": "radulator",
        "source_path": str(source),
        "default_branch": "main",
        "project_id": None,
        "remote_repository": _remote_repository(),
    }
    request = signed_request(
        key,
        sequence=1,
        nonce="operator-nonce",
        method="register_repository",
        body=body,
    )
    controller = BrokerRPCServer(
        broker=broker,
        surface="controller",
        allowed_uid=os.geteuid(),
        client_key=key,
    )
    with pytest.raises(ProtocolError, match="unavailable"):
        controller.dispatch(peer_uid=os.geteuid(), message=request)
    operator = BrokerRPCServer(
        broker=broker,
        surface="operator",
        allowed_uid=os.geteuid(),
        client_key=key,
    )
    response = operator.dispatch(peer_uid=os.geteuid(), message=request)
    assert response["result"]["repository_id"] == "radulator"
    broker.close()


def test_broker_seatbelt_profile_denies_inet_but_allows_unix_socket(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_seatbelt_profile

    if shutil.which("sandbox-exec") is None:
        pytest.skip("sandbox-exec is unavailable on this macOS host")

    state = tmp_path / "state"
    workspace = tmp_path / "workspaces"
    state.mkdir()
    workspace.mkdir()
    profile = render_broker_seatbelt_profile(
        state_dir=state,
        workspace_root=workspace,
        socket_dir=tmp_path,
    )
    inet = subprocess.run(
        [
            "sandbox-exec",
            "-p",
            profile,
            ".venv/bin/python",
            "-c",
            "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(('127.0.0.1', 0))",
        ],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    assert inet.returncode != 0
    unix = subprocess.run(
        [
            "sandbox-exec",
            "-p",
            profile,
            ".venv/bin/python",
            "-c",
            "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
        ],
        cwd=Path(__file__).parents[2],
        capture_output=True,
        text=True,
        check=False,
    )
    assert unix.returncode == 0, unix.stderr


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a root-owned staging host")
def test_cross_uid_os_ownership_denies_model_read_even_outside_tool_sandbox(
    tmp_path,
):
    """The staging canary models computer_use driving an unsandboxed Terminal."""
    from hermes_cli.kanban_broker_canary import cross_uid_read_denied

    del tmp_path
    staging = Path(tempfile.mkdtemp(prefix="hkb-secret-", dir="/tmp"))
    try:
        staging.chmod(0o711)
        secret = staging / "broker-secret"
        secret.write_text("never visible", encoding="utf-8")
        secret.chmod(0o600)
        os.chown(secret, 1, 1)
        assert cross_uid_read_denied(secret, model_uid=2, model_gid=2) is True
    finally:
        shutil.rmtree(staging)


@pytest.mark.skipif(os.geteuid() != 0, reason="requires a root-owned staging host")
def test_cross_uid_publisher_bundle_and_socket_matrix():
    """Staging canary for publisher-read/model-deny and socket peer groups."""
    from hermes_cli.kanban_broker_canary import cross_uid_publisher_read_matrix
    from hermes_cli.kanban_broker_canary import cross_uid_socket_connect_matrix

    staging = Path(tempfile.mkdtemp(prefix="hkb-publisher-canary-", dir="/tmp"))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        staging.chmod(0o711)
        bundle = staging / "handoff.bundle"
        bundle.write_bytes(b"exact bundle")
        os.chown(bundle, 1, 3)
        bundle.chmod(0o640)
        assert cross_uid_publisher_read_matrix(
            bundle,
            model_uid=2,
            model_gid=2,
            publisher_uid=3,
            publisher_gid=3,
        )
        endpoint = staging / "publisher.sock"
        listener.bind(str(endpoint))
        listener.listen(4)
        os.chown(endpoint, 1, 3)
        endpoint.chmod(0o660)
        assert cross_uid_socket_connect_matrix(
            endpoint,
            model_uid=2,
            model_gid=2,
            client_uid=3,
            client_gid=3,
        )
    finally:
        listener.close()
        shutil.rmtree(staging)

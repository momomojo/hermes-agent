"""Contract tests for the deterministic dedicated-broker plan renderer."""

from __future__ import annotations

import base64
import json
import plistlib
import stat
from pathlib import Path

import pytest


def _inventory() -> dict:
    return {
        "contract": "hermes.kanban_broker_host_inventory.v1",
        "accounts": [
            {"name": "root", "uid": 0, "gid": 0},
            {"name": "_hermesbroker", "uid": 401, "gid": 701},
            {"name": "_hermescontroller", "uid": 402, "gid": 702},
            {"name": "_hermespublisher", "uid": 403, "gid": 703},
            {"name": "_hermesmodel", "uid": 501, "gid": 704},
        ],
        "groups": [
            {"name": "wheel", "gid": 0},
            {"name": "_hermesbroker", "gid": 701},
            {"name": "_hermescontroller", "gid": 702},
            {"name": "_hermespublisher", "gid": 703},
            {"name": "_hermesworkspace", "gid": 704},
        ],
    }


def _desired() -> dict:
    return {
        "broker": {"user": "_hermesbroker", "uid": 401, "gid": 701},
        "controller": {
            "user": "_hermescontroller",
            "uid": 402,
            "gid": 702,
            "group": "_hermescontroller",
            "group_gid": 702,
        },
        "publisher": {
            "user": "_hermespublisher",
            "uid": 403,
            "gid": 703,
            "group": "_hermespublisher",
            "group_gid": 703,
        },
        "operator": {"user": "root", "uid": 0, "gid": 0, "group": "wheel", "group_gid": 0},
        "model": {"user": "_hermesmodel", "uid": 501, "gid": 704},
        "workspace": {"group": "_hermesworkspace", "gid": 704},
    }


def _render(tmp_path: Path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    return render_broker_installation_plan(
        host_inventory=_inventory(),
        desired_identities=_desired(),
        install_root=tmp_path / "install",
        runtime_source_root=Path(__file__).parents[2] / "hermes_cli",
        radulator_source_sha="a" * 40,
        dispatcher_profile="radulator",
    )


def test_renderer_requires_explicit_source_sha_and_dispatcher_profile(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    with pytest.raises(ValueError, match="source SHA"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            runtime_source_root=Path(__file__).parents[2] / "hermes_cli",
            radulator_source_sha=None,
            dispatcher_profile="radulator",
        )
    with pytest.raises(ValueError, match="dispatcher profile"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            runtime_source_root=Path(__file__).parents[2] / "hermes_cli",
            radulator_source_sha="a" * 40,
            dispatcher_profile="",
        )


def test_renderer_rejects_occupied_or_name_id_mismatch(tmp_path):
    inventory = _inventory()
    inventory["accounts"].append({"name": "attacker", "uid": 402, "gid": 900})
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    with pytest.raises(ValueError, match="occupied"):
        render_broker_installation_plan(
            host_inventory=inventory,
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            runtime_source_root=Path(__file__).parents[2] / "hermes_cli",
            radulator_source_sha="a" * 40,
            dispatcher_profile="radulator",
        )


def test_renderer_emits_exact_remote_policy_and_immutable_artifact_manifest(tmp_path):
    plan = _render(tmp_path)
    assert plan["contract"] == "hermes.kanban_broker_install_plan.v1"
    assert plan["radulator_source_sha"] == "a" * 40
    assert plan["service_config"]["enabled"] is False
    assert plan["service_config"]["trusted_publisher_enabled"] is False
    assert ["wheel", 0] in plan["identity_plan"]["groups"]
    assert plan["identity_plan"]["operator"] == {
        "user": "root", "uid": 0, "gid": 0, "group": "wheel", "group_gid": 0
    }
    policy = plan["remote_policy"]
    assert policy == {
        "contract": "hermes.github_repository.v1",
        "host": "github.com",
        "owner": "momomojo",
        "name": "Radulator",
        "full_name": "momomojo/Radulator",
        "repository_id": 1027532341,
        "canonical_url": "https://github.com/momomojo/Radulator",
        "is_fork": False,
        "publication_policy": {
            "pull_request_base": "develop",
            "workflow_id": 227376261,
            "workflow_name": "E2E Tests",
            "workflow_path": ".github/workflows/e2e-tests.yml",
            "workflow_event": "pull_request",
            "required_job_names": [
                "Smoke Tests",
                "Targeted Calculator Tests",
                "Hermes Release Control Tests",
            ],
            "required_app": {"id": 15368, "slug": "github-actions"},
            "ready_label_actor": {"id": 35302851, "login": "momomojo", "type": "User"},
            "ready_label": "ready-for-gate",
        },
    }
    artifacts = plan["artifacts"]
    assert artifacts == sorted(artifacts, key=lambda item: item["path"])
    assert all({"path", "uid", "gid", "mode", "kind"} <= set(item) for item in artifacts)
    assert any(item["kind"] == "canary_key" and item["uid"] == 0 for item in artifacts)
    assert any(item["kind"] == "worker_client_config" for item in artifacts)
    runtime = plan["runtime"]
    assert runtime["entrypoint_mode"] == 0o555
    assert runtime["package_root_mode"] == 0o555
    assert runtime["package_file_mode"] in {0o444, 0o555}
    # The broker is Seatbelt-wrapped; the worker is a separate unprivileged
    # launchd job. Both use the immutable -I entrypoint and no PYTHONPATH.
    payloads = plan["asset_payload_manifest"]["payloads"]
    broker_raw = next(
        value for path, value in payloads.items() if path.endswith("ai.hermes.kanban-broker.plist")
    )
    worker_raw = next(
        value for path, value in payloads.items() if path.endswith("ai.hermes.kanban-worker.plist")
    )
    broker_plist = plistlib.loads(base64.b64decode(broker_raw))
    worker_plist = plistlib.loads(base64.b64decode(worker_raw))
    assert "/usr/bin/sandbox-exec" in broker_plist["ProgramArguments"]
    assert "/usr/bin/sandbox-exec" not in worker_plist["ProgramArguments"]
    assert "-I" in broker_plist["ProgramArguments"] and "-I" in worker_plist["ProgramArguments"]
    assert "PYTHONPATH" not in broker_plist["EnvironmentVariables"]
    assert "PYTHONPATH" not in worker_plist["EnvironmentVariables"]


def test_remote_policy_is_accepted_by_the_broker_registration_schema():
    from hermes_cli.kanban_dedicated_broker import _normalize_github_repository

    # The JSON writer must remain directly consumable by broker-register; the
    # production source SHA is bound by the outer install plan instead.
    from hermes_cli.kanban_broker_install import render_radulator_remote_policy

    policy = render_radulator_remote_policy(source_sha="a" * 40)
    assert _normalize_github_repository(policy) == policy


def test_writer_is_atomic_and_does_not_print_secret_payloads(tmp_path, capsys):
    from hermes_cli.kanban_broker_install import write_broker_installation_plan

    plan = _render(tmp_path)
    output_root = tmp_path / "output"
    result = write_broker_installation_plan(plan, output_root=output_root)
    assert result["output_root"] == str(output_root)
    assert (output_root / "install/identities.json").is_file()
    payload = json.loads((output_root / "install/payloads.json").read_text())
    assert payload["contract"] == "hermes.kanban_broker_asset_payloads.v1"
    assert all(not path.name.startswith(".") for path in output_root.rglob("*"))
    assert stat.S_IMODE((output_root / "install/payloads.json").stat().st_mode) == 0o600
    assert capsys.readouterr().out == ""


def test_cli_accepts_reviewed_inputs_and_writes_the_disabled_plan(tmp_path, capsys):
    from hermes_cli.kanban_broker_install import main

    inventory_path = tmp_path / "inventory.json"
    desired_path = tmp_path / "desired.json"
    inventory_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    desired = _desired()
    desired["contract"] = "hermes.kanban_broker_desired_identities.v1"
    desired_path.write_text(json.dumps(desired), encoding="utf-8")
    inventory_path.chmod(0o600)
    desired_path.chmod(0o600)
    output_root = tmp_path / "output"
    assert main([
        "render-plan",
        "--inventory",
        str(inventory_path),
        "--desired-identities",
        str(desired_path),
        "--install-root",
        str(tmp_path / "install"),
        "--output-root",
        str(output_root),
        "--runtime-source-root",
        str(Path(__file__).parents[2] / "hermes_cli"),
        "--source-sha",
        "a" * 40,
        "--dispatcher-profile",
        "radulator",
    ]) == 0
    assert (output_root / "install/remote-policy.json").is_file()
    assert capsys.readouterr().out == ""

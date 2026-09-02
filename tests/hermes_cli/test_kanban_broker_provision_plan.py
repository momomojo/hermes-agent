"""Contract tests for the deterministic dedicated-broker plan renderer."""

from __future__ import annotations

import base64
import json
import plistlib
import subprocess
import tarfile
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
        "memberships": [
            {"user": "_hermesbroker", "group": "_hermescontroller"},
            {"user": "_hermesbroker", "group": "_hermespublisher"},
            {"user": "_hermesbroker", "group": "wheel"},
            {"user": "_hermesbroker", "group": "_hermesworkspace"},
            {"user": "_hermescontroller", "group": "_hermescontroller"},
            {"user": "_hermespublisher", "group": "_hermespublisher"},
            {"user": "root", "group": "wheel"},
            {"user": "_hermesmodel", "group": "_hermesworkspace"},
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


def _runtime_inputs(tmp_path: Path) -> tuple[Path, Path, str, str]:
    python_archive = Path(
        "/private/tmp/hermes-python-runtime-build/cpython-3.11.15+20260602-aarch64-apple-darwin-install_only.tar.gz"
    )
    if not python_archive.is_file():
        pytest.skip("verified CPython runtime archive is unavailable")
    package_root = tmp_path / "hermes-install" / "hermes_cli"
    package_root.mkdir(parents=True, exist_ok=True)
    required = {
        "__init__.py",
        "main.py",
        "kanban_broker_canary.py",
        "kanban_broker_client.py",
        "kanban_broker_install.py",
        "kanban_broker_protocol.py",
        "kanban_broker_service.py",
        "kanban_broker_worker.py",
        "kanban_dedicated_broker.py",
    }
    for name in required:
        (package_root / name).write_text("# sealed runtime fixture\n", encoding="utf-8")
    package_archive = tmp_path / "hermes-install.tar.gz"
    with tarfile.open(package_archive, "w:gz") as stream:
        stream.add(package_root.parent, arcname="hermes-install")
    import hashlib

    return (
        python_archive,
        package_archive,
        hashlib.sha256(python_archive.read_bytes()).hexdigest(),
        hashlib.sha256(package_archive.read_bytes()).hexdigest(),
    )


def _render(tmp_path: Path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    python_archive, package_archive, python_sha, package_sha = _runtime_inputs(tmp_path)
    return render_broker_installation_plan(
        host_inventory=_inventory(),
        desired_identities=_desired(),
        install_root=tmp_path / "install",
        runtime_archive_path=python_archive,
        runtime_archive_sha256=python_sha,
        hermes_install_archive_path=package_archive,
        hermes_install_archive_sha256=package_sha,
        hermes_source_sha="b" * 40,
        radulator_source_path=tmp_path / "radulator-checkout",
        radulator_source_sha="a" * 40,
        dispatcher_profile="radulator",
    )


def _runtime_kwargs(tmp_path: Path) -> dict:
    python_archive, package_archive, python_sha, package_sha = _runtime_inputs(tmp_path)
    return {
        "runtime_archive_path": python_archive,
        "runtime_archive_sha256": python_sha,
        "hermes_install_archive_path": package_archive,
        "hermes_install_archive_sha256": package_sha,
    }


def test_renderer_requires_explicit_source_sha_and_dispatcher_profile(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    with pytest.raises(ValueError, match="source SHA"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **_runtime_kwargs(tmp_path),
            hermes_source_sha="b" * 40,
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=None,
            dispatcher_profile="radulator",
        )
    with pytest.raises(ValueError, match="dispatcher profile"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **_runtime_kwargs(tmp_path),
            hermes_source_sha="b" * 40,
            radulator_source_path=tmp_path / "radulator-checkout",
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
            **_runtime_kwargs(tmp_path),
            hermes_source_sha="b" * 40,
            radulator_source_path=tmp_path / "radulator-checkout",
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
    assert not any(item["kind"] == "worker_client_config" for item in artifacts)
    assert {item["kind"] for item in artifacts} >= {
        "runtime_entrypoint", "runtime_direct_probe"
    }
    runtime = plan["runtime"]
    assert runtime["entrypoint_mode"] == 0o555
    assert runtime["package_root_mode"] == 0o555
    assert runtime["package_file_mode"] in {0o444, 0o555}
    import hashlib

    package_prefix = "lib/python3.11/site-packages/hermes_cli/"
    package_entries = [
        {
            **entry,
            "path": entry["path"][len(package_prefix):],
        }
        for entry in runtime["sealed_runtime"]["entries"]
        if entry["path"].startswith(package_prefix)
        and entry["path"] != package_prefix
        and "__pycache__" not in Path(entry["path"]).parts
        and not entry["path"].endswith((".pyc", ".pyo"))
    ]
    expected_package_sha = hashlib.sha256(
        json.dumps(package_entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert runtime["package_manifest_sha256"] == expected_package_sha
    assert runtime["package_manifest_sha256"] == plan["service_config"]["package_manifest_sha256"]
    assert runtime["runtime_manifest_path"].endswith("/install/runtime-manifest.json")
    assert plan["hermes_source_sha"] == "b" * 40
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
    manifest_raw = next(
        value for path, value in payloads.items() if path.endswith("runtime-manifest.json")
    )
    runtime_manifest = json.loads(base64.b64decode(manifest_raw))
    assert runtime_manifest["contract"] == "hermes.kanban_broker_runtime_manifest.v1"
    attestation_raw = next(
        value for path, value in payloads.items() if path.endswith("runtime-attestation.json")
    )
    attestation = json.loads(base64.b64decode(attestation_raw))
    assert attestation["hermes_source_sha"] == "b" * 40
    assert attestation["hermes_install_archive_sha256"] == runtime["sealed_runtime"]["archives"][1]["sha256"]
    assert attestation["runtime_manifest_path"] == runtime_manifest["runtime_root"].replace(
        "/runtime/sealed", "/install/runtime-manifest.json"
    )


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
    assert not (output_root / "config/service.json").exists()
    assert not (output_root / "launchd").exists()
    assert payload["external_payloads"]
    assert len((output_root / "install/payloads.json").read_bytes()) < 4 * 1024 * 1024
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
    python_archive, package_archive, python_sha, package_sha = _runtime_inputs(tmp_path)
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
        "--runtime-archive",
        str(python_archive),
        "--runtime-archive-sha256",
        python_sha,
        "--hermes-install-archive",
        str(package_archive),
        "--hermes-install-archive-sha256",
        package_sha,
        "--hermes-source-sha",
        "b" * 40,
        "--radulator-source-path",
        str(tmp_path / "radulator-checkout"),
        "--source-sha",
        "a" * 40,
        "--dispatcher-profile",
        "radulator",
    ]) == 0
    assert (output_root / "install/filesystem.json").is_file()
    assert not (output_root / "install/remote-policy.json").exists()
    assert capsys.readouterr().out == ""


def test_output_root_rebases_embedded_routing_bytes_and_metadata(tmp_path):
    from hermes_cli.kanban_broker_install import write_broker_installation_plan

    plan = _render(tmp_path / "source")
    output_root = tmp_path / "rebased"
    write_broker_installation_plan(plan, output_root=output_root)
    filesystem = json.loads(
        (output_root / "install/filesystem.json").read_text(encoding="utf-8")
    )
    payload_manifest = json.loads(
        (output_root / "install/payloads.json").read_text(encoding="utf-8")
    )
    files = {item["path"]: item for item in filesystem["files"]}
    payload_paths = set(payload_manifest["payloads"])
    payload_paths.update(item["path"] for item in payload_manifest["external_payloads"])
    assert payload_paths == set(files)
    for path, encoded in payload_manifest["payloads"].items():
        content = base64.b64decode(encoded)
        assert len(content) == files[path]["size"]
        import hashlib

        assert hashlib.sha256(content).hexdigest() == files[path]["sha256"]
        assert str(tmp_path / "source" / "install").encode() not in content
    service_path = next(path for path in payload_manifest["payloads"] if path.endswith("/config/service.json"))
    service = json.loads(base64.b64decode(payload_manifest["payloads"][service_path]))
    assert service["install_root"] == str(output_root)
    assert service["runtime_manifest_path"].startswith(str(output_root) + "/")
    attestation_path = next(
        path for path in payload_manifest["payloads"] if path.endswith("runtime-attestation.json")
    )
    attestation = json.loads(base64.b64decode(payload_manifest["payloads"][attestation_path]))
    assert attestation["service_config_sha256"] == hashlib.sha256(
        base64.b64decode(payload_manifest["payloads"][service_path])
    ).hexdigest()


def test_allocator_accepts_unassigned_service_block_and_rejects_gid_collision():
    from hermes_cli.kanban_broker_install import allocate_desired_identities

    inventory = {
        "contract": "hermes.kanban_broker_host_inventory.v1",
        "accounts": [{"name": "root", "uid": 0, "gid": 0}],
        "groups": [{"name": "wheel", "gid": 0}],
        "memberships": [{"user": "root", "group": "wheel"}],
    }
    desired = allocate_desired_identities(inventory)
    assert [desired[role]["uid"] for role in ("broker", "controller", "publisher", "model")] == [450, 451, 452, 453]
    inventory["groups"].append({"name": "occupied", "gid": 450})
    with pytest.raises(ValueError, match="occupied"):
        allocate_desired_identities(inventory)


def test_runtime_archive_rejects_upward_symlink(tmp_path):
    import hashlib

    from hermes_cli.kanban_broker_install import _read_runtime_archive_manifest

    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo("python/bin/python3")
        member.type = tarfile.SYMTYPE
        member.linkname = "../../outside"
        stream.addfile(member)
    with pytest.raises(ValueError, match="escapes"):
        _read_runtime_archive_manifest(
            archive,
            expected_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            strip_prefix="python",
            required_paths=set(),
            role="CPython",
        )


def test_direct_isolated_publisher_wrapper_imports_sealed_hermes_client(tmp_path):
    """Exercise the same ``python -I trusted_publisher.py`` contract as Radulator."""
    python_archive, _package_archive, _python_sha, _package_sha = _runtime_inputs(tmp_path)
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    with tarfile.open(python_archive, "r:gz") as stream:
        stream.extractall(runtime_root)
    sealed_root = runtime_root / "python"
    package_root = sealed_root / "lib/python3.11/site-packages/hermes_cli"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("\n", encoding="utf-8")
    (package_root / "kanban_broker_client.py").write_text(
        "SEALED = True\n", encoding="utf-8"
    )
    wrapper = sealed_root / "trusted_publisher.py"
    wrapper.write_text(
        "from hermes_cli import kanban_broker_client\n"
        "from pathlib import Path\n"
        "assert kanban_broker_client.SEALED\n"
        "assert Path(kanban_broker_client.__file__).resolve().is_relative_to(Path(__file__).resolve().parent)\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(sealed_root / "bin/python3.11"), "-I", str(wrapper)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    assert result.returncode == 0, result.stderr

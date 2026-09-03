"""Contract tests for the deterministic dedicated-broker plan renderer."""

from __future__ import annotations

import base64
import json
import plistlib
import subprocess
import tarfile
import stat
import sys
import venv
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


def _runtime_inputs(tmp_path: Path) -> tuple[Path, Path, str, str, Path, str]:
    """Build deterministic bounded fixtures; the real-CPython check is separate."""
    import hashlib

    from hermes_cli import kanban_broker_install as installer

    tmp_path.mkdir(parents=True, exist_ok=True)

    def write_archive(path: Path, root_name: str, files: dict[str, object]):
        with tarfile.open(path, "w:gz") as stream:
            roots = {root_name + "/"}
            for name in files:
                parts = name.split("/")
                roots.update(
                    "/".join([root_name, *parts[:index]]) + "/"
                    for index in range(1, len(parts))
                )
            for name in sorted(roots):
                member = tarfile.TarInfo(name)
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                member.mtime = 0
                member.uid = member.gid = 0
                stream.addfile(member)
            for name, value in sorted(files.items()):
                if isinstance(value, tuple):
                    content, mode = value
                else:
                    content, mode = value, 0o444
                member = tarfile.TarInfo(f"{root_name}/{name}")
                member.size = len(content)
                member.mode = mode
                member.mtime = 0
                member.uid = member.gid = 0
                stream.addfile(member, __import__("io").BytesIO(content))

    python_archive = tmp_path / "cpython-runtime.tar.gz"
    write_archive(
        python_archive,
        "python",
        {
            "bin/python3.11": (b"sealed-python-fixture\n", 0o555),
            "bin/python3": (b"sealed-python-fixture\n", 0o555),
            "lib/python3.11/fixture.py": (b"RUNTIME = True\n", 0o664),
        },
    )
    python_sha = hashlib.sha256(python_archive.read_bytes()).hexdigest()
    # Tests exercise the renderer's shape with a bounded fixture.  Production
    # retains the reviewed digest and the separate integration test exercises
    # the official archive when it is available.
    installer.OFFICIAL_RUNTIME_ARCHIVE_SHA256 = python_sha

    package_files = {
        "hermes_cli/__init__.py": b"from .kanban_broker_client import CLIENT_CONTRACT\n",
        "hermes_cli/main.py": (
            b"from hermes_cli.kanban_broker_client import CLIENT_CONTRACT\n"
            b"from hermes_dep.runtime import DEPENDENCY\n"
            b"def main():\n    return CLIENT_CONTRACT + ':' + DEPENDENCY\n"
            b"if __name__ == '__main__':\n    raise SystemExit(main())\n"
        ),
        "hermes_cli/kanban_broker_canary.py": b"CANARY = True\n",
        "hermes_cli/kanban_broker_client.py": b"CLIENT_CONTRACT = 'sealed-v1'\n",
        "hermes_cli/kanban_broker_install.py": b"INSTALLER = True\n",
        "hermes_cli/kanban_broker_protocol.py": b"PROTOCOL = True\n",
        "hermes_cli/kanban_broker_service.py": b"SERVICE = True\n",
        "hermes_cli/kanban_broker_worker.py": b"WORKER = True\n",
        "hermes_cli/kanban_dedicated_broker.py": b"BROKER = True\n",
        "hermes_dep/__init__.py": b"from .runtime import DEPENDENCY\n",
        "hermes_dep/runtime.py": b"DEPENDENCY = 'sealed-dependency'\n",
    }
    package_archive = tmp_path / "hermes-install.tar.gz"
    write_archive(package_archive, "hermes-install", package_files)
    package_sha = hashlib.sha256(package_archive.read_bytes()).hexdigest()
    provenance_entries = []
    names = {"hermes_cli/", "hermes_dep/"}
    for name in package_files:
        parts = name.split("/")
        names.update("/".join(parts[:index]) + "/" for index in range(1, len(parts)))
    for name in sorted(names):
        provenance_entries.append({
            "path": name,
            "type": "directory",
            "mode": 0o555,
            "origin": "first-party" if name.startswith("hermes_cli/") else "dependency",
        })
    for name, content in sorted(package_files.items()):
        mode = 0o444
        provenance_entries.append({
            "path": name,
            "type": "file",
            "mode": 0o555 if mode & 0o111 else 0o444,
            "origin": "first-party" if name.startswith("hermes_cli/") else "dependency",
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    provenance_entries.sort(key=lambda item: item["path"])
    hermes_source = tmp_path / "hermes-source"
    hermes_source.mkdir(parents=True, exist_ok=True)
    (hermes_source / "pyproject.toml").write_text("[project]\nname='hermes'\n", encoding="utf-8")
    (hermes_source / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    if not (hermes_source / ".git").exists():
        subprocess.run(["/usr/bin/git", "init", "-q", str(hermes_source)], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "config", "user.name", "fixture"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "add", "pyproject.toml", "uv.lock"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "commit", "-qm", "fixture"], check=True)
    source_sha = subprocess.run(
        ["/usr/bin/git", "-C", str(hermes_source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    source_tree_sha = subprocess.run(
        ["/usr/bin/git", "-C", str(hermes_source), "rev-parse", "HEAD^{tree}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    pyproject_bytes = (hermes_source / "pyproject.toml").read_bytes()
    uv_lock_bytes = (hermes_source / "uv.lock").read_bytes()
    provenance = {
        "contract": "hermes.kanban_broker_hermes_install_provenance.v1",
        "schema_version": 1,
        "builder_contract": "hermes.kanban_broker_hermes_install_builder.v1",
        "hermes_source_sha": source_sha,
        "hermes_source_tree_sha": source_tree_sha,
        "pyproject_sha256": hashlib.sha256(pyproject_bytes).hexdigest(),
        "uv_lock_sha256": hashlib.sha256(uv_lock_bytes).hexdigest(),
        "pyproject_lock_sha256": hashlib.sha256(pyproject_bytes + b"\0" + uv_lock_bytes).hexdigest(),
        "install_archive_sha256": package_sha,
        "entries": provenance_entries,
    }
    provenance_path = tmp_path / "hermes-install.provenance.json"
    provenance_path.write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
    provenance_sha = hashlib.sha256(provenance_path.read_bytes()).hexdigest()
    return python_archive, package_archive, python_sha, package_sha, provenance_path, provenance_sha


def _publisher_probe(tmp_path: Path) -> tuple[Path, str]:
    import hashlib

    checkout = tmp_path / "radulator-checkout"
    script_dir = checkout / "ops/hermes/radulator"
    script_dir.mkdir(parents=True, exist_ok=True)
    (script_dir / "lifecycle_controller.py").write_text(
        "def main():\n    return 0\n", encoding="utf-8"
    )
    path = script_dir / "trusted_publisher.py"
    path.write_text(
        "# argparse contract: --broker-client-config, list_publish_obligations\n"
        "from hermes_cli import kanban_broker_client\n"
        "import json\n"
        "if '--runtime-preflight' in __import__('sys').argv:\n"
        "    print(json.dumps({'contract':'radulator.publisher_runtime_preflight.v1',"
        "'status':'PASS','python_executable':__import__('sys').executable,"
        "'python_version':__import__('platform').python_version(),"
        "'runtime_root':__import__('sys').prefix,"
        "'runtime_manifest_sha256':'0'*64,"
        "'broker_client_module':kanban_broker_client.__file__,"
        "'broker_rpc':'PASS'}, sort_keys=True))\n"
    )
    if not (checkout / ".git").exists():
        subprocess.run(["/usr/bin/git", "init", "-q", str(checkout)], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(checkout), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(checkout), "config", "user.name", "fixture"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(checkout), "add", "ops"], check=True)
        subprocess.run(["/usr/bin/git", "-C", str(checkout), "commit", "-qm", "fixture"], check=True)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def _radulator_source_sha(tmp_path: Path) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(tmp_path / "radulator-checkout"), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _hermes_source_sha(tmp_path: Path) -> str:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(tmp_path / "hermes-source"), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def _render(tmp_path: Path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    python_archive, package_archive, python_sha, package_sha, provenance_path, provenance_sha = _runtime_inputs(tmp_path)
    publisher_probe, publisher_probe_sha = _publisher_probe(tmp_path)
    return render_broker_installation_plan(
        host_inventory=_inventory(),
        desired_identities=_desired(),
        install_root=tmp_path / "install",
        runtime_archive_path=python_archive,
        runtime_archive_sha256=python_sha,
        hermes_install_archive_path=package_archive,
        hermes_install_archive_sha256=package_sha,
        hermes_install_provenance_path=provenance_path,
        hermes_install_provenance_sha256=provenance_sha,
        publisher_probe_path=publisher_probe,
        publisher_probe_sha256=publisher_probe_sha,
        hermes_source_sha=_hermes_source_sha(tmp_path),
        hermes_source_path=tmp_path / "hermes-source",
        radulator_source_path=tmp_path / "radulator-checkout",
        radulator_source_sha=_radulator_source_sha(tmp_path),
        dispatcher_profile="radulator",
    )


def _runtime_kwargs(tmp_path: Path) -> dict:
    (
        python_archive,
        package_archive,
        python_sha,
        package_sha,
        provenance_path,
        provenance_sha,
    ) = _runtime_inputs(tmp_path)
    publisher_probe, publisher_probe_sha = _publisher_probe(tmp_path)
    return {
        "runtime_archive_path": python_archive,
        "runtime_archive_sha256": python_sha,
        "hermes_install_archive_path": package_archive,
        "hermes_install_archive_sha256": package_sha,
        "hermes_install_provenance_path": provenance_path,
        "hermes_install_provenance_sha256": provenance_sha,
        "publisher_probe_path": publisher_probe,
        "publisher_probe_sha256": publisher_probe_sha,
        "hermes_source_path": tmp_path / "hermes-source",
    }


def test_renderer_requires_explicit_source_sha_and_dispatcher_profile(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    with pytest.raises(ValueError, match="source SHA"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **_runtime_kwargs(tmp_path),
            hermes_source_sha=_hermes_source_sha(tmp_path),
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=None,
            dispatcher_profile="radulator",
        )


def test_renderer_rejects_lookalike_publisher_script_outside_reviewed_checkout(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan
    import hashlib

    kwargs = _runtime_kwargs(tmp_path)
    fake = tmp_path / "lookalike-trusted-publisher.py"
    fake.write_text("print('PASS')\n", encoding="utf-8")
    kwargs["publisher_probe_path"] = fake
    kwargs["publisher_probe_sha256"] = hashlib.sha256(fake.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="reviewed Radulator path"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **kwargs,
            hermes_source_sha=_hermes_source_sha(tmp_path),
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=_radulator_source_sha(tmp_path),
            dispatcher_profile="radulator",
        )
    with pytest.raises(ValueError, match="dispatcher profile"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **_runtime_kwargs(tmp_path),
            hermes_source_sha=_hermes_source_sha(tmp_path),
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=_radulator_source_sha(tmp_path),
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
            hermes_source_sha=_hermes_source_sha(tmp_path),
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=_radulator_source_sha(tmp_path),
            dispatcher_profile="radulator",
        )


def test_renderer_emits_exact_remote_policy_and_immutable_artifact_manifest(tmp_path):
    plan = _render(tmp_path)
    assert plan["contract"] == "hermes.kanban_broker_install_plan.v1"
    assert plan["radulator_source_sha"] == _radulator_source_sha(tmp_path)
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
    assert plan["hermes_source_sha"] == _hermes_source_sha(tmp_path)
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
    assert attestation["hermes_source_sha"] == _hermes_source_sha(tmp_path)
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
    (
        python_archive,
        package_archive,
        python_sha,
        package_sha,
        provenance_path,
        provenance_sha,
    ) = _runtime_inputs(tmp_path)
    publisher_probe, publisher_probe_sha = _publisher_probe(tmp_path)
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
        "--hermes-install-provenance",
        str(provenance_path),
        "--hermes-install-provenance-sha256",
        provenance_sha,
        "--publisher-probe",
        str(publisher_probe),
        "--publisher-probe-sha256",
        publisher_probe_sha,
        "--hermes-source-sha",
        _hermes_source_sha(tmp_path),
        "--hermes-source-path",
        str(tmp_path / "hermes-source"),
        "--radulator-source-path",
        str(tmp_path / "radulator-checkout"),
        "--source-sha",
        _radulator_source_sha(tmp_path),
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
    env_root = tmp_path / "runtime"
    venv.EnvBuilder(with_pip=False, clear=True).create(env_root)
    package_root = env_root / "lib/python3.11/site-packages/hermes_cli"
    package_root.mkdir(parents=True)
    (package_root / "__init__.py").write_text("\n", encoding="utf-8")
    (package_root / "kanban_broker_client.py").write_text(
        "SEALED = True\n", encoding="utf-8"
    )
    wrapper = package_root.parent / "trusted_publisher.py"
    wrapper.write_text(
        "from hermes_cli import kanban_broker_client\n"
        "from pathlib import Path\n"
        "assert kanban_broker_client.SEALED\n"
        "assert Path(kanban_broker_client.__file__).resolve().is_relative_to(Path(__file__).resolve().parent)\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [str(env_root / "bin/python"), "-I", "-B", str(wrapper)],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    assert result.returncode == 0, result.stderr


def test_hermes_install_archive_executes_main_and_dependency_closure(tmp_path):
    """The staged install input must be runnable, not comment-only fixtures."""
    _python_archive, package_archive, *_rest = _runtime_inputs(tmp_path)
    extracted = tmp_path / "hermes-install"
    extracted.mkdir()
    with tarfile.open(package_archive, "r:gz") as stream:
        stream.extractall(extracted)
    site_packages = extracted / "hermes-install"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            (
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "from hermes_cli.main import main; "
                "assert main() == 'sealed-v1:sealed-dependency'"
            ),
            str(site_packages),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    assert result.returncode == 0, result.stderr


def test_renderer_requires_complete_hermes_provenance_manifest(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    (
        python_archive,
        package_archive,
        python_sha,
        package_sha,
        _provenance_path,
        _provenance_sha,
    ) = _runtime_inputs(tmp_path)
    publisher_probe, publisher_probe_sha = _publisher_probe(tmp_path)
    provenance = tmp_path / "hermes-install.provenance.json"
    with pytest.raises(ValueError, match="provenance"):
        render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            runtime_archive_path=python_archive,
            runtime_archive_sha256=python_sha,
            hermes_install_archive_path=package_archive,
            hermes_install_archive_sha256=package_sha,
            hermes_install_provenance_path=provenance,
            hermes_install_provenance_sha256="a" * 64,
            publisher_probe_path=publisher_probe,
            publisher_probe_sha256=publisher_probe_sha,
            hermes_source_sha=_hermes_source_sha(tmp_path),
            hermes_source_path=tmp_path / "hermes-source",
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=_radulator_source_sha(tmp_path),
            dispatcher_profile="radulator",
        )


def test_runtime_tree_manifest_rejects_tampered_and_unexpected_entries(tmp_path):
    from hermes_cli.kanban_broker_install import _verify_runtime_tree_against_manifest

    runtime = tmp_path / "sealed"
    package = runtime / "lib/python3.11/site-packages/hermes_cli"
    package.mkdir(parents=True)
    (runtime / "bin").mkdir()
    (runtime / "bin/python3.11").write_bytes(b"python")
    (package / "__init__.py").write_bytes(b"VALUE = 1\n")
    entries = [
        {"path": "bin/", "type": "directory", "mode": 0o755},
        {"path": "bin/python3.11", "type": "file", "mode": 0o755,
         "size": 6, "sha256": ""},
        {"path": "lib/", "type": "directory", "mode": 0o755},
        {"path": "lib/python3.11/", "type": "directory", "mode": 0o755},
        {"path": "lib/python3.11/site-packages/", "type": "directory", "mode": 0o755},
        {"path": "lib/python3.11/site-packages/hermes_cli/", "type": "directory", "mode": 0o755},
        {"path": "lib/python3.11/site-packages/hermes_cli/__init__.py", "type": "file", "mode": 0o644,
         "size": 10, "sha256": ""},
    ]
    import hashlib

    entries[1]["sha256"] = hashlib.sha256(b"python").hexdigest()
    entries[-1]["sha256"] = hashlib.sha256(b"VALUE = 1\n").hexdigest()
    with pytest.raises(ValueError, match="manifest"):
        _verify_runtime_tree_against_manifest(
            runtime,
            entries,
            expected_owner_uid=runtime.stat().st_uid,
            expected_owner_gid=runtime.stat().st_gid,
        )
    (runtime / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    entries[0]["mode"] = stat.S_IMODE((runtime / "bin").stat().st_mode)
    entries[2]["mode"] = stat.S_IMODE((runtime / "lib").stat().st_mode)
    entries[3]["mode"] = stat.S_IMODE((runtime / "lib/python3.11").stat().st_mode)
    entries[4]["mode"] = stat.S_IMODE((runtime / "lib/python3.11/site-packages").stat().st_mode)
    entries[5]["mode"] = stat.S_IMODE(package.stat().st_mode)
    entries[1]["mode"] = stat.S_IMODE((runtime / "bin/python3.11").stat().st_mode)
    entries[-1]["mode"] = stat.S_IMODE((package / "__init__.py").stat().st_mode)
    with pytest.raises(ValueError, match="unexpected"):
        _verify_runtime_tree_against_manifest(
            runtime,
            entries,
            expected_owner_uid=runtime.stat().st_uid,
            expected_owner_gid=runtime.stat().st_gid,
        )


def test_runtime_tree_manifest_compares_regular_file_mode_exactly(tmp_path):
    from hermes_cli.kanban_broker_install import _verify_runtime_tree_against_manifest

    runtime = tmp_path / "sealed"
    runtime.mkdir()
    payload = runtime / "payload.py"
    payload.write_text("VALUE = 1\n", encoding="utf-8")
    payload.chmod(0o444)
    import hashlib

    entries = [{
        "path": "payload.py",
        "type": "file",
        "mode": 0o444,
        "size": payload.stat().st_size,
        "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
    }]
    _verify_runtime_tree_against_manifest(
        runtime,
        entries,
        expected_owner_uid=runtime.stat().st_uid,
        expected_owner_gid=runtime.stat().st_gid,
    )
    payload.chmod(0o666)
    with pytest.raises(ValueError, match="metadata"):
        _verify_runtime_tree_against_manifest(
            runtime,
            entries,
            expected_owner_uid=runtime.stat().st_uid,
            expected_owner_gid=runtime.stat().st_gid,
        )


def test_official_runtime_provenance_binds_astral_origin():
    from hermes_cli import kanban_broker_install as installer

    assert installer.OFFICIAL_RUNTIME_SOURCE_REPOSITORY == "astral-sh/python-build-standalone"
    assert installer.OFFICIAL_RUNTIME_RELEASE_URL.startswith(
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260602/"
    )


def test_hermes_install_builder_rejects_arbitrary_toy_closure(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    source = tmp_path / "hermes-source"
    source.mkdir()
    (source / "pyproject.toml").write_text("[project]\nname='hermes'\n", encoding="utf-8")
    (source / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    subprocess.run(["/usr/bin/git", "init", "-q", str(source)], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "config", "user.name", "fixture"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "add", "pyproject.toml", "uv.lock"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
    source_sha = subprocess.run(
        ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    install = tmp_path / "install-closure"
    (install / "hermes_cli").mkdir(parents=True)
    (install / "hermes_cli/main.py").write_text("def main(): return 0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source-derived|lock|pyproject"):
        installer.build_hermes_install_archive(
            source_root=source,
            install_root=install,
            source_sha=source_sha,
            output_archive=tmp_path / "closure.tar.gz",
            output_provenance=tmp_path / "closure.provenance.json",
        )


def test_radulator_source_replacement_after_commit_is_rejected(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    kwargs = _runtime_kwargs(tmp_path)
    probe = kwargs["publisher_probe_path"]
    original = probe.read_bytes()
    probe.write_bytes(original + b"\nprint('lookalike')\n")
    kwargs["publisher_probe_sha256"] = __import__("hashlib").sha256(
        probe.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="Git|reviewed|source"):
        installer.render_broker_installation_plan(
            host_inventory=_inventory(),
            desired_identities=_desired(),
            install_root=tmp_path / "install",
            **kwargs,
            hermes_source_sha=_hermes_source_sha(tmp_path),
            radulator_source_path=tmp_path / "radulator-checkout",
            radulator_source_sha=_radulator_source_sha(tmp_path),
            dispatcher_profile="radulator",
        )


def test_rendered_runtime_attestation_is_pending_until_activation(tmp_path):
    plan = _render(tmp_path)
    payloads = plan["asset_payload_manifest"]["payloads"]
    raw = next(
        value for path, value in payloads.items()
        if path.endswith("runtime-attestation.json")
    )
    attestation = json.loads(base64.b64decode(raw))
    assert attestation["active"] is False
    assert attestation["revoked"] is True
    assert attestation["isolated_probe"]["outcome"] == "PENDING"


def test_registration_file_requires_and_consumes_expected_source_sha(tmp_path, monkeypatch):
    from hermes_cli import kanban

    registration = tmp_path / "broker-register.json"
    registration.write_text(json.dumps({
        "contract": "hermes.kanban_broker_register_request.v1",
        "repository_id": "radulator",
        "source_path": str(tmp_path / "checkout"),
        "default_branch": "develop",
        "project_id": None,
        "remote_repository": {"contract": "hermes.github_repository.v1"},
        "expected_source_sha": "a" * 40,
    }), encoding="utf-8")
    seen = {}
    monkeypatch.setattr(
        "hermes_cli.kanban_broker_routing.register_repository",
        lambda request: seen.update(request) or {"base_sha": request["expected_source_sha"]},
    )
    args = type("Args", (), {"registration_file": registration, "json": True,
                              "repository_id": None, "source_path": None,
                              "default_branch": None, "project_id": None,
                              "remote_repository_json": None,
                              "expected_source_sha": None})()
    assert kanban._cmd_broker_register(args) == 0
    assert seen["expected_source_sha"] == "a" * 40


def test_render_materializes_named_profile_and_consumed_routing_config(tmp_path):
    plan = _render(tmp_path)
    payloads = plan["asset_payload_manifest"]["payloads"]
    profile_paths = [path for path in payloads if "/profiles/radulator/" in path]
    assert profile_paths
    assert any(path.endswith("kanban-routing.json") for path in profile_paths)
    routing = next(
        json.loads(base64.b64decode(value))
        for path, value in payloads.items()
        if path.endswith("kanban-routing.json")
    )
    assert routing["profile"] == "radulator"
    assert routing["controller_client_config"].endswith("clients/controller/client.json")
    assert routing["publisher_client_config"].endswith("clients/publisher/client.json")
    assert routing["operator_client_config"].endswith("clients/operator/client.json")
    profile_yaml = next(
        base64.b64decode(value).decode("utf-8")
        for path, value in payloads.items()
        if path.endswith("/profiles/radulator/config.yaml")
    )
    assert "dedicated_broker_enabled: false" in profile_yaml
    assert "trusted_publisher_enabled: false" in profile_yaml
    assert "dedicated_broker_publisher_client_config:" in profile_yaml

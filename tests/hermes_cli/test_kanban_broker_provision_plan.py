"""Contract tests for the deterministic dedicated-broker plan renderer."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import plistlib
import shutil
import subprocess
import tarfile
import stat
import tempfile
import threading
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


_REAL_HERMES_BUILDER: tuple[Path, Path, Path, str] | None = None


def _real_hermes_builder() -> tuple[Path, Path, Path, str]:
    """Build the current checkout through the reviewed locked builder once.

    The checkout used by tests is dirty (the test itself is being edited), so
    first make a clean Git archive and commit it with fixed metadata.  This is
    intentionally the same source-derived/uv-backed path production uses;
    provenance is never hand-authored by a test fixture.
    """
    global _REAL_HERMES_BUILDER
    if _REAL_HERMES_BUILDER is not None:
        return _REAL_HERMES_BUILDER
    import hashlib

    from hermes_cli import kanban_broker_install as installer

    checkout_root = Path(tempfile.mkdtemp(prefix="hermes-real-builder-", dir="/private/tmp"))
    source = checkout_root / "source"
    source.mkdir()
    repository_root = Path(__file__).resolve().parents[2]
    archive = subprocess.run(
        ["/usr/bin/git", "archive", "--format=tar", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
        stream.extractall(source)
    subprocess.run(["/usr/bin/git", "init", "-q", str(source)], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "config", "user.email", "fixture@example.invalid"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "config", "user.name", "fixture"], check=True)
    subprocess.run(["/usr/bin/git", "-C", str(source), "add", "-A"], check=True)
    git_env = {
        **os.environ,
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
    }
    subprocess.run(
        ["/usr/bin/git", "-C", str(source), "commit", "-qm", "fixture"],
        check=True,
        env=git_env,
    )
    source_sha = subprocess.run(
        ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    install_root = checkout_root / "install"
    package_archive = checkout_root / "hermes-install.tar.gz"
    provenance_path = checkout_root / "hermes-install.provenance.json"
    installer.build_hermes_install_archive(
        source_root=source,
        install_root=install_root,
        source_sha=source_sha,
        output_archive=package_archive,
        output_provenance=provenance_path,
        uv_executable=Path("/opt/homebrew/bin/uv"),
    )
    _REAL_HERMES_BUILDER = (source, install_root, package_archive, source_sha)
    return _REAL_HERMES_BUILDER


def _runtime_inputs(tmp_path: Path) -> tuple[Path, Path, str, str, Path, str]:
    """Use real Hermes builder output plus a bounded runtime archive fixture."""
    import hashlib

    from hermes_cli import kanban_broker_install as installer

    tmp_path.mkdir(parents=True, exist_ok=True)
    real_source, _real_install, real_package_archive, _source_sha = _real_hermes_builder()
    hermes_source = tmp_path / "hermes-source"
    if not hermes_source.exists():
        # A shared sparse checkout retains the exact Git object database and
        # source tree identity while avoiding a per-test copy of the large
        # repository checkout.  Git archive still reads the complete commit.
        subprocess.run(
            ["/usr/bin/git", "clone", "--shared", "--no-checkout", "-q", str(real_source), str(hermes_source)],
            check=True,
        )
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "sparse-checkout", "init", "--no-cone"], check=True)
        subprocess.run(
            [
                "/usr/bin/git", "-C", str(hermes_source), "sparse-checkout", "set",
                "pyproject.toml", "uv.lock", "hermes_cli/", "hermes_constants.py", "utils.py",
            ],
            check=True,
        )
        subprocess.run(["/usr/bin/git", "-C", str(hermes_source), "checkout", "-q", "--detach", "HEAD"], check=True)
    package_archive = tmp_path / "hermes-install.tar.gz"
    if not package_archive.exists():
        shutil.copy2(real_package_archive, package_archive)
    package_sha = hashlib.sha256(package_archive.read_bytes()).hexdigest()
    provenance_path = tmp_path / "hermes-install.provenance.json"
    if not provenance_path.exists():
        shutil.copy2(real_package_archive.parent / "hermes-install.provenance.json", provenance_path)
    provenance_sha = hashlib.sha256(provenance_path.read_bytes()).hexdigest()

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
                stream.addfile(member, io.BytesIO(content))

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
        "import argparse, json, platform, sys\n"
        "from pathlib import Path\n"
        "from hermes_cli import kanban_broker_client\n"
        "parser = argparse.ArgumentParser()\n"
        "parser.add_argument('--runtime-preflight', action='store_true', required=True)\n"
        "parser.add_argument('--runtime-root', required=True)\n"
        "parser.add_argument('--runtime-manifest', required=True)\n"
        "parser.add_argument('--runtime-manifest-sha256', required=True)\n"
        "parser.add_argument('--runtime-python-version', required=True)\n"
        "parser.add_argument('--runtime-python-sha256', required=True)\n"
        "parser.add_argument('--repository-id', required=True)\n"
        "parser.add_argument('--broker-client-config', required=True)\n"
        "args = parser.parse_args()\n"
        "client = kanban_broker_client.load_broker_client(Path(args.broker_client_config), expected_surface='publisher')\n"
        "client.call('list_publish_obligations', {'contract':'hermes.publisher_obligation_query.v1', 'repository_id':args.repository_id, 'after_created_at':0, 'after_receipt_id':'', 'limit':1})\n"
        "print(json.dumps({'contract':'radulator.publisher_runtime_preflight.v1',"
        "'status':'PASS','python_executable':sys.executable,"
        "'python_version':platform.python_version(),"
        "'runtime_root':args.runtime_root,"
        "'runtime_manifest_sha256':args.runtime_manifest_sha256,"
        "'broker_client_module':kanban_broker_client.__file__,"
        "'broker_rpc':'PASS'}, sort_keys=True, separators=(',', ':')))\n"
    )
    if not (checkout / ".git").exists():
        subprocess.run(["/usr/bin/git", "init", "-q", "-b", "develop", str(checkout)], check=True)
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
    _source, env_root, _archive, _source_sha = _real_hermes_builder()
    wrapper = tmp_path / "trusted_publisher.py"
    wrapper.write_text(
        "from hermes_cli import kanban_broker_client\n"
        "assert kanban_broker_client.__file__.startswith(__import__('sys').prefix)\n"
        "print(kanban_broker_client.__file__)\n",
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
    assert str(env_root) in result.stdout


def test_hermes_install_archive_executes_main_and_dependency_closure(tmp_path):
    """The staged install input must be runnable, not comment-only fixtures."""
    _source, env_root, package_archive, _source_sha = _real_hermes_builder()
    provenance = json.loads(
        (package_archive.parent / "hermes-install.provenance.json").read_text(encoding="utf-8")
    )
    assert len(provenance["entries"]) > 100
    wrapper = tmp_path / "worker_import.py"
    wrapper.write_text(
        "from hermes_cli.main import main\n"
        "from hermes_cli import kanban_broker_client\n"
        "assert callable(main)\n"
        "assert kanban_broker_client.__file__.startswith(__import__('sys').prefix)\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(env_root / "bin/python"),
            "-I",
            "-B",
            str(wrapper),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    assert result.returncode == 0, result.stderr


def test_publisher_preflight_observes_one_real_broker_rpc(tmp_path):
    """The isolated Radulator command must prove a live authenticated RPC."""
    from hermes_cli.kanban_broker_install import render_broker_client_config
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_service import BrokerSocketService
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    uid = os.geteuid()
    gid = os.getegid()
    root = tmp_path / "broker"
    broker = DedicatedKanbanBroker(
        state_dir=root / "state",
        workspace_root=root / "workspaces",
        publisher_handoff_root=root / "handoffs",
        broker_uid=uid,
        controller_uid=uid,
        publisher_uid=uid,
        operator_uid=uid,
        worker_uid=uid,
        workspace_gid=gid,
        publisher_gid=gid,
        trusted_publisher_enabled=True,
    )
    broker.initialize()
    observed: list[dict] = []
    original_list = broker.list_publish_obligations

    def observe(*, peer_uid: int, query: dict) -> dict:
        observed.append(dict(query))
        return original_list(peer_uid=peer_uid, query=query)

    broker.list_publish_obligations = observe  # type: ignore[method-assign]
    # macOS AF_UNIX endpoints are capped at 104 bytes; keep this test socket
    # short while the state/config paths remain under pytest's temp root.
    socket_parent = Path(tempfile.mkdtemp(prefix="hbs-", dir="/tmp"))
    os.chown(socket_parent, uid, gid)
    socket_parent.chmod(0o710)
    socket_path = socket_parent / "publisher.sock"
    key_path = root / "keys/publisher.key"
    key_path.parent.mkdir(parents=True)
    key = hashlib.sha256(b"publisher-preflight-test-key").digest()
    key_path.write_bytes(key)
    os.chown(key_path, uid, gid)
    key_path.chmod(0o640)
    sequence_path = root / "sequences/publisher/client.sequence"
    sequence_path.parent.mkdir(parents=True)
    sequence_path.parent.chmod(0o700)
    config_path = root / "clients/publisher/client.json"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        render_broker_client_config(
            surface="publisher",
            socket_path=socket_path,
            expected_broker_uid=uid,
            key_path=key_path,
            sequence_path=sequence_path,
        ),
        encoding="utf-8",
    )
    os.chown(config_path, uid, gid)
    config_path.chmod(0o600)
    server = BrokerRPCServer(
        broker=broker,
        surface="publisher",
        allowed_uid=uid,
        client_key=key,
    )
    service = BrokerSocketService(
        surfaces={"publisher": {"path": socket_path, "gid": gid, "server": server}},
        broker_uid=uid,
        max_inflight=2,
    )
    service.start()
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    try:
        _source, env_root, _archive, _source_sha = _real_hermes_builder()
        probe, _probe_sha = _publisher_probe(tmp_path)
        manifest = tmp_path / "runtime-manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        result = subprocess.run(
            [
                str(env_root / "bin/python"), "-I", "-B", str(probe),
                "--runtime-preflight",
                "--runtime-root", str(env_root),
                "--runtime-manifest", str(manifest),
                "--runtime-manifest-sha256", "a" * 64,
                "--runtime-python-version", "3.11.15",
                "--runtime-python-sha256", "b" * 64,
                "--repository-id", "radulator",
                "--broker-client-config", str(config_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        assert result.returncode == 0, result.stderr
        response = json.loads(result.stdout)
        assert response == {
            "broker_client_module": response["broker_client_module"],
            "broker_rpc": "PASS",
            "contract": "radulator.publisher_runtime_preflight.v1",
            "python_executable": str(env_root / "bin/python"),
            "python_version": "3.11.15",
            "runtime_manifest_sha256": "a" * 64,
            "runtime_root": str(env_root),
            "status": "PASS",
        }
        assert str(env_root) in response["broker_client_module"]
        assert observed == [{
            "contract": "hermes.publisher_obligation_query.v1",
            "repository_id": "radulator",
            "after_created_at": 0,
            "after_receipt_id": "",
            "limit": 1,
        }]
    finally:
        service.stop()
        thread.join(timeout=2)
        service.close()
        broker.close()


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


def test_renderer_rejects_legacy_provenance_with_migration_error(tmp_path):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    kwargs = _runtime_kwargs(tmp_path)
    path = kwargs["hermes_install_provenance_path"]
    document = json.loads(path.read_text(encoding="utf-8"))
    for field in ("first_party_git_archive_sha256", "locked_packages", "installed_distributions", "installer"):
        document.pop(field)
    path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    kwargs["hermes_install_provenance_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="legacy provenance requires migration"):
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


MODERN_PROVENANCE_FIELDS = (
    "contract",
    "schema_version",
    "builder_contract",
    "hermes_source_sha",
    "hermes_source_tree_sha",
    "pyproject_sha256",
    "uv_lock_sha256",
    "pyproject_lock_sha256",
    "first_party_git_archive_sha256",
    "locked_packages",
    "installed_distributions",
    "installer",
    "install_archive_sha256",
    "entries",
)


@pytest.mark.parametrize("field", MODERN_PROVENANCE_FIELDS)
def test_renderer_rejects_missing_every_modern_provenance_field(tmp_path, field):
    from hermes_cli.kanban_broker_install import render_broker_installation_plan

    kwargs = _runtime_kwargs(tmp_path)
    provenance_path = kwargs["hermes_install_provenance_path"]
    document = json.loads(provenance_path.read_text(encoding="utf-8"))
    del document[field]
    provenance_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    kwargs["hermes_install_provenance_sha256"] = __import__("hashlib").sha256(
        provenance_path.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="modern|provenance|schema|lock"):
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


@pytest.mark.parametrize("field", MODERN_PROVENANCE_FIELDS)
def test_cli_rejects_missing_every_modern_provenance_field(tmp_path, field):
    from hermes_cli.kanban_broker_install import main

    inventory_path = tmp_path / "inventory.json"
    desired_path = tmp_path / "desired.json"
    inventory_path.write_text(json.dumps(_inventory()), encoding="utf-8")
    desired = _desired()
    desired["contract"] = "hermes.kanban_broker_desired_identities.v1"
    desired_path.write_text(json.dumps(desired), encoding="utf-8")
    inventory_path.chmod(0o600)
    desired_path.chmod(0o600)
    kwargs = _runtime_kwargs(tmp_path)
    provenance_path = kwargs["hermes_install_provenance_path"]
    document = json.loads(provenance_path.read_text(encoding="utf-8"))
    del document[field]
    provenance_path.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    provenance_sha = __import__("hashlib").sha256(provenance_path.read_bytes()).hexdigest()
    publisher_probe, publisher_probe_sha = _publisher_probe(tmp_path)
    with pytest.raises(ValueError, match="modern|provenance|schema|lock"):
        main([
            "render-plan",
            "--inventory", str(inventory_path),
            "--desired-identities", str(desired_path),
            "--install-root", str(tmp_path / "install"),
            "--output-root", str(tmp_path / "output"),
            "--runtime-archive", str(kwargs["runtime_archive_path"]),
            "--runtime-archive-sha256", str(kwargs["runtime_archive_sha256"]),
            "--hermes-install-archive", str(kwargs["hermes_install_archive_path"]),
            "--hermes-install-archive-sha256", str(kwargs["hermes_install_archive_sha256"]),
            "--hermes-install-provenance", str(provenance_path),
            "--hermes-install-provenance-sha256", provenance_sha,
            "--publisher-probe", str(publisher_probe),
            "--publisher-probe-sha256", publisher_probe_sha,
            "--hermes-source-sha", _hermes_source_sha(tmp_path),
            "--hermes-source-path", str(kwargs["hermes_source_path"]),
            "--radulator-source-path", str(tmp_path / "radulator-checkout"),
            "--source-sha", _radulator_source_sha(tmp_path),
            "--dispatcher-profile", "radulator",
        ])


@pytest.mark.parametrize("field", MODERN_PROVENANCE_FIELDS)
def test_seal_rejects_missing_every_modern_provenance_field(tmp_path, field, monkeypatch):
    from hermes_cli import kanban_broker_install as installer

    plan = _render(tmp_path / "render")
    offline = tmp_path / "offline"
    installer.write_broker_installation_plan(plan, output_root=offline)
    payload_path = offline / "install/payloads.json"
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    compact = payload["hermes_install_provenance"]
    if field in compact["fields"]:
        compact["fields"].remove(field)
    else:
        # The compact seal record has no copy of the recursive entry/list
        # values; deleting its bound field list is the equivalent fail-closed
        # mutation at the sealed-plan boundary.
        compact.pop("fields", None)
    payload_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    payload_path.chmod(0o600)
    monkeypatch.setattr(installer.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="modern Hermes provenance"):
        installer.seal_broker_installation_plan(
            input_root=offline,
            output_root=tmp_path / "sealed",
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


def test_registration_wire_path_persists_and_reads_back_expected_source_sha(tmp_path):
    """Exercise authenticated operator registration against the real broker."""
    from hermes_cli.kanban_broker_install import render_radulator_remote_policy
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer, signed_request
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    probe, _probe_sha = _publisher_probe(tmp_path)
    source = probe.parents[3]
    source_sha = _radulator_source_sha(tmp_path)
    uid = os.geteuid()
    gid = os.getegid()
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        publisher_handoff_root=tmp_path / "handoffs",
        broker_uid=uid,
        controller_uid=uid,
        publisher_uid=uid,
        operator_uid=uid,
        worker_uid=uid,
        workspace_gid=gid,
        publisher_gid=gid,
    )
    broker.initialize()
    try:
        key = hashlib.sha256(b"operator-registration-test-key").digest()
        server = BrokerRPCServer(
            broker=broker,
            surface="operator",
            allowed_uid=uid,
            client_key=key,
        )
        body = {
            "repository_id": "radulator",
            "source_path": str(source),
            "default_branch": "develop",
            "project_id": None,
            "remote_repository": render_radulator_remote_policy(source_sha=source_sha),
            "expected_source_sha": source_sha,
        }
        result = server.dispatch(
            peer_uid=uid,
            message=signed_request(
                key,
                sequence=1,
                nonce="registration-test-1",
                method="register_repository",
                body=body,
            ),
        )
        assert result["ok"] is True
        registered = result["result"]
        assert registered["base_sha"] == source_sha
        row = broker.conn.execute(
            "SELECT base_sha, default_branch, source_path FROM repositories WHERE repository_id=?",
            ("radulator",),
        ).fetchone()
        assert row is not None
        assert (row["base_sha"], row["default_branch"], row["source_path"]) == (
            source_sha,
            "develop",
            str(source),
        )
        replay = server.dispatch(
            peer_uid=uid,
            message=signed_request(
                key,
                sequence=2,
                nonce="registration-test-2",
                method="register_repository",
                body=body,
            ),
        )
        assert replay["ok"] is True
        assert replay["result"]["base_sha"] == source_sha
    finally:
        broker.close()


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


def test_profile_activation_descriptor_write_and_model_owner_readback(tmp_path, monkeypatch):
    """Exercise the root-writer/model-file transition without host mutation."""
    from types import SimpleNamespace

    from hermes_cli import kanban_broker_install as installer

    uid = os.geteuid()
    gid = os.getegid()
    profile_parent = tmp_path / "profiles/radulator"
    profile_parent.mkdir(parents=True)
    # The non-root test runner cannot chown a temporary directory to root.  It
    # still executes the descriptor-relative writer and verifies the actual
    # model-owned output; only the parent ownership observation is represented
    # as the reviewed root-owned boundary.
    profile_parent.chmod(0o755)
    profile_path = profile_parent / "config.yaml"
    profile_path.write_text(
        "kanban:\n"
        "  dedicated_broker_enabled: false\n"
        "  trusted_publisher_enabled: false\n"
        "  dedicated_broker_controller_client_config: /tmp/controller.json\n"
        "  dedicated_broker_publisher_client_config: /tmp/publisher.json\n"
        "  dedicated_broker_operator_client_config: /tmp/operator.json\n"
        "  dedicated_broker_registration_file: /tmp/register.json\n"
        "  dedicated_broker_expected_source_sha: " + "a" * 40 + "\n"
        "  dedicated_broker_dispatcher_profile: radulator\n",
        encoding="utf-8",
    )
    profile_path.chmod(0o600)
    os.chown(profile_path, uid, gid)
    original_lstat = Path.lstat

    def reviewed_parent_lstat(path: Path):
        info = original_lstat(path)
        if path == profile_parent:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o555,
                st_uid=0,
                st_gid=0,
                st_nlink=info.st_nlink,
            )
        return info

    monkeypatch.setattr(Path, "lstat", reviewed_parent_lstat)
    config = {
        "dispatcher_profile_config_path": str(profile_path),
        "model_uid": uid,
        "workspace_gid": gid,
    }
    installer._set_dispatcher_profile_activation(config, enabled=True)
    enabled = profile_path.read_text(encoding="utf-8")
    assert "dedicated_broker_enabled: true" in enabled
    assert "trusted_publisher_enabled: true" in enabled
    info = profile_path.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, 0o600)
    installer._set_dispatcher_profile_activation(config, enabled=False)
    disabled = profile_path.read_text(encoding="utf-8")
    assert "dedicated_broker_enabled: false" in disabled
    assert "trusted_publisher_enabled: false" in disabled

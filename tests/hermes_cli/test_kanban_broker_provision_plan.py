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


# The provisioning plan renderer, builder and toolchain staging are macOS-only:
# they pin the aarch64 Apple Darwin uv/CPython release artifacts and Apple git.
pytestmark = pytest.mark.macos_only

_OFFICIAL_TOOLCHAIN_CACHE = Path.home() / "Library/Caches/hermes-broker-tests"
_TEST_TOOLCHAIN = None


def _fetch_official_archive(name: str, url: str, sha256: str, size: int) -> Path:
    """Return the exact pinned release asset, downloading it once per host."""
    archives = _OFFICIAL_TOOLCHAIN_CACHE / "archives"
    archives.mkdir(parents=True, exist_ok=True)
    target = archives / name
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == sha256:
        return target
    import urllib.request

    with urllib.request.urlopen(url, timeout=600) as response:  # noqa: S310 - pinned https release asset
        data = response.read(size + 1)
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise RuntimeError(f"official toolchain asset {name} did not match its pinned identity")
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(target)
    return target


def _test_toolchain():
    """Stage the pinned official uv and CPython once per host under the test uid.

    Every pin except location and owner is shared with production, so the
    same observation and validation code runs against genuine release bytes.
    """
    global _TEST_TOOLCHAIN
    if _TEST_TOOLCHAIN is not None:
        return _TEST_TOOLCHAIN
    import dataclasses

    from hermes_cli import kanban_broker_install as installer

    root = _OFFICIAL_TOOLCHAIN_CACHE / "toolchain"
    trust = dataclasses.replace(
        installer.HERMES_PRODUCTION_TOOLCHAIN,
        uv_executable=root / "uv",
        python_root=root / "cpython-3.11.15",
        owner_uid=os.getuid(),
        owner_gid=os.getgid(),
    )
    try:
        installer._observe_uv_identity(trust)
        installer._observe_python_identity(trust)
    except ValueError:
        if root.exists():
            for dirpath, _dirnames, _filenames in os.walk(root):
                os.chmod(dirpath, 0o700)
            shutil.rmtree(root)
        cpython = _fetch_official_archive(
            installer.OFFICIAL_RUNTIME_ASSET_NAME,
            installer.OFFICIAL_RUNTIME_RELEASE_URL,
            installer.OFFICIAL_RUNTIME_ARCHIVE_SHA256,
            installer.OFFICIAL_RUNTIME_ARCHIVE_SIZE,
        )
        uv = _fetch_official_archive(
            installer.HERMES_UV_ASSET_NAME,
            installer.HERMES_UV_RELEASE_URL,
            installer.HERMES_UV_ARCHIVE_SHA256,
            installer.HERMES_UV_ASSET_SIZE,
        )
        installer.stage_toolchain(cpython_archive=cpython, uv_archive=uv, toolchain=trust)
    _TEST_TOOLCHAIN = trust
    return trust


def _fixture_tags() -> list:
    from hermes_cli import kanban_broker_install as installer

    return installer._python_identity_supported_tags({
        "marker_environment": {"python_version": "3.11"},
        "mac_version": "26.3",
        "machine": "arm64",
    })


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
        toolchain=_test_toolchain(),
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
    (script_dir / "publisher_service_install.py").write_text(
        "def build_service_plan():\n    return {}\n", encoding="utf-8"
    )
    cron = script_dir / "trusted_publisher_cron.sh"
    cron.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    cron.chmod(0o755)
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
        toolchain=_test_toolchain(),
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
        "toolchain": _test_toolchain(),
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


def test_cli_accepts_reviewed_inputs_and_writes_the_disabled_plan(tmp_path, capsys, monkeypatch):
    from hermes_cli import kanban_broker_install as installer
    from hermes_cli.kanban_broker_install import main

    # The CLI has no toolchain flag; production trust is fixed in code and the
    # module attribute is the only seam, used here to point at the staged
    # official toolchain owned by the test uid.
    monkeypatch.setattr(installer, "HERMES_PRODUCTION_TOOLCHAIN", _test_toolchain())

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
            toolchain=_test_toolchain(),
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
    "uv_identity",
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
def test_cli_rejects_missing_every_modern_provenance_field(tmp_path, field, monkeypatch):
    from hermes_cli import kanban_broker_install as installer
    from hermes_cli.kanban_broker_install import main

    monkeypatch.setattr(installer, "HERMES_PRODUCTION_TOOLCHAIN", _test_toolchain())

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
            toolchain=_test_toolchain(),
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
    with pytest.raises(ValueError, match="metadata|mutable"):
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
            toolchain=_test_toolchain(),
        )


def test_hermes_install_provenance_v1_is_rejected_after_contract_upgrade(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    kwargs = _runtime_kwargs(tmp_path)
    provenance = kwargs["hermes_install_provenance_path"]
    document = json.loads(provenance.read_text(encoding="utf-8"))
    document["contract"] = "hermes.kanban_broker_hermes_install_provenance.v1"
    provenance.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    kwargs["hermes_install_provenance_sha256"] = hashlib.sha256(
        provenance.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="contract|modern|version"):
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


def test_renderer_rejects_installed_distribution_not_in_locked_resolution(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    kwargs = _runtime_kwargs(tmp_path)
    provenance = kwargs["hermes_install_provenance_path"]
    document = json.loads(provenance.read_text(encoding="utf-8"))
    document["installed_distributions"].append({
        "name": "unlocked-malware",
        "version": "1.0.0",
        "record": "unlocked_malware-1.0.0.dist-info/RECORD",
        "artifact": {
            "url": "https://files.pythonhosted.org/unlocked-malware.whl",
            "sha256": "a" * 64,
            "size": 1,
        },
    })
    provenance.write_text(json.dumps(document, sort_keys=True), encoding="utf-8")
    kwargs["hermes_install_provenance_sha256"] = hashlib.sha256(
        provenance.read_bytes()
    ).hexdigest()
    with pytest.raises(ValueError, match="lock|distribution|closure"):
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


def test_hermes_builder_requires_pinned_uv_identity(tmp_path):
    """A look-alike uv is rejected even when its version output matches."""
    import dataclasses

    from hermes_cli import kanban_broker_install as installer

    source, _env, _archive, source_sha = _real_hermes_builder()
    fake_uv = tmp_path / "fake-uv"
    fake_uv.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'uv 0.11.5 (95eaa68c8 2026-04-08 aarch64-apple-darwin)'\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o555)
    trust = dataclasses.replace(_test_toolchain(), uv_executable=fake_uv)
    with pytest.raises(ValueError, match="staged tool|immutable|digest|pinned"):
        installer.build_hermes_install_archive(
            source_root=source,
            install_root=tmp_path / "install",
            source_sha=source_sha,
            output_archive=tmp_path / "closure.tar.gz",
            output_provenance=tmp_path / "closure.provenance.json",
            toolchain=trust,
        )


def test_uv_identity_rejects_user_owned_fake_even_when_metadata_matches(tmp_path):
    """Owner is part of the trust root: a matching digest, size and version
    under the wrong uid must still be rejected by the production pins."""
    import dataclasses

    from hermes_cli import kanban_broker_install as installer

    fake_uv = tmp_path / "fake-uv"
    fake_uv.write_text(
        "#!/bin/sh\nprintf '%s\\n' 'uv 0.11.5 (95eaa68c8 2026-04-08 aarch64-apple-darwin)'\n",
        encoding="utf-8",
    )
    fake_uv.chmod(0o555)
    content = fake_uv.read_bytes()
    trust = dataclasses.replace(
        installer.HERMES_PRODUCTION_TOOLCHAIN,
        uv_executable=fake_uv,
        uv_sha256=hashlib.sha256(content).hexdigest(),
        uv_size=len(content),
    )
    assert os.getuid() != 0
    with pytest.raises(ValueError, match="root-owned"):
        installer._observe_uv_identity(trust)


def test_builder_refuses_to_run_as_a_uid_other_than_the_toolchain_owner(tmp_path):
    import dataclasses

    from hermes_cli import kanban_broker_install as installer

    source, _env, _archive, source_sha = _real_hermes_builder()
    trust = dataclasses.replace(_test_toolchain(), owner_uid=os.getuid() + 1)
    with pytest.raises(PermissionError, match="toolchain owner"):
        installer.build_hermes_install_archive(
            source_root=source,
            install_root=tmp_path / "install",
            source_sha=source_sha,
            output_archive=tmp_path / "closure.tar.gz",
            output_provenance=tmp_path / "closure.provenance.json",
            toolchain=trust,
        )


def test_staged_toolchain_matches_the_official_release_pins():
    from hermes_cli import kanban_broker_install as installer

    trust = _test_toolchain()
    uv_identity = installer._observe_uv_identity(trust)
    assert uv_identity["sha256"] == installer.HERMES_UV_SHA256
    assert uv_identity["version"] == installer.HERMES_UV_VERSION
    assert uv_identity["mode"] == 0o555 and uv_identity["nlink"] == 1
    python_identity = installer._observe_python_identity(trust)
    assert python_identity["version"] == installer.OFFICIAL_RUNTIME_VERSION
    assert python_identity["tree_sha256"] == installer.OFFICIAL_RUNTIME_TREE_SHA256
    assert python_identity["machine"] == "arm64"
    assert python_identity["marker_environment"]["python_full_version"] == "3.11.15"
    assert trust.uv_provenance["archive_sha256"] == installer.HERMES_UV_ARCHIVE_SHA256
    assert trust.uv_provenance["executable_sha256"] == installer.HERMES_UV_SHA256
    assert trust.uv_provenance["archive_sha256"] != trust.uv_provenance["executable_sha256"]


def test_wheel_selection_uses_the_recorded_builder_identity_and_never_sdists():
    from hermes_cli import kanban_broker_install as installer

    tags = _fixture_tags()
    assert any(str(tag) == "cp311-cp311-macosx_11_0_arm64" for tag in tags)
    assert not any("x86_64" in str(tag) for tag in tags)
    package = {
        "name": "sample",
        "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [
            {"url": "https://files.pythonhosted.org/packages/a/sample-1.0.tar.gz", "sha256": "a" * 64, "size": 1},
            {"url": "https://files.pythonhosted.org/packages/b/sample-1.0-cp311-cp311-manylinux_2_17_x86_64.whl", "sha256": "b" * 64, "size": 1},
            {"url": "https://files.pythonhosted.org/packages/c/sample-1.0-py3-none-any.whl", "sha256": "c" * 64, "size": 1},
            {"url": "https://files.pythonhosted.org/packages/d/sample-1.0-cp311-cp311-macosx_11_0_arm64.whl", "sha256": "d" * 64, "size": 1},
        ],
    }
    selected = installer._selected_locked_artifact(package, supported_tags=tags)
    assert selected["sha256"] == "d" * 64
    sdist_only = {**package, "artifacts": package["artifacts"][:1]}
    with pytest.raises(ValueError, match="no wheel"):
        installer._selected_locked_artifact(sdist_only, supported_tags=tags)


def test_lock_parser_requires_the_reviewed_index_and_builder_markers():
    from hermes_cli import kanban_broker_install as installer

    environment = {
        "implementation_name": "cpython", "implementation_version": "3.11.15",
        "os_name": "posix", "platform_machine": "arm64", "platform_release": "25.3.0",
        "platform_system": "Darwin", "platform_version": "Darwin Kernel Version 25.3.0",
        "python_full_version": "3.11.15", "platform_python_implementation": "CPython",
        "python_version": "3.11", "sys_platform": "darwin",
    }

    def lock(registry: str, url: str, marker: str = "") -> bytes:
        marker_line = f'resolution-markers = ["{marker}"]\n' if marker else ""
        return (
            "version = 1\n"
            "[[package]]\nname = \"hermes\"\nversion = \"0.1\"\nsource = { editable = \".\" }\n"
            "dependencies = [{ name = \"sample\" }]\n"
            f"[[package]]\nname = \"sample\"\nversion = \"1.0\"\nsource = {{ registry = \"{registry}\" }}\n"
            + marker_line
            + f"wheels = [{{ url = \"{url}\", hash = \"sha256:{'a' * 64}\", size = 1 }}]\n"
        ).encode("utf-8")

    good = lock("https://pypi.org/simple", "https://files.pythonhosted.org/packages/s/sample-1.0-py3-none-any.whl")
    assert [item["name"] for item in installer._locked_uv_packages(good, marker_environment=environment)] == ["sample"]
    with pytest.raises(ValueError, match="reviewed registry"):
        installer._locked_uv_packages(
            lock("https://mirror.example/simple", "https://files.pythonhosted.org/packages/s/sample-1.0-py3-none-any.whl"),
            marker_environment=environment,
        )
    with pytest.raises(ValueError, match="index host"):
        installer._locked_uv_packages(
            lock("https://pypi.org/simple", "https://files.example/sample-1.0-py3-none-any.whl"),
            marker_environment=environment,
        )
    with pytest.raises(ValueError, match="one active package"):
        installer._locked_uv_packages(
            lock("https://pypi.org/simple", "https://files.pythonhosted.org/packages/s/sample-1.0-py3-none-any.whl", "sys_platform == 'win32'"),
            marker_environment=environment,
        )
    with pytest.raises(ValueError, match="marker environment"):
        installer._locked_uv_packages(good, marker_environment={"python_version": "3.11"})


def test_uv_export_must_reproduce_the_active_lock_graph():
    from hermes_cli import kanban_broker_install as installer

    environment = {
        "implementation_name": "cpython", "implementation_version": "3.11.15",
        "os_name": "posix", "platform_machine": "arm64", "platform_release": "25.3.0",
        "platform_system": "Darwin", "platform_version": "Darwin Kernel Version 25.3.0",
        "python_full_version": "3.11.15", "platform_python_implementation": "CPython",
        "python_version": "3.11", "sys_platform": "darwin",
    }
    locked = [{
        "name": "sample", "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [
            {"url": "https://files.pythonhosted.org/packages/s/sample-1.0-py3-none-any.whl", "sha256": "a" * 64, "size": 1},
            {"url": "https://files.pythonhosted.org/packages/s/sample-1.0.tar.gz", "sha256": "b" * 64, "size": 1},
        ],
    }]
    export = (
        "# This file was autogenerated by uv\n"
        "sample==1.0 \\\n"
        f"    --hash=sha256:{'a' * 64} \\\n"
        f"    --hash=sha256:{'b' * 64}\n"
        "    # via hermes\n"
        "colorama==0.4.6 ; sys_platform == 'win32' \\\n"
        f"    --hash=sha256:{'c' * 64}\n"
    )
    installer._verify_uv_export_matches_lock(export, locked=locked, marker_environment=environment)
    with pytest.raises(ValueError, match="differs from the active uv.lock graph"):
        installer._verify_uv_export_matches_lock(
            export.replace("a" * 64, "f" * 64), locked=locked, marker_environment=environment
        )
    with pytest.raises(ValueError, match="differs from the active uv.lock graph"):
        installer._verify_uv_export_matches_lock(
            export + f"extra==2.0 \\\n    --hash=sha256:{'e' * 64}\n",
            locked=locked, marker_environment=environment,
        )
    with pytest.raises(ValueError, match="omits an artifact hash"):
        installer._verify_uv_export_matches_lock(
            "sample==1.0\n", locked=locked, marker_environment=environment
        )


def test_installed_distribution_rejects_direct_url_and_wheel_record_mismatch(tmp_path):
    import zipfile

    from hermes_cli import kanban_broker_install as installer

    def row(path: str, content: bytes) -> str:
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        return f"{path},sha256={digest},{len(content)}\n"

    payload = b"VALUE = 1\n"
    metadata = b"Metadata-Version: 2.3\nName: sample\nVersion: 1.0\n\n"
    site_packages = _record_fixture(
        tmp_path,
        row("sample/__init__.py", payload)
        + row("sample-1.0.dist-info/METADATA", metadata)
        + "sample-1.0.dist-info/RECORD,,\n",
    )
    (site_packages / "sample/__init__.py").write_bytes(payload)
    (site_packages / "sample-1.0.dist-info/METADATA").write_bytes(metadata)

    def wheel(record_payload: bytes) -> bytes:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("sample/__init__.py", record_payload)
            archive.writestr("sample-1.0.dist-info/METADATA", metadata)
            archive.writestr(
                "sample-1.0.dist-info/RECORD",
                row("sample/__init__.py", record_payload)
                + row("sample-1.0.dist-info/METADATA", metadata)
                + "sample-1.0.dist-info/RECORD,,\n",
            )
        return buffer.getvalue()

    locked = [{
        "name": "sample", "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [{"url": "https://files.pythonhosted.org/packages/s/sample-1.0-py3-none-any.whl", "sha256": "a" * 64, "size": 1}],
    }]
    installed = installer._verify_installed_distributions(
        site_packages, locked, supported_tags=_fixture_tags(), wheel_bytes=lambda artifact: wheel(payload)
    )
    assert installed[0]["artifact"]["sha256"] == "a" * 64
    with pytest.raises(ValueError, match="not bound to the locked wheel"):
        installer._verify_installed_distributions(
            site_packages, locked, supported_tags=_fixture_tags(), wheel_bytes=lambda artifact: wheel(b"VALUE = 2\n")
        )
    (site_packages / "sample-1.0.dist-info/direct_url.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="registry-locked"):
        installer._verify_installed_distributions(
            site_packages, locked, supported_tags=_fixture_tags()
        )


def _record_fixture(tmp_path: Path, record: str) -> Path:
    site_packages = tmp_path / "env/lib/python3.11/site-packages"
    dist_info = site_packages / "sample-1.0.dist-info"
    package = site_packages / "sample"
    dist_info.mkdir(parents=True)
    package.mkdir()
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.3\nName: sample\nVersion: 1.0\n\n", encoding="utf-8"
    )
    (dist_info / "RECORD").write_text(record, encoding="utf-8")
    return site_packages


def test_installed_distribution_rejects_blank_record_digest(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    site_packages = _record_fixture(
        tmp_path,
        "sample/__init__.py,,10\n"
        "sample-1.0.dist-info/METADATA,,51\n"
        "sample-1.0.dist-info/RECORD,,\n",
    )
    locked = [{
        "name": "sample",
        "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [{"url": "https://files.pythonhosted.org/packages/py3/s/sample/sample-1.0-py3-none-any.whl", "sha256": "a" * 64, "size": 1}],
    }]
    with pytest.raises(ValueError, match="RECORD|sha256|digest"):
        installer._verify_installed_distributions(site_packages, locked, supported_tags=_fixture_tags())


def test_installed_distribution_rejects_unrecorded_file(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    site_packages = _record_fixture(
        tmp_path,
        "sample-1.0.dist-info/METADATA,,51\n"
        "sample-1.0.dist-info/RECORD,,\n",
    )
    locked = [{
        "name": "sample",
        "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [{"url": "https://files.pythonhosted.org/packages/py3/s/sample/sample-1.0-py3-none-any.whl", "sha256": "a" * 64, "size": 1}],
    }]
    with pytest.raises(ValueError, match="unrecorded|coverage|RECORD"):
        installer._verify_installed_distributions(site_packages, locked, supported_tags=_fixture_tags())


def test_installed_distribution_rejects_metadata_only_closure(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    site_packages = tmp_path / "env/lib/python3.11/site-packages"
    dist_info = site_packages / "sample-1.0.dist-info"
    dist_info.mkdir(parents=True)
    metadata = b"Metadata-Version: 2.3\nName: sample\nVersion: 1.0\n\n"
    (dist_info / "METADATA").write_bytes(metadata)

    def row(path: str, content: bytes) -> str:
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
        return f"{path},sha256={digest},{len(content)}\n"

    (dist_info / "RECORD").write_text(
        row("sample-1.0.dist-info/METADATA", metadata)
        + "sample-1.0.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    locked = [{
        "name": "sample",
        "version": "1.0",
        "source": {"registry": "https://pypi.org/simple"},
        "artifacts": [{"url": "https://files.pythonhosted.org/packages/py3/s/sample/sample-1.0-py3-none-any.whl", "sha256": "a" * 64, "size": 1}],
    }]
    with pytest.raises(ValueError, match="payload|complete|closure"):
        installer._verify_installed_distributions(site_packages, locked, supported_tags=_fixture_tags())


def test_rendered_worker_profile_directories_pass_real_worker_validation(tmp_path):
    from hermes_cli import kanban_broker_install as installer
    from hermes_cli.kanban_broker_worker import validate_worker_credential_home

    runtime_root = tmp_path / "runtime/hermes_cli"
    runtime_assets = installer.render_runtime_package_assets(
        source_root=Path(__file__).resolve().parents[2] / "hermes_cli",
        destination_root=runtime_root,
    )
    owner = os.getuid()
    group = os.getgid()
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
        "model_uid": owner,
        "controller_uid": 402,
        "controller_gid": 702,
        "publisher_uid": 403,
        "publisher_gid": 703,
        "operator_uid": 0,
        "operator_gid": 0,
        "workspace_gid": group,
        "canary_key_path": str(tmp_path / "canary/canary.key"),
        "package_root": str(runtime_root),
        "package_manifest_sha256": runtime_assets["package_manifest_sha256"],
        "dispatcher_profile": "radulator",
    }
    filesystem = installer.render_filesystem_provision_plan(
        config=config,
        service_config_path=tmp_path / "config/service.json",
        seatbelt_profile_path=tmp_path / "config/broker.sb",
        launchd_plist_path=tmp_path / "launchd/broker.plist",
        worker_launchd_plist_path=tmp_path / "launchd/worker.plist",
        client_config_paths={
            "controller": tmp_path / "clients/controller/client.json",
            "publisher": tmp_path / "clients/publisher/client.json",
            "operator": tmp_path / "clients/operator/client.json",
        },
        sequence_paths={
            "controller": tmp_path / "sequences/controller/sequence",
            "publisher": tmp_path / "sequences/publisher/sequence",
            "operator": tmp_path / "sequences/operator/sequence",
        },
        runtime_assets=runtime_assets,
    )
    directory_plan = {
        item["path"]: item for item in filesystem["directories"]
    }
    for relative in ("worker-home", "worker-home/profiles", "worker-home/profiles/radulator"):
        item = directory_plan[str(tmp_path / relative)]
        assert (item["uid"], item["gid"], item["mode"]) == (owner, group, 0o700)
        path = Path(item["path"])
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(item["mode"])
    validated = validate_worker_credential_home(
        tmp_path / "worker-home", profile="radulator", expected_owner_uid=owner
    )
    assert validated["profile_home"] == str(tmp_path / "worker-home/profiles/radulator")


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
    profile_path.chmod(0o640)
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
        "dispatcher_profile_owner_uid": uid,
        "dispatcher_profile_owner_gid": gid,
        "model_uid": uid + 1,
        "workspace_gid": gid,
    }
    installer._set_dispatcher_profile_activation(config, enabled=True)
    enabled = profile_path.read_text(encoding="utf-8")
    assert "dedicated_broker_enabled: true" in enabled
    assert "trusted_publisher_enabled: true" in enabled
    info = profile_path.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, 0o640)
    installer._set_dispatcher_profile_activation(config, enabled=False)
    disabled = profile_path.read_text(encoding="utf-8")
    assert "dedicated_broker_enabled: false" in disabled
    assert "trusted_publisher_enabled: false" in disabled


def test_rendered_routing_overlay_is_root_owned_group_readable_and_worker_bound(tmp_path):
    """The routing authority lives outside the model-owned profile home."""
    plan = _render(tmp_path)
    files = {item["path"]: item for item in plan["filesystem_plan"]["files"]}
    directories = {item["path"]: item for item in plan["filesystem_plan"]["directories"]}
    overlay_root = tmp_path / "install/routing/radulator"
    workspace_gid = int(_desired()["workspace"]["gid"])
    for name, kind in (("kanban-routing.json", "dispatcher_routing_config"), ("config.yaml", "dispatcher_profile_config")):
        record = files[str(overlay_root / name)]
        assert (record["uid"], record["gid"], record["mode"], record["kind"]) == (0, workspace_gid, 0o640, kind)
    assert (directories[str(overlay_root)]["uid"], directories[str(overlay_root)]["mode"]) == (0, 0o555)
    model_profile = tmp_path / "install/worker-home/profiles/radulator"
    model_uid = int(_desired()["model"]["uid"])
    assert (directories[str(model_profile)]["uid"], directories[str(model_profile)]["mode"]) == (model_uid, 0o700)
    assert files[str(model_profile / "config.yaml")]["uid"] == model_uid
    payloads = plan["asset_payload_manifest"]["payloads"]
    service_config = json.loads(base64.b64decode(next(
        value for path, value in payloads.items() if path.endswith("/config/service.json")
    )))
    assert service_config["dispatcher_profile_config_path"] == str(overlay_root / "config.yaml")
    assert service_config["dispatcher_profile_owner_uid"] == 0
    assert service_config["dispatcher_profile_owner_gid"] == workspace_gid
    worker_plist = plistlib.loads(base64.b64decode(next(
        value for path, value in payloads.items() if path.endswith("ai.hermes.kanban-worker.plist")
    )))
    arguments = worker_plist["ProgramArguments"]
    assert arguments[arguments.index("--routing-config") + 1] == str(overlay_root / "config.yaml")


def test_runtime_attestation_replacement_is_inode_and_digest_bound(tmp_path):
    """Finding 3: activation/rollback replace the attestation only when the
    exact previous inode and digest still hold, then read back the result."""
    from hermes_cli import kanban_broker_install as installer

    path = tmp_path / "runtime-attestation.json"
    initial = b'{"active": false}\n'
    path.write_bytes(initial)
    path.chmod(0o644)
    info = path.lstat()
    # macOS gives new files the parent directory's group, which need not be
    # the process's primary group; the owner seam binds to the real values.
    uid, gid = info.st_uid, info.st_gid
    replacement = b'{"active": true}\n'
    installer._replace_runtime_attestation(
        path, replacement,
        expected_sha256=hashlib.sha256(initial).hexdigest(),
        expected_info=info, owner_uid=uid, owner_gid=gid,
    )
    assert path.read_bytes() == replacement
    assert stat.S_IMODE(path.lstat().st_mode) == 0o644
    assert not list(tmp_path.glob(".runtime-attestation.json.*.tmp"))
    # stale digest: caller believes the old bytes are still present
    with pytest.raises(ValueError, match="differs|changed"):
        installer._replace_runtime_attestation(
            path, b'{"active": false}\n',
            expected_sha256=hashlib.sha256(initial).hexdigest(),
            expected_info=path.lstat(), owner_uid=uid, owner_gid=gid,
        )
    # stale inode: the file was replaced underneath the caller
    stale_info = path.lstat()
    path.unlink()
    path.write_bytes(replacement)
    path.chmod(0o644)
    with pytest.raises(ValueError, match="changed before update"):
        installer._replace_runtime_attestation(
            path, b'{"active": false}\n',
            expected_sha256=hashlib.sha256(replacement).hexdigest(),
            expected_info=stale_info, owner_uid=uid, owner_gid=gid,
        )
    # symlink swap and wrong owner expectation both fail closed
    real = tmp_path / "real.json"
    real.write_bytes(replacement)
    real.chmod(0o644)
    link = tmp_path / "link.json"
    link.symlink_to(real)
    with pytest.raises(ValueError):
        installer._replace_runtime_attestation(
            link, b'{"active": false}\n',
            expected_sha256=hashlib.sha256(replacement).hexdigest(),
            expected_info=real.lstat(), owner_uid=uid, owner_gid=gid,
        )
    with pytest.raises(ValueError, match="changed before update"):
        installer._replace_runtime_attestation(
            path, b'{"active": false}\n',
            expected_sha256=hashlib.sha256(replacement).hexdigest(),
            expected_info=path.lstat(),
        )
    assert path.read_bytes() == replacement


def test_runtime_attestation_state_transitions_through_the_replacement_primitive(tmp_path, monkeypatch):
    """Render -> stage -> activate -> rollback attestation updates succeed on a
    rendered attestation with runtime_attestation_path present, where the
    previous immutable writer refused every changed state."""
    from hermes_cli import kanban_broker_install as installer

    plan = _render(tmp_path)
    payloads = plan["asset_payload_manifest"]["payloads"]
    attestation_raw = next(
        base64.b64decode(value) for path, value in payloads.items()
        if path.endswith("runtime-attestation.json")
    )
    attestation_path = tmp_path / "runtime-attestation.json"
    attestation_path.write_bytes(attestation_raw)
    attestation_path.chmod(0o644)
    uid, gid = attestation_path.lstat().st_uid, attestation_path.lstat().st_gid
    service_config = json.loads(base64.b64decode(next(
        value for path, value in payloads.items() if path.endswith("/config/service.json")
    )))
    config = {**service_config, "runtime_attestation_path": str(attestation_path)}
    service_config_path = tmp_path / "service.json"
    service_config_path.write_text(json.dumps(config), encoding="utf-8")
    # The unprivileged runner cannot create root-owned files: the attestation
    # owner seam points at the test uid while the real descriptor-relative
    # replacement, digest/inode binding and readback run unchanged.  The
    # root-owned runtime manifest and publisher probe observations are the
    # only pieces represented rather than executed here.
    monkeypatch.setattr(installer, "RUNTIME_ATTESTATION_OWNER", (uid, gid))
    monkeypatch.setattr(installer, "_read_runtime_manifest_file", lambda *args, **kwargs: {"entries": []})
    config.pop("publisher_probe_path", None)
    installer._update_runtime_attestation(config, service_config_path=service_config_path, active=False, revoked=True)
    staged = json.loads(attestation_path.read_bytes())
    assert (staged["active"], staged["revoked"], staged["isolated_probe"]["outcome"]) == (False, True, "PENDING")
    probe = {"command": [config["python_executable"], "-I", "-B", str(Path(config["python_executable"]).parent.parent / "runtime-probe.py")], "outcome": "PASS"}
    installer._update_runtime_attestation(
        config, service_config_path=service_config_path, active=True, revoked=False,
        isolated_probe=probe, publisher_probe_status="PASS",
    )
    active = json.loads(attestation_path.read_bytes())
    assert (active["active"], active["revoked"], active["publisher_probe_status"]) == (True, False, "PASS")
    assert active["isolated_probe"] == probe
    installer._update_runtime_attestation(config, service_config_path=service_config_path, active=False, revoked=True)
    rolled_back = json.loads(attestation_path.read_bytes())
    assert (rolled_back["active"], rolled_back["revoked"]) == (False, True)
    assert rolled_back["isolated_probe"] == probe
    with pytest.raises(ValueError, match="cannot activate"):
        installer._update_runtime_attestation(
            config, service_config_path=service_config_path, active=True, revoked=False,
            isolated_probe={**probe, "outcome": "PENDING"}, publisher_probe_status="PASS",
        )


def _radulator_style_manifest(script_dir: Path) -> tuple[list[dict], str]:
    """Radulator's ``_source_manifest`` algorithm, restated for the fixture."""
    entries = []
    for name in ("lifecycle_controller.py", "publisher_service_install.py", "trusted_publisher.py", "trusted_publisher_cron.sh"):
        content = (script_dir / name).read_bytes()
        entries.append({"path": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest(), "mode": 0o555 if name.endswith(".sh") else 0o444})
    entries.sort(key=lambda item: item["path"])
    digest = hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return entries, digest


def test_renderer_binds_the_radulator_publisher_asset_manifest(tmp_path):
    from hermes_cli import kanban_broker_install as installer

    plan = _render(tmp_path)
    payloads = plan["asset_payload_manifest"]["payloads"]
    service_config = json.loads(base64.b64decode(next(
        value for path, value in payloads.items() if path.endswith("/config/service.json")
    )))
    entries, digest = _radulator_style_manifest(tmp_path / "radulator-checkout/ops/hermes/radulator")
    assert service_config["radulator_publisher_asset_manifest_sha256"] == digest
    probe, probe_sha = _publisher_probe(tmp_path)
    bound = installer._validate_radulator_publisher_source(
        tmp_path / "radulator-checkout",
        expected_source_sha=_radulator_source_sha(tmp_path),
        publisher_probe=probe,
        publisher_probe_sha256=probe_sha,
        git_executable=Path("/usr/bin/git"),
    )
    assert bound["publisher_asset_manifest"] == entries
    assert bound["publisher_asset_manifest_sha256"] == digest
    # Replacing any reviewed asset after the commit is rejected, not re-hashed.
    cron = tmp_path / "radulator-checkout/ops/hermes/radulator/trusted_publisher_cron.sh"
    original = cron.read_bytes()
    cron.write_bytes(original + b"echo tampered\n")
    try:
        with pytest.raises(ValueError, match="clean|reviewed Git blob"):
            installer._validate_radulator_publisher_source(
                tmp_path / "radulator-checkout",
                expected_source_sha=_radulator_source_sha(tmp_path),
                publisher_probe=probe,
                publisher_probe_sha256=probe_sha,
                git_executable=Path("/usr/bin/git"),
            )
    finally:
        cron.write_bytes(original)


def test_publisher_asset_manifest_matches_radulators_own_installer_when_available():
    """Digest parity with the real Radulator installer on a real clean checkout."""
    import importlib.util

    from hermes_cli import kanban_broker_install as installer

    checkout = Path.home() / "Documents/Codex-works/Radulator-source"
    module_path = checkout / "ops/hermes/radulator/publisher_service_install.py"
    if not module_path.is_file():
        pytest.skip("real Radulator checkout is not available on this host")
    status = subprocess.run(
        ["/usr/bin/git", "-C", str(checkout), "status", "--porcelain=v1", "--untracked-files=all"],
        check=True, capture_output=True, text=True,
    ).stdout
    if status:
        pytest.skip("real Radulator checkout is not clean")
    head = subprocess.run(
        ["/usr/bin/git", "-C", str(checkout), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    probe = module_path.parent / "trusted_publisher.py"
    bound = installer._validate_radulator_publisher_source(
        checkout,
        expected_source_sha=head,
        publisher_probe=probe,
        publisher_probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
        git_executable=Path("/usr/bin/git"),
    )
    spec = importlib.util.spec_from_file_location("radulator_publisher_service_install", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert tuple(module.SOURCE_ASSETS) == installer.RADULATOR_PUBLISHER_ASSETS
    entries, digest = module._source_manifest(module_path.parent, expected_uid=os.getuid())
    assert bound["publisher_asset_manifest"] == entries
    assert bound["publisher_asset_manifest_sha256"] == digest

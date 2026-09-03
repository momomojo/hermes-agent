"""Render the disabled-first macOS launchd broker service definition."""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import grp
import gzip
import hashlib
import hmac
import io
import json
import os
import plistlib
import posixpath
import pwd
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, cast

from hermes_cli.kanban_dedicated_broker import KANBAN_BROKER_SECURITY_BOUNDARY


ACTIVATION_CANARY_CONTRACT = "hermes.kanban_broker_activation_canary.v1"
ACTIVATION_CANARY_CHECKS = (
    "root_execution",
    "identity_separation",
    "group_separation",
    "socket_parent_traversal",
    "state_denied_model",
    "authority_db_denied_model",
    "workspace_edit_secret_denied",
    "publisher_bundle_matrix",
    "controller_socket_matrix",
    "publisher_socket_matrix",
    "operator_socket_matrix",
    "worker_socket_matrix",
    "network_denied",
    "credential_env_scrubbed",
    "routing_profile_binding",
    "publisher_runtime_preflight",
    "isolated_runtime_import",
    "model_terminal_denied",
    "computer_use_denied_by_uid",
)
_ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
_MAX_POSIX_ID = 2**31 - 2
_MAX_RUNTIME_FILE_BYTES = 4 * 1024 * 1024
_MAX_RUNTIME_ARCHIVE_FILE_BYTES = 32 * 1024 * 1024
_MAX_RUNTIME_PACKAGE_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_PACKAGE_ENTRIES = 4096
_MAX_RUNTIME_ARCHIVE_BYTES = 128 * 1024 * 1024
_MAX_RUNTIME_ARCHIVE_UNPACKED_BYTES = 384 * 1024 * 1024
_MAX_RUNTIME_ARCHIVE_ENTRIES = 100_000
OFFICIAL_RUNTIME_RELEASE = "20260602"
OFFICIAL_RUNTIME_ASSET_ID = 436826623
OFFICIAL_RUNTIME_VERSION = "3.11.15"
OFFICIAL_RUNTIME_ARCHIVE_SHA256 = "01f0de017aacd7528084dbacd46c66cfe9a0b0cd1255be0c24854b7985dd130e"
SEALED_RUNTIME_CONTRACT = "hermes.kanban_broker_sealed_runtime.v1"
RUNTIME_MANIFEST_CONTRACT = "hermes.kanban_broker_runtime_manifest.v1"
HERMES_INSTALL_PROVENANCE_CONTRACT = "hermes.kanban_broker_hermes_install_provenance.v1"
HERMES_INSTALL_BUILDER_CONTRACT = "hermes.kanban_broker_hermes_install_builder.v1"
HERMES_INSTALL_PROVENANCE_FIELDS = frozenset({
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
})
HERMES_INSTALL_PROVENANCE_SEAL_FIELDS = frozenset({
    "contract",
    "schema_version",
    "fields",
    "hermes_source_sha",
    "install_archive_sha256",
    "provenance_sha256",
    "entry_count",
    "locked_package_count",
    "installed_distribution_count",
})
PUBLISHER_PROBE_CONTRACT = "radulator.publisher_runtime_preflight.v1"
OFFICIAL_RUNTIME_SOURCE_REPOSITORY = "astral-sh/python-build-standalone"
OFFICIAL_RUNTIME_RELEASE_TAG = "20260602"
OFFICIAL_RUNTIME_ASSET_NAME = (
    "cpython-3.11.15+20260602-aarch64-apple-darwin-install_only.tar.gz"
)
OFFICIAL_RUNTIME_RELEASE_URL = (
    "https://github.com/astral-sh/python-build-standalone/releases/download/"
    f"{OFFICIAL_RUNTIME_RELEASE_TAG}/{OFFICIAL_RUNTIME_ASSET_NAME}"
)
OFFICIAL_RUNTIME_VERIFICATION_STATUS = "external-sha256-bound"
OFFICIAL_RUNTIME_ATTESTATION_IDENTITY = "operator-supplied-sha256"
OFFICIAL_RUNTIME_ATTESTATION_STATUS = "bound-no-signature"

# These contracts describe the reviewed, data-only provisioning edge.  The
# existing v1 identity/filesystem/service contracts remain the apply boundary;
# this outer plan binds them together without changing the service lifecycle.
BROKER_INSTALL_PLAN_CONTRACT = "hermes.kanban_broker_install_plan.v1"
HOST_IDENTITY_INVENTORY_CONTRACT = "hermes.kanban_broker_host_inventory.v1"
DESIRED_IDENTITIES_CONTRACT = "hermes.kanban_broker_desired_identities.v1"
REMOTE_POLICY_CONTRACT = "hermes.github_repository.v1"
ASSET_PAYLOAD_CONTRACT = "hermes.kanban_broker_asset_payloads.v1"
RUNTIME_ENTRYPOINT_CONTENT = """#!/bin/false
\"\"\"Self-contained Hermes broker runtime entrypoint.\"\"\"
from __future__ import annotations

import importlib
import runpy
import sys
from pathlib import Path


def main() -> int:
    # The entrypoint is invoked as ``python3 -I entrypoint -m module ...``.
    # -I removes PYTHONPATH and the ambient checkout.  Hermes is installed in
    # the interpreter's real site-packages directory so direct ``python -I
    # script.py`` callers (including Radulator) use this same sealed closure.
    runtime_root = Path(__file__).resolve().parent.parent
    site_packages = runtime_root / "lib" / "python3.11" / "site-packages"
    sys.path.insert(0, str(site_packages))
    if not (str(runtime_root) == sys.prefix == sys.base_prefix):
        raise SystemExit("sealed runtime prefix is outside the install root")
    if not (sys.version_info >= (3, 11) and sys.version_info < (3, 14)):
        raise SystemExit("sealed runtime Python version is unsupported")
    if any(
        not (Path(path).resolve() == runtime_root
             or runtime_root in Path(path).resolve().parents)
        for path in sys.path if path
    ):
        raise SystemExit("sealed runtime sys.path escaped the install root")
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-import":
        module = importlib.import_module(sys.argv[2])
        module_path = getattr(module, "__file__", None)
        if not module_path:
            raise SystemExit("sealed runtime module has no file identity")
        resolved_module = Path(module_path).resolve()
        if not (resolved_module == runtime_root
                or runtime_root in resolved_module.parents):
            raise SystemExit("sealed runtime module escaped the install root")
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--verify-runtime":
        module = importlib.import_module("hermes_cli.kanban_broker_client")
        module_path = getattr(module, "__file__", None)
        if not module_path:
            raise SystemExit("Hermes broker client has no file identity")
        resolved_module = Path(module_path).resolve()
        if not (resolved_module == runtime_root
                or runtime_root in resolved_module.parents):
            raise SystemExit("Hermes broker client escaped the install root")
        return 0
    if len(sys.argv) < 3 or sys.argv[1] != "-m":
        raise SystemExit("runtime entrypoint requires -m module")
    module = sys.argv[2]
    sys.argv[:] = [module, *sys.argv[3:]]
    runpy.run_module(module, run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""
RUNTIME_DIRECT_PROBE_CONTENT = """#!/bin/false
\"\"\"Direct isolated-script canary for the sealed Hermes runtime.\"\"\"
from __future__ import annotations

import importlib
import sys
from pathlib import Path

runtime_root = Path(__file__).resolve().parent
if not (str(runtime_root) == sys.prefix == sys.base_prefix):
    raise SystemExit(\"sealed runtime prefix is outside the install root\")
if not (sys.version_info >= (3, 11) and sys.version_info < (3, 14)):
    raise SystemExit(\"sealed runtime Python version is unsupported\")
for path in sys.path:
    if path:
        resolved = Path(path).resolve()
        if resolved != runtime_root and runtime_root not in resolved.parents:
            raise SystemExit(\"sealed runtime sys.path escaped the install root\")
module = importlib.import_module(\"hermes_cli.kanban_broker_client\")
module_path = getattr(module, \"__file__\", None)
if not module_path:
    raise SystemExit(\"Hermes broker client has no file identity\")
resolved_module = Path(module_path).resolve()
if resolved_module != runtime_root and runtime_root not in resolved_module.parents:
    raise SystemExit(\"Hermes broker client escaped the install root\")
"""


def render_broker_service_config(
    *,
    install_root: Path,
    service_config_path: Path | None = None,
    state_dir: Path,
    workspace_root: Path,
    worker_hermes_root: Path,
    publisher_handoff_root: Path,
    controller_socket: Path,
    publisher_socket: Path,
    operator_socket: Path,
    worker_socket: Path,
    controller_key_path: Path,
    publisher_key_path: Path,
    operator_key_path: Path,
    broker_uid: int,
    broker_gid: int,
    model_uid: int,
    controller_uid: int,
    controller_gid: int,
    publisher_uid: int,
    publisher_gid: int,
    operator_uid: int,
    operator_gid: int,
    workspace_gid: int,
    trusted_publisher_enabled: bool,
    python_executable: Path = Path("/usr/bin/python3"),
    python_sha256: str | None = None,
    git_executable: Path = Path("/usr/bin/git"),
    package_root: Path | None = None,
    package_manifest_sha256: str | None = None,
    canary_key_path: Path | None = None,
    seatbelt_profile_path: Path | None = None,
    launchd_plist_path: Path | None = None,
    worker_launchd_plist_path: Path | None = None,
    runtime_entrypoint_path: Path | None = None,
    runtime_entrypoint_sha256: str | None = None,
    remote_policy_path: Path | None = None,
    remote_policy_source_sha: str | None = None,
    dispatcher_profile: str | None = None,
    dispatcher_routing_config_path: Path | None = None,
    dispatcher_profile_config_path: Path | None = None,
    publisher_probe_path: Path | None = None,
    publisher_probe_sha256: str | None = None,
    publisher_client_config: Path | None = None,
    controller_client_config: Path | None = None,
    operator_client_config: Path | None = None,
    publisher_repository_id: str | None = None,
    registration_file_path: Path | None = None,
    runtime_attestation_path: Path | None = None,
    runtime_manifest_path: Path | None = None,
    runtime_manifest_sha256: str | None = None,
    hermes_source_sha: str | None = None,
    hermes_install_archive_sha256: str | None = None,
    python_version: str | None = None,
    install_nonce: str | None = None,
) -> str:
    """Render install-time broker assets in the mandatory disabled state."""
    validate_identity_separation(
        broker_uid=broker_uid,
        model_uid=model_uid,
        controller_uid=controller_uid,
        publisher_uid=publisher_uid,
    )
    broker_uid = _validated_positive_id(broker_uid, field="broker uid")
    broker_gid = _validated_positive_id(broker_gid, field="broker gid")
    controller_uid = _validated_positive_id(controller_uid, field="controller uid")
    controller_gid = _validated_positive_id(controller_gid, field="controller gid")
    publisher_uid = _validated_positive_id(publisher_uid, field="publisher uid")
    publisher_gid = _validated_positive_id(publisher_gid, field="publisher gid")
    model_uid = _validated_positive_id(model_uid, field="model uid")
    workspace_gid = _validated_positive_id(workspace_gid, field="workspace gid")
    operator_uid = _validated_nonnegative_id(operator_uid, field="operator uid")
    operator_gid = _validated_nonnegative_id(operator_gid, field="operator gid")
    if trusted_publisher_enabled is not False:
        raise ValueError("publisher activation must remain false during asset install")
    if (
        package_root is None
        or package_manifest_sha256 is None
        or canary_key_path is None
        or launchd_plist_path is None
        or worker_launchd_plist_path is None
    ):
        raise ValueError("immutable runtime and canary key bindings are required")
    if not re.fullmatch(r"[0-9a-f]{64}", str(package_manifest_sha256)):
        raise ValueError("package manifest digest is invalid")
    python_executable = Path(python_executable)
    git_executable = Path(git_executable)
    install_root = Path(install_root)
    package_root = Path(package_root)
    canary_key_path = Path(canary_key_path)
    seatbelt_profile_path = Path(
        seatbelt_profile_path
        if seatbelt_profile_path is not None
        else Path(state_dir) / "broker.sb"
    )
    launchd_plist_path = Path(launchd_plist_path)
    worker_launchd_plist_path = Path(worker_launchd_plist_path)
    if runtime_entrypoint_path is not None:
        runtime_entrypoint_path = Path(runtime_entrypoint_path)
        if not re.fullmatch(r"[0-9a-f]{64}", str(runtime_entrypoint_sha256)):
            raise ValueError("runtime entrypoint digest is invalid")
    elif runtime_entrypoint_sha256 is not None:
        raise ValueError("runtime entrypoint digest requires an entrypoint path")
    if remote_policy_path is not None:
        remote_policy_path = Path(remote_policy_path)
        if not re.fullmatch(r"[0-9a-f]{40}", str(remote_policy_source_sha)):
            raise ValueError("remote policy source SHA is invalid")
    elif remote_policy_source_sha is not None:
        raise ValueError("remote policy source SHA requires a policy path")
    if runtime_attestation_path is not None:
        runtime_attestation_path = Path(runtime_attestation_path)
    if runtime_manifest_path is not None:
        runtime_manifest_path = Path(runtime_manifest_path)
    for runtime_path in (
        python_executable,
        git_executable,
        install_root,
        package_root,
        canary_key_path,
        seatbelt_profile_path,
        launchd_plist_path,
        worker_launchd_plist_path,
        *([runtime_entrypoint_path] if runtime_entrypoint_path is not None else []),
        *([remote_policy_path] if remote_policy_path is not None else []),
        *([runtime_attestation_path] if runtime_attestation_path is not None else []),
        *([runtime_manifest_path] if runtime_manifest_path is not None else []),
        *([publisher_probe_path] if publisher_probe_path is not None else []),
        *([publisher_client_config] if publisher_client_config is not None else []),
        *([registration_file_path] if registration_file_path is not None else []),
    ):
        if not runtime_path.is_absolute():
            raise ValueError("broker runtime identity paths must be absolute")
    for private_path in (
        Path(state_dir),
        Path(workspace_root),
        Path(worker_hermes_root),
        Path(publisher_handoff_root),
        Path(controller_socket),
        Path(publisher_socket),
        Path(operator_socket),
        Path(worker_socket),
        Path(controller_key_path),
        Path(publisher_key_path),
        Path(operator_key_path),
        package_root,
        canary_key_path,
        seatbelt_profile_path,
        *([runtime_entrypoint_path] if runtime_entrypoint_path is not None else []),
        *([remote_policy_path] if remote_policy_path is not None else []),
        *([runtime_attestation_path] if runtime_attestation_path is not None else []),
        *([runtime_manifest_path] if runtime_manifest_path is not None else []),
        *([publisher_probe_path] if publisher_probe_path is not None else []),
        *([publisher_client_config] if publisher_client_config is not None else []),
        *([registration_file_path] if registration_file_path is not None else []),
    ):
        if private_path == install_root or install_root not in private_path.parents:
            raise ValueError("broker private assets must be below the install root")
    payload = {
        "contract": "hermes.kanban_broker_service_config.v1",
        "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
        "enabled": False,
        "trusted_publisher_enabled": False,
        "max_inflight": 8,
        "install_nonce": install_nonce or secrets.token_hex(32),
        "install_root": str(install_root),
        "state_dir": str(Path(state_dir)),
        "workspace_root": str(Path(workspace_root)),
        "worker_hermes_root": str(Path(worker_hermes_root)),
        "publisher_handoff_root": str(Path(publisher_handoff_root)),
        "controller_socket": str(Path(controller_socket)),
        "publisher_socket": str(Path(publisher_socket)),
        "operator_socket": str(Path(operator_socket)),
        "worker_socket": str(Path(worker_socket)),
        "controller_key_path": str(Path(controller_key_path)),
        "publisher_key_path": str(Path(publisher_key_path)),
        "operator_key_path": str(Path(operator_key_path)),
        "broker_uid": int(broker_uid),
        "broker_gid": int(broker_gid),
        "model_uid": int(model_uid),
        "controller_uid": int(controller_uid),
        "controller_gid": int(controller_gid),
        "publisher_uid": int(publisher_uid),
        "publisher_gid": int(publisher_gid),
        "operator_uid": int(operator_uid),
        "operator_gid": int(operator_gid),
        "workspace_gid": int(workspace_gid),
        "python_executable": str(python_executable),
        "python_sha256": (
            _validated_hex_sha(python_sha256, field="Python SHA256", length=64)
            if python_sha256 is not None
            else _safe_file_sha256(python_executable)
        ),
        "git_executable": str(git_executable),
        "git_sha256": _safe_file_sha256(git_executable),
        "package_root": str(package_root),
        "package_manifest_sha256": str(package_manifest_sha256),
        "canary_key_path": str(canary_key_path),
        "seatbelt_profile_path": str(seatbelt_profile_path),
        "launchd_plist_path": str(launchd_plist_path),
        "worker_launchd_plist_path": str(worker_launchd_plist_path),
    }
    if service_config_path is not None:
        service_path = Path(service_config_path)
        if not service_path.is_absolute() or ".." in service_path.parts:
            raise ValueError("service config path is invalid")
        payload["service_config_path"] = str(service_path)
    if runtime_entrypoint_path is not None:
        payload["runtime_entrypoint_path"] = str(runtime_entrypoint_path)
        payload["runtime_entrypoint_sha256"] = str(runtime_entrypoint_sha256)
    if remote_policy_path is not None:
        payload["remote_policy_path"] = str(remote_policy_path)
        payload["remote_policy_source_sha"] = str(remote_policy_source_sha)
    if dispatcher_profile is not None:
        if not isinstance(dispatcher_profile, str) or not dispatcher_profile:
            raise ValueError("dispatcher profile is required when provided")
        payload["dispatcher_profile"] = dispatcher_profile
    if dispatcher_routing_config_path is not None:
        routing_path = Path(dispatcher_routing_config_path)
        if not routing_path.is_absolute() or ".." in routing_path.parts:
            raise ValueError("dispatcher routing config path is invalid")
        payload["dispatcher_routing_config_path"] = str(routing_path)
    if dispatcher_profile_config_path is not None:
        profile_config_path = Path(dispatcher_profile_config_path)
        if not profile_config_path.is_absolute() or ".." in profile_config_path.parts:
            raise ValueError("dispatcher profile config path is invalid")
        payload["dispatcher_profile_config_path"] = str(profile_config_path)
    if publisher_probe_path is not None:
        publisher_probe_path = Path(publisher_probe_path)
        if not publisher_probe_path.is_absolute() or ".." in publisher_probe_path.parts:
            raise ValueError("publisher preflight script path is invalid")
        if publisher_probe_sha256 is None:
            raise ValueError("publisher preflight script digest is required")
        payload["publisher_probe_path"] = str(publisher_probe_path)
        payload["publisher_probe_sha256"] = _validated_hex_sha(
            publisher_probe_sha256, field="publisher preflight script SHA256", length=64
        )
        payload["publisher_probe_contract"] = PUBLISHER_PROBE_CONTRACT
    elif publisher_probe_sha256 is not None:
        raise ValueError("publisher preflight script path is required for its digest")
    if publisher_client_config is not None:
        publisher_client_config = Path(publisher_client_config)
        if not publisher_client_config.is_absolute() or ".." in publisher_client_config.parts:
            raise ValueError("publisher client config path is invalid")
        payload["publisher_client_config"] = str(publisher_client_config)
    for client_name, client_path in (
        ("controller_client_config", controller_client_config),
        ("operator_client_config", operator_client_config),
    ):
        if client_path is None:
            continue
        client_path = Path(client_path)
        if not client_path.is_absolute() or ".." in client_path.parts:
            raise ValueError(f"{client_name} path is invalid")
        payload[client_name] = str(client_path)
    if publisher_repository_id is not None:
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", str(publisher_repository_id)) is None:
            raise ValueError("publisher repository id is invalid")
        payload["publisher_repository_id"] = str(publisher_repository_id)
    if registration_file_path is not None:
        registration_file_path = Path(registration_file_path)
        if not registration_file_path.is_absolute() or ".." in registration_file_path.parts:
            raise ValueError("broker registration file path is invalid")
        payload["registration_file_path"] = str(registration_file_path)
    if runtime_attestation_path is not None:
        payload["runtime_attestation_path"] = str(runtime_attestation_path)
    if runtime_manifest_path is not None:
        payload["runtime_manifest_path"] = str(runtime_manifest_path)
        payload["runtime_manifest_sha256"] = _validated_hex_sha(
            runtime_manifest_sha256, field="runtime manifest SHA256", length=64
        )
    elif any(value is not None for value in (runtime_manifest_sha256, hermes_source_sha,
                                              hermes_install_archive_sha256,
                                              python_version)):
        raise ValueError("runtime manifest path is required for runtime metadata")
    if hermes_source_sha is not None:
        payload["hermes_source_sha"] = _validated_hex_sha(
            hermes_source_sha, field="Hermes source SHA", length=40
        )
    if hermes_install_archive_sha256 is not None:
        payload["hermes_install_archive_sha256"] = _validated_hex_sha(
            hermes_install_archive_sha256,
            field="Hermes install archive SHA256",
            length=64,
        )
    if python_version is not None:
        if python_version != OFFICIAL_RUNTIME_VERSION:
            raise ValueError("Python runtime version is not the reviewed version")
        payload["python_version"] = python_version
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _safe_file_sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    target = Path(path)
    parent_fd: int | None = None
    try:
        parent_fd = _open_directory_fd(target.parent)
        parent_before = os.fstat(parent_fd)
        fd = os.open(target.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise ValueError("runtime identity file is unavailable") from exc
    try:
        before = os.fstat(fd)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("runtime identity file must be a real file")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("runtime identity file changed during hashing")
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev, parent_after.st_ino
        ):
            raise ValueError("runtime identity file parent changed during hashing")
        return digest.hexdigest()
    finally:
        os.close(fd)
        os.close(parent_fd)


def _read_sealed_file_bytes(
    path: Path,
    *,
    max_bytes: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one regular file through an O_NOFOLLOW descriptor with readback."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    target = Path(path)
    parent_fd: int | None = None
    try:
        parent_fd = _open_directory_fd(target.parent)
        parent_before = os.fstat(parent_fd)
        fd = os.open(target.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise ValueError("sealed file is unavailable") from exc
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > int(max_bytes)):
            raise ValueError("sealed file is not a bounded regular file")
        if expected_size is not None and before.st_size != int(expected_size):
            raise ValueError("sealed file size differs from the reviewed input")
        chunks: list[bytes] = []
        remaining = int(max_bytes) + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != before.st_size or len(content) > int(max_bytes):
            raise ValueError("sealed file changed or exceeds the size limit")
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("sealed file changed during read")
        if expected_sha256 is not None and hashlib.sha256(content).hexdigest() != expected_sha256:
            raise ValueError("sealed file digest differs from the reviewed input")
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev, parent_after.st_ino
        ):
            raise ValueError("sealed file parent changed during read")
        return content, before
    finally:
        os.close(fd)
        os.close(parent_fd)


def _apple_system_binary_sha256(path: Path) -> str:
    """Pin an Apple system executable without treating cryptex hardlinks as mutable."""
    binary = Path(path)
    if binary != Path("/usr/bin/git"):
        raise ValueError("Git executable must be the reviewed Apple /usr/bin/git")
    info = binary.lstat()
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o111
    ):
        raise ValueError("Apple Git executable is mutable or unsafe")
    return _safe_file_sha256(binary)


def runtime_package_manifest(
    package_root: Path, *, expected_owner_uid: int, expected_owner_gid: int | None = None
) -> dict[str, object]:
    """Hash a symlink-free, owner-pinned immutable Python package tree."""

    root = Path(package_root)
    root_info = root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != int(expected_owner_uid)
        or (
            expected_owner_gid is not None
            and root_info.st_gid != int(expected_owner_gid)
        )
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise ValueError("runtime package root is mutable or unsafe")
    entries: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda value: value.name):
            info = child.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or info.st_uid != int(expected_owner_uid)
                or (
                    expected_owner_gid is not None
                    and info.st_gid != int(expected_owner_gid)
                )
            ):
                raise ValueError("runtime package contains a symlink or wrong owner")
            relative = child.relative_to(root).as_posix()
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o022:
                raise ValueError("runtime package contains a mutable path")
            if child.name == "__pycache__" or child.suffix in {".pyc", ".pyo"}:
                continue
            if stat.S_ISDIR(info.st_mode):
                entries.append({"path": relative + "/", "mode": mode})
                pending.append(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                entries.append({
                    "path": relative,
                    "mode": mode,
                    "size": int(info.st_size),
                    "sha256": _safe_file_sha256(child),
                })
            else:
                raise ValueError("runtime package contains a special or linked file")
    entries.sort(key=lambda item: str(item["path"]))
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"entries": entries, "sha256": hashlib.sha256(encoded).hexdigest()}


def render_runtime_package_assets(
    *, source_root: Path, destination_root: Path
) -> dict[str, object]:
    """Snapshot package bytes into a root-owned immutable install plan.

    The returned payloads must be serialized into the root-owned asset payload
    manifest consumed by ``provision-assets``.  Their hashes and destination
    modes reproduce ``runtime_package_manifest`` exactly after installation.
    """

    source_input = Path(source_root)
    if not source_input.is_absolute():
        raise ValueError("runtime package source must be absolute")
    _validated_install_path(source_input, field="runtime package source", allow_root=True)
    if source_input.is_symlink():
        raise ValueError("runtime package source must not be a symlink")
    source = source_input.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("runtime package source must be a directory")
    destination = Path(destination_root)
    if not destination.is_absolute():
        raise ValueError("runtime package destination must be absolute")
    _validated_install_path(destination, field="runtime package destination", allow_root=True)
    if destination == Path(destination.anchor):
        raise ValueError("runtime package destination must be bounded")
    if destination.is_symlink():
        raise ValueError("runtime package destination must not be a symlink")
    directories = [{"path": str(destination), "uid": 0, "gid": 0, "mode": 0o555}]
    files: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    manifest_entries: list[dict[str, object]] = []
    package_bytes = 0
    for item in sorted(source.rglob("*"), key=lambda value: value.as_posix()):
        relative = item.relative_to(source)
        if "__pycache__" in relative.parts or item.suffix in {".pyc", ".pyo"}:
            continue
        info = item.lstat()
        target = destination.joinpath(*relative.parts)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("runtime source package contains a symlink")
        if len(manifest_entries) >= _MAX_RUNTIME_PACKAGE_ENTRIES:
            raise ValueError("runtime source package contains too many entries")
        if stat.S_ISDIR(info.st_mode):
            directories.append({"path": str(target), "uid": 0, "gid": 0, "mode": 0o555})
            manifest_entries.append({"path": relative.as_posix() + "/", "mode": 0o555})
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("runtime source package contains a special file")
        if info.st_size > _MAX_RUNTIME_FILE_BYTES or package_bytes + info.st_size > _MAX_RUNTIME_PACKAGE_BYTES:
            raise ValueError("runtime source package exceeds the size limit")
        content = item.read_bytes()
        if len(content) > _MAX_RUNTIME_FILE_BYTES or package_bytes + len(content) > _MAX_RUNTIME_PACKAGE_BYTES:
            raise ValueError("runtime source package changed beyond the size limit")
        package_bytes += len(content)
        mode = 0o555 if stat.S_IMODE(info.st_mode) & 0o111 else 0o444
        digest = hashlib.sha256(content).hexdigest()
        files.append({
            "path": str(target),
            "uid": 0,
            "gid": 0,
            "mode": mode,
            "kind": "runtime_package",
            "sha256": digest,
        })
        payloads[str(target)] = content
        manifest_entries.append({
            "path": relative.as_posix(),
            "mode": mode,
            "size": len(content),
            "sha256": digest,
        })
    manifest_entries.sort(key=lambda item: str(item["path"]))
    manifest_sha = hashlib.sha256(
        json.dumps(manifest_entries, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return {
        "contract": "hermes.kanban_broker_runtime_assets.v1",
        "destination_root": str(destination),
        "directories": directories,
        "files": files,
        "payloads": payloads,
        "package_manifest_sha256": manifest_sha,
    }


def _archive_relative_name(name: str) -> str:
    if (
        not isinstance(name, str)
        or not name
        or "\x00" in name
        or name.startswith("/")
        or "\\" in name
    ):
        raise ValueError("runtime archive member path is unsafe")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("runtime archive member path is unsafe")
    normalized = path.as_posix()
    if normalized != name:
        raise ValueError("runtime archive member path is not normalized")
    return normalized


def _archive_link_target(member_name: str, link_name: str, names: set[str]) -> str:
    if (
        not isinstance(link_name, str)
        or not link_name
        or "\x00" in link_name
        or link_name.startswith("/")
        or "\\" in link_name
    ):
        raise ValueError("runtime archive link target is unsafe")
    parent = PurePosixPath(member_name).parent
    target = PurePosixPath(posixpath.normpath((parent / link_name).as_posix()))
    if target.is_absolute() or any(part in {"", ".", ".."} for part in target.parts):
        raise ValueError("runtime archive link target escapes the sealed root")
    normalized = target.as_posix()
    if normalized not in names:
        raise ValueError("runtime archive link target is missing")
    return normalized


def _read_runtime_archive_manifest(
    archive_path: Path,
    *,
    expected_sha256: str,
    strip_prefix: str,
    required_paths: set[str],
    role: str,
) -> dict[str, object]:
    """Validate one staged tar archive and return a recursive sealed manifest."""
    archive = _validated_install_path(archive_path, field=f"{role} archive")
    if not archive.is_absolute():
        raise ValueError(f"{role} archive must be an absolute real file")
    digest = _validated_hex_sha(expected_sha256, field=f"{role} archive SHA256", length=64)
    archive_data, info = _read_sealed_file_bytes(
        archive,
        max_bytes=_MAX_RUNTIME_ARCHIVE_BYTES,
        expected_sha256=digest,
    )
    observed = digest
    prefix = _archive_relative_name(strip_prefix.rstrip("/")) + "/"
    entries: list[dict[str, object]] = []
    names: set[str] = set()
    unpacked_bytes = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as stream:
            members = stream.getmembers()
            if len(members) > _MAX_RUNTIME_ARCHIVE_ENTRIES:
                raise ValueError(f"{role} archive contains too many entries")
            for member in members:
                raw_name = member.name.rstrip("/") if member.isdir() else member.name
                name = _archive_relative_name(raw_name)
                if name == prefix[:-1]:
                    continue
                if not name.startswith(prefix):
                    raise ValueError(f"{role} archive contains a path outside {prefix}")
                relative = name[len(prefix):]
                if not relative:
                    continue
                relative = _archive_relative_name(relative)
                if relative in names:
                    raise ValueError(f"{role} archive contains duplicate paths")
                names.add(relative)
            # Directory members are optional in tar archives.  Add implicit
            # parent directories to the link target allow-list so a relative
            # link may safely point at one without permitting an upward path.
            for item in list(names):
                parent = PurePosixPath(item).parent
                while str(parent) not in {"", "."}:
                    names.add(parent.as_posix())
                    parent = parent.parent
            for member in members:
                raw_name = member.name.rstrip("/") if member.isdir() else member.name
                name = _archive_relative_name(raw_name)
                if not name.startswith(prefix) or name == prefix[:-1]:
                    continue
                relative = _archive_relative_name(name[len(prefix):])
                mode = stat.S_IMODE(member.mode)
                if member.isdir():
                    entries.append({"path": relative + "/", "type": "directory", "mode": 0o555})
                    continue
                if member.issym():
                    target = _archive_link_target(relative, member.linkname, names)
                    entries.append({"path": relative, "type": "symlink", "target": target, "mode": 0o555})
                    continue
                if member.islnk() or not member.isfile():
                    raise ValueError(f"{role} archive contains an unsupported special or hard-linked file")
                # The reviewed archives carry ordinary distribution modes
                # (0644/0755, and the pinned CPython asset uses 0664/0775).
                # Harden those source modes for the installed sealed tree.
                # The live verifier below records and compares the resulting
                # exact mode, so a later chmod(2) cannot be normalized away.
                mode = 0o555 if mode & 0o111 else 0o444
                if member.size < 0 or member.size > _MAX_RUNTIME_ARCHIVE_FILE_BYTES or unpacked_bytes + member.size > _MAX_RUNTIME_ARCHIVE_UNPACKED_BYTES:
                    raise ValueError(f"{role} archive exceeds the unpacked size limit")
                handle = stream.extractfile(member)
                if handle is None:
                    raise ValueError(f"{role} archive file cannot be read")
                content = handle.read(_MAX_RUNTIME_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > _MAX_RUNTIME_ARCHIVE_FILE_BYTES:
                    raise ValueError(f"{role} archive file changed or exceeds the size limit")
                unpacked_bytes += len(content)
                digest = hashlib.sha256(content).hexdigest()
                entries.append({
                    "path": relative,
                    "type": "file",
                    "mode": mode,
                    "size": len(content),
                    "sha256": digest,
                })
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{role} archive is not a valid bounded tar.gz") from exc
    entries.sort(key=lambda item: str(item["path"]))
    available = {str(item["path"]).rstrip("/") for item in entries}
    for item in list(available):
        parent = PurePosixPath(item).parent
        while str(parent) not in {"", "."}:
            available.add(parent.as_posix())
            parent = parent.parent
    if not required_paths.issubset(available):
        missing = sorted(required_paths - available)
        raise ValueError(f"{role} archive is missing required runtime paths: {missing}")
    return {
        "source_path": str(archive),
        "sha256": observed,
        "size": int(info.st_size),
        "strip_prefix": prefix,
        "role": role,
        "entries": entries,
    }


def _read_archive_file_contents(
    archive_path: Path, *, strip_prefix: str
) -> dict[str, bytes]:
    """Read bounded regular members for provenance/content validation only."""
    archive_data, _info = _read_sealed_file_bytes(
        Path(archive_path), max_bytes=_MAX_RUNTIME_ARCHIVE_BYTES
    )
    prefix = _archive_relative_name(strip_prefix.rstrip("/")) + "/"
    contents: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as stream:
            members = stream.getmembers()
            if len(members) > _MAX_RUNTIME_ARCHIVE_ENTRIES:
                raise ValueError("runtime archive contains too many entries")
            for member in members:
                raw_name = member.name.rstrip("/") if member.isdir() else member.name
                name = _archive_relative_name(raw_name)
                if not name.startswith(prefix) or name == prefix[:-1]:
                    continue
                relative = _archive_relative_name(name[len(prefix):])
                if not member.isfile():
                    continue
                if member.size < 0 or member.size > _MAX_RUNTIME_ARCHIVE_FILE_BYTES:
                    raise ValueError("runtime archive file exceeds the size limit")
                handle = stream.extractfile(member)
                if handle is None:
                    raise ValueError("runtime archive file cannot be read")
                content = handle.read(_MAX_RUNTIME_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size or len(content) > _MAX_RUNTIME_ARCHIVE_FILE_BYTES:
                    raise ValueError("runtime archive file changed or exceeds the size limit")
                if relative in contents:
                    raise ValueError("runtime archive contains duplicate paths")
                contents[relative] = content
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("runtime archive is not a valid bounded tar.gz") from exc
    return contents


def _read_hermes_install_provenance(
    path: Path,
    *,
    expected_sha256: str,
    expected_archive_sha256: str,
    expected_source_sha: str,
) -> dict[str, object]:
    """Read the externally-built, complete Hermes install provenance record."""
    provenance_path = _validated_install_path(
        path, field="Hermes install provenance manifest"
    )
    expected_digest = _validated_hex_sha(
        expected_sha256, field="Hermes install provenance SHA256", length=64
    )
    try:
        raw, info = _read_sealed_file_bytes(
            provenance_path,
            max_bytes=_MAX_RUNTIME_FILE_BYTES,
            expected_sha256=expected_digest,
        )
    except ValueError as exc:
        raise ValueError("Hermes install provenance manifest digest or file is invalid") from exc
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) not in {0o444, 0o600, 0o644}:
        raise ValueError("Hermes install provenance manifest ownership or mode is unsafe")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Hermes install provenance manifest is invalid JSON") from exc
    if not isinstance(value, dict) or set(value) != HERMES_INSTALL_PROVENANCE_FIELDS:
        raise ValueError(
            "Hermes install provenance must use the modern source-derived schema; "
            "legacy provenance requires migration"
        )
    if value.get("contract") != HERMES_INSTALL_PROVENANCE_CONTRACT or value.get("schema_version") != 1:
        raise ValueError("Hermes install provenance contract is unsupported")
    if value.get("builder_contract") != HERMES_INSTALL_BUILDER_CONTRACT:
        raise ValueError("Hermes install provenance was not produced by the reviewed builder")
    if value.get("hermes_source_sha") != expected_source_sha:
        raise ValueError("Hermes install provenance source SHA differs from the reviewed input")
    _validated_hex_sha(
        value.get("pyproject_lock_sha256"),
        field="Hermes pyproject/lock SHA256",
        length=64,
    )
    _validated_hex_sha(value.get("hermes_source_tree_sha"), field="Hermes source tree SHA", length=40)
    _validated_hex_sha(value.get("pyproject_sha256"), field="Hermes pyproject SHA256", length=64)
    _validated_hex_sha(value.get("uv_lock_sha256"), field="Hermes uv.lock SHA256", length=64)
    if value.get("install_archive_sha256") != expected_archive_sha256:
        raise ValueError("Hermes install provenance archive SHA differs from the staged archive")
    _validated_hex_sha(
        value.get("first_party_git_archive_sha256"),
        field="Hermes first-party Git archive SHA256",
        length=64,
    )
    locked = value.get("locked_packages")
    if not isinstance(locked, list) or len(locked) < 2:
        raise ValueError("Hermes install provenance lock closure is incomplete")
    previous_lock_key: tuple[str, str] | None = None
    for package in locked:
        if not isinstance(package, dict) or set(package) != {"name", "version", "source", "artifacts"}:
            raise ValueError("Hermes install provenance lock record is malformed")
        name, version, source, artifacts = (
            package.get("name"), package.get("version"), package.get("source"), package.get("artifacts")
        )
        if not isinstance(name, str) or not isinstance(version, str) or not isinstance(source, dict) or not isinstance(artifacts, list) or not artifacts:
            raise ValueError("Hermes install provenance lock record is incomplete")
        lock_key = (name.lower().replace("_", "-").replace(".", "-"), version)
        if previous_lock_key is not None and lock_key < previous_lock_key:
            raise ValueError("Hermes install provenance lock records are not ordered")
        previous_lock_key = lock_key
        previous_artifact: tuple[str, str] | None = None
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"url", "sha256", "size"}:
                raise ValueError("Hermes install provenance artifact record is malformed")
            if not isinstance(artifact.get("url"), str) or isinstance(artifact.get("size"), bool) or not isinstance(artifact.get("size"), int) or int(artifact["size"]) <= 0:
                raise ValueError("Hermes install provenance artifact record is incomplete")
            digest = _validated_hex_sha(artifact.get("sha256"), field="Hermes locked artifact SHA256", length=64)
            artifact_key = (str(artifact["url"]), digest)
            if previous_artifact is not None and artifact_key < previous_artifact:
                raise ValueError("Hermes install provenance artifacts are not ordered")
            previous_artifact = artifact_key
    installed = value.get("installed_distributions")
    if not isinstance(installed, list) or not installed:
        raise ValueError("Hermes install provenance has no installed distributions")
    for distribution in installed:
        if not isinstance(distribution, dict) or set(distribution) != {"name", "version", "record"}:
            raise ValueError("Hermes installed distribution record is malformed")
        if not all(isinstance(distribution.get(key), str) and distribution[key] for key in ("name", "version", "record")):
            raise ValueError("Hermes installed distribution record is incomplete")
        _archive_relative_name(str(distribution["record"]))
    installer = value.get("installer")
    if not isinstance(installer, dict) or set(installer) != {"name", "contract", "python"} or installer.get("name") != "uv" or installer.get("contract") != "sync --frozen --no-dev --no-editable":
        raise ValueError("Hermes install provenance installer is not the reviewed locked build")
    entries = value.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Hermes install provenance entry set is empty")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Hermes install provenance entry is malformed")
        entry_type = entry.get("type")
        expected_fields = {
            "path", "type", "mode", "origin",
        }
        if entry_type == "file":
            expected_fields |= {"size", "sha256"}
        elif entry_type == "symlink":
            expected_fields |= {"target"}
        elif entry_type != "directory":
            raise ValueError("Hermes install provenance entry type is unsupported")
        if set(entry) != expected_fields:
            raise ValueError("Hermes install provenance entry fields are not exact")
        path_value = entry.get("path")
        if not isinstance(path_value, str) or path_value in seen:
            raise ValueError("Hermes install provenance has duplicate or invalid paths")
        relative = _archive_relative_name(path_value.rstrip("/") if entry_type == "directory" else path_value)
        if entry_type == "directory":
            relative += "/"
        if relative != path_value:
            raise ValueError("Hermes install provenance path is not normalized")
        origin = entry.get("origin")
        if origin not in {"first-party", "dependency"}:
            raise ValueError("Hermes install provenance origin is invalid")
        mode = entry.get("mode")
        if (
            isinstance(mode, bool)
            or not isinstance(mode, int)
            or mode < 0
            or mode > 0o777
            or mode & 0o222
        ):
            raise ValueError("Hermes install provenance mode is invalid")
        normalized_entry = dict(entry)
        if entry_type == "file":
            if (
                isinstance(entry.get("size"), bool)
                or not isinstance(entry.get("size"), int)
                or entry["size"] < 0
            ):
                raise ValueError("Hermes install provenance file size is invalid")
            _validated_hex_sha(entry.get("sha256"), field="Hermes install file SHA256", length=64)
        seen.add(relative)
        normalized.append(normalized_entry)
    normalized.sort(key=lambda item: str(item["path"]))
    if normalized != entries:
        raise ValueError("Hermes install provenance entries are not deterministically ordered")
    all_names = {str(entry["path"]).rstrip("/") for entry in normalized}
    for entry in normalized:
        if entry["type"] == "symlink":
            _archive_link_target(
                str(entry["path"]), str(entry.get("target") or ""), all_names
            )
    if not any(
        str(entry["path"]).startswith("hermes_cli/")
        and entry["type"] == "file"
        for entry in normalized
    ):
        raise ValueError("Hermes install provenance has no first-party Hermes package")
    if not any(
        not str(entry["path"]).startswith("hermes_cli/")
        and entry["type"] in {"file", "directory"}
        and entry["origin"] == "dependency"
        for entry in normalized
    ):
        raise ValueError("Hermes install provenance has no dependency closure")
    return {**value, "entries": normalized}


def _validate_hermes_install_closure(
    archive_path: Path,
    *,
    archive_sha256: str,
    provenance_path: Path,
    provenance_sha256: str,
    hermes_source_sha: str,
) -> dict[str, object]:
    archive = _read_runtime_archive_manifest(
        archive_path,
        expected_sha256=archive_sha256,
        strip_prefix="hermes-install",
        required_paths={
            "hermes_cli/__init__.py",
            "hermes_cli/main.py",
            "hermes_cli/kanban_broker_canary.py",
            "hermes_cli/kanban_broker_client.py",
            "hermes_cli/kanban_broker_install.py",
            "hermes_cli/kanban_broker_protocol.py",
            "hermes_cli/kanban_broker_service.py",
            "hermes_cli/kanban_broker_worker.py",
            "hermes_cli/kanban_dedicated_broker.py",
            "hermes_constants.py",
            "utils.py",
        },
        role="Hermes install",
    )
    provenance = _read_hermes_install_provenance(
        provenance_path,
        expected_sha256=provenance_sha256,
        expected_archive_sha256=archive_sha256,
        expected_source_sha=hermes_source_sha,
    )
    archive_entries = cast(list[dict[str, object]], archive["entries"])
    provenance_entries = cast(list[dict[str, object]], provenance["entries"])
    comparable_provenance = [
        {key: value for key, value in entry.items() if key != "origin"}
        for entry in provenance_entries
    ]
    if archive_entries != comparable_provenance:
        raise ValueError("Hermes install archive does not match its complete provenance entry set")
    contents = _read_archive_file_contents(archive_path, strip_prefix="hermes-install")
    for entry in cast(list[dict[str, object]], provenance["entries"]):
        if entry["type"] != "file":
            continue
        content = contents.get(str(entry["path"]))
        if content is None or hashlib.sha256(content).hexdigest() != str(entry["sha256"]):
            raise ValueError("Hermes install archive content differs from provenance")
        if str(entry["path"]) in {
            "hermes_cli/__init__.py", "hermes_cli/main.py", "hermes_cli/kanban_broker_canary.py",
            "hermes_cli/kanban_broker_client.py", "hermes_cli/kanban_broker_install.py",
            "hermes_cli/kanban_broker_protocol.py", "hermes_cli/kanban_broker_service.py",
            "hermes_cli/kanban_broker_worker.py", "hermes_cli/kanban_dedicated_broker.py",
            "hermes_constants.py",
            "utils.py",
        }:
            try:
                tree = ast.parse(content.decode("utf-8"), filename=str(entry["path"]))
            except (UnicodeDecodeError, SyntaxError) as exc:
                raise ValueError("Hermes install first-party module is not valid Python") from exc
            executable_nodes = [node for node in tree.body if not isinstance(node, ast.Expr) or not isinstance(getattr(node, "value", None), ast.Constant) or not isinstance(node.value.value, str)]
            if not executable_nodes:
                raise ValueError("Hermes install first-party module is a placeholder")
    main_content = contents.get("hermes_cli/main.py", b"")
    if b"def main" not in main_content:
        raise ValueError("Hermes install main module does not provide the worker entrypoint")
    return {"archive": archive, "provenance": provenance}


def _read_publisher_probe(path: Path, *, expected_sha256: str) -> dict[str, object]:
    """Bind the exact external Radulator preflight script without executing it."""
    probe = _validated_install_path(path, field="publisher preflight script")
    expected = _validated_hex_sha(
        expected_sha256, field="publisher preflight script SHA256", length=64
    )
    try:
        raw, info = _read_sealed_file_bytes(
            probe, max_bytes=_MAX_RUNTIME_FILE_BYTES, expected_sha256=expected
        )
    except ValueError as exc:
        raise ValueError("publisher preflight script digest or file is invalid") from exc
    if (
        info.st_uid not in {0, os.geteuid()}
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in {0o444, 0o555, 0o644}
    ):
        raise ValueError("publisher preflight script ownership or mode is unsafe")
    try:
        ast.parse(raw.decode("utf-8"), filename=str(probe))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise ValueError("publisher preflight script is not valid Python") from exc
    if any(
        token not in raw
        for token in (
            b"kanban_broker_client",
            b"runtime-preflight",
            b"list_publish_obligations",
            b"--broker-client-config",
        )
    ):
        raise ValueError("publisher preflight script does not implement the reviewed contract")
    return {
        "source_path": str(probe),
        "sha256": expected,
        "size": len(raw),
        "contract": PUBLISHER_PROBE_CONTRACT,
    }


def _validate_radulator_publisher_source(
    checkout: Path,
    *,
    expected_source_sha: str,
    publisher_probe: Path,
    publisher_probe_sha256: str,
    git_executable: Path,
) -> dict[str, object]:
    """Bind the preflight to the reviewed Radulator checkout and Git HEAD.

    A digest supplied for an arbitrary Python file is not a trust boundary:
    an operator could point it at a look-alike script which prints PASS.  The
    production path is fixed to the reviewed Radulator source tree, and the
    checkout's immutable HEAD is checked with the pinned Apple Git identity.
    """
    source = Path(checkout)
    expected = _validated_hex_sha(
        expected_source_sha, field="Radulator source SHA", length=40
    )
    if not source.is_absolute() or source == Path(source.anchor):
        raise ValueError("Radulator source checkout must be a bounded absolute directory")
    source_info = source.lstat()
    if (
        stat.S_ISLNK(source_info.st_mode)
        or not stat.S_ISDIR(source_info.st_mode)
        or source_info.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(source_info.st_mode) & 0o022
    ):
        raise ValueError("Radulator source checkout ownership or mode is unsafe")
    expected_probe = source / "ops" / "hermes" / "radulator" / "trusted_publisher.py"
    probe = Path(publisher_probe)
    if probe != expected_probe:
        raise ValueError("publisher preflight script is not the reviewed Radulator path")
    lifecycle = source / "ops" / "hermes" / "radulator" / "lifecycle_controller.py"
    lifecycle_info = lifecycle.lstat()
    if (
        stat.S_ISLNK(lifecycle_info.st_mode)
        or not stat.S_ISREG(lifecycle_info.st_mode)
        or lifecycle_info.st_uid not in {0, os.geteuid()}
        or lifecycle_info.st_nlink != 1
        or stat.S_IMODE(lifecycle_info.st_mode) & 0o022
    ):
        raise ValueError("Radulator lifecycle controller is unsafe or unavailable")
    git = Path(git_executable)
    status = subprocess.run(
        [str(git), "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False, capture_output=True, text=True, timeout=10,
        env=_git_command_environment(),
    )
    if status.returncode != 0 or status.stdout:
        raise ValueError("Radulator source checkout must be clean and source-derived")
    try:
        result = subprocess.run(
            [str(git), "-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Radulator source HEAD cannot be verified") from exc
    head = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[0-9a-f]{40}", head) is None:
        raise ValueError("Radulator source checkout has no verifiable Git HEAD")
    if head != expected:
        raise ValueError("Radulator source SHA does not match Git HEAD")
    # A clean HEAD alone does not bind the two executable inputs: a caller
    # could replace a tracked file and then supply its replacement digest.
    # Compare both bytes and executable mode with the immutable Git blobs.
    reviewed_probe_sha: str | None = None
    for relative, actual in (
        ("ops/hermes/radulator/trusted_publisher.py", probe),
        ("ops/hermes/radulator/lifecycle_controller.py", lifecycle),
    ):
        listing = subprocess.run(
            [str(git), "-C", str(source), "ls-tree", "-z", expected, "--", relative],
            check=False, capture_output=True, timeout=10, env=_git_command_environment(),
        )
        records = listing.stdout.split(b"\0") if listing.returncode == 0 else []
        records = [record for record in records if record]
        if len(records) != 1 or b"\t" not in records[0]:
            raise ValueError("Radulator reviewed source file is not bound to Git")
        metadata, path_bytes = records[0].split(b"\t", 1)
        fields = metadata.split()
        if len(fields) != 3 or fields[1] != b"blob" or path_bytes.decode("utf-8") != relative:
            raise ValueError("Radulator reviewed source Git entry is invalid")
        mode, blob_sha = fields[0], fields[2]
        if mode not in {b"100644", b"100755"} or re.fullmatch(rb"[0-9a-f]{40}", blob_sha) is None:
            raise ValueError("Radulator reviewed source Git mode or blob is invalid")
        blob = subprocess.run(
            [str(git), "-C", str(source), "cat-file", "blob", blob_sha.decode("ascii")],
            check=False, capture_output=True, timeout=10, env=_git_command_environment(),
        )
        if blob.returncode != 0:
            raise ValueError("Radulator reviewed source Git blob is unavailable")
        actual_bytes, actual_info = _read_sealed_file_bytes(
            actual, max_bytes=_MAX_RUNTIME_FILE_BYTES
        )
        executable = bool(stat.S_IMODE(actual_info.st_mode) & 0o111)
        if actual_bytes != blob.stdout or executable != (mode == b"100755"):
            raise ValueError("Radulator source file differs from the reviewed Git blob")
        if relative == "ops/hermes/radulator/trusted_publisher.py":
            reviewed_probe_sha = hashlib.sha256(blob.stdout).hexdigest()
    probe_info = _read_publisher_probe(
        probe, expected_sha256=publisher_probe_sha256
    )
    if reviewed_probe_sha != probe_info["sha256"]:
        raise ValueError("publisher preflight digest is not the reviewed Git blob")
    return {
        **probe_info,
        "source_sha": head,
        "source_path": str(source),
        "lifecycle_controller_path": str(lifecycle),
        "lifecycle_controller_sha256": _safe_file_sha256(lifecycle),
    }


def _validate_hermes_source_provenance(
    source_root: Path,
    *,
    expected_source_sha: str,
    provenance: dict[str, object],
    git_executable: Path,
) -> None:
    """Check builder provenance against the actual Hermes checkout bytes."""
    source = Path(source_root)
    expected = _validated_hex_sha(expected_source_sha, field="Hermes source SHA", length=40)
    if not source.is_absolute() or source == Path(source.anchor):
        raise ValueError("Hermes source checkout must be a bounded absolute directory")
    info = source.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("Hermes source checkout ownership or mode is unsafe")
    git = Path(git_executable)
    if git != Path("/usr/bin/git"):
        raise ValueError("Hermes source verification requires /usr/bin/git")
    try:
        status = subprocess.run(
            [str(git), "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False, capture_output=True, text=True, timeout=10,
            env=_git_command_environment(),
        )
        head = subprocess.run(
            [str(git), "-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False, capture_output=True, text=True, timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"},
        )
        tree = subprocess.run(
            [str(git), "-C", str(source), "rev-parse", "--verify", "HEAD^{tree}"],
            check=False, capture_output=True, text=True, timeout=10,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Hermes source Git identity cannot be verified") from exc
    if (
        status.returncode != 0
        or status.stdout
        or head.returncode != 0
        or head.stdout.strip() != expected
        or re.fullmatch(r"[0-9a-f]{40}", tree.stdout.strip()) is None
    ):
        raise ValueError("Hermes source SHA does not match Git HEAD")
    pyproject, _ = _read_sealed_file_bytes(source / "pyproject.toml", max_bytes=_MAX_RUNTIME_FILE_BYTES)
    uv_lock, _ = _read_sealed_file_bytes(source / "uv.lock", max_bytes=_MAX_RUNTIME_FILE_BYTES)
    if provenance.get("hermes_source_tree_sha") != tree.stdout.strip():
        raise ValueError("Hermes source tree SHA differs from provenance")
    if provenance.get("pyproject_sha256") != hashlib.sha256(pyproject).hexdigest():
        raise ValueError("Hermes pyproject digest differs from provenance")
    if provenance.get("uv_lock_sha256") != hashlib.sha256(uv_lock).hexdigest():
        raise ValueError("Hermes uv.lock digest differs from provenance")
    lock_digest = hashlib.sha256(pyproject + b"\0" + uv_lock).hexdigest()
    if provenance.get("pyproject_lock_sha256") != lock_digest:
        raise ValueError("Hermes pyproject/lock digest differs from the checkout")
    locked = _locked_uv_packages(uv_lock)
    if provenance.get("locked_packages") != locked:
        raise ValueError("Hermes install provenance lock records differ from uv.lock")
    _archive_bytes, _first_party_files = _git_archive_hermes_cli(
        source, expected=expected, git=git
    )
    if provenance.get("first_party_git_archive_sha256") != hashlib.sha256(_archive_bytes).hexdigest():
        raise ValueError("Hermes first-party install bytes differ from the reviewed Git archive")


def render_sealed_runtime_plan(
    *,
    runtime_archive_path: Path,
    runtime_archive_sha256: str,
    hermes_install_archive_path: Path,
    hermes_install_archive_sha256: str,
    hermes_install_provenance_path: Path,
    hermes_install_provenance_sha256: str,
    hermes_source_sha: str,
    hermes_source_path: Path | None = None,
    runtime_root: Path,
    entrypoint_path: Path,
) -> dict[str, object]:
    """Bind official CPython and a complete staged Hermes install closure."""
    root = _validated_install_path(runtime_root, field="sealed runtime root", allow_root=True)
    entrypoint = _validated_install_path(entrypoint_path, field="sealed runtime entrypoint", install_root=root)
    if entrypoint.parent.parent != root:
        raise ValueError("sealed runtime entrypoint must be below runtime/bin")
    python = _read_runtime_archive_manifest(
        runtime_archive_path,
        expected_sha256=runtime_archive_sha256,
        strip_prefix="python",
        required_paths={"bin/python3.11", "bin/python3", "lib/python3.11"},
        role="CPython",
    )
    if runtime_archive_sha256 != OFFICIAL_RUNTIME_ARCHIVE_SHA256:
        raise ValueError("CPython archive is not the reviewed official runtime artifact")
    closure = _validate_hermes_install_closure(
        hermes_install_archive_path,
        archive_sha256=hermes_install_archive_sha256,
        provenance_path=hermes_install_provenance_path,
        provenance_sha256=hermes_install_provenance_sha256,
        hermes_source_sha=hermes_source_sha,
    )
    hermes = cast(dict[str, object], closure["archive"])
    provenance = cast(dict[str, object], closure["provenance"])
    if hermes_source_path is not None:
        _validate_hermes_source_provenance(
            Path(hermes_source_path),
            expected_source_sha=hermes_source_sha,
            provenance=provenance,
            git_executable=Path("/usr/bin/git"),
        )
    merged: dict[str, dict[str, object]] = {}
    for item in python["entries"]:
        path = str(item["path"])
        merged[path] = dict(item)
    # The Hermes archive is a staged install closure.  Relocating the package
    # under CPython's real site-packages makes the sealed interpreter usable by
    # direct ``python -I script.py`` callers as well as by hermes-python.
    package_prefix = "lib/python3.11/site-packages/"
    for item in hermes["entries"]:
        source_path = str(item["path"])
        path = package_prefix + source_path
        if source_path == "hermes_cli":
            path = package_prefix + "hermes_cli/"
        elif source_path.startswith("hermes_cli/"):
            path = package_prefix + source_path
        else:
            # Dependency closure entries are expected to be install-relative;
            # preserve them beneath site-packages without allowing a second
            # top-level tree outside the runtime.
            path = package_prefix + source_path
        if path.endswith("//"):
            path = path[:-1]
        relocated = dict(item)
        relocated["path"] = path
        if relocated.get("type") == "symlink":
            target = str(relocated.get("target") or "")
            # Symlink targets in the source archive are relative to their
            # archive root (the manifest has already resolved the link
            # relative to its member).  Relocate that root-relative target to
            # the corresponding site-packages path while retaining an
            # internal-only target.
            relocated["target"] = package_prefix + target
        prior = merged.get(path)
        if prior is not None and prior != relocated:
            raise ValueError("sealed runtime archives overlap with different entries")
        merged[path] = relocated
    # Tar files may omit directory members.  Materialization still creates
    # those parents, so make the recursive sealed manifest describe them
    # explicitly and bind the package manifest to the same tree.
    for item in list(merged.values()):
        relative = PurePosixPath(str(item["path"]).rstrip("/"))
        parent = relative.parent
        while str(parent) not in {"", "."}:
            directory_path = parent.as_posix() + "/"
            prior = merged.get(directory_path)
            if prior is not None and prior.get("type") != "directory":
                raise ValueError("sealed runtime path has a file/directory collision")
            merged.setdefault(
                directory_path,
                {"path": directory_path, "type": "directory", "mode": 0o555},
            )
            parent = parent.parent
    merged["bin/hermes-python"] = {
        "path": "bin/hermes-python",
        "type": "file",
        "mode": 0o555,
        "size": len(RUNTIME_ENTRYPOINT_CONTENT.encode("utf-8")),
        "sha256": hashlib.sha256(RUNTIME_ENTRYPOINT_CONTENT.encode("utf-8")).hexdigest(),
    }
    merged["runtime-probe.py"] = {
        "path": "runtime-probe.py",
        "type": "file",
        "mode": 0o555,
        "size": len(RUNTIME_DIRECT_PROBE_CONTENT.encode("utf-8")),
        "sha256": hashlib.sha256(RUNTIME_DIRECT_PROBE_CONTENT.encode("utf-8")).hexdigest(),
    }
    python_entry = merged.get("bin/python3.11")
    if not isinstance(python_entry, dict) or python_entry.get("type") != "file":
        raise ValueError("sealed runtime Python executable is not a regular file")
    hermes_package_prefix = package_prefix + "hermes_cli/"
    # ``package_manifest_sha256`` is the worker's fast startup binding for
    # the exact package root passed in its plist.  Keep it scoped to that
    # root; the complete CPython + dependency closure remains covered by the
    # recursive runtime manifest above.
    package_entries = [
        {
            **item,
            "path": str(item["path"])[len(hermes_package_prefix):],
        }
        for item in sorted(merged.values(), key=lambda entry: str(entry["path"]))
        if str(item["path"]).startswith(hermes_package_prefix)
        and str(item["path"]) != hermes_package_prefix
        and "__pycache__" not in PurePosixPath(str(item["path"])).parts
        and not str(item["path"]).endswith((".pyc", ".pyo"))
    ]
    package_manifest_sha = hashlib.sha256(
        _canonical_json_bytes(package_entries)
    ).hexdigest()
    runtime_manifest_sha = hashlib.sha256(
        _canonical_json_bytes([merged[path] for path in sorted(merged)])
    ).hexdigest()
    return {
        "contract": SEALED_RUNTIME_CONTRACT,
        "schema_version": 1,
        "runtime_root": str(root),
        "entrypoint_path": str(entrypoint),
        "direct_probe_path": str(root / "runtime-probe.py"),
        "direct_probe_sha256": str(merged["runtime-probe.py"]["sha256"]),
        "python_executable_path": str(root / "bin/python3.11"),
        "python_sha256": str(python_entry["sha256"]),
        "package_root": str(root / "lib/python3.11/site-packages/hermes_cli"),
        "package_manifest_sha256": package_manifest_sha,
        "runtime_manifest_sha256": runtime_manifest_sha,
        "python_version": OFFICIAL_RUNTIME_VERSION,
        "official_release": OFFICIAL_RUNTIME_RELEASE,
        "official_asset_id": OFFICIAL_RUNTIME_ASSET_ID,
        "official_source_repository": OFFICIAL_RUNTIME_SOURCE_REPOSITORY,
        "official_release_tag": OFFICIAL_RUNTIME_RELEASE_TAG,
        "official_asset_name": OFFICIAL_RUNTIME_ASSET_NAME,
        "official_release_url": OFFICIAL_RUNTIME_RELEASE_URL,
        "verification_status": OFFICIAL_RUNTIME_VERIFICATION_STATUS,
        "hermes_source_sha": hermes_source_sha,
        "hermes_pyproject_lock_sha256": str(provenance["pyproject_lock_sha256"]),
        "hermes_provenance_path": str(Path(hermes_install_provenance_path)),
        "hermes_provenance_sha256": str(hermes_install_provenance_sha256),
        "archives": [python, hermes],
        "entries": [merged[path] for path in sorted(merged)],
    }


def validate_runtime_identity(
    config: dict,
    *,
    expected_package_owner_uid: int = 0,
) -> dict[str, str]:
    """Verify exact immutable runtime identities before any activation."""

    identities: dict[str, str] = {}
    for name in ("python", "git"):
        path = Path(config[f"{name}_executable"])
        info = path.lstat()
        git_system_binary = name == "git" and path == Path("/usr/bin/git")
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or (not git_system_binary and info.st_nlink != 1)
            or stat.S_IMODE(info.st_mode) & 0o022
            or not stat.S_IMODE(info.st_mode) & 0o111
        ):
            raise ValueError(f"{name} runtime is mutable or unsafe")
        digest = _apple_system_binary_sha256(path) if git_system_binary else _safe_file_sha256(path)
        if digest != config.get(f"{name}_sha256"):
            raise ValueError(f"{name} runtime digest changed")
        identities[f"{name}_executable"] = str(path)
        identities[f"{name}_sha256"] = digest
    package_root = Path(config["package_root"])
    required_modules = {
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
    if any(not (package_root / name).is_file() for name in required_modules):
        raise ValueError("runtime package is incomplete")
    package = runtime_package_manifest(
        package_root,
        expected_owner_uid=expected_package_owner_uid,
        expected_owner_gid=0,
    )
    if package["sha256"] != config.get("package_manifest_sha256"):
        raise ValueError("runtime package manifest changed")
    identities["package_root"] = str(package_root)
    identities["package_manifest_sha256"] = str(package["sha256"])
    entrypoint_value = config.get("runtime_entrypoint_path")
    if entrypoint_value is not None:
        entrypoint = Path(entrypoint_value)
        runtime_root = Path(config["python_executable"]).parent.parent
        if entrypoint != runtime_root / "bin/hermes-python":
            raise ValueError("runtime entrypoint is outside the sealed runtime")
        try:
            entrypoint_info = entrypoint.lstat()
        except OSError as exc:
            raise ValueError("runtime entrypoint is unavailable") from exc
        if (
            stat.S_ISLNK(entrypoint_info.st_mode)
            or not stat.S_ISREG(entrypoint_info.st_mode)
            or entrypoint_info.st_uid != int(expected_package_owner_uid)
            or stat.S_IMODE(entrypoint_info.st_mode) != 0o555
            or entrypoint_info.st_nlink != 1
        ):
            raise ValueError("runtime entrypoint is mutable or unsafe")
        digest = _safe_file_sha256(entrypoint)
        if digest != config.get("runtime_entrypoint_sha256"):
            raise ValueError("runtime entrypoint digest changed")
        identities["runtime_entrypoint_path"] = str(entrypoint)
        identities["runtime_entrypoint_sha256"] = digest
    publisher_probe_value = config.get("publisher_probe_path")
    if publisher_probe_value is not None:
        publisher_probe = Path(str(publisher_probe_value))
        if config.get("publisher_probe_contract") != PUBLISHER_PROBE_CONTRACT:
            raise ValueError("publisher preflight contract is unsupported")
        try:
            probe_info = publisher_probe.lstat()
        except OSError as exc:
            raise ValueError("publisher preflight script is unavailable") from exc
        if (
            stat.S_ISLNK(probe_info.st_mode)
            or not stat.S_ISREG(probe_info.st_mode)
            or probe_info.st_uid != 0
            or probe_info.st_gid != 0
            or probe_info.st_nlink != 1
            or stat.S_IMODE(probe_info.st_mode) != 0o555
        ):
            raise ValueError("publisher preflight script is mutable or unsafe")
        probe_digest = _safe_file_sha256(publisher_probe)
        if probe_digest != config.get("publisher_probe_sha256"):
            raise ValueError("publisher preflight script digest changed")
        identities["publisher_probe_path"] = str(publisher_probe)
        identities["publisher_probe_sha256"] = probe_digest
    manifest_value = config.get("runtime_manifest_path")
    if manifest_value is not None:
        if config.get("python_version") != OFFICIAL_RUNTIME_VERSION:
            raise ValueError("Python runtime version is unsupported")
        _validated_hex_sha(
            config.get("hermes_source_sha"), field="Hermes source SHA", length=40
        )
        _validated_hex_sha(
            config.get("hermes_install_archive_sha256"),
            field="Hermes install archive SHA256",
            length=64,
        )
        manifest_path = Path(str(manifest_value))
        manifest_sha = _validated_hex_sha(
            config.get("runtime_manifest_sha256"),
            field="runtime manifest SHA256",
            length=64,
        )
        runtime_root = Path(config["python_executable"]).parent.parent
        manifest = _read_runtime_manifest_file(
            manifest_path,
            expected_sha256=manifest_sha,
            expected_runtime_root=runtime_root,
            expected_python_executable=Path(config["python_executable"]),
            expected_python_version=str(config.get("python_version") or ""),
        )
        _verify_runtime_tree_against_manifest(
            runtime_root,
            cast(list[dict[str, object]], manifest["entries"]),
            expected_owner_uid=expected_package_owner_uid,
            expected_owner_gid=0,
        )
        identities["runtime_manifest_path"] = str(manifest_path)
        identities["runtime_manifest_sha256"] = str(manifest["runtime_manifest_sha256"])
    return identities


def _validated_account_name(value: str) -> str:
    if not isinstance(value, str) or not _ACCOUNT_NAME_RE.fullmatch(value):
        raise ValueError("broker account or group name is invalid")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _validated_positive_id(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_POSIX_ID:
        raise ValueError(f"{field} must be a positive integer")
    return int(value)


def _validated_nonnegative_id(value: object, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_POSIX_ID:
        raise ValueError(f"{field} must be a non-negative integer")
    return int(value)


def _validated_hex_sha(value: object, *, field: str, length: int) -> str:
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError(f"{field} must be an exact lowercase SHA-{length * 4}")
    return value


def _official_runtime_provenance(*, sha256: str) -> dict[str, object]:
    """Return the non-secret identity of the externally verified runtime."""
    return {
        "source_repository": OFFICIAL_RUNTIME_SOURCE_REPOSITORY,
        "release_tag": OFFICIAL_RUNTIME_RELEASE_TAG,
        "asset_id": OFFICIAL_RUNTIME_ASSET_ID,
        "asset_name": OFFICIAL_RUNTIME_ASSET_NAME,
        "release_url": OFFICIAL_RUNTIME_RELEASE_URL,
        "sha256": _validated_hex_sha(
            sha256, field="CPython runtime archive SHA256", length=64
        ),
        "verification_status": OFFICIAL_RUNTIME_VERIFICATION_STATUS,
        "attestation_identity": OFFICIAL_RUNTIME_ATTESTATION_IDENTITY,
        "attestation_status": OFFICIAL_RUNTIME_ATTESTATION_STATUS,
    }


def _validated_install_path(
    value: Path | str,
    *,
    field: str,
    install_root: Path | None = None,
    allow_root: bool = False,
) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field} must be absolute and normalized")
    # Existing symlink components would let a renderer silently place an
    # artifact outside the reviewed root.  Missing components are safe to
    # create later; the writer repeats this check immediately before rename.
    current = Path(path.anchor)
    for part in path.parts[1:-1] if path.name else path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise ValueError(f"{field} contains a symlink component")
        except OSError as exc:
            raise ValueError(f"{field} cannot be inspected") from exc
    if install_root is not None:
        root = Path(install_root)
        if path == root and allow_root:
            return path
        if path == root or root not in path.parents:
            raise ValueError(f"{field} escapes the install root")
    return path


def _inventory_records(value: object, *, kind: str) -> list[dict[str, object]]:
    if isinstance(value, dict):
        records = list(value.values())
    elif isinstance(value, list):
        records = value
    else:
        raise ValueError(f"host identity {kind} inventory must be a list")
    result: list[dict[str, object]] = []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"host identity {kind} record is malformed")
        expected = {"name", "uid", "gid"} if kind == "accounts" else {"name", "gid"}
        if set(record) != expected:
            raise ValueError(f"host identity {kind} record fields are not exact")
        name = _validated_account_name(record["name"])
        gid = _validated_nonnegative_id(record["gid"], field=f"host identity {kind} gid")
        normalized: dict[str, object] = {"name": name, "gid": gid}
        if kind == "accounts":
            normalized["uid"] = _validated_nonnegative_id(record["uid"], field="host identity account uid")
        result.append(normalized)
    result.sort(key=lambda row: (str(row["name"]), int(row["uid"] if kind == "accounts" else row["gid"])))
    names = [str(row["name"]) for row in result]
    ids = [int(row["uid"] if kind == "accounts" else row["gid"]) for row in result]
    if len(names) != len(set(names)) or len(ids) != len(set(ids)):
        raise ValueError(f"host identity {kind} inventory has occupied duplicate names or IDs")
    return result


def _validate_host_identity_inventory(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"contract", "accounts", "groups", "memberships"}:
        raise ValueError("host identity inventory fields are not exact")
    if value.get("contract") != HOST_IDENTITY_INVENTORY_CONTRACT:
        raise ValueError("unsupported host identity inventory contract")
    accounts = _inventory_records(value.get("accounts"), kind="accounts")
    groups = _inventory_records(value.get("groups"), kind="groups")
    by_name = {str(row["name"]): row for row in accounts}
    root = by_name.get("root")
    if root != {"name": "root", "uid": 0, "gid": 0}:
        raise ValueError("host identity inventory must contain exact root account")
    group_by_name = {str(row["name"]): row for row in groups}
    wheel = group_by_name.get("wheel")
    if wheel != {"name": "wheel", "gid": 0}:
        raise ValueError("host identity inventory must contain exact wheel group")
    memberships_value = value.get("memberships")
    if not isinstance(memberships_value, list):
        raise ValueError("host identity memberships inventory must be a list")
    memberships: list[dict[str, str]] = []
    known_users = set(by_name)
    known_groups = set(group_by_name)
    for item in memberships_value:
        if not isinstance(item, dict) or set(item) != {"user", "group"}:
            raise ValueError("host identity membership fields are not exact")
        user = _validated_account_name(item["user"])
        group = _validated_account_name(item["group"])
        if user not in known_users or group not in known_groups:
            raise ValueError("host identity membership references an unknown identity")
        memberships.append({"user": user, "group": group})
    memberships.sort(key=lambda item: (item["user"], item["group"]))
    if len({(item["user"], item["group"]) for item in memberships}) != len(memberships):
        raise ValueError("host identity memberships contain duplicates")
    return {"accounts": accounts, "groups": groups, "memberships": memberships}


def _desired_identity_specs(value: object) -> dict[str, dict[str, object]]:
    roles = {"broker", "controller", "publisher", "operator", "model", "workspace"}
    if not isinstance(value, dict):
        raise ValueError("desired broker identities must contain every reviewed role")
    if value.get("contract") == DESIRED_IDENTITIES_CONTRACT:
        value = {role: value.get(role) for role in roles}
    if set(value) != roles:
        raise ValueError("desired broker identities must contain every reviewed role")
    result: dict[str, dict[str, object]] = {}
    account_fields = {
        "broker": {"user", "uid", "gid"},
        "controller": {"user", "uid", "gid", "group", "group_gid"},
        "publisher": {"user", "uid", "gid", "group", "group_gid"},
        "operator": {"user", "uid", "gid", "group", "group_gid"},
        "model": {"user", "uid", "gid"},
    }
    for role, expected in account_fields.items():
        item = value[role]
        if not isinstance(item, dict) or set(item) != expected:
            raise ValueError(f"desired {role} identity fields are not exact")
        normalized = dict(item)
        normalized["user"] = _validated_account_name(normalized["user"])
        normalized["uid"] = (
            _validated_nonnegative_id(normalized["uid"], field=f"{role} uid")
            if role == "operator"
            else _validated_positive_id(normalized["uid"], field=f"{role} uid")
        )
        normalized["gid"] = _validated_nonnegative_id(normalized["gid"], field=f"desired {role} gid")
        if role in {"controller", "publisher", "operator"}:
            normalized["group"] = _validated_account_name(normalized["group"])
            normalized["group_gid"] = _validated_nonnegative_id(
                normalized["group_gid"], field=f"desired {role} group gid"
            )
        result[role] = normalized
    workspace = value["workspace"]
    if not isinstance(workspace, dict) or set(workspace) != {"group", "gid"}:
        raise ValueError("desired workspace group fields are not exact")
    workspace_group = _validated_account_name(workspace["group"])
    workspace_gid = _validated_positive_id(workspace["gid"], field="workspace gid")
    result["workspace"] = {"group": workspace_group, "gid": workspace_gid}
    if result["operator"] != {
        "user": "root", "uid": 0, "gid": 0, "group": "wheel", "group_gid": 0
    }:
        raise ValueError("operator identity must be root with the wheel group")
    if result["controller"]["gid"] != result["controller"]["group_gid"]:
        raise ValueError("controller account and group IDs must match")
    if result["publisher"]["gid"] != result["publisher"]["group_gid"]:
        raise ValueError("publisher account and group IDs must match")
    if result["model"]["gid"] != workspace_gid:
        raise ValueError("model account must use the workspace group")
    if result["broker"]["gid"] == 0:
        raise ValueError("broker group ID must be positive")
    uid_values = [int(result[role]["uid"]) for role in ("broker", "controller", "publisher", "model")]
    if len(uid_values) != len(set(uid_values)):
        raise ValueError("broker, controller, publisher, and model UIDs must be distinct")
    if any(uid <= 0 for uid in uid_values):
        raise ValueError("service identities must be non-root")
    gid_values = [
        int(result["broker"]["gid"]),
        int(result["controller"]["group_gid"]),
        int(result["publisher"]["group_gid"]),
        0,
        workspace_gid,
    ]
    if len(gid_values) != len(set(gid_values)):
        raise ValueError("broker, controller, publisher, operator, and workspace groups must be distinct")
    users = [str(result[role]["user"]) for role in ("broker", "controller", "publisher", "model")]
    groups = [
        str(result["broker"]["user"]),
        str(result["controller"]["group"]),
        str(result["publisher"]["group"]),
        "wheel",
        workspace_group,
    ]
    if len(users) != len(set(users)) or len(groups) != len(set(groups)):
        raise ValueError("broker service account and group names must be distinct")
    return result


def _validate_inventory_against_desired(
    inventory: dict[str, object], desired: dict[str, dict[str, object]]
) -> None:
    accounts = cast(list[dict[str, object]], inventory["accounts"])
    groups = cast(list[dict[str, object]], inventory["groups"])
    account_by_name = {str(row["name"]): row for row in accounts}
    account_by_uid = {int(row["uid"]): row for row in accounts}
    group_by_name = {str(row["name"]): row for row in groups}
    group_by_gid = {int(row["gid"]): row for row in groups}
    account_specs = [desired[role] for role in ("broker", "controller", "publisher", "model", "operator")]
    for spec in account_specs:
        name, uid, gid = str(spec["user"]), int(spec["uid"]), int(spec["gid"])
        existing_name = account_by_name.get(name)
        if existing_name is not None and (int(existing_name["uid"]), int(existing_name["gid"])) != (uid, gid):
            raise ValueError(f"host account name/ID mismatch for {name}")
        existing_uid = account_by_uid.get(uid)
        if existing_uid is not None and str(existing_uid["name"]) != name:
            raise ValueError(f"host account UID {uid} is occupied by another name")
    group_specs = [
        (str(desired["broker"]["user"]), int(desired["broker"]["gid"])),
        (str(desired["controller"]["group"]), int(desired["controller"]["group_gid"])),
        (str(desired["publisher"]["group"]), int(desired["publisher"]["group_gid"])),
        ("wheel", 0),
        (str(desired["workspace"]["group"]), int(desired["workspace"]["gid"])),
    ]
    for name, gid in group_specs:
        existing_name = group_by_name.get(name)
        if existing_name is not None and int(existing_name["gid"]) != gid:
            raise ValueError(f"host group name/ID mismatch for {name}")
        existing_gid = group_by_gid.get(gid)
        if existing_gid is not None and str(existing_gid["name"]) != name:
            raise ValueError(f"host group ID {gid} is occupied by another name")
    expected_memberships = {
        (str(desired["broker"]["user"]), str(desired["controller"]["group"])),
        (str(desired["broker"]["user"]), str(desired["publisher"]["group"])),
        (str(desired["broker"]["user"]), "wheel"),
        (str(desired["broker"]["user"]), str(desired["workspace"]["group"])),
        (str(desired["controller"]["user"]), str(desired["controller"]["group"])),
        (str(desired["publisher"]["user"]), str(desired["publisher"]["group"])),
        ("root", "wheel"),
        (str(desired["model"]["user"]), str(desired["workspace"]["group"])),
    }
    relevant_users = {
        str(desired[role]["user"])
        for role in ("broker", "controller", "publisher", "model", "operator")
    }
    observed_memberships = {
        (str(item["user"]), str(item["group"]))
        for item in cast(list[dict[str, str]], inventory["memberships"])
        if str(item["user"]) in relevant_users
    }
    # A host inventory may intentionally omit the new service identities: the
    # following root-only apply step creates those records.  Existing service
    # identities, however, must have an exact supplementary-group set before
    # any directory-service mutation is authorized.
    existing_expected_memberships = {
        pair for pair in expected_memberships
        if pair[0] in account_by_name
    }
    if observed_memberships != existing_expected_memberships:
        unexpected = sorted(observed_memberships - expected_memberships)
        missing = sorted(existing_expected_memberships - observed_memberships)
        raise ValueError(f"host identity memberships differ (unexpected={unexpected}, missing={missing})")


def allocate_desired_identities(
    host_inventory: object,
    *,
    broker_user: str = "_hermesbroker",
    controller_user: str = "_hermescontroller",
    publisher_user: str = "_hermespublisher",
    model_user: str = "_hermesmodel",
    broker_group: str = "_hermesbroker",
    controller_group: str = "_hermescontroller",
    publisher_group: str = "_hermespublisher",
    workspace_group: str = "_hermesworkspace",
) -> dict[str, object]:
    """Allocate the reviewed 450-453 UID/GID block from an explicit inventory."""
    inventory = _validate_host_identity_inventory(host_inventory)
    names = [broker_user, controller_user, publisher_user, model_user,
             broker_group, controller_group, publisher_group, workspace_group]
    for name in names:
        _validated_account_name(name)
    ids = {"broker": 450, "controller": 451, "publisher": 452, "model": 453}
    accounts = cast(list[dict[str, object]], inventory["accounts"])
    groups = cast(list[dict[str, object]], inventory["groups"])
    by_uid = {int(item["uid"]): str(item["name"]) for item in accounts}
    by_gid = {int(item["gid"]): str(item["name"]) for item in groups}
    by_name_account = {str(item["name"]): (int(item["uid"]), int(item["gid"])) for item in accounts}
    by_name_group = {str(item["name"]): int(item["gid"]) for item in groups}
    for role, ident in ids.items():
        user = {"broker": broker_user, "controller": controller_user,
                "publisher": publisher_user, "model": model_user}[role]
        group = {"broker": broker_group, "controller": controller_group,
                 "publisher": publisher_group, "model": workspace_group}[role]
        if ident in by_uid and by_uid[ident] != user:
            raise ValueError(f"allocated UID {ident} is occupied by another name")
        if ident in by_gid and by_gid[ident] != group:
            raise ValueError(f"allocated GID {ident} is occupied by another name")
        if user in by_name_account and by_name_account[user] != (ident, ident):
            raise ValueError(f"existing account {user} has the wrong allocated IDs")
        if group in by_name_group and by_name_group[group] != ident:
            raise ValueError(f"existing group {group} has the wrong allocated ID")
    desired = {
        "contract": DESIRED_IDENTITIES_CONTRACT,
        "broker": {"user": broker_user, "uid": 450, "gid": 450},
        "controller": {"user": controller_user, "uid": 451, "gid": 451,
                       "group": controller_group, "group_gid": 451},
        "publisher": {"user": publisher_user, "uid": 452, "gid": 452,
                      "group": publisher_group, "group_gid": 452},
        "operator": {"user": "root", "uid": 0, "gid": 0,
                     "group": "wheel", "group_gid": 0},
        "model": {"user": model_user, "uid": 453, "gid": 453},
        "workspace": {"group": workspace_group, "gid": 453},
    }
    # Re-run the exact identity validator so custom names cannot introduce a
    # cross-role name collision after the fixed reviewed allocation is chosen.
    _desired_identity_specs(desired)
    return desired


def render_radulator_remote_policy(*, source_sha: str) -> dict[str, object]:
    """Return the reviewed Radulator policy with a caller-supplied source SHA."""
    # The source SHA is validated here as a required review input, while the
    # emitted object remains the exact ``hermes.github_repository.v1`` shape
    # consumed by broker-register.  It is bound separately by the outer plan.
    _validated_hex_sha(source_sha, field="Radulator source SHA", length=40)
    return {
        "contract": REMOTE_POLICY_CONTRACT,
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


def render_identity_provision_plan(
    *,
    broker_user: str,
    broker_uid: int,
    broker_gid: int,
    controller_user: str,
    controller_uid: int,
    controller_group: str,
    controller_gid: int,
    publisher_user: str,
    publisher_uid: int,
    publisher_group: str,
    publisher_gid: int,
    operator_user: str,
    operator_uid: int,
    operator_group: str,
    operator_gid: int,
    model_user: str,
    model_uid: int,
    workspace_group: str,
    workspace_gid: int,
) -> dict:
    """Render the idempotent account/group intent; execution is root-only."""

    names = {
        name: _validated_account_name(value)
        for name, value in {
            "broker_user": broker_user,
            "controller_user": controller_user,
            "controller_group": controller_group,
            "publisher_user": publisher_user,
            "publisher_group": publisher_group,
            "operator_user": operator_user,
            "operator_group": operator_group,
            "model_user": model_user,
            "workspace_group": workspace_group,
        }.items()
    }
    validate_identity_separation(
        broker_uid=broker_uid,
        model_uid=model_uid,
        controller_uid=controller_uid,
        publisher_uid=publisher_uid,
    )
    broker_uid = _validated_positive_id(broker_uid, field="broker uid")
    broker_gid = _validated_positive_id(broker_gid, field="broker gid")
    controller_uid = _validated_positive_id(controller_uid, field="controller uid")
    controller_gid = _validated_positive_id(controller_gid, field="controller gid")
    publisher_uid = _validated_positive_id(publisher_uid, field="publisher uid")
    publisher_gid = _validated_positive_id(publisher_gid, field="publisher gid")
    model_uid = _validated_positive_id(model_uid, field="model uid")
    workspace_gid = _validated_positive_id(workspace_gid, field="workspace gid")
    operator_uid = _validated_nonnegative_id(operator_uid, field="operator uid")
    operator_gid = _validated_nonnegative_id(operator_gid, field="operator gid")
    positive_ids = (
        broker_uid,
        broker_gid,
        controller_uid,
        controller_gid,
        publisher_uid,
        publisher_gid,
        model_uid,
        workspace_gid,
    )
    if any(int(value) <= 0 for value in positive_ids):
        raise ValueError("broker service identity IDs must be positive")
    if int(operator_uid) < 0 or int(operator_gid) < 0:
        raise ValueError("operator identity IDs must be non-negative")
    if (
        names["operator_user"] != "root"
        or int(operator_uid) != 0
        or int(operator_gid) != 0
        or names["operator_group"] != "wheel"
    ):
        raise ValueError("operator identity must be root with the wheel group")
    groups = [
        [names["broker_user"], int(broker_gid)],
        [names["controller_group"], int(controller_gid)],
        [names["publisher_group"], int(publisher_gid)],
        [names["workspace_group"], int(workspace_gid)],
    ]
    group_ids = [int(gid) for _name, gid in groups] + [int(operator_gid)]
    if len(group_ids) != len(set(group_ids)):
        raise ValueError("broker, controller, publisher, operator, and workspace groups must be distinct")
    users = [
        [names["broker_user"], int(broker_uid), int(broker_gid)],
        [names["controller_user"], int(controller_uid), int(controller_gid)],
        [names["publisher_user"], int(publisher_uid), int(publisher_gid)],
        [names["model_user"], int(model_uid), int(workspace_gid)],
    ]
    user_names = [str(item[0]) for item in users]
    group_names = [str(item[0]) for item in groups] + [names["operator_group"]]
    if len(user_names) != len(set(user_names)) or len(group_names) != len(set(group_names)):
        raise ValueError("broker service account and group names must be distinct")
    allowed_same_names = {
        (names["broker_user"], names["broker_user"]),
        (names["controller_user"], names["controller_group"]),
        (names["publisher_user"], names["publisher_group"]),
        (names["operator_user"], names["operator_group"]),
    }
    if any(
        (user_name, group_name) not in allowed_same_names
        for user_name in user_names
        for group_name in group_names
        if user_name == group_name
    ):
        raise ValueError("service account and group names collide")
    memberships = [
        [names["broker_user"], names["controller_group"]],
        [names["broker_user"], names["publisher_group"]],
        [names["broker_user"], names["operator_group"]],
        [names["broker_user"], names["workspace_group"]],
        [names["controller_user"], names["controller_group"]],
        [names["publisher_user"], names["publisher_group"]],
        [names["operator_user"], names["operator_group"]],
        [names["model_user"], names["workspace_group"]],
    ]
    return {
        "contract": "hermes.kanban_broker_identity_plan.v1",
        "groups": groups,
        "users": users,
        "memberships": memberships,
        "expected_ids": {
            "broker": [names["broker_user"], int(broker_uid), int(broker_gid)],
            "controller": [
                names["controller_user"],
                int(controller_uid),
                int(controller_gid),
            ],
            "publisher": [
                names["publisher_user"],
                int(publisher_uid),
                int(publisher_gid),
            ],
            "operator": [names["operator_user"], int(operator_uid), int(operator_gid)],
            "model": [names["model_user"], int(model_uid), int(workspace_gid)],
        },
    }


def render_identity_provision_commands(plan: dict) -> list[list[str]]:
    """Render argv-only macOS account commands; never a shell program string."""

    if (
        not isinstance(plan, dict)
        or plan.get("contract") != "hermes.kanban_broker_identity_plan.v1"
    ):
        raise ValueError("unsupported broker identity plan")
    commands: list[list[str]] = []
    for name, gid in plan.get("groups", []):
        name = _validated_account_name(name)
        commands.extend([
            ["/usr/bin/dscl", ".", "-create", f"/Groups/{name}"],
            [
                "/usr/bin/dscl",
                ".",
                "-create",
                f"/Groups/{name}",
                "PrimaryGroupID",
                str(int(gid)),
            ],
        ])
    for name, uid, gid in plan.get("users", []):
        name = _validated_account_name(name)
        record = f"/Users/{name}"
        commands.extend([
            ["/usr/bin/dscl", ".", "-create", record],
            ["/usr/bin/dscl", ".", "-create", record, "UniqueID", str(int(uid))],
            [
                "/usr/bin/dscl",
                ".",
                "-create",
                record,
                "PrimaryGroupID",
                str(int(gid)),
            ],
            ["/usr/bin/dscl", ".", "-create", record, "NFSHomeDirectory", "/var/empty"],
            ["/usr/bin/dscl", ".", "-create", record, "UserShell", "/usr/bin/false"],
            ["/usr/bin/dscl", ".", "-create", record, "Password", "*"],
        ])
    for user, group in plan.get("memberships", []):
        commands.append([
            "/usr/sbin/dseditgroup",
            "-o",
            "edit",
            "-a",
            _validated_account_name(user),
            "-t",
            "user",
            _validated_account_name(group),
        ])
    return commands


def provision_identity_plan(
    plan: dict,
    *,
    runner=subprocess.run,
) -> None:
    """Idempotently provision and reread dedicated macOS identities as root."""

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("broker identity provisioning requires root")
    if (
        not isinstance(plan, dict)
        or plan.get("contract") != "hermes.kanban_broker_identity_plan.v1"
    ):
        raise ValueError("unsupported broker identity plan")
    group_missing: set[str] = set()
    for name, gid in plan.get("groups", []):
        name = _validated_account_name(name)
        try:
            existing = grp.getgrnam(name)
        except KeyError:
            try:
                collision = grp.getgrgid(int(gid))
            except KeyError:
                group_missing.add(name)
            else:
                raise ValueError(
                    f"group ID {gid} already belongs to {collision.gr_name}"
                )
        else:
            if int(existing.gr_gid) != int(gid):
                raise ValueError(f"existing group {name} has the wrong ID")
    user_missing: set[str] = set()
    for name, uid, gid in plan.get("users", []):
        name = _validated_account_name(name)
        try:
            existing = pwd.getpwnam(name)
        except KeyError:
            try:
                collision = pwd.getpwuid(int(uid))
            except KeyError:
                user_missing.add(name)
            else:
                raise ValueError(f"UID {uid} already belongs to {collision.pw_name}")
        else:
            if (int(existing.pw_uid), int(existing.pw_gid)) != (int(uid), int(gid)):
                raise ValueError(f"existing account {name} has the wrong IDs")
    # Read every existing account's supplementary memberships before running
    # any dscl command.  This closes the partial-mutation window when a host
    # has an unexpected group (for example gid 80) on one of the service
    # identities.
    membership_policy = plan.get("membership_policy")
    if membership_policy is not None:
        if not isinstance(membership_policy, list):
            raise ValueError("identity membership policy is malformed")
        actual_pairs = {
            (str(item[0]), str(item[1])) for item in plan.get("memberships", [])
            if isinstance(item, (list, tuple)) and len(item) == 2
        }
        policy_pairs = {
            (str(item.get("user")), str(item.get("group")))
            for item in membership_policy
            if isinstance(item, dict)
        }
        if actual_pairs != policy_pairs or len(actual_pairs) != len(plan.get("memberships", [])):
            raise ValueError("identity membership policy does not bind the plan")
        group_gids = {str(name): int(gid) for name, gid in plan.get("groups", [])}
        expected_primary = {
            str(name): int(gid) for name, _uid, gid in plan.get("users", [])
        }
        expected_memberships: dict[str, set[int]] = {
            name: {gid} for name, gid in expected_primary.items()
        }
        for item in membership_policy:
            if not isinstance(item, dict) or set(item) != {"user", "group"}:
                raise ValueError("identity membership policy fields are not exact")
            user = _validated_account_name(item["user"])
            group = _validated_account_name(item["group"])
            if group not in group_gids:
                try:
                    group_gids[group] = int(grp.getgrnam(group).gr_gid)
                except KeyError as exc:
                    raise ValueError("identity membership policy references unknown group") from exc
            expected_memberships.setdefault(user, set()).add(group_gids[group])
        for name in sorted(expected_memberships):
            if name in user_missing:
                continue
            account = pwd.getpwnam(name)
            observed = set(os.getgrouplist(account.pw_name, int(account.pw_gid)))
            if observed != expected_memberships[name]:
                raise ValueError(
                    f"existing account {name} has unexpected supplementary groups"
                )
    commands = render_identity_provision_commands(plan)
    for command in commands:
        if command[0] != "/usr/bin/dscl":
            continue
        record = command[3] if len(command) > 3 else ""
        if (
            record.startswith("/Groups/")
            and record.split("/", 2)[-1] not in group_missing
        ):
            continue
        if (
            record.startswith("/Users/")
            and record.split("/", 2)[-1] not in user_missing
        ):
            continue
        runner(
            command,
            check=True,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
    # Membership edits are safe and idempotent, including for pre-existing identities.
    for command in commands:
        if command[0] == "/usr/sbin/dseditgroup":
            runner(
                command,
                check=True,
                capture_output=True,
                text=True,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            )
    expected = plan.get("expected_ids", {})
    for role in ("broker", "controller", "publisher", "operator", "model"):
        name, uid, _gid = expected[role]
        account = pwd.getpwnam(name)
        if (int(account.pw_uid), int(account.pw_gid)) != (int(uid), int(_gid)):
            raise ValueError(f"{role} identity readback failed")
    for name, gid in plan.get("groups", []):
        if int(grp.getgrnam(name).gr_gid) != int(gid):
            raise ValueError(f"group {name} readback failed")
    memberships = system_group_memberships({
        int(value[1]) for value in expected.values()
    })
    if membership_policy is not None:
        by_uid = {int(value[1]): str(role) for role, value in expected.items()}
        expected_by_uid = {
            int(expected[role][1]): set(expected_memberships[str(expected[role][0])])
            for role in by_uid.values()
        }
        for uid, expected_groups in expected_by_uid.items():
            if memberships.get(uid, set()) != expected_groups:
                raise ValueError("identity membership readback contains unexpected groups")
    validate_group_separation(
        broker_uid=int(expected["broker"][1]),
        model_uid=int(expected["model"][1]),
        controller_uid=int(expected["controller"][1]),
        controller_gid=int(expected["controller"][2]),
        publisher_uid=int(expected["publisher"][1]),
        publisher_gid=int(expected["publisher"][2]),
        operator_uid=int(expected["operator"][1]),
        operator_gid=int(expected["operator"][2]),
        workspace_gid=int(expected["model"][2]),
        memberships=memberships,
    )


def render_filesystem_provision_plan(
    *,
    config: dict,
    service_config_path: Path,
    seatbelt_profile_path: Path,
    launchd_plist_path: Path,
    worker_launchd_plist_path: Path,
    client_config_paths: dict[str, Path],
    sequence_paths: dict[str, Path],
    runtime_assets: dict[str, object],
    sealed_runtime_plan: dict[str, object] | None = None,
    additional_files: list[dict[str, Any]] | None = None,
    additional_directories: list[dict[str, Any]] | None = None,
) -> dict:
    """Render exact ownership/modes for a disabled install before any writes."""

    required_surfaces = {"controller", "publisher", "operator"}
    if (
        set(client_config_paths) != required_surfaces
        or set(sequence_paths) != required_surfaces
    ):
        raise ValueError("all exact broker client surfaces are required")
    if (
        not isinstance(runtime_assets, dict)
        or runtime_assets.get("contract") != "hermes.kanban_broker_runtime_assets.v1"
        or runtime_assets.get("destination_root") != str(Path(config["package_root"]))
        or runtime_assets.get("package_manifest_sha256")
        != config.get("package_manifest_sha256")
        or not isinstance(runtime_assets.get("directories"), list)
        or not isinstance(runtime_assets.get("files"), list)
    ):
        raise ValueError("immutable runtime asset plan does not bind the config")
    install_root = Path(config["install_root"])
    if not install_root.is_absolute() or install_root.parent == install_root:
        raise ValueError("broker install root must be a bounded absolute directory")
    private_paths = [
        Path(config[name])
        for name in (
            "state_dir",
            "workspace_root",
            "worker_hermes_root",
            "publisher_handoff_root",
            "controller_socket",
            "publisher_socket",
            "operator_socket",
            "worker_socket",
            "controller_key_path",
            "publisher_key_path",
            "operator_key_path",
            "canary_key_path",
            "package_root",
        )
    ]
    private_paths.extend([
        Path(service_config_path),
        Path(seatbelt_profile_path),
        *[Path(value) for value in client_config_paths.values()],
        *[Path(value) for value in sequence_paths.values()],
        *([Path(item["path"]) for item in additional_files or []]),
        *([Path(item["path"]) for item in additional_directories or []]),
    ])
    if any(
        path == install_root or install_root not in path.parents
        for path in private_paths
    ):
        raise ValueError("broker private filesystem plan escapes the install root")
    broker_uid = int(config["broker_uid"])
    broker_gid = int(config["broker_gid"])
    workspace_gid = int(config["workspace_gid"])
    publisher_gid = int(config["publisher_gid"])
    surface_ids = {
        "controller": (int(config["controller_uid"]), int(config["controller_gid"])),
        "publisher": (int(config["publisher_uid"]), publisher_gid),
        "operator": (int(config["operator_uid"]), int(config["operator_gid"])),
    }
    runtime_directories = cast(
        list[dict[str, Any]], runtime_assets["directories"]
    )
    runtime_files = cast(list[dict[str, Any]], runtime_assets["files"])
    directories: list[dict[str, Any]] = [
        {"path": str(install_root), "uid": 0, "gid": 0, "mode": 0o711},
        {
            "path": str(Path(config["state_dir"])),
            "uid": broker_uid,
            "gid": broker_gid,
            "mode": 0o700,
        },
        {
            "path": str(Path(config["workspace_root"])),
            "uid": broker_uid,
            "gid": workspace_gid,
            "mode": 0o710,
        },
        {
            "path": str(Path(config["worker_hermes_root"])),
            "uid": int(config["model_uid"]),
            "gid": workspace_gid,
            "mode": 0o700,
        },
        {
            "path": str(Path(config["publisher_handoff_root"])),
            "uid": broker_uid,
            "gid": publisher_gid,
            "mode": 0o710,
        },
        {
            "path": str(Path(service_config_path).parent),
            "uid": broker_uid,
            "gid": broker_gid,
            "mode": 0o700,
        },
        {
            "path": str(Path(config["worker_socket"]).parent),
            "uid": int(config["model_uid"]),
            "gid": workspace_gid,
            "mode": 0o710,
        },
        {
            "path": str(Path(launchd_plist_path).parent),
            "uid": 0,
            "gid": 0,
            "mode": 0o755,
        },
        {
            "path": str(Path(config["canary_key_path"]).parent),
            "uid": 0,
            "gid": 0,
            "mode": 0o700,
        },
        {"path": str(Path(config["package_root"])), "uid": 0, "gid": 0, "mode": 0o555},
    ]
    directories.extend(runtime_directories)
    for surface, (uid, gid) in surface_ids.items():
        directories.extend([
            {
                "path": str(Path(config[f"{surface}_socket"]).parent),
                "uid": broker_uid,
                "gid": gid,
                "mode": 0o710,
            },
            {
                "path": str(Path(config[f"{surface}_key_path"]).parent),
                "uid": broker_uid,
                "gid": gid,
                "mode": 0o710,
            },
            {
                "path": str(Path(client_config_paths[surface]).parent),
                "uid": uid,
                "gid": gid,
                "mode": 0o700,
            },
            {
                "path": str(Path(sequence_paths[surface]).parent),
                "uid": uid,
                "gid": gid,
                "mode": 0o700,
            },
        ])
    directories.extend(additional_directories or [])
    deduplicated: dict[str, dict] = {}
    for item in directories:
        prior = deduplicated.get(item["path"])
        if prior is not None and prior != item:
            raise ValueError("broker asset parents with different authority overlap")
        deduplicated[item["path"]] = item
    for item in list(deduplicated.values()):
        path = Path(item["path"])
        if path == install_root or install_root not in path.parents:
            continue
        parent = path.parent
        while parent != install_root:
            key = str(parent)
            deduplicated.setdefault(
                key,
                {"path": key, "uid": 0, "gid": 0, "mode": 0o711},
            )
            parent = parent.parent
    files: list[dict[str, Any]] = [
        {
            "path": str(Path(service_config_path)),
            "uid": broker_uid,
            "gid": broker_gid,
            "mode": 0o600,
            "kind": "service_config",
        },
        {
            "path": str(Path(seatbelt_profile_path)),
            "uid": broker_uid,
            "gid": broker_gid,
            "mode": 0o600,
            "kind": "seatbelt_profile",
        },
        {
            "path": str(Path(launchd_plist_path)),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "launchd_plist",
        },
        {
            "path": str(Path(worker_launchd_plist_path)),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "worker_launchd_plist",
        },
        {
            "path": str(Path(config["canary_key_path"])),
            "uid": 0,
            "gid": 0,
            "mode": 0o600,
            "kind": "canary_key",
        },
    ]
    files.extend(runtime_files)
    for surface, (uid, gid) in surface_ids.items():
        files.extend([
            {
                "path": str(Path(config[f"{surface}_key_path"])),
                "uid": broker_uid,
                "gid": gid,
                "mode": 0o640,
                "kind": f"{surface}_key",
            },
            {
                "path": str(Path(client_config_paths[surface])),
                "uid": uid,
                "gid": gid,
                "mode": 0o600,
                "kind": f"{surface}_client_config",
            },
            {
                "path": str(Path(sequence_paths[surface])),
                "uid": uid,
                "gid": gid,
                "mode": 0o600,
                "kind": f"{surface}_sequence",
            },
        ])
    files.extend(additional_files or [])
    result = {
        "contract": "hermes.kanban_broker_filesystem_plan.v1",
        "schema_version": 1,
        "directories": sorted(deduplicated.values(), key=lambda item: item["path"]),
        "files": sorted(files, key=lambda item: item["path"]),
    }
    if sealed_runtime_plan is not None:
        if not isinstance(sealed_runtime_plan, dict) or sealed_runtime_plan.get("contract") != SEALED_RUNTIME_CONTRACT:
            raise ValueError("sealed runtime filesystem binding is malformed")
        result["sealed_runtime"] = {
            "contract": SEALED_RUNTIME_CONTRACT,
            "runtime_root": str(sealed_runtime_plan["runtime_root"]),
            "entrypoint_path": str(sealed_runtime_plan["entrypoint_path"]),
            "direct_probe_path": str(sealed_runtime_plan["direct_probe_path"]),
            "direct_probe_sha256": str(sealed_runtime_plan["direct_probe_sha256"]),
            "python_executable_path": str(sealed_runtime_plan["python_executable_path"]),
            "python_sha256": str(sealed_runtime_plan["python_sha256"]),
            "package_root": str(sealed_runtime_plan["package_root"]),
            "package_manifest_sha256": str(sealed_runtime_plan["package_manifest_sha256"]),
            "hermes_source_sha": str(sealed_runtime_plan["hermes_source_sha"]),
            "hermes_pyproject_lock_sha256": str(sealed_runtime_plan["hermes_pyproject_lock_sha256"]),
            "hermes_provenance_path": str(sealed_runtime_plan["hermes_provenance_path"]),
            "hermes_provenance_sha256": str(sealed_runtime_plan["hermes_provenance_sha256"]),
            "runtime_manifest_sha256": str(sealed_runtime_plan["runtime_manifest_sha256"]),
            "official_release": str(sealed_runtime_plan["official_release"]),
            "official_asset_id": int(sealed_runtime_plan["official_asset_id"]),
            "archives": [
                {
                    "role": str(archive["role"]),
                    "path": str(archive["source_path"]),
                    "sha256": str(archive["sha256"]),
                    "size": int(archive["size"]),
                }
                for archive in sealed_runtime_plan["archives"]
            ],
        }
    return result


def render_broker_client_config(
    *,
    surface: str,
    socket_path: Path,
    expected_broker_uid: int,
    key_path: Path,
    sequence_path: Path,
) -> str:
    """Render a credential-free pointer to one exact authenticated RPC surface."""

    if surface not in {"controller", "publisher", "operator", "worker"}:
        raise ValueError("unsupported broker client surface")
    payload = {
        "contract": "hermes.kanban_broker_client_config.v1",
        "surface": surface,
        "socket_path": str(Path(socket_path)),
        "expected_broker_uid": int(expected_broker_uid),
        "key_path": str(Path(key_path)),
        "sequence_path": str(Path(sequence_path)),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def render_dispatcher_routing_config(
    *,
    profile: str,
    controller_client_config: Path,
    publisher_client_config: Path,
    operator_client_config: Path,
    registration_file: Path,
    expected_source_sha: str,
) -> str:
    """Render the named profile's non-secret routing handoff."""
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", profile) is None:
        raise ValueError("dispatcher profile is invalid")
    source_sha = _validated_hex_sha(
        expected_source_sha, field="Radulator source SHA", length=40
    )
    paths = {
        "controller_client_config": Path(controller_client_config),
        "publisher_client_config": Path(publisher_client_config),
        "operator_client_config": Path(operator_client_config),
        "registration_file": Path(registration_file),
    }
    if any(not path.is_absolute() or ".." in path.parts for path in paths.values()):
        raise ValueError("dispatcher routing config paths are invalid")
    payload = {
        "contract": "hermes.kanban_broker_routing.v1",
        "schema_version": 1,
        "profile": profile,
        "dedicated_broker_enabled": False,
        "trusted_publisher_enabled": False,
        "controller_client_config": str(paths["controller_client_config"]),
        "publisher_client_config": str(paths["publisher_client_config"]),
        "operator_client_config": str(paths["operator_client_config"]),
        "registration_file": str(paths["registration_file"]),
        "expected_source_sha": source_sha,
    }
    return _json_artifact_bytes(payload).decode("utf-8")


def render_dispatcher_profile_config_yaml(
    *,
    profile: str,
    controller_client_config: Path,
    publisher_client_config: Path,
    operator_client_config: Path,
    registration_file: Path,
    expected_source_sha: str,
) -> str:
    """Render the profile config consumed by ``kanban_broker_routing``.

    This deliberately uses the tiny supported subset of YAML rather than a
    new runtime dependency.  Values are absolute, bounded paths and are
    emitted in a fixed order for reproducible plans.
    """
    if re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", profile) is None:
        raise ValueError("dispatcher profile is invalid")
    source_sha = _validated_hex_sha(
        expected_source_sha, field="Radulator source SHA", length=40
    )
    paths = {
        "controller": Path(controller_client_config),
        "publisher": Path(publisher_client_config),
        "operator": Path(operator_client_config),
        "registration": Path(registration_file),
    }
    if any(not path.is_absolute() or ".." in path.parts for path in paths.values()):
        raise ValueError("dispatcher profile config paths are invalid")
    # Keep this as a flat nested ``kanban`` mapping: config.py and
    # kanban_broker_routing.py both resolve these exact keys.
    return (
        "kanban:\n"
        "  dedicated_broker_enabled: false\n"
        "  trusted_publisher_enabled: false\n"
        f"  dedicated_broker_controller_client_config: {paths['controller']}\n"
        f"  dedicated_broker_publisher_client_config: {paths['publisher']}\n"
        f"  dedicated_broker_operator_client_config: {paths['operator']}\n"
        f"  dedicated_broker_registration_file: {paths['registration']}\n"
        f"  dedicated_broker_expected_source_sha: {source_sha}\n"
        f"  dedicated_broker_dispatcher_profile: {profile}\n"
    )


def _absolute_parts(path: Path) -> tuple[str, ...]:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("broker asset paths must be absolute and normalized")
    return tuple(part for part in path.parts if part != "/")


def _open_directory_fd(path: Path) -> int:
    parts = _absolute_parts(Path(path))
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _provision_directory_asset(item: dict) -> None:
    path = Path(item["path"])
    parent_fd = _open_directory_fd(path.parent)
    parent_before = os.fstat(parent_fd)
    name = path.name
    created = False
    try:
        try:
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            os.mkdir(name, mode=int(item["mode"]), dir_fd=parent_fd)
            created = True
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise ValueError("broker directory asset must be a real directory") from exc
        try:
            if created:
                os.fchown(fd, int(item["uid"]), int(item["gid"]))
                os.fchmod(fd, int(item["mode"]))
            info = os.fstat(fd)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != int(item["uid"])
                or info.st_gid != int(item["gid"])
                or stat.S_IMODE(info.st_mode) != int(item["mode"])
            ):
                raise ValueError("broker directory asset ownership or mode mismatches")
        finally:
            os.close(fd)
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
            raise ValueError("broker directory parent changed during provisioning")
    finally:
        os.close(parent_fd)


def _provision_file_asset(item: dict, payload: bytes | None) -> None:
    path = Path(item["path"])
    parent_fd = _open_directory_fd(path.parent)
    parent_before = os.fstat(parent_fd)
    name = path.name
    try:
        try:
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            if payload is None:
                if str(item.get("kind", "")).endswith("_key"):
                    payload = secrets.token_bytes(32)
                elif str(item.get("kind", "")).endswith("_sequence"):
                    payload = b""
                else:
                    raise ValueError(f"missing payload for broker asset {path}")
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            fd = os.open(name, flags, int(item["mode"]), dir_fd=parent_fd)
            try:
                os.fchown(fd, int(item["uid"]), int(item["gid"]))
                os.fchmod(fd, int(item["mode"]))
                view = memoryview(payload)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise ValueError("broker file asset must be a real file") from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != int(item["uid"])
                or info.st_gid != int(item["gid"])
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != int(item["mode"])
            ):
                raise ValueError("broker file asset ownership or mode mismatches")
            read_limit = _MAX_RUNTIME_ARCHIVE_BYTES if str(item.get("kind")) == "runtime_archive" else 1024 * 1024
            chunks: list[bytes] = []
            remaining = read_limit + 1
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            existing = b"".join(chunks)
            expected_sha = item.get("sha256")
            if (
                expected_sha is not None
                and hashlib.sha256(existing).hexdigest() != expected_sha
            ):
                raise ValueError("broker file asset digest differs from install plan")
            if str(item.get("kind", "")).endswith("_key"):
                if len(existing) != 32:
                    raise ValueError("broker surface key has invalid length")
            elif payload is None or existing != payload:
                raise ValueError("existing broker file asset differs from install plan")
            after = os.fstat(fd)
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ValueError("broker file asset changed during provisioning")
            parent_after = os.fstat(parent_fd)
            if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
                raise ValueError("broker file parent changed during provisioning")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _ensure_directory_tree(
    path: Path, *, mode: int, uid: int, gid: int, apply_final: bool = True
) -> None:
    """Create a directory path using only descriptor-relative no-follow opens."""
    parts = _absolute_parts(Path(path))
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        for index, part in enumerate(parts):
            created = False
            parent_before = os.fstat(fd)
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=fd,
                )
            except FileNotFoundError:
                os.mkdir(part, mode=0o711, dir_fd=fd)
                created = True
                child = os.open(
                    part,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=fd,
                )
            try:
                before = os.fstat(child)
                if not stat.S_ISDIR(before.st_mode):
                    raise ValueError("runtime extraction encountered a non-directory")
                if created or (apply_final and index == len(parts) - 1):
                    os.fchown(child, int(uid), int(gid))
                    os.fchmod(child, int(mode) if apply_final and index == len(parts) - 1 else 0o711)
                after = os.fstat(child)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise ValueError("runtime extraction directory changed during provisioning")
                parent_after = os.fstat(fd)
                if (parent_before.st_dev, parent_before.st_ino) != (
                    parent_after.st_dev, parent_after.st_ino
                ):
                    raise ValueError("runtime extraction parent changed during provisioning")
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def _runtime_extract_file(path: Path, content: bytes, *, mode: int, uid: int, gid: int) -> None:
    parent_fd = _open_directory_fd(Path(path).parent)
    parent_before = os.fstat(parent_fd)
    name = Path(path).name
    try:
        try:
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        except FileNotFoundError:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                int(mode),
                dir_fd=parent_fd,
            )
            try:
                os.fchown(fd, int(uid), int(gid))
                os.fchmod(fd, int(mode))
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != int(uid)
                    or before.st_gid != int(gid) or before.st_nlink != 1
                    or stat.S_IMODE(before.st_mode) != int(mode)):
                raise ValueError("runtime file ownership or mode is unsafe")
            chunks: list[bytes] = []
            remaining = len(content) + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            existing = b"".join(chunks)
            after = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
            ):
                raise ValueError("runtime file changed during provisioning")
            if existing != content:
                raise ValueError("runtime file differs from sealed archive")
            parent_after = os.fstat(parent_fd)
            if (parent_before.st_dev, parent_before.st_ino) != (
                parent_after.st_dev, parent_after.st_ino
            ):
                raise ValueError("runtime file parent changed during provisioning")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _runtime_extract_symlink(path: Path, target: str) -> None:
    parent_fd = _open_directory_fd(Path(path).parent)
    parent_before = os.fstat(parent_fd)
    name = Path(path).name
    try:
        try:
            info = os.lstat(name, dir_fd=parent_fd)
        except FileNotFoundError:
            os.symlink(target, name, dir_fd=parent_fd)
            created_info = os.lstat(name, dir_fd=parent_fd)
            if not stat.S_ISLNK(created_info.st_mode) or os.readlink(
                name, dir_fd=parent_fd
            ) != target:
                raise ValueError("runtime symlink changed during provisioning")
            parent_after = os.fstat(parent_fd)
            if (parent_before.st_dev, parent_before.st_ino) != (
                parent_after.st_dev, parent_after.st_ino
            ):
                raise ValueError("runtime symlink parent changed during provisioning")
            return
        observed_target = os.readlink(name, dir_fd=parent_fd)
        after = os.lstat(name, dir_fd=parent_fd)
        if (info.st_dev, info.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("runtime symlink changed during provisioning")
        if not stat.S_ISLNK(info.st_mode) or observed_target != target:
            raise ValueError("runtime symlink differs from sealed archive")
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev, parent_after.st_ino
        ):
            raise ValueError("runtime symlink parent changed during provisioning")
    finally:
        os.close(parent_fd)


def _read_runtime_manifest_file(
    path: Path, *, expected_sha256: str, expected_runtime_root: Path,
    expected_python_executable: Path, expected_python_version: str,
) -> dict[str, object]:
    _validated_install_path(path, field="runtime manifest")
    raw, info = _read_sealed_file_bytes(
        path, max_bytes=4 * 1024 * 1024, expected_sha256=None
    )
    if (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644):
        raise ValueError("runtime manifest ownership or mode is unsafe")
    try:
        manifest = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime manifest is invalid JSON") from exc
    required = {
        "contract", "schema_version", "runtime_root", "python_executable",
        "python_version", "provenance", "runtime_manifest_sha256", "entries",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != required
        or manifest.get("contract") != RUNTIME_MANIFEST_CONTRACT
        or manifest.get("schema_version") != 1
        or manifest.get("runtime_root") != str(expected_runtime_root)
        or manifest.get("python_executable") != str(expected_python_executable)
        or manifest.get("python_version") != expected_python_version
        or manifest.get("provenance") != _official_runtime_provenance(
            sha256=OFFICIAL_RUNTIME_ARCHIVE_SHA256
        )
        or manifest.get("runtime_manifest_sha256") != expected_sha256
        or not isinstance(manifest.get("entries"), list)
    ):
        raise ValueError("runtime manifest fields are not exact")
    if hashlib.sha256(_canonical_json_bytes(manifest["entries"])).hexdigest() != expected_sha256:
        raise ValueError("runtime manifest digest does not match the sealed plan")
    return manifest


def _verify_runtime_tree_against_manifest(
    runtime_root: Path,
    expected_entries: list[dict[str, object]],
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
) -> None:
    """Compare every installed runtime node with the sealed recursive manifest."""
    root = Path(runtime_root)
    root_fd = _open_directory_fd(root)
    try:
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != int(expected_owner_uid)
            or root_info.st_gid != int(expected_owner_gid)
            or stat.S_IMODE(root_info.st_mode) & 0o022
        ):
            raise ValueError("sealed runtime root ownership or mode is unsafe")
        observed: list[dict[str, object]] = []

        def visit(directory_fd: int, prefix: PurePosixPath) -> None:
            parent_before = os.fstat(directory_fd)
            try:
                with os.scandir(directory_fd) as stream:
                    children = sorted(stream, key=lambda item: item.name)
                    for child in children:
                        name = child.name
                        if (
                            not isinstance(name, str)
                            or name in {"", ".", ".."}
                            or "/" in name
                            or "\\" in name
                        ):
                            raise ValueError("sealed runtime contains an unsafe path")
                        relative = prefix / name
                        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            target = os.readlink(name, dir_fd=directory_fd)
                            if (
                                not target
                                or target.startswith("/")
                                or "\\" in target
                                or "\x00" in target
                            ):
                                raise ValueError("sealed runtime symlink target is unsafe")
                            resolved = PurePosixPath(
                                posixpath.normpath((relative.parent / target).as_posix())
                            )
                            if resolved.is_absolute() or any(
                                part in {"", ".", ".."} for part in resolved.parts
                            ):
                                raise ValueError("sealed runtime symlink escapes its root")
                            observed.append({
                                "path": relative.as_posix(),
                                "type": "symlink",
                                "target": resolved.as_posix(),
                                "mode": 0o555,
                            })
                        elif stat.S_ISDIR(info.st_mode):
                            if (
                                info.st_uid != int(expected_owner_uid)
                                or info.st_gid != int(expected_owner_gid)
                            ):
                                raise ValueError("sealed runtime directory ownership changed")
                            observed.append({
                                "path": relative.as_posix() + "/",
                                "type": "directory",
                                "mode": stat.S_IMODE(info.st_mode),
                            })
                            child_fd = os.open(
                                name,
                                os.O_RDONLY
                                | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0)
                                | getattr(os, "O_CLOEXEC", 0),
                                dir_fd=directory_fd,
                            )
                            try:
                                visit(child_fd, relative)
                            finally:
                                os.close(child_fd)
                        elif stat.S_ISREG(info.st_mode):
                            if (
                                info.st_uid != int(expected_owner_uid)
                                or info.st_gid != int(expected_owner_gid)
                                or info.st_nlink != 1
                            ):
                                raise ValueError("sealed runtime file ownership changed")
                            child_fd = os.open(
                                name,
                                os.O_RDONLY
                                | getattr(os, "O_NOFOLLOW", 0)
                                | getattr(os, "O_CLOEXEC", 0),
                                dir_fd=directory_fd,
                            )
                            try:
                                opened = os.fstat(child_fd)
                                if (
                                    opened.st_dev != info.st_dev
                                    or opened.st_ino != info.st_ino
                                    or opened.st_size != info.st_size
                                ):
                                    raise ValueError("sealed runtime file changed during verification")
                                digest = hashlib.sha256()
                                total = 0
                                while True:
                                    chunk = os.read(child_fd, 1024 * 1024)
                                    if not chunk:
                                        break
                                    total += len(chunk)
                                    if total > _MAX_RUNTIME_PACKAGE_BYTES:
                                        raise ValueError("sealed runtime file exceeds the size limit")
                                    digest.update(chunk)
                                closed = os.fstat(child_fd)
                                if (
                                    opened.st_dev,
                                    opened.st_ino,
                                    opened.st_size,
                                    opened.st_mtime_ns,
                                ) != (
                                    closed.st_dev,
                                    closed.st_ino,
                                    closed.st_size,
                                    closed.st_mtime_ns,
                                ):
                                    raise ValueError("sealed runtime file changed during verification")
                            finally:
                                os.close(child_fd)
                            observed.append({
                                "path": relative.as_posix(),
                                "type": "file",
                                "mode": stat.S_IMODE(info.st_mode),
                                "size": int(info.st_size),
                                "sha256": digest.hexdigest(),
                            })
                        else:
                            raise ValueError("sealed runtime contains an unsupported special file")
            finally:
                parent_after = os.fstat(directory_fd)
                if (parent_before.st_dev, parent_before.st_ino) != (
                    parent_after.st_dev, parent_after.st_ino
                ):
                    raise ValueError("sealed runtime directory changed during verification")

        visit(root_fd, PurePosixPath())
    finally:
        os.close(root_fd)
    if observed != expected_entries:
        expected_paths = {str(item.get("path")) for item in expected_entries}
        observed_paths = {str(item.get("path")) for item in observed}
        unexpected = sorted(observed_paths - expected_paths)
        missing = sorted(expected_paths - observed_paths)
        if unexpected:
            raise ValueError(f"sealed runtime contains unexpected entries: {unexpected[:8]}")
        if missing:
            raise ValueError(f"sealed runtime is missing manifest entries: {missing[:8]}")
        raise ValueError("sealed runtime entry metadata differs from its manifest")


def _materialize_sealed_runtime(
    filesystem_plan: dict[str, object], *, runtime_probe=None
) -> None:
    descriptor = filesystem_plan.get("sealed_runtime")
    if not isinstance(descriptor, dict) or descriptor.get("contract") != SEALED_RUNTIME_CONTRACT:
        raise ValueError("filesystem plan has no sealed runtime binding")
    destinations = descriptor.get("archive_destinations")
    if not isinstance(destinations, list) or len(destinations) != 2:
        raise ValueError("sealed runtime archive destinations are incomplete")
    for destination in destinations:
        if not isinstance(destination, dict) or set(destination) != {"path", "sha256", "size"}:
            raise ValueError("sealed runtime archive destination fields are not exact")
        archive_path = destination.get("path")
        if not isinstance(archive_path, str) or not Path(archive_path).is_absolute() or ".." in Path(archive_path).parts:
            raise ValueError("sealed runtime archive destination is invalid")
        _validated_hex_sha(destination.get("sha256"), field="sealed runtime archive SHA256", length=64)
        size = destination.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > _MAX_RUNTIME_ARCHIVE_BYTES:
            raise ValueError("sealed runtime archive destination size is invalid")
    runtime_root = Path(str(descriptor["runtime_root"]))
    entrypoint = Path(str(descriptor["entrypoint_path"]))
    direct_probe = Path(str(descriptor.get("direct_probe_path") or ""))
    bound = render_sealed_runtime_plan(
        runtime_archive_path=Path(str(destinations[0]["path"])),
        runtime_archive_sha256=str(destinations[0]["sha256"]),
        hermes_install_archive_path=Path(str(destinations[1]["path"])),
        hermes_install_archive_sha256=str(destinations[1]["sha256"]),
        hermes_install_provenance_path=Path(str(descriptor.get("hermes_provenance_path") or "")),
        hermes_install_provenance_sha256=str(descriptor.get("hermes_provenance_sha256") or ""),
        hermes_source_sha=str(descriptor.get("hermes_source_sha") or ""),
        runtime_root=runtime_root,
        entrypoint_path=entrypoint,
    )
    for field in ("python_sha256", "package_manifest_sha256", "runtime_manifest_sha256"):
        if str(descriptor.get(field)) != str(bound[field]):
            raise ValueError("sealed runtime manifest binding differs from archives")
    if (
        direct_probe != Path(str(bound["direct_probe_path"]))
        or str(descriptor.get("direct_probe_sha256")) != str(bound["direct_probe_sha256"])
    ):
        raise ValueError("sealed runtime direct probe binding differs from archives")
    if descriptor.get("official_release") != OFFICIAL_RUNTIME_RELEASE or int(descriptor.get("official_asset_id", -1)) != OFFICIAL_RUNTIME_ASSET_ID:
        raise ValueError("sealed runtime official artifact binding is invalid")
    manifest_path = Path(str(descriptor.get("runtime_manifest_path") or ""))
    manifest = _read_runtime_manifest_file(
        manifest_path,
        expected_sha256=str(bound["runtime_manifest_sha256"]),
        expected_runtime_root=runtime_root,
        expected_python_executable=Path(str(bound["python_executable_path"])),
        expected_python_version=str(bound["python_version"]),
    )
    if manifest["entries"] != bound["entries"]:
        raise ValueError("runtime manifest entries differ from the sealed plan")
    archives = [
        _read_runtime_archive_manifest(
            Path(str(destinations[0]["path"])),
            expected_sha256=str(destinations[0]["sha256"]),
            strip_prefix="python",
            required_paths={"bin/python3.11", "bin/python3", "lib/python3.11"},
            role="CPython",
        ),
        cast(
            dict[str, object],
            _validate_hermes_install_closure(
                Path(str(destinations[1]["path"])),
                archive_sha256=str(destinations[1]["sha256"]),
                provenance_path=Path(str(descriptor.get("hermes_provenance_path") or "")),
                provenance_sha256=str(descriptor.get("hermes_provenance_sha256") or ""),
                hermes_source_sha=str(descriptor.get("hermes_source_sha") or ""),
            )["archive"],
        ),
    ]
    if str(archives[0]["sha256"]) != OFFICIAL_RUNTIME_ARCHIVE_SHA256:
        raise ValueError("sealed runtime CPython archive is not the reviewed artifact")
    _ensure_directory_tree(runtime_root, mode=0o711, uid=0, gid=0)
    package_prefix = PurePosixPath("lib/python3.11/site-packages")
    archive_contents: list[dict[str, bytes]] = []
    for index, archive in enumerate(archives):
        contents: dict[str, bytes] = {}
        archive_data, _archive_info = _read_sealed_file_bytes(
            Path(str(destinations[index]["path"])),
            max_bytes=_MAX_RUNTIME_ARCHIVE_BYTES,
            expected_size=int(destinations[index].get("size", 0))
            if destinations[index].get("size") is not None else None,
            expected_sha256=str(destinations[index]["sha256"]),
        )
        with tarfile.open(fileobj=io.BytesIO(archive_data), mode="r:gz") as stream:
            for member in stream.getmembers():
                raw_name = member.name.rstrip("/") if member.isdir() else member.name
                if not raw_name.startswith("python/" if index == 0 else "hermes-install/"):
                    continue
                source = raw_name.split("/", 1)[1]
                if member.isfile():
                    handle = stream.extractfile(member)
                    if handle is None:
                        raise ValueError("sealed runtime archive file cannot be read")
                    contents[source] = handle.read(_MAX_RUNTIME_ARCHIVE_FILE_BYTES + 1)
        archive_contents.append(contents)
    for index, archive in enumerate(archives):
        for item in cast(list[dict[str, object]], archive["entries"]):
            source = str(item["path"]).rstrip("/")
            destination_rel = PurePosixPath(source)
            if index == 1:
                destination_rel = package_prefix / source
            destination = runtime_root / destination_rel.as_posix()
            if item["type"] == "directory":
                _ensure_directory_tree(destination, mode=0o555, uid=0, gid=0)
            elif item["type"] == "file":
                parent = destination.parent
                _ensure_directory_tree(parent, mode=0o555, uid=0, gid=0)
                content = archive_contents[index].get(source)
                if content is None:
                    raise ValueError("sealed runtime archive file cannot be read")
                if hashlib.sha256(content).hexdigest() != str(item["sha256"]):
                    raise ValueError("sealed runtime archive changed during extraction")
                _runtime_extract_file(destination, content, mode=int(item["mode"]), uid=0, gid=0)
            elif item["type"] == "symlink":
                source_target = str(item["target"])
                # Manifest targets are normalized relative to the archive
                # root, so resolve them directly under the destination root.
                target_rel = PurePosixPath(source_target)
                if index == 1:
                    target_rel = package_prefix / target_rel
                target_rel = PurePosixPath(posixpath.normpath(target_rel.as_posix()))
                link_target = posixpath.relpath(target_rel.as_posix(), start=PurePosixPath(source).parent.as_posix() if index == 0 else (package_prefix / PurePosixPath(source).parent).as_posix())
                _runtime_extract_symlink(destination, link_target)
            else:
                raise ValueError("sealed runtime manifest contains an unsupported entry")
    _runtime_extract_file(entrypoint, RUNTIME_ENTRYPOINT_CONTENT.encode("utf-8"), mode=0o555, uid=0, gid=0)
    _runtime_extract_file(direct_probe, RUNTIME_DIRECT_PROBE_CONTENT.encode("utf-8"), mode=0o555, uid=0, gid=0)
    # The immutable root and every directory in the recursive closure become
    # non-writable only after all files and the wrapper have been materialized.
    # This also tightens implicit parent directories for archives that omit
    # explicit tar directory members.
    runtime_directories: set[Path] = {runtime_root}
    for item in cast(list[dict[str, object]], bound["entries"]):
        relative = PurePosixPath(str(item["path"]).rstrip("/"))
        destination = runtime_root / relative
        directory = destination if item["type"] == "directory" else destination.parent
        while directory != runtime_root and runtime_root in directory.parents:
            runtime_directories.add(directory)
            directory = directory.parent
        runtime_directories.add(runtime_root)
    for directory in sorted(runtime_directories, key=lambda value: len(value.parts)):
        _ensure_directory_tree(directory, mode=0o555, uid=0, gid=0)
    _verify_runtime_tree_against_manifest(
        runtime_root,
        cast(list[dict[str, object]], manifest["entries"]),
        expected_owner_uid=0,
        expected_owner_gid=0,
    )
    probe = runtime_probe or verify_isolated_runtime_import
    try:
        probe(
            python_executable=Path(str(bound["python_executable_path"])),
            entrypoint_path=entrypoint,
            direct_probe_path=direct_probe,
            module="hermes_cli.kanban_broker_client",
        )
    except Exception as exc:
        raise ValueError("sealed runtime isolated import probe failed") from exc


def provision_filesystem_plan(
    plan: dict,
    *,
    payloads: dict[str, bytes],
    runtime_probe=None,
) -> None:
    """Materialize one exact disabled plan without following symlinks."""

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("broker asset provisioning requires root")
    if (
        not isinstance(plan, dict)
        or plan.get("contract") != "hermes.kanban_broker_filesystem_plan.v1"
    ):
        raise ValueError("unsupported broker filesystem plan")
    directories = plan.get("directories")
    files = plan.get("files")
    if not isinstance(directories, list) or not isinstance(files, list):
        raise ValueError("broker filesystem plan is malformed")
    strict_records = all(
        isinstance(item, dict) and {"sha256", "size", "secret"}.issubset(item)
        for item in files
    )
    if strict_records:
        for item in directories:
            _validate_plan_artifact_record(item, directory=True)
        for item in files:
            _validate_plan_artifact_record(item, directory=False)
    paths = [str(item.get("path")) for item in [*directories, *files]]
    if len(paths) != len(set(paths)):
        raise ValueError("broker filesystem plan contains duplicate paths")
    if any(not Path(path).is_absolute() or ".." in Path(path).parts for path in paths):
        raise ValueError("broker filesystem plan contains an unsafe path")
    for item in sorted(directories, key=lambda value: len(Path(value["path"]).parts)):
        _provision_directory_asset(item)
    for item in files:
        _provision_file_asset(item, payloads.get(str(item["path"])))
    if "sealed_runtime" in plan:
        _materialize_sealed_runtime(plan, runtime_probe=runtime_probe)


def provision_disabled_install(
    plan: dict,
    *,
    payloads: dict[str, bytes],
    service_config_path: Path,
    runner=subprocess.run,
) -> None:
    """Provision exact assets only after proving both services are disabled.

    A false config flag is not a launchd state boundary: an older loaded job
    could keep running across an idempotent reinstall.  Refuse that case, set
    both labels disabled before writing any asset, and positively reread the
    launchd disabled registry after the byte-identical filesystem transaction.
    """

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("disabled broker provisioning requires root")
    path = Path(service_config_path)
    matching = [
        item
        for item in plan.get("files", [])
        if item.get("kind") == "service_config" and item.get("path") == str(path)
    ]
    if len(matching) != 1:
        raise ValueError("filesystem plan does not bind one exact service config")
    _disable_unloaded_launchd_services(runner)
    provision_filesystem_plan(plan, payloads=payloads)
    info = path.lstat()
    if info.st_uid <= 0:
        raise ValueError("broker service config must be owned by the broker UID")
    if not verify_service_disabled(path, expected_owner_uid=int(info.st_uid)):
        raise ValueError("broker asset installation did not remain disabled")
    _verify_launchd_services_disabled(runner)


def render_rollback_plan(
    *,
    python_executable: Path,
    operator_client_config: Path,
    service_config: Path,
) -> dict[str, list[str]]:
    """Return non-destructive quiesce/bootout/disabled-readback commands."""
    python = str(Path(python_executable))
    return {
        "quiesce": [
            python,
            "-m",
            "hermes_cli.kanban_broker_client",
            "quiesce",
            "--config",
            str(Path(operator_client_config)),
        ],
        "bootout": [
            "/bin/launchctl",
            "bootout",
            "system/ai.hermes.kanban-broker",
        ],
        "disable_config": [
            python,
            "-m",
            "hermes_cli.kanban_broker_install",
            "disable",
            "--config",
            str(Path(service_config)),
        ],
        "assert_disabled": [
            python,
            "-m",
            "hermes_cli.kanban_broker_install",
            "verify-disabled",
            "--config",
            str(Path(service_config)),
        ],
    }


def _read_service_config_file(
    path: Path, *, expected_owner_uid: int
) -> tuple[dict, os.stat_result]:
    path = Path(path)
    _validated_install_path(path, field="broker service config")
    # Give callers a stable diagnostic for an explicitly supplied symlink;
    # the descriptor-relative O_NOFOLLOW read below remains authoritative for
    # races between this advisory check and opening the file.
    try:
        if stat.S_ISLNK(path.lstat().st_mode):
            raise ValueError("broker service config must be a real file mode 0600")
    except FileNotFoundError as exc:
        raise ValueError("broker service config must be a real file mode 0600") from exc
    raw, before = _read_sealed_file_bytes(path, max_bytes=1024 * 1024)
    if (before.st_uid != int(expected_owner_uid)
            or stat.S_IMODE(before.st_mode) != 0o600):
        raise ValueError("broker service config must be a real file mode 0600")
    try:
        config = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("broker service config is invalid JSON") from exc
    if (
        not isinstance(config, dict)
        or config.get("contract") != "hermes.kanban_broker_service_config.v1"
        or config.get("broker_boundary") != KANBAN_BROKER_SECURITY_BOUNDARY
        or int(config.get("broker_uid", -1)) != int(expected_owner_uid)
    ):
        raise ValueError("broker service config identity does not verify")
    return config, before


def service_config_sha256(path: Path, *, expected_owner_uid: int) -> str:
    """Hash the exact safely-read service config for canary binding."""

    _config, _info = _read_service_config_file(
        Path(path), expected_owner_uid=expected_owner_uid
    )
    raw, _info = _read_sealed_file_bytes(Path(path), max_bytes=1024 * 1024)
    return hashlib.sha256(raw).hexdigest()


def _read_canary_key(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(Path(path), flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size != 32
        ):
            raise ValueError("activation canary key ownership is unsafe")
        key = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(key) != 32:
        raise ValueError("activation canary key length is invalid")
    return key


def generate_activation_attestation(
    *,
    service_config_path: Path,
    expected_owner_uid: int,
    now: int | None = None,
) -> dict:
    """Execute the one reviewed root runner and sign only observed results."""

    if os.geteuid() != 0:  # windows-footgun: ok - root-only activation runner
        raise PermissionError("activation canary generation requires root")
    from hermes_cli import kanban_broker_canary

    config, _info = _read_service_config_file(
        service_config_path, expected_owner_uid=expected_owner_uid
    )
    if (
        config.get("enabled") is not True
        or config.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError(
            "activation canaries require the staged non-publishing service"
        )
    runtime_identity = validate_runtime_identity(config, expected_package_owner_uid=0)
    package_root = Path(config["package_root"]).resolve(strict=True)
    expected_installer = (package_root / "kanban_broker_install.py").resolve(
        strict=True
    )
    expected_runner = (package_root / "kanban_broker_canary.py").resolve(strict=True)
    if Path(__file__).resolve(strict=True) != expected_installer:
        raise ValueError("activation installer is outside the installed package")
    runner_path = Path(kanban_broker_canary.__file__).resolve(strict=True)
    if runner_path != expected_runner:
        raise ValueError("activation canary runner is outside the installed package")
    observations = kanban_broker_canary.run_activation_canaries(config)
    issued_at = int(time.time() if now is None else now)
    unsigned = {
        "contract": ACTIVATION_CANARY_CONTRACT,
        "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
        "service_config_sha256": service_config_sha256(
            service_config_path, expected_owner_uid=expected_owner_uid
        ),
        "install_nonce": config.get("install_nonce"),
        "issued_at": issued_at,
        "runner_path": str(runner_path),
        "runner_sha256": _safe_file_sha256(runner_path),
        "runtime_identity": runtime_identity,
        "observations": observations,
    }
    unsigned_bytes = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    payload_sha = hashlib.sha256(unsigned_bytes).hexdigest()
    signed = {**unsigned, "attestation_payload_sha256": payload_sha}
    key = _read_canary_key(Path(config["canary_key_path"]))
    signed_bytes = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    signed["attestation_hmac"] = hmac.new(key, signed_bytes, hashlib.sha256).hexdigest()
    return signed


def _replace_service_config(
    path: Path,
    *,
    original: os.stat_result,
    payload: dict,
) -> dict:
    path = Path(path)
    parent = path.parent
    parent_fd = _open_directory_fd(parent)
    parent_before = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_IMODE(parent_before.st_mode) & 0o022
    ):
        os.close(parent_fd)
        raise ValueError("broker config parent must not be group/world writable")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    name = path.name
    temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchown(fd, int(original.st_uid), int(original.st_gid))
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_after = os.fstat(parent_fd)
        if (parent_after.st_dev, parent_after.st_ino) != (
            parent_before.st_dev,
            parent_before.st_ino,
        ):
            raise ValueError("broker config parent changed during update")
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError("broker service config changed during update")
        os.replace(
            temporary_name,
            name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)
    reread, _info = _read_service_config_file(
        path, expected_owner_uid=int(original.st_uid)
    )
    return reread


def validate_activation_attestation(
    *,
    config: dict,
    service_digest: str,
    attestation: dict,
    now: int | None = None,
) -> None:
    """Require a fresh exact-config root-canary record before activation."""

    current = int(time.time() if now is None else now)
    exact_fields = {
        "contract",
        "broker_boundary",
        "service_config_sha256",
        "install_nonce",
        "issued_at",
        "runner_path",
        "runner_sha256",
        "runtime_identity",
        "observations",
        "attestation_payload_sha256",
        "attestation_hmac",
    }
    if (
        not isinstance(attestation, dict)
        or set(attestation) != exact_fields
        or attestation.get("contract") != ACTIVATION_CANARY_CONTRACT
        or attestation.get("broker_boundary") != KANBAN_BROKER_SECURITY_BOUNDARY
        or attestation.get("service_config_sha256") != service_digest
        or attestation.get("install_nonce") != config.get("install_nonce")
    ):
        raise ValueError("activation canary attestation does not bind this install")
    issued_at = attestation.get("issued_at")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or issued_at > current + 30
        or current - issued_at > 900
    ):
        raise ValueError("activation canary attestation is stale")
    observations = attestation.get("observations")
    if not isinstance(observations, dict) or set(observations) != set(
        ACTIVATION_CANARY_CHECKS
    ):
        raise ValueError("activation canary set is incomplete")
    failed: list[str] = []
    for name in ACTIVATION_CANARY_CHECKS:
        observation = observations.get(name)
        if (
            not isinstance(observation, dict)
            or set(observation) != {"outcome", "detail"}
            or observation.get("outcome") != "PASS"
            or not isinstance(observation.get("detail"), str)
        ):
            failed.append(name)
    if failed:
        raise ValueError(f"activation canary failed closed: {', '.join(failed)}")
    runtime = validate_runtime_identity(config, expected_package_owner_uid=0)
    if attestation.get("runtime_identity") != runtime:
        raise ValueError("activation canary runtime identity changed")
    runner = Path(str(attestation.get("runner_path") or ""))
    expected_runner = (
        Path(config["package_root"]) / "kanban_broker_canary.py"
    ).resolve(strict=True)
    if runner.resolve(strict=True) != expected_runner:
        raise ValueError("activation canary runner is outside the installed package")
    if _safe_file_sha256(runner) != attestation.get("runner_sha256"):
        raise ValueError("activation canary runner identity changed")
    unsigned = {
        key: value
        for key, value in attestation.items()
        if key not in {"attestation_payload_sha256", "attestation_hmac"}
    }
    unsigned_bytes = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if hashlib.sha256(unsigned_bytes).hexdigest() != attestation.get(
        "attestation_payload_sha256"
    ):
        raise ValueError("activation canary payload digest changed")
    signed = {
        key: value for key, value in attestation.items() if key != "attestation_hmac"
    }
    key = _read_canary_key(Path(config["canary_key_path"]))
    expected_hmac = hmac.new(
        key,
        json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(
        str(attestation.get("attestation_hmac") or ""), expected_hmac
    ):
        raise ValueError("activation canary signature does not verify")


def activate_service_config(
    path: Path,
    *,
    expected_owner_uid: int,
    attestation: dict,
    now: int | None = None,
) -> dict:
    """Promote a staged service to publishing only after signed canaries pass."""

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("broker activation requires root")
    config, original = _read_service_config_file(
        Path(path), expected_owner_uid=expected_owner_uid
    )
    if (
        config.get("enabled") is not True
        or config.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError("broker activation requires an exact staged starting state")
    digest = service_config_sha256(path, expected_owner_uid=expected_owner_uid)
    validate_activation_attestation(
        config=config,
        service_digest=digest,
        attestation=attestation,
        now=now,
    )
    activated = dict(config)
    activated["trusted_publisher_enabled"] = True
    activated_bytes = _json_artifact_bytes(activated)
    activated_digest = hashlib.sha256(activated_bytes).hexdigest()
    try:
        # Publish the active attestation first, bound to the exact bytes that
        # will be installed.  Until the final config rename succeeds the
        # service still has trusted_publisher_enabled=false and therefore
        # cannot publish; a crash leaves an explicit mismatch for startup to
        # reject and rollback.
        if config.get("runtime_attestation_path") is not None:
            _update_runtime_attestation(
                config,
                service_config_path=Path(path),
                active=True,
                revoked=False,
                isolated_probe={
                    "command": [
                        str(config["python_executable"]),
                        "-I",
                        "-B",
                        str(Path(config["python_executable"]).parent.parent / "runtime-probe.py"),
                    ],
                    "outcome": "PASS",
                },
                publisher_probe_status="PASS",
                service_config_sha256=activated_digest,
            )
        _set_dispatcher_profile_activation(config, enabled=True)
        reread = _replace_service_config(path, original=original, payload=activated)
        if (
            reread.get("enabled") is not True
            or reread.get("trusted_publisher_enabled") is not True
            or service_config_sha256(path, expected_owner_uid=expected_owner_uid)
            != activated_digest
        ):
            raise ValueError("broker activation readback failed")
        return reread
    except Exception:
        # Best-effort local recovery is itself fail-closed; the outer
        # activation flow also performs launchd bootout and disabled readback.
        try:
            disable_service_config(path, expected_owner_uid=expected_owner_uid)
        except Exception:
            pass
        raise


def stage_service_config(path: Path, *, expected_owner_uid: int) -> dict:
    """Enter non-publishing canary mode from the exact disabled state."""

    if os.geteuid() != 0:  # windows-footgun: ok - root-only staging
        raise PermissionError("broker staging requires root")
    config, original = _read_service_config_file(
        Path(path), expected_owner_uid=expected_owner_uid
    )
    if (
        config.get("enabled") is not False
        or config.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError("broker staging requires the exact disabled state")
    staged = dict(config)
    staged["enabled"] = True
    staged["trusted_publisher_enabled"] = False
    reread = _replace_service_config(path, original=original, payload=staged)
    if (
        reread.get("enabled") is not True
        or reread.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError("broker staging readback failed")
    _update_runtime_attestation(
        reread, service_config_path=Path(path), active=False, revoked=True
    )
    return reread


def _launchctl(
    runner,
    arguments: list[str],
) -> None:
    runner(
        ["/bin/launchctl", *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )


_BROKER_LAUNCHD_LABELS = (
    "ai.hermes.kanban-broker",
    "ai.hermes.kanban-worker",
)


def _launchctl_query(runner, arguments: list[str]):
    return runner(
        ["/bin/launchctl", *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )


def _disable_unloaded_launchd_services(runner) -> None:
    for label in _BROKER_LAUNCHD_LABELS:
        status = _launchctl_query(runner, ["print", f"system/{label}"])
        if int(getattr(status, "returncode", 1)) == 0:
            raise ValueError(
                f"broker launchd service is already loaded and must be quiesced: {label}"
            )
    for label in _BROKER_LAUNCHD_LABELS:
        _launchctl(runner, ["disable", f"system/{label}"])


def _verify_launchd_services_disabled(runner) -> None:
    status = _launchctl_query(runner, ["print-disabled", "system"])
    if int(getattr(status, "returncode", 1)) != 0:
        raise ValueError("launchd disabled-state readback failed")
    output = str(getattr(status, "stdout", "") or "")
    for label in _BROKER_LAUNCHD_LABELS:
        pattern = re.compile(
            rf'^\s*"?{re.escape(label)}"?\s*=>\s*true\s*$',
            re.MULTILINE,
        )
        if pattern.search(output) is None:
            raise ValueError(f"launchd label is not positively disabled: {label}")


def _rollback_failed_activation(
    *,
    service_config_path: Path,
    expected_owner_uid: int,
    runner,
) -> None:
    """Restore and prove the exact disabled state after activation starts."""

    errors: list[str] = []
    # Disable KeepAlive before bootout. Each mutation is independent because
    # only the authoritative readbacks below are accepted as proof of safety.
    for label in _BROKER_LAUNCHD_LABELS:
        try:
            _launchctl_query(runner, ["disable", f"system/{label}"])
        except Exception:
            pass
    try:
        disable_service_config(
            service_config_path, expected_owner_uid=expected_owner_uid
        )
    except Exception as exc:
        errors.append(f"disable config: {type(exc).__name__}")
    for label in _BROKER_LAUNCHD_LABELS:
        try:
            _launchctl_query(runner, ["bootout", f"system/{label}"])
        except Exception:
            pass
    for label in _BROKER_LAUNCHD_LABELS:
        try:
            status = _launchctl_query(runner, ["print", f"system/{label}"])
        except Exception as exc:
            errors.append(f"launchd absence readback {label}: {type(exc).__name__}")
            continue
        if int(getattr(status, "returncode", 0)) == 0:
            errors.append(f"launchd label remained loaded: {label}")
    try:
        _verify_launchd_services_disabled(runner)
    except Exception as exc:
        errors.append(f"disabled-state readback: {type(exc).__name__}")
    try:
        if not verify_service_disabled(
            service_config_path, expected_owner_uid=expected_owner_uid
        ):
            errors.append("broker config did not remain disabled")
    except Exception as exc:
        errors.append(f"disabled config readback: {type(exc).__name__}")
    if errors:
        raise ValueError(
            "broker activation rollback failed closed: " + "; ".join(errors)
        )


def _register_activation_repository(
    config: dict[str, object], *, operator_client_config: Path
) -> dict[str, object]:
    """Consume the sealed registration input through the real broker socket."""
    registration_value = config.get("registration_file_path")
    if not isinstance(registration_value, str):
        raise ValueError("broker activation registration file is required")
    registration_path = Path(registration_value)
    raw, info = _read_sealed_file_bytes(
        registration_path, max_bytes=1024 * 1024
    )
    if (
        info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) not in {0o600, 0o644}
    ):
        raise ValueError("broker activation registration file ownership or mode is unsafe")
    try:
        registration = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("broker activation registration file is invalid") from exc
    required = {
        "contract", "repository_id", "source_path", "default_branch", "project_id",
        "remote_repository", "expected_source_sha",
    }
    if (
        not isinstance(registration, dict)
        or set(registration) != required
        or registration.get("contract") != "hermes.kanban_broker_register_request.v1"
        or not isinstance(registration.get("repository_id"), str)
        or not isinstance(registration.get("source_path"), str)
        or not isinstance(registration.get("default_branch"), str)
        or not isinstance(registration.get("remote_repository"), dict)
        or re.fullmatch(r"[0-9a-f]{40}", str(registration.get("expected_source_sha"))) is None
    ):
        raise ValueError("broker activation registration fields are not exact")
    expected_sha = str(registration["expected_source_sha"])
    configured_sha = config.get("remote_policy_source_sha")
    if configured_sha != expected_sha:
        raise ValueError("broker activation registration SHA differs from service policy")
    from hermes_cli.kanban_broker_client import load_broker_client

    client = load_broker_client(operator_client_config, expected_surface="operator")
    request = dict(registration)
    request.pop("contract", None)
    result = client.call("register_repository", request)
    expected_source = Path(str(registration["source_path"])).resolve(strict=True)
    if (
        not isinstance(result, dict)
        or set(result) != {
            "repository_id", "source_path", "default_branch", "base_sha", "fingerprint",
            "project_id", "remote_repository", "remote_repository_sha256",
        }
        or result.get("repository_id") != registration["repository_id"]
        or result.get("source_path") != str(expected_source)
        or result.get("default_branch") != registration["default_branch"]
        or result.get("base_sha") != expected_sha
        or result.get("project_id") != registration["project_id"]
        or result.get("remote_repository") != registration["remote_repository"]
    ):
        raise ValueError("broker activation registration readback does not match the sealed input")
    return result


def activate_installation(
    *,
    service_config_path: Path,
    expected_owner_uid: int,
    launchd_plist_path: Path,
    worker_launchd_plist_path: Path,
    operator_client_config: Path,
    now: int | None = None,
    runner=subprocess.run,
    canary_generator=generate_activation_attestation,
) -> dict:
    """Activate, bootstrap, and positively read back one staged broker install."""

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("broker installation activation requires root")
    config, _info = _read_service_config_file(
        service_config_path, expected_owner_uid=expected_owner_uid
    )
    if int(config.get("operator_uid", -1)) != 0:
        raise ValueError("reviewed activation requires the root operator surface")
    if (
        config.get("enabled") is not False
        or config.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError("broker activation requires the exact disabled state")
    try:
        stage_service_config(service_config_path, expected_owner_uid=expected_owner_uid)
        _launchctl(
            runner,
            ["enable", "system/ai.hermes.kanban-worker"],
        )
        _launchctl(
            runner,
            ["enable", "system/ai.hermes.kanban-broker"],
        )
        _launchctl(
            runner,
            ["bootstrap", "system", str(Path(worker_launchd_plist_path))],
        )
        _launchctl(
            runner,
            ["bootstrap", "system", str(Path(launchd_plist_path))],
        )
        _launchctl(
            runner,
            ["kickstart", "-k", "system/ai.hermes.kanban-worker"],
        )
        _launchctl(
            runner,
            ["kickstart", "-k", "system/ai.hermes.kanban-broker"],
        )
        deadline = time.monotonic() + 10.0
        required_sockets = [
            Path(config[name])
            for name in (
                "controller_socket",
                "publisher_socket",
                "operator_socket",
                "worker_socket",
            )
        ]
        while not all(path.is_socket() for path in required_sockets):
            if time.monotonic() >= deadline:
                raise ValueError("broker activation sockets did not become ready")
            time.sleep(0.05)
        # Registration is an operator-authorized broker operation.  It is
        # consumed from the sealed file so activation cannot silently drift
        # from the source SHA or remote policy encoded by the plan.
        _register_activation_repository(
            config, operator_client_config=Path(operator_client_config)
        )
        attestation = canary_generator(
            service_config_path=service_config_path,
            expected_owner_uid=expected_owner_uid,
            now=now,
        )
        result = activate_service_config(
            service_config_path,
            expected_owner_uid=expected_owner_uid,
            attestation=attestation,
            now=now,
        )
        _launchctl(
            runner,
            ["kickstart", "-k", "system/ai.hermes.kanban-broker"],
        )
        from hermes_cli.kanban_broker_client import load_broker_client

        client = load_broker_client(
            Path(operator_client_config), expected_surface="operator"
        )
        status = client.call(
            "quiesce_status",
            {"contract": "hermes.kanban_broker_quiesce_status.v1"},
        )
        if status != {
            "contract": "hermes.kanban_broker_quiesce_status.v1",
            "quiescing": False,
            "inflight": 0,
        }:
            raise ValueError("broker activation readback did not reach idle service")
        reread, _new_info = _read_service_config_file(
            service_config_path, expected_owner_uid=expected_owner_uid
        )
        if reread.get("enabled") is not True:
            raise ValueError("broker activation config readback failed")
        return result
    except Exception as activation_error:
        try:
            _rollback_failed_activation(
                service_config_path=service_config_path,
                expected_owner_uid=expected_owner_uid,
                runner=runner,
            )
        except Exception as rollback_error:
            raise rollback_error from activation_error
        raise


def rollback_installation(
    *,
    service_config_path: Path,
    expected_owner_uid: int,
    operator_client_config: Path,
    worker_service_label: str = "ai.hermes.kanban-worker",
    runner=subprocess.run,
    wait_seconds: float = 30.0,
) -> dict:
    """Drain, prevent restart, boot out, and prove both labels are absent."""

    if os.geteuid() != 0:  # windows-footgun: ok - macOS root installer only
        raise PermissionError("broker installation rollback requires root")
    if worker_service_label != "ai.hermes.kanban-worker":
        raise ValueError("rollback worker service label is not the reviewed label")
    from hermes_cli.kanban_broker_client import load_broker_client
    from hermes_cli.kanban_broker_client import quiesce_and_wait

    client = load_broker_client(
        Path(operator_client_config), expected_surface="operator"
    )
    quiesce_and_wait(client, wait_seconds=wait_seconds)
    errors: list[str] = []
    # Disable KeepAlive admission before bootout so a successfully quiesced
    # process cannot race launchd and restart between the two transactions.
    for label in _BROKER_LAUNCHD_LABELS:
        try:
            _launchctl(runner, ["disable", f"system/{label}"])
        except Exception as exc:
            errors.append(f"disable {label}: {type(exc).__name__}")
    disabled: dict | None = None
    try:
        disabled = disable_service_config(
            service_config_path, expected_owner_uid=expected_owner_uid
        )
    except Exception as exc:
        errors.append(f"disable config: {type(exc).__name__}")
    for label in _BROKER_LAUNCHD_LABELS:
        # bootout is idempotent: an already-absent label may return nonzero.
        try:
            _launchctl_query(runner, ["bootout", f"system/{label}"])
        except Exception:
            # A mutation transport error is not an outcome. Continue through
            # the other label and authoritative absence readbacks below.
            pass
    for label in _BROKER_LAUNCHD_LABELS:
        try:
            status = _launchctl_query(runner, ["print", f"system/{label}"])
        except Exception as exc:
            errors.append(f"launchd absence readback {label}: {type(exc).__name__}")
            continue
        if int(getattr(status, "returncode", 0)) == 0:
            errors.append(f"launchd label remained loaded: {label}")
    try:
        _verify_launchd_services_disabled(runner)
    except Exception as exc:
        errors.append(f"disabled-state readback: {type(exc).__name__}")
    try:
        if not verify_service_disabled(
            service_config_path, expected_owner_uid=expected_owner_uid
        ):
            errors.append("broker config did not remain disabled")
    except Exception as exc:
        errors.append(f"disabled config readback: {type(exc).__name__}")
    if errors:
        raise ValueError("broker rollback failed closed: " + "; ".join(errors))
    if disabled is None:
        raise ValueError("broker rollback failed closed: disabled config is unavailable")
    return disabled


def _git_command_environment() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _source_git_identity(source: Path, *, expected: str, git: Path) -> tuple[str, str]:
    """Return HEAD/tree only for a clean checkout with immutable Git state."""
    if git != Path("/usr/bin/git"):
        raise ValueError("Hermes source verification requires /usr/bin/git")
    status = subprocess.run(
        [str(git), "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False, capture_output=True, text=True, timeout=10,
        env=_git_command_environment(),
    )
    if status.returncode != 0 or status.stdout:
        raise ValueError("Hermes source checkout must be clean and source-derived")
    head_result = subprocess.run(
        [str(git), "-C", str(source), "rev-parse", "--verify", "HEAD^{commit}"],
        check=False, capture_output=True, text=True, timeout=10,
        env=_git_command_environment(),
    )
    tree_result = subprocess.run(
        [str(git), "-C", str(source), "rev-parse", "--verify", "HEAD^{tree}"],
        check=False, capture_output=True, text=True, timeout=10,
        env=_git_command_environment(),
    )
    head = head_result.stdout.strip()
    tree = tree_result.stdout.strip()
    if (
        head_result.returncode != 0
        or head != expected
        or re.fullmatch(r"[0-9a-f]{40}", tree) is None
    ):
        raise ValueError("Hermes source SHA/tree does not match the clean checkout")
    return head, tree


def _locked_uv_packages(uv_lock: bytes) -> list[dict[str, object]]:
    """Extract the complete non-editable package set from a real uv.lock."""
    try:
        document = tomllib.loads(uv_lock.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("Hermes uv.lock is not a valid locked document") from exc
    if document.get("version") != 1 or not isinstance(document.get("package"), list):
        raise ValueError("Hermes uv.lock has no supported package set")
    records: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for package in document["package"]:
        if not isinstance(package, dict):
            raise ValueError("Hermes uv.lock package record is malformed")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name):
            raise ValueError("Hermes uv.lock package name is invalid")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+!~-]{0,127}", version):
            raise ValueError("Hermes uv.lock package version is invalid")
        if not isinstance(source, dict):
            raise ValueError("Hermes uv.lock package source is missing")
        # The repository itself is intentionally copied from Git below.  It
        # must never be accepted as an editable dependency in the installed
        # closure, while every third-party package must carry lock artifacts.
        if "editable" in source:
            if source.get("editable") != ".":
                raise ValueError("Hermes uv.lock has an unsupported editable package")
            continue
        artifacts: list[dict[str, object]] = []
        for key in ("sdist", "wheels"):
            values = package.get(key, []) if key == "wheels" else [package.get(key)]
            if key == "wheels" and not isinstance(values, list):
                raise ValueError("Hermes uv.lock wheel artifacts are malformed")
            if key == "sdist" and values == [None]:
                values = []
            for artifact in values:
                if not isinstance(artifact, dict):
                    raise ValueError("Hermes uv.lock package has no artifact hash")
                url = artifact.get("url")
                digest = artifact.get("hash")
                size = artifact.get("size")
                if (
                    not isinstance(url, str)
                    or not url.startswith(("https://", "http://"))
                    or not isinstance(digest, str)
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                    or isinstance(size, bool)
                    or not isinstance(size, int)
                    or size <= 0
                ):
                    raise ValueError("Hermes uv.lock package has no complete artifact hash")
                artifacts.append({"url": url, "sha256": digest[7:], "size": size})
        if not artifacts:
            raise ValueError("Hermes uv.lock package has no artifact hash")
        key = (name.lower().replace("_", "-").replace(".", "-"), version)
        if key in seen:
            raise ValueError("Hermes uv.lock contains duplicate package records")
        seen.add(key)
        records.append({
            "name": name,
            "version": version,
            "source": {str(k): source[k] for k in sorted(source)},
            "artifacts": sorted(artifacts, key=lambda item: (str(item["url"]), str(item["sha256"]))),
        })
    if len(records) < 2:
        raise ValueError("Hermes lock does not describe a complete dependency closure")
    records.sort(key=lambda item: (str(item["name"]).lower(), str(item["version"])))
    return records


def _git_archive_hermes_cli(source: Path, *, expected: str, git: Path) -> tuple[bytes, dict[str, bytes]]:
    """Read first-party bytes from the exact Git commit; never from install_root."""
    result = subprocess.run(
        [
            str(git), "-C", str(source), "archive", "--format=tar", expected,
            "--", "hermes_cli", "hermes_constants.py", "utils.py",
        ],
        check=False, capture_output=True, timeout=30, env=_git_command_environment(),
    )
    if result.returncode != 0 or not result.stdout:
        raise ValueError("Hermes first-party Git archive cannot be read")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as stream:
            for member in stream.getmembers():
                raw = member.name.rstrip("/") if member.isdir() else member.name
                if raw == "hermes_cli":
                    continue
                if raw not in {"hermes_constants.py", "utils.py"} and not raw.startswith("hermes_cli/"):
                    raise ValueError("Hermes Git archive contains an unexpected path")
                relative = _archive_relative_name(raw)
                if member.isdir():
                    continue
                if member.issym() or member.islnk() or not member.isfile():
                    raise ValueError("Hermes first-party Git archive contains an unsafe entry")
                if member.size < 1 or member.size > _MAX_RUNTIME_ARCHIVE_FILE_BYTES:
                    raise ValueError("Hermes first-party Git archive entry is too large")
                handle = stream.extractfile(member)
                if handle is None:
                    raise ValueError("Hermes first-party Git archive entry is unreadable")
                content = handle.read(_MAX_RUNTIME_ARCHIVE_FILE_BYTES + 1)
                if len(content) != member.size:
                    raise ValueError("Hermes first-party Git archive entry changed")
                if relative in files:
                    raise ValueError("Hermes first-party Git archive contains duplicate paths")
                files[relative] = content
    except (OSError, tarfile.TarError) as exc:
        raise ValueError("Hermes first-party Git archive is invalid") from exc
    required = {
        "hermes_cli/__init__.py", "hermes_cli/main.py", "hermes_cli/kanban_broker_client.py",
        "hermes_cli/kanban_broker_worker.py", "hermes_cli/kanban_broker_service.py",
        "hermes_cli/kanban_broker_protocol.py", "hermes_cli/kanban_broker_install.py",
        "hermes_cli/kanban_dedicated_broker.py", "hermes_cli/kanban_broker_canary.py",
    }
    if not required.issubset(files):
        raise ValueError("Hermes Git archive is missing the complete first-party broker closure")
    return result.stdout, files


def _verify_installed_distributions(site_packages: Path, locked: list[dict[str, object]]) -> list[dict[str, object]]:
    """Verify every installed dist-info RECORD and bind it to uv.lock."""
    locked_by_key = {
        (str(item["name"]).lower().replace("_", "-").replace(".", "-"), str(item["version"])): item
        for item in locked
    }
    installed: list[dict[str, object]] = []
    for metadata_path in sorted(site_packages.glob("*.dist-info/METADATA"), key=lambda p: p.as_posix()):
        raw, _ = _read_sealed_file_bytes(metadata_path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
        metadata: dict[str, str] = {}
        for line in raw.decode("utf-8").splitlines():
            if not line:
                break
            if ": " in line:
                key, value = line.split(": ", 1)
                if key in {"Name", "Version"}:
                    metadata[key] = value
        name, version = metadata.get("Name"), metadata.get("Version")
        key = (str(name).lower().replace("_", "-").replace(".", "-"), str(version))
        if not name or not version or key not in locked_by_key:
            raise ValueError("installed Hermes dependency is not bound to uv.lock")
        dist_info = metadata_path.parent
        record_path = dist_info / "RECORD"
        record_raw, _ = _read_sealed_file_bytes(record_path, max_bytes=_MAX_RUNTIME_FILE_BYTES)
        try:
            rows = list(csv.reader(record_raw.decode("utf-8").splitlines()))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise ValueError("installed Hermes dependency RECORD is invalid") from exc
        seen: set[str] = set()
        for row in rows:
            if len(row) != 3 or not row[0] or row[0].startswith("/") or "\\" in row[0]:
                raise ValueError("installed Hermes dependency RECORD path is unsafe")
            relative = PurePosixPath(row[0])
            if row[0] in seen or row[0].startswith("/") or "\\" in row[0] or "\x00" in row[0]:
                raise ValueError("installed Hermes dependency RECORD path is unsafe")
            seen.add(row[0])
            install_root = site_packages.parents[2]
            candidate = site_packages / Path(row[0])
            candidate_info = candidate.lstat()
            if stat.S_ISLNK(candidate_info.st_mode) or not stat.S_ISREG(candidate_info.st_mode):
                raise ValueError("installed Hermes dependency RECORD target is unsafe")
            target = candidate.resolve()
            if target != install_root and install_root not in target.parents:
                raise ValueError("installed Hermes dependency RECORD path escapes the staging root")
            if not target.is_file():
                raise ValueError("installed Hermes dependency RECORD is incomplete")
            if row[1].startswith("sha256="):
                expected = row[1][len("sha256="):]
                actual = base64.urlsafe_b64encode(hashlib.sha256(target.read_bytes()).digest()).decode("ascii").rstrip("=")
                if expected != actual:
                    raise ValueError("installed Hermes dependency RECORD digest differs")
        direct_url = dist_info / "direct_url.json"
        if direct_url.exists():
            direct_raw, _ = _read_sealed_file_bytes(direct_url, max_bytes=_MAX_RUNTIME_FILE_BYTES)
            try:
                direct = json.loads(direct_raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("installed Hermes dependency direct_url is invalid") from exc
            if not isinstance(direct, dict) or any(key not in {"url", "archive_info", "vcs_info", "dir_info"} for key in direct):
                raise ValueError("installed Hermes dependency direct_url is not exact")
        installed.append({"name": name, "version": version, "record": str(record_path.relative_to(site_packages).as_posix())})
    if not installed:
        raise ValueError("Hermes dependency closure has no installed distributions")
    installed.sort(key=lambda item: (str(item["name"]).lower(), str(item["version"])))
    return installed


def build_hermes_install_archive(
    *,
    source_root: Path,
    install_root: Path,
    source_sha: str,
    output_archive: Path,
    output_provenance: Path,
    git_executable: Path = Path("/usr/bin/git"),
    uv_executable: Path = Path("/opt/homebrew/bin/uv"),
) -> dict[str, str]:
    """Build a source-derived, locked, non-editable Hermes closure.

    The install root is deliberately an output directory, never an input
    tree.  First-party bytes come from ``git archive`` at the clean reviewed
    commit; third-party bytes come from a fresh ``uv sync --frozen`` using the
    real lockfile.  This keeps a caller from making an arbitrary directory
    look like a reviewed Hermes installation by merely self-attesting it.
    """
    source = Path(source_root)
    install = Path(install_root)
    expected = _validated_hex_sha(source_sha, field="Hermes source SHA", length=40)
    for path, field in ((source, "Hermes source checkout"),):
        if not path.is_absolute() or path == Path(path.anchor):
            raise ValueError(f"{field} must be a bounded absolute directory")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"{field} must be a real directory")
    git = Path(git_executable)
    uv = Path(uv_executable)
    if not uv.is_absolute() or ".." in uv.parts:
        raise ValueError("Hermes locked installer path is invalid")
    try:
        _head, tree = _source_git_identity(source, expected=expected, git=git)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Hermes source Git identity cannot be verified") from exc
    pyproject, _ = _read_sealed_file_bytes(
        source / "pyproject.toml", max_bytes=_MAX_RUNTIME_FILE_BYTES
    )
    uv_lock, _ = _read_sealed_file_bytes(
        source / "uv.lock", max_bytes=_MAX_RUNTIME_FILE_BYTES
    )
    locked_packages = _locked_uv_packages(uv_lock)
    git_archive, first_party_files = _git_archive_hermes_cli(
        source, expected=expected, git=git
    )
    pyproject_sha = hashlib.sha256(pyproject).hexdigest()
    uv_lock_sha = hashlib.sha256(uv_lock).hexdigest()
    lock_sha = hashlib.sha256(pyproject + b"\0" + uv_lock).hexdigest()

    if install.exists():
        info = install.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("Hermes install closure staging root must be a fresh directory")
        if any(install.iterdir()):
            raise ValueError("Hermes install closure staging root must be fresh and source-derived")
    else:
        install.mkdir(parents=True, mode=0o700)
    os.chmod(install, 0o700)
    if install.stat().st_uid != os.geteuid() or stat.S_IMODE(install.stat().st_mode) != 0o700:
        raise ValueError("Hermes install closure staging root ownership is unsafe")
    try:
        with tempfile.TemporaryDirectory(prefix="hermes-uv-cache-") as cache_dir:
            env = {
                "PATH": "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
                "UV_CACHE_DIR": cache_dir,
                "UV_PROJECT_ENVIRONMENT": str(install),
                "UV_NO_PROGRESS": "1",
                "UV_PYTHON_DOWNLOADS": "never",
                "PYTHONNOUSERSITE": "1",
            }
            result = subprocess.run(
                [str(uv), "sync", "--frozen", "--no-dev", "--no-install-project",
                 "--no-editable", "--link-mode", "copy", "--python", sys.executable],
                cwd=str(source), check=False, capture_output=True, timeout=600, env=env,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Hermes locked dependency build could not run") from exc
    if result.returncode != 0:
        raise ValueError("Hermes locked dependency build failed")
    version_dir = install / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    site_packages = version_dir / "site-packages"
    if not site_packages.is_dir() or site_packages.is_symlink():
        raise ValueError("Hermes locked dependency build did not produce site-packages")
    # Install the first-party package from the exact Git archive into the real
    # site-packages directory.  This is what makes ``python -I script.py``
    # import the same package as the broker entrypoint.
    first_party_root = site_packages / "hermes_cli"
    if first_party_root.exists() or first_party_root.is_symlink():
        raise ValueError("Hermes dependency build unexpectedly supplied editable first-party bytes")
    for path_value, content in sorted(first_party_files.items()):
        target = site_packages.joinpath(*PurePosixPath(path_value).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        os.chmod(target, 0o444)
    os.chmod(first_party_root, 0o555)
    # Freeze every installed path before making the detached archive.  The
    # archive's manifest consequently records the exact mode that startup
    # verification must observe, including native files and stdlib metadata.
    for directory, dirs, files in os.walk(site_packages, topdown=False, followlinks=False):
        for name in files:
            target = Path(directory) / name
            info = target.lstat()
            if stat.S_ISLNK(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("Hermes dependency closure contains an unsupported file")
            os.chmod(target, 0o555 if stat.S_IMODE(info.st_mode) & 0o111 else 0o444)
        for name in dirs:
            target = Path(directory) / name
            if not target.is_symlink():
                os.chmod(target, 0o555)
    installed_distributions = _verify_installed_distributions(site_packages, locked_packages)
    entries: list[dict[str, object]] = []
    contents: dict[str, bytes] = {}
    links: dict[str, str] = {}
    all_paths = sorted(site_packages.rglob("*"), key=lambda item: item.as_posix())
    if len(all_paths) > _MAX_RUNTIME_ARCHIVE_ENTRIES:
        raise ValueError("Hermes install closure contains too many entries")
    for item in all_paths:
        relative = item.relative_to(site_packages)
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ValueError("Hermes install closure path is unsafe")
        info = item.lstat()
        path_value = relative.as_posix()
        origin = (
            "first-party"
            if path_value == "hermes_cli"
            or path_value.startswith("hermes_cli/")
            or path_value == "hermes_constants.py"
            or path_value == "utils.py"
            else "dependency"
        )
        mode = stat.S_IMODE(info.st_mode)
        if stat.S_ISDIR(info.st_mode):
            if mode != 0o555:
                raise ValueError("Hermes install closure directory mode is not immutable")
            entries.append({"path": path_value + "/", "type": "directory", "mode": mode, "origin": origin})
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1 or mode & 0o222 or info.st_size < 0 or info.st_size > _MAX_RUNTIME_ARCHIVE_FILE_BYTES:
                raise ValueError("Hermes install closure contains a mutable or linked file")
            content, _ = _read_sealed_file_bytes(item, max_bytes=_MAX_RUNTIME_ARCHIVE_FILE_BYTES)
            contents[path_value] = content
            entries.append({"path": path_value, "type": "file", "mode": mode, "origin": origin, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(item)
            if not target or target.startswith("/") or "\\" in target or "\x00" in target:
                raise ValueError("Hermes install closure symlink target is unsafe")
            resolved = PurePosixPath(posixpath.normpath((PurePosixPath(path_value).parent / target).as_posix()))
            if resolved.is_absolute() or any(part in {"", ".", ".."} for part in resolved.parts):
                raise ValueError("Hermes install closure symlink escapes the root")
            links[path_value] = resolved.as_posix()
            entries.append({"path": path_value, "type": "symlink", "target": resolved.as_posix(), "mode": 0o555, "origin": origin})
        else:
            raise ValueError("Hermes install closure contains a special file")
    available = {str(entry["path"]).rstrip("/") for entry in entries}
    if "hermes_cli/main.py" not in available or "hermes_cli/kanban_broker_client.py" not in available:
        raise ValueError("Hermes install closure is missing the source-derived broker entrypoint")
    if not any(entry["origin"] == "dependency" for entry in entries):
        raise ValueError("Hermes install closure is missing locked dependencies")
    for link, target in links.items():
        if target not in available:
            raise ValueError("Hermes install closure symlink target is missing")
    entries.sort(key=lambda item: str(item["path"]))
    raw_tar = io.BytesIO()
    with tarfile.open(fileobj=raw_tar, mode="w", format=tarfile.PAX_FORMAT) as stream:
        root_member = tarfile.TarInfo("hermes-install/")
        root_member.type = tarfile.DIRTYPE
        root_member.mode = 0o555
        root_member.uid = root_member.gid = 0
        root_member.mtime = 0
        stream.addfile(root_member)
        for entry in entries:
            relative = str(entry["path"])
            name = "hermes-install/" + relative
            member = tarfile.TarInfo(name)
            member.uid = member.gid = 0
            member.mtime = 0
            member.mode = int(entry["mode"])
            if entry["type"] == "directory":
                member.type = tarfile.DIRTYPE
                stream.addfile(member)
            elif entry["type"] == "file":
                content = contents[relative]
                member.size = len(content)
                stream.addfile(member, io.BytesIO(content))
            else:
                member.type = tarfile.SYMTYPE
                parent = PurePosixPath(relative).parent
                member.linkname = posixpath.relpath(str(entry["target"]), start=parent.as_posix())
                stream.addfile(member)
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb", mtime=0) as gzip_stream:
        gzip_stream.write(raw_tar.getvalue())
    archive_bytes = compressed.getvalue()
    archive_sha = hashlib.sha256(archive_bytes).hexdigest()
    provenance = {
        "contract": HERMES_INSTALL_PROVENANCE_CONTRACT,
        "schema_version": 1,
        "builder_contract": HERMES_INSTALL_BUILDER_CONTRACT,
        "hermes_source_sha": expected,
        "hermes_source_tree_sha": tree,
        "pyproject_sha256": pyproject_sha,
        "uv_lock_sha256": uv_lock_sha,
        "pyproject_lock_sha256": lock_sha,
        "first_party_git_archive_sha256": hashlib.sha256(git_archive).hexdigest(),
        "locked_packages": locked_packages,
        "installed_distributions": installed_distributions,
        "installer": {"name": "uv", "contract": "sync --frozen --no-dev --no-editable", "python": sys.version.split()[0]},
        "install_archive_sha256": archive_sha,
        "entries": entries,
    }
    provenance_bytes = _json_artifact_bytes(provenance)
    output_archive = Path(output_archive)
    output_provenance = Path(output_provenance)
    for output in (output_archive, output_provenance):
        if not output.is_absolute() or output == Path(output.anchor):
            raise ValueError("Hermes builder outputs must be bounded absolute files")
        output.parent.mkdir(parents=True, exist_ok=True)
    _atomic_artifact_write(output_archive, archive_bytes, mode=0o444, uid=os.geteuid(), gid=os.getegid())
    _atomic_artifact_write(output_provenance, provenance_bytes, mode=0o644, uid=os.geteuid(), gid=os.getegid())
    return {
        "archive_sha256": archive_sha,
        "provenance_sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "source_sha": expected,
        "source_tree_sha": tree,
        "pyproject_lock_sha256": lock_sha,
    }


def disable_service_config(path: Path, *, expected_owner_uid: int) -> dict:
    """Atomically restore both activation gates to exact false."""
    path = Path(path)
    config, original = _read_service_config_file(
        path, expected_owner_uid=expected_owner_uid
    )
    disabled = dict(config)
    disabled["enabled"] = False
    disabled["trusted_publisher_enabled"] = False
    reread = _replace_service_config(path, original=original, payload=disabled)
    if (
        reread.get("enabled") is not False
        or reread.get("trusted_publisher_enabled") is not False
    ):
        raise ValueError("broker service config disable readback failed")
    _update_runtime_attestation(
        reread, service_config_path=path, active=False, revoked=True
    )
    _set_dispatcher_profile_activation(reread, enabled=False)
    return reread


def verify_service_disabled(path: Path, *, expected_owner_uid: int) -> bool:
    config, _info = _read_service_config_file(
        Path(path), expected_owner_uid=expected_owner_uid
    )
    return bool(
        config.get("enabled") is False
        and config.get("trusted_publisher_enabled") is False
    )


def _read_root_json(
    path: Path,
    *,
    contract: str,
    allow_current_owner: bool = False,
    allow_unprivileged_owner: bool = False,
) -> dict:
    path = Path(path)
    _validated_install_path(path, field="broker installer input")
    raw, info = _read_sealed_file_bytes(path, max_bytes=4 * 1024 * 1024)
    allowed_owners = (
        None
        if allow_unprivileged_owner
        else ({0, os.geteuid()} if allow_current_owner else {0})
    )
    if allowed_owners is not None and info.st_uid not in allowed_owners:
        raise ValueError("broker installer input must be root-owned mode 0600")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("broker installer input must be root-owned mode 0600")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("broker installer input is invalid JSON") from exc
    if not isinstance(value, dict) or value.get("contract") != contract:
        raise ValueError("broker installer input contract is unsupported")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hermes_cli.kanban_broker_install")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("disable", "verify-disabled"):
        child = subparsers.add_parser(command)
        child.add_argument("--config", type=Path, required=True)
    render = subparsers.add_parser(
        "render-plan",
        aliases=("plan",),
        help="render a disabled broker installation plan without host mutations",
    )
    render.add_argument("--inventory", "--host-inventory", type=Path, required=True)
    render.add_argument("--desired-identities", "--identities", type=Path, required=True)
    render.add_argument("--install-root", type=Path, required=True)
    render.add_argument("--output-root", type=Path)
    render.add_argument("--runtime-archive", type=Path, required=True)
    render.add_argument("--runtime-archive-sha256", required=True)
    render.add_argument("--hermes-install-archive", type=Path, required=True)
    render.add_argument("--hermes-install-archive-sha256", required=True)
    render.add_argument("--hermes-install-provenance", type=Path, required=True)
    render.add_argument("--hermes-install-provenance-sha256", required=True)
    render.add_argument("--publisher-probe", type=Path, required=True)
    render.add_argument("--publisher-probe-sha256", required=True)
    render.add_argument("--hermes-source-sha", required=True)
    render.add_argument("--hermes-source-path", type=Path, required=True)
    render.add_argument("--radulator-source-path", type=Path, required=True)
    render.add_argument("--source-sha", "--radulator-source-sha", required=True)
    render.add_argument("--dispatcher-profile", required=True)
    render.add_argument("--git", type=Path, default=Path("/usr/bin/git"))
    render.add_argument("--install-nonce")
    seal = subparsers.add_parser(
        "seal-plan",
        help="seal offline plan inputs as root-owned apply documents",
    )
    seal.add_argument("--input-root", type=Path, required=True)
    seal.add_argument("--output-root", type=Path, required=True)
    inventory_check = subparsers.add_parser(
        "validate-inventory", help="validate a complete explicit host identity inventory"
    )
    inventory_check.add_argument("--inventory", type=Path, required=True)
    allocator = subparsers.add_parser(
        "allocate-identities", help="render the reviewed deterministic 450-453 identity allocation"
    )
    allocator.add_argument("--inventory", type=Path, required=True)
    allocator.add_argument("--output", type=Path, required=True)
    builder = subparsers.add_parser(
        "build-hermes-install",
        help="build a reproducible complete Hermes install closure archive",
    )
    builder.add_argument("--source-root", type=Path, required=True)
    builder.add_argument("--install-root", type=Path, required=True)
    builder.add_argument("--source-sha", required=True)
    builder.add_argument("--output-archive", type=Path, required=True)
    builder.add_argument("--output-provenance", type=Path, required=True)
    builder.add_argument("--git", type=Path, default=Path("/usr/bin/git"))
    builder.add_argument("--uv", type=Path, default=Path("/opt/homebrew/bin/uv"))
    builder.add_argument("--json", action="store_true")
    identities = subparsers.add_parser("provision-identities")
    identities.add_argument("--plan", type=Path, required=True)
    assets = subparsers.add_parser("provision-assets")
    assets.add_argument("--plan", type=Path, required=True)
    assets.add_argument("--payloads", type=Path, required=True)
    assets.add_argument("--config", type=Path, required=True)
    activate = subparsers.add_parser("activate")
    activate.add_argument("--config", type=Path, required=True)
    activate.add_argument("--plist", type=Path, required=True)
    activate.add_argument("--worker-plist", type=Path, required=True)
    activate.add_argument("--operator-config", type=Path, required=True)
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--config", type=Path, required=True)
    rollback.add_argument("--operator-config", type=Path, required=True)
    rollback.add_argument("--wait-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    if args.command in {"render-plan", "plan"}:
        def read_input(path: Path, expected: str) -> dict:
            value = _read_root_json(Path(path), contract=expected, allow_current_owner=True)
            return value
        plan = render_broker_installation_plan(
            host_inventory=read_input(args.inventory, HOST_IDENTITY_INVENTORY_CONTRACT),
            desired_identities=read_input(args.desired_identities, DESIRED_IDENTITIES_CONTRACT),
            install_root=args.install_root,
            runtime_archive_path=args.runtime_archive,
            runtime_archive_sha256=args.runtime_archive_sha256,
            hermes_install_archive_path=args.hermes_install_archive,
            hermes_install_archive_sha256=args.hermes_install_archive_sha256,
            hermes_install_provenance_path=args.hermes_install_provenance,
            hermes_install_provenance_sha256=args.hermes_install_provenance_sha256,
            publisher_probe_path=args.publisher_probe,
            publisher_probe_sha256=args.publisher_probe_sha256,
            hermes_source_sha=args.hermes_source_sha,
            hermes_source_path=args.hermes_source_path,
            radulator_source_path=args.radulator_source_path,
            radulator_source_sha=args.source_sha,
            dispatcher_profile=args.dispatcher_profile,
            git_executable=args.git,
            install_nonce=args.install_nonce,
        )
        write_broker_installation_plan(
            plan,
            output_root=args.output_root if args.output_root is not None else args.install_root,
        )
        return 0
    if args.command == "validate-inventory":
        _validate_host_identity_inventory(
            _read_root_json(args.inventory, contract=HOST_IDENTITY_INVENTORY_CONTRACT, allow_current_owner=True)
        )
        return 0
    if args.command == "allocate-identities":
        desired = allocate_desired_identities(
            _read_root_json(args.inventory, contract=HOST_IDENTITY_INVENTORY_CONTRACT, allow_current_owner=True)
        )
        output = _validated_install_path(args.output, field="identity allocation output", allow_root=False)
        _atomic_artifact_write(output, _json_artifact_bytes(desired), mode=0o600, uid=os.geteuid(), gid=os.getegid())
        return 0
    if args.command == "build-hermes-install":
        result = build_hermes_install_archive(
            source_root=args.source_root,
            install_root=args.install_root,
            source_sha=args.source_sha,
            output_archive=args.output_archive,
            output_provenance=args.output_provenance,
            git_executable=args.git,
            uv_executable=args.uv,
        )
        # Only digests and reviewed source identity are emitted.  No archive
        # bytes or source contents are printed by this command.
        if args.json:
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    if args.command == "seal-plan":
        seal_broker_installation_plan(
            input_root=args.input_root,
            output_root=args.output_root,
        )
        return 0
    if os.geteuid() != 0:  # windows-footgun: ok - macOS launchd installer only
        raise PermissionError("broker install/rollback commands require root")
    if args.command == "provision-identities":
        provision_identity_plan(
            _read_root_json(args.plan, contract="hermes.kanban_broker_identity_plan.v1")
        )
        return 0
    if args.command == "provision-assets":
        plan = _read_root_json(
            args.plan, contract="hermes.kanban_broker_filesystem_plan.v1"
        )
        encoded = _read_root_json(
            args.payloads, contract="hermes.kanban_broker_asset_payloads.v1"
        )
        raw_payloads = encoded.get("payloads")
        external = encoded.get("external_payloads", [])
        if not isinstance(raw_payloads, dict) or not isinstance(external, list):
            raise ValueError("broker asset payload manifest is malformed")
        payloads: dict[str, bytes] = {}
        for path, value in raw_payloads.items():
            if not isinstance(path, str) or not isinstance(value, str):
                raise ValueError("broker asset payload entry is malformed")
            try:
                payloads[path] = base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise ValueError("broker asset payload is not valid base64") from exc
        seen_external: set[str] = set()
        for item in external:
            if not isinstance(item, dict) or set(item) != {"path", "source_path", "sha256", "size"}:
                raise ValueError("broker external payload fields are not exact")
            destination = item["path"]
            source = item["source_path"]
            if (not isinstance(destination, str) or not isinstance(source, str)
                    or destination in seen_external or not Path(destination).is_absolute()
                    or not Path(source).is_absolute()):
                raise ValueError("broker external payload path is invalid")
            _validated_install_path(destination, field="broker external destination")
            source_path = _validated_install_path(source, field="broker external source")
            seen_external.add(destination)
            size = item["size"]
            if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > _MAX_RUNTIME_ARCHIVE_BYTES:
                raise ValueError("broker external payload size is invalid")
            digest = _validated_hex_sha(item["sha256"], field="external payload SHA256", length=64)
            data, _source_info = _read_sealed_file_bytes(
                source_path,
                max_bytes=_MAX_RUNTIME_ARCHIVE_BYTES,
                expected_size=size,
                expected_sha256=digest,
            )
            payloads[destination] = data
        provision_disabled_install(
            plan,
            payloads=payloads,
            service_config_path=args.config,
        )
        return 0
    info = args.config.lstat()
    expected_owner_uid = int(info.st_uid)
    if expected_owner_uid <= 0:
        raise ValueError("broker service config must be owned by a non-root broker")
    if args.command == "disable":
        disable_service_config(args.config, expected_owner_uid=expected_owner_uid)
        return 0
    if args.command == "activate":
        activate_installation(
            service_config_path=args.config,
            expected_owner_uid=expected_owner_uid,
            launchd_plist_path=args.plist,
            worker_launchd_plist_path=args.worker_plist,
            operator_client_config=args.operator_config,
        )
        return 0
    if args.command == "rollback":
        rollback_installation(
            service_config_path=args.config,
            expected_owner_uid=expected_owner_uid,
            operator_client_config=args.operator_config,
            wait_seconds=args.wait_seconds,
        )
        return 0
    if not verify_service_disabled(args.config, expected_owner_uid=expected_owner_uid):
        raise ValueError("broker service config is not disabled")
    return 0


def validate_identity_separation(
    *, broker_uid: int, model_uid: int, controller_uid: int, publisher_uid: int
) -> None:
    """Reject an installation that collapses a privileged UID into the model."""
    privileged = {
        "broker": int(broker_uid),
        "controller": int(controller_uid),
        "publisher": int(publisher_uid),
    }
    if int(model_uid) in privileged.values() or len(set(privileged.values())) != 3:
        raise ValueError(
            "broker, controller, publisher, and model identities must be distinct"
        )
    if any(uid <= 0 for uid in (*privileged.values(), int(model_uid))):
        raise ValueError("service and model identities must be non-root")


def system_group_memberships(uids: set[int]) -> dict[int, set[int]]:
    """Resolve supplementary memberships from the host account database."""
    result: dict[int, set[int]] = {}
    for uid in uids:
        try:
            account = pwd.getpwuid(int(uid))
        except KeyError as exc:
            raise ValueError(f"service UID {uid} does not exist") from exc
        result[int(uid)] = set(os.getgrouplist(account.pw_name, account.pw_gid))
    return result


def validate_group_separation(
    *,
    broker_uid: int,
    model_uid: int,
    controller_uid: int,
    controller_gid: int,
    publisher_uid: int,
    publisher_gid: int,
    operator_uid: int,
    operator_gid: int,
    workspace_gid: int,
    memberships: dict[int, set[int]],
) -> None:
    """Prove client keys, sockets, bundles, and workspaces use disjoint groups."""
    controller_gid = int(controller_gid)
    publisher_gid = int(publisher_gid)
    operator_gid = int(operator_gid)
    workspace_gid = int(workspace_gid)
    if len({controller_gid, publisher_gid, operator_gid, workspace_gid}) != 4:
        raise ValueError(
            "controller, publisher, operator, and workspace groups must be distinct"
        )
    normalized = {
        int(uid): {int(gid) for gid in groups} for uid, groups in memberships.items()
    }
    required = {
        int(model_uid): workspace_gid,
        int(controller_uid): controller_gid,
        int(publisher_uid): publisher_gid,
        int(operator_uid): operator_gid,
    }
    for uid, gid in required.items():
        if gid not in normalized.get(uid, set()):
            raise ValueError(
                f"service UID {uid} is not a member of required group {gid}"
            )
    broker_groups = normalized.get(int(broker_uid), set())
    for gid in (controller_gid, publisher_gid, operator_gid, workspace_gid):
        if gid not in broker_groups:
            raise ValueError(f"broker identity is not a member of required group {gid}")
    model_groups = normalized[int(model_uid)]
    if publisher_gid in model_groups:
        raise ValueError("model identity is a member of the publisher group")
    if controller_gid in model_groups:
        raise ValueError("model identity is a member of the controller group")
    if operator_gid in model_groups:
        raise ValueError("model identity is a member of the operator group")
    if workspace_gid in normalized[int(publisher_uid)]:
        raise ValueError("publisher identity is a member of the worker workspace group")
    if workspace_gid in normalized[int(controller_uid)]:
        raise ValueError(
            "controller identity is a member of the worker workspace group"
        )
    forbidden_by_uid = {
        int(controller_uid): {publisher_gid, operator_gid, workspace_gid},
        int(publisher_uid): {controller_gid, operator_gid, workspace_gid},
        int(operator_uid): {controller_gid, publisher_gid, workspace_gid},
    }
    for uid, forbidden in forbidden_by_uid.items():
        overlap = normalized.get(uid, set()) & forbidden
        if overlap:
            raise ValueError(
                f"service UID {uid} has forbidden cross-surface groups {sorted(overlap)}"
            )


def render_broker_seatbelt_profile(
    *, state_dir: Path, workspace_root: Path, socket_dir: Path
) -> str:
    """Deny IP networking while retaining broker-owned Unix socket IPC.

    Cross-UID Unix ownership remains the primary confidentiality boundary.
    Seatbelt is defense in depth that removes the broker's push/exfiltration
    path without blocking its local Unix control and reverse-worker sockets.
    """
    state = json.dumps(str(Path(state_dir)))
    workspaces = json.dumps(str(Path(workspace_root)))
    sockets = json.dumps(str(Path(socket_dir)))
    return " ".join((
        "(version 1)",
        "(allow default)",
        '(deny network-bind (local ip "*:*"))',
        '(deny network-inbound (local ip "*:*"))',
        '(deny network-outbound (remote ip "*:*"))',
        f"(allow file-read* file-write* (subpath {state}) (subpath {workspaces}) (subpath {sockets}))",
    ))


def render_launchd_plist(
    *,
    python_executable: Path,
    config_path: Path,
    state_dir: Path,
    broker_user: str = "_hermesbroker",
    sandbox_profile: Path | None = None,
    package_root: Path | None = None,
    runtime_entrypoint_path: Path | None = None,
    runtime_manifest_path: Path | None = None,
) -> str:
    """Return a launchd plist with no credentials and no activation flag."""
    profile_path = (
        Path(sandbox_profile) if sandbox_profile else Path(state_dir) / "broker.sb"
    )
    if package_root is None or not Path(package_root).is_absolute():
        raise ValueError("broker launchd package root must be absolute")
    if runtime_entrypoint_path is not None and not Path(runtime_entrypoint_path).is_absolute():
        raise ValueError("broker runtime entrypoint must be absolute")
    if runtime_manifest_path is not None and not Path(runtime_manifest_path).is_absolute():
        raise ValueError("broker runtime manifest must be absolute")
    program = [
        str(Path(python_executable)),
        "-m",
        "hermes_cli.kanban_broker_service",
        "serve",
        "--config",
        str(Path(config_path)),
    ]
    if runtime_entrypoint_path is not None:
        program = [
            str(Path(python_executable)),
            "-B",
            "-I",
            str(Path(runtime_entrypoint_path)),
            "-m",
            "hermes_cli.kanban_broker_service",
            "serve",
            "--config",
            str(Path(config_path)),
        ]
    payload = {
        "Label": "ai.hermes.kanban-broker",
        "ProgramArguments": [
            "/usr/bin/sandbox-exec",
            "-f",
            str(profile_path),
            *program,
        ],
        "UserName": broker_user,
        "ProcessType": "Background",
        # launchctl keeps the label disabled until the explicit root-only
        # activation transaction.  Once enabled, these settings recover the
        # broker after a crash and across reboot so journals are swept.
        "RunAtLoad": True,
        "KeepAlive": True,
        "Umask": 0o077,
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    }
    if runtime_manifest_path is not None:
        payload["EnvironmentVariables"]["HERMES_KANBAN_RUNTIME_MANIFEST"] = str(
            Path(runtime_manifest_path)
        )
    if runtime_entrypoint_path is None:
        payload["EnvironmentVariables"]["PYTHONPATH"] = str(Path(package_root).parent)
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")


def render_worker_launchd_plist(
    *,
    python_executable: Path,
    python_sha256: str,
    package_root: Path,
    package_manifest_sha256: str,
    worker_socket: Path,
    workspace_root: Path,
    broker_uid: int,
    workspace_gid: int,
    model_user: str,
    worker_hermes_root: Path,
    runtime_entrypoint_path: Path | None = None,
    runtime_entrypoint_sha256: str | None = None,
    runtime_manifest_path: Path | None = None,
    runtime_manifest_sha256: str | None = None,
) -> str:
    """Render the persistent unprivileged reverse-worker listener."""

    if not all(
        Path(path).is_absolute()
        for path in (
            python_executable,
            package_root,
            worker_socket,
            workspace_root,
            worker_hermes_root,
        )
    ):
        raise ValueError("worker launchd paths must be absolute")
    if runtime_entrypoint_path is not None and not Path(runtime_entrypoint_path).is_absolute():
        raise ValueError("worker runtime entrypoint must be absolute")
    if runtime_entrypoint_path is not None:
        _validated_hex_sha(runtime_entrypoint_sha256, field="worker runtime entrypoint SHA256", length=64)
    elif runtime_entrypoint_sha256 is not None:
        raise ValueError("worker runtime entrypoint SHA requires an entrypoint path")
    if runtime_manifest_path is not None and not Path(runtime_manifest_path).is_absolute():
        raise ValueError("worker runtime manifest must be absolute")
    if runtime_manifest_path is not None:
        _validated_hex_sha(runtime_manifest_sha256, field="worker runtime manifest SHA256", length=64)
    elif runtime_manifest_sha256 is not None:
        raise ValueError("worker runtime manifest SHA requires a manifest path")
    if not re.fullmatch(r"[0-9a-f]{64}", str(python_sha256)) or not re.fullmatch(
        r"[0-9a-f]{64}", str(package_manifest_sha256)
    ):
        raise ValueError("worker launchd runtime digests are invalid")
    payload = {
        "Label": "ai.hermes.kanban-worker",
        "ProgramArguments": [
            str(Path(python_executable)),
            "-B",
            *(["-I", str(Path(runtime_entrypoint_path))] if runtime_entrypoint_path is not None else []),
            "-m",
            "hermes_cli.kanban_broker_worker",
            "serve",
            "--socket",
            str(Path(worker_socket)),
            "--workspace-root",
            str(Path(workspace_root)),
            "--broker-uid",
            str(int(broker_uid)),
            "--workspace-gid",
            str(int(workspace_gid)),
            "--python",
            str(Path(python_executable)),
            "--python-sha256",
            str(python_sha256),
            "--package-root",
            str(Path(package_root)),
            "--package-manifest-sha256",
            str(package_manifest_sha256),
            "--worker-hermes-root",
            str(Path(worker_hermes_root)),
            *( ["--runtime-entrypoint", str(Path(runtime_entrypoint_path))]
               if runtime_entrypoint_path is not None else []),
            *( ["--runtime-entrypoint-sha256", str(runtime_entrypoint_sha256)]
               if runtime_entrypoint_path is not None else []),
            *( ["--runtime-manifest-path", str(Path(runtime_manifest_path)),
                "--runtime-manifest-sha256", str(runtime_manifest_sha256)]
               if runtime_manifest_path is not None else []),
        ],
        "UserName": _validated_account_name(model_user),
        "ProcessType": "Background",
        "RunAtLoad": True,
        "KeepAlive": True,
        "Umask": 0o077,
        "EnvironmentVariables": {
            "HOME": str(Path(worker_hermes_root)),
            "HERMES_HOME": str(Path(worker_hermes_root)),
            "XDG_CONFIG_HOME": str(Path(worker_hermes_root) / ".config"),
            "XDG_DATA_HOME": str(Path(worker_hermes_root) / ".local/share"),
            "XDG_STATE_HOME": str(Path(worker_hermes_root) / ".local/state"),
            "XDG_CACHE_HOME": str(Path(worker_hermes_root) / ".cache"),
            "GNUPGHOME": str(Path(worker_hermes_root) / ".gnupg"),
            "HERMES_KANBAN_CREDENTIAL_POLICY": "github-denied-v1",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": os.devnull,
            "GIT_SSH_COMMAND": "/usr/bin/false",
        },
    }
    if runtime_entrypoint_path is None:
        payload["EnvironmentVariables"]["PYTHONPATH"] = str(Path(package_root).parent)
    if runtime_manifest_path is not None:
        payload["EnvironmentVariables"]["HERMES_KANBAN_RUNTIME_MANIFEST"] = str(
            Path(runtime_manifest_path)
        )
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")


def render_runtime_entrypoint_asset(*, entrypoint_path: Path, package_root: Path) -> dict[str, object]:
    """Describe the tiny -I bootstrap that imports only the installed package."""
    entrypoint = Path(entrypoint_path)
    package = Path(package_root)
    if not entrypoint.is_absolute() or not package.is_absolute():
        raise ValueError("runtime entrypoint and package paths must be absolute")
    runtime_root = entrypoint.parent.parent
    if package != runtime_root / "lib/python3.11/site-packages/hermes_cli":
        raise ValueError("runtime entrypoint must bind the interpreter site-packages")
    content = RUNTIME_ENTRYPOINT_CONTENT.encode("utf-8")
    return {
        "path": str(entrypoint),
        "uid": 0,
        "gid": 0,
        "mode": 0o555,
        "kind": "runtime_entrypoint",
        "sha256": hashlib.sha256(content).hexdigest(),
        "size": len(content),
        "content": content,
    }


def verify_isolated_runtime_import(
    *,
    python_executable: Path,
    entrypoint_path: Path,
    direct_probe_path: Path | None = None,
    module: str = "hermes_cli.kanban_broker_client",
    runner=subprocess.run,
) -> None:
    """Prove an installed runtime imports without PYTHONPATH or a checkout."""
    if not module or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", module) is None:
        raise ValueError("runtime import module is invalid")
    if direct_probe_path is not None:
        probe = Path(direct_probe_path)
        if not probe.is_absolute() or ".." in probe.parts:
            raise ValueError("runtime direct probe path is invalid")
        command = [str(Path(python_executable)), "-I", "-B", str(probe)]
    else:
        command = [
            str(Path(python_executable)), "-I", str(Path(entrypoint_path)),
            "--verify-import", module,
        ]
    result = runner(
        command,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
    )
    if int(getattr(result, "returncode", 1)) != 0:
        raise ValueError("installed Hermes runtime import failed")


def _json_artifact_bytes(value: object) -> bytes:
    return _canonical_json_bytes(value) + b"\n"


def render_broker_installation_plan(
    *,
    host_inventory: dict,
    desired_identities: dict,
    install_root: Path,
    runtime_archive_path: Path,
    runtime_archive_sha256: str,
    hermes_install_archive_path: Path,
    hermes_install_archive_sha256: str,
    hermes_install_provenance_path: Path,
    hermes_install_provenance_sha256: str,
    publisher_probe_path: Path,
    publisher_probe_sha256: str,
    hermes_source_sha: str | None,
    hermes_source_path: Path | None = None,
    radulator_source_path: Path,
    radulator_source_sha: str | None,
    dispatcher_profile: str,
    git_executable: Path = Path("/usr/bin/git"),
    install_nonce: str | None = None,
) -> dict[str, object]:
    """Render every reviewed broker artifact without applying host changes.

    All paths and identity values are inputs to this pure renderer.  The
    resulting payload manifest is consumed by the existing
    ``provision-assets`` command; this function never invokes ``dscl``,
    ``launchctl``, sudo, or a service.
    """
    inventory = _validate_host_identity_inventory(host_inventory)
    desired = _desired_identity_specs(desired_identities)
    _validate_inventory_against_desired(inventory, desired)
    if not isinstance(dispatcher_profile, str) or re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", dispatcher_profile
    ) is None:
        raise ValueError("dispatcher profile is invalid")
    source_sha = _validated_hex_sha(
        radulator_source_sha, field="Radulator source SHA", length=40
    )
    hermes_commit_sha = _validated_hex_sha(
        hermes_source_sha, field="Hermes source SHA", length=40
    )
    if hermes_source_path is None:
        raise ValueError("Hermes source checkout is required for provenance verification")
    radulator_checkout = _validated_install_path(
        radulator_source_path, field="Radulator source checkout"
    )
    if radulator_checkout == Path(radulator_checkout.anchor):
        raise ValueError("Radulator source checkout must be a bounded path")
    try:
        if radulator_checkout.is_symlink():
            raise ValueError("Radulator source checkout must not be a symlink")
    except OSError as exc:
        raise ValueError("Radulator source checkout cannot be inspected") from exc
    remote_policy = render_radulator_remote_policy(source_sha=source_sha)
    root = _validated_install_path(install_root, field="install root", allow_root=True)
    if root == Path(root.anchor):
        raise ValueError("install root must be a bounded directory")
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        root_info = None
    if root_info is not None and (stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)):
        raise ValueError("install root must be a real directory")
    python_archive = Path(runtime_archive_path)
    hermes_archive = Path(hermes_install_archive_path)
    git = Path(git_executable)
    if not git.is_absolute() or ".." in git.parts:
        raise ValueError("Git executable path is invalid")
    git_digest = _apple_system_binary_sha256(git)
    publisher_probe = _validate_radulator_publisher_source(
        radulator_checkout,
        expected_source_sha=source_sha,
        publisher_probe=Path(publisher_probe_path),
        publisher_probe_sha256=publisher_probe_sha256,
        git_executable=git,
    )

    state_dir = root / "state"
    workspace_root = root / "workspaces"
    worker_home = root / "worker-home"
    profile_root = worker_home / "profiles" / dispatcher_profile
    dispatcher_routing_config_path = profile_root / "kanban-routing.json"
    dispatcher_profile_config_path = profile_root / "config.yaml"
    handoff_root = root / "publisher-handoffs"
    socket_root = root / "sockets"
    key_root = root / "keys"
    client_root = root / "clients"
    sequence_root = root / "sequences"
    sealed_runtime_root = root / "runtime" / "sealed"
    package_root = sealed_runtime_root / "hermes_cli"
    entrypoint_path = sealed_runtime_root / "bin" / "hermes-python"
    python = sealed_runtime_root / "bin" / "python3.11"
    service_config_path = root / "config" / "service.json"
    seatbelt_path = state_dir / "broker.sb"
    launchd_root = root / "launchd"
    launchd_path = launchd_root / "ai.hermes.kanban-broker.plist"
    worker_launchd_path = launchd_root / "ai.hermes.kanban-worker.plist"
    canary_key_path = root / "canary" / "canary.key"
    remote_policy_path = root / "install" / "remote-policy.json"
    identity_path = root / "install" / "identities.json"
    filesystem_path = root / "install" / "filesystem.json"
    payloads_path = root / "install" / "payloads.json"
    surface_paths = {
        surface: root / "sockets" / surface / f"{surface}.sock"
        for surface in ("controller", "publisher", "operator")
    }
    surface_keys = {
        surface: key_root / surface / f"{surface}.key"
        for surface in ("controller", "publisher", "operator")
    }
    client_paths = {
        surface: client_root / surface / "client.json"
        for surface in ("controller", "publisher", "operator")
    }
    sequence_paths = {
        surface: sequence_root / surface / "client.sequence"
        for surface in ("controller", "publisher", "operator")
    }
    worker_socket = socket_root / "worker" / "worker.sock"
    runtime_input_root = root / "install" / "runtime-inputs"
    runtime_python_archive_path = runtime_input_root / "cpython-runtime.tar.gz"
    runtime_hermes_archive_path = runtime_input_root / "hermes-install.tar.gz"
    runtime_hermes_provenance_path = runtime_input_root / "hermes-install.provenance.json"
    runtime_publisher_probe_path = runtime_input_root / "trusted_publisher.py"
    registration_path = root / "install" / "broker-register.json"
    runtime_manifest_path = root / "install" / "runtime-manifest.json"
    runtime_attestation_path = root / "install" / "runtime-attestation.json"

    if install_nonce is None:
        install_nonce = hashlib.sha256(
            _canonical_json_bytes({
                "inventory": inventory,
                "desired": desired,
                "install_root": str(root),
                "hermes_source_sha": hermes_commit_sha,
                "runtime_archive_sha256": runtime_archive_sha256,
                "hermes_install_archive_sha256": hermes_install_archive_sha256,
                "source_sha": source_sha,
                "radulator_source_path": str(radulator_checkout),
                "dispatcher_profile": dispatcher_profile,
            })
        ).hexdigest()
    if not isinstance(install_nonce, str) or re.fullmatch(r"[0-9a-f]{64}", install_nonce) is None:
        raise ValueError("install nonce must be 64 lowercase hexadecimal characters")

    sealed_runtime = render_sealed_runtime_plan(
        runtime_archive_path=python_archive,
        runtime_archive_sha256=runtime_archive_sha256,
        hermes_install_archive_path=hermes_archive,
        hermes_install_archive_sha256=hermes_install_archive_sha256,
        hermes_install_provenance_path=hermes_install_provenance_path,
        hermes_install_provenance_sha256=hermes_install_provenance_sha256,
        hermes_source_sha=hermes_commit_sha,
        hermes_source_path=hermes_source_path,
        runtime_root=sealed_runtime_root,
        entrypoint_path=entrypoint_path,
    )
    # The sidecar is copied into the root-owned staged input tree; keep the
    # source path only in the offline external-input record, never in the
    # apply descriptor consumed by the sealed runtime.
    sealed_runtime["hermes_provenance_path"] = str(runtime_hermes_provenance_path)
    package_root = Path(str(sealed_runtime["package_root"]))
    python = Path(str(sealed_runtime["python_executable_path"]))
    # The legacy runtime-assets renderer remains available for existing pure
    # renderer callers, but this installation plan never embeds a mutable
    # checkout or package-file tree.  The two reviewed archive inputs are
    # copied as external payloads and expanded only by the root apply edge.
    runtime_assets = {
        "contract": "hermes.kanban_broker_runtime_assets.v1",
        "destination_root": str(package_root),
        "package_manifest_sha256": str(sealed_runtime["package_manifest_sha256"]),
        "provenance_sha256": str(sealed_runtime["hermes_provenance_sha256"]),
        "hermes_pyproject_lock_sha256": str(sealed_runtime["hermes_pyproject_lock_sha256"]),
        "directories": [],
        "files": [],
    }
    runtime_entrypoint = render_runtime_entrypoint_asset(
        entrypoint_path=entrypoint_path,
        package_root=package_root,
    )

    ids = {
        role: desired[role]
        for role in ("broker", "controller", "publisher", "operator", "model")
    }
    identity_plan = render_identity_provision_plan(
        broker_user=str(ids["broker"]["user"]),
        broker_uid=int(ids["broker"]["uid"]),
        broker_gid=int(ids["broker"]["gid"]),
        controller_user=str(ids["controller"]["user"]),
        controller_uid=int(ids["controller"]["uid"]),
        controller_group=str(ids["controller"]["group"]),
        controller_gid=int(ids["controller"]["group_gid"]),
        publisher_user=str(ids["publisher"]["user"]),
        publisher_uid=int(ids["publisher"]["uid"]),
        publisher_group=str(ids["publisher"]["group"]),
        publisher_gid=int(ids["publisher"]["group_gid"]),
        operator_user=str(ids["operator"]["user"]),
        operator_uid=int(ids["operator"]["uid"]),
        operator_group=str(ids["operator"]["group"]),
        operator_gid=int(ids["operator"]["group_gid"]),
        model_user=str(ids["model"]["user"]),
        model_uid=int(ids["model"]["uid"]),
        workspace_group=str(desired["workspace"]["group"]),
        workspace_gid=int(desired["workspace"]["gid"]),
    )
    # The existing renderer intentionally omits the pre-existing operator
    # group.  The sealed installation plan records it explicitly so the
    # operator=root/wheel boundary is reviewed alongside the provisioned
    # service identities; provision_identity_plan remains idempotent because
    # wheel is expected to already exist at gid 0.
    identity_plan["groups"].append(["wheel", 0])
    identity_plan["groups"] = sorted(identity_plan["groups"], key=lambda item: (str(item[0]), int(item[1])))
    identity_plan["operator"] = {"user": "root", "uid": 0, "gid": 0, "group": "wheel", "group_gid": 0}
    identity_plan["workspace"] = {
        "group": str(desired["workspace"]["group"]),
        "gid": int(desired["workspace"]["gid"]),
    }
    identity_plan.update({
        "schema_version": 1,
        "host_inventory_sha256": hashlib.sha256(_canonical_json_bytes(inventory)).hexdigest(),
        "desired_identities_sha256": hashlib.sha256(_canonical_json_bytes(desired_identities)).hexdigest(),
        "membership_policy": [
            {"user": user, "group": group}
            for user, group in identity_plan["memberships"]
        ],
    })
    config = json.loads(render_broker_service_config(
        install_root=root,
        service_config_path=service_config_path,
        state_dir=state_dir,
        workspace_root=workspace_root,
        worker_hermes_root=worker_home,
        publisher_handoff_root=handoff_root,
        controller_socket=surface_paths["controller"],
        publisher_socket=surface_paths["publisher"],
        operator_socket=surface_paths["operator"],
        worker_socket=worker_socket,
        controller_key_path=surface_keys["controller"],
        publisher_key_path=surface_keys["publisher"],
        operator_key_path=surface_keys["operator"],
        broker_uid=int(ids["broker"]["uid"]),
        broker_gid=int(ids["broker"]["gid"]),
        model_uid=int(ids["model"]["uid"]),
        controller_uid=int(ids["controller"]["uid"]),
        controller_gid=int(ids["controller"]["group_gid"]),
        publisher_uid=int(ids["publisher"]["uid"]),
        publisher_gid=int(ids["publisher"]["group_gid"]),
        operator_uid=0,
        operator_gid=0,
        workspace_gid=int(desired["workspace"]["gid"]),
        trusted_publisher_enabled=False,
        python_executable=python,
        python_sha256=str(sealed_runtime["python_sha256"]),
        git_executable=git,
        package_root=package_root,
        package_manifest_sha256=str(runtime_assets["package_manifest_sha256"]),
        canary_key_path=canary_key_path,
        seatbelt_profile_path=seatbelt_path,
        launchd_plist_path=launchd_path,
        worker_launchd_plist_path=worker_launchd_path,
        runtime_entrypoint_path=entrypoint_path,
        runtime_entrypoint_sha256=str(runtime_entrypoint["sha256"]),
        runtime_attestation_path=runtime_attestation_path,
        runtime_manifest_path=runtime_manifest_path,
        runtime_manifest_sha256=str(sealed_runtime["runtime_manifest_sha256"]),
        hermes_source_sha=hermes_commit_sha,
        hermes_install_archive_sha256=str(sealed_runtime["archives"][1]["sha256"]),
        python_version=OFFICIAL_RUNTIME_VERSION,
        remote_policy_path=remote_policy_path,
        remote_policy_source_sha=source_sha,
        dispatcher_profile=dispatcher_profile,
        dispatcher_routing_config_path=dispatcher_routing_config_path,
        dispatcher_profile_config_path=dispatcher_profile_config_path,
        publisher_probe_path=runtime_publisher_probe_path,
        publisher_probe_sha256=str(publisher_probe["sha256"]),
        publisher_client_config=client_paths["publisher"],
        controller_client_config=client_paths["controller"],
        operator_client_config=client_paths["operator"],
        publisher_repository_id="radulator",
        registration_file_path=registration_path,
        install_nonce=install_nonce,
    ))
    clients: dict[str, bytes] = {}
    for surface in ("controller", "publisher", "operator"):
        clients[str(client_paths[surface])] = render_broker_client_config(
            surface=surface,
            socket_path=surface_paths[surface],
            expected_broker_uid=int(ids["broker"]["uid"]),
            key_path=surface_keys[surface],
            sequence_path=sequence_paths[surface],
        ).encode("utf-8")
    routing_config = render_dispatcher_routing_config(
        profile=dispatcher_profile,
        controller_client_config=client_paths["controller"],
        publisher_client_config=client_paths["publisher"],
        operator_client_config=client_paths["operator"],
        registration_file=registration_path,
        expected_source_sha=source_sha,
    ).encode("utf-8")
    profile_config = render_dispatcher_profile_config_yaml(
        profile=dispatcher_profile,
        controller_client_config=client_paths["controller"],
        publisher_client_config=client_paths["publisher"],
        operator_client_config=client_paths["operator"],
        registration_file=registration_path,
        expected_source_sha=source_sha,
    ).encode("utf-8")
    seatbelt = render_broker_seatbelt_profile(
        state_dir=state_dir,
        workspace_root=workspace_root,
        socket_dir=socket_root,
    ).encode("utf-8") + b"\n"
    broker_plist = render_launchd_plist(
        python_executable=python,
        config_path=service_config_path,
        state_dir=state_dir,
        broker_user=str(ids["broker"]["user"]),
        sandbox_profile=seatbelt_path,
        package_root=package_root,
        runtime_entrypoint_path=entrypoint_path,
        runtime_manifest_path=runtime_manifest_path,
    ).encode("utf-8")
    worker_plist = render_worker_launchd_plist(
        python_executable=python,
        python_sha256=str(config["python_sha256"]),
        package_root=package_root,
        package_manifest_sha256=str(runtime_assets["package_manifest_sha256"]),
        worker_socket=worker_socket,
        workspace_root=workspace_root,
        broker_uid=int(ids["broker"]["uid"]),
        workspace_gid=int(desired["workspace"]["gid"]),
        model_user=str(ids["model"]["user"]),
        worker_hermes_root=worker_home,
        runtime_entrypoint_path=entrypoint_path,
        runtime_entrypoint_sha256=str(runtime_entrypoint["sha256"]),
        runtime_manifest_path=runtime_manifest_path,
        runtime_manifest_sha256=str(sealed_runtime["runtime_manifest_sha256"]),
    ).encode("utf-8")
    registration = {
        "contract": "hermes.kanban_broker_register_request.v1",
        "repository_id": "radulator",
        "source_path": str(radulator_checkout),
        "default_branch": "develop",
        "project_id": None,
        "remote_repository": remote_policy,
        "expected_source_sha": source_sha,
    }
    runtime_manifest = {
        "contract": RUNTIME_MANIFEST_CONTRACT,
        "schema_version": 1,
        "runtime_root": str(sealed_runtime_root),
        "python_executable": str(python),
        "python_version": OFFICIAL_RUNTIME_VERSION,
        "provenance": _official_runtime_provenance(sha256=runtime_archive_sha256),
        "runtime_manifest_sha256": str(sealed_runtime["runtime_manifest_sha256"]),
        "entries": sealed_runtime["entries"],
    }
    runtime_manifest_bytes = _json_artifact_bytes(runtime_manifest)
    if len(runtime_manifest_bytes) > 4 * 1024 * 1024:
        raise ValueError("sealed runtime manifest exceeds the plan size limit")
    runtime_attestation = {
        "contract": "hermes.kanban_broker_runtime_attestation.v1",
        "schema_version": 1,
        "active": False,
        "revoked": True,
        "service_config_sha256": hashlib.sha256(_json_artifact_bytes(config)).hexdigest(),
        "hermes_source_sha": hermes_commit_sha,
        "hermes_install_archive_sha256": str(hermes_install_archive_sha256),
        "hermes_pyproject_lock_sha256": str(sealed_runtime["hermes_pyproject_lock_sha256"]),
        "hermes_provenance_sha256": str(sealed_runtime["hermes_provenance_sha256"]),
        "radulator_source_sha": source_sha,
        "runtime_root": str(sealed_runtime_root),
        "runtime_manifest_path": str(runtime_manifest_path),
        "python_executable": str(python),
        "python_version": OFFICIAL_RUNTIME_VERSION,
        "python_sha256": str(sealed_runtime["python_sha256"]),
        "runtime_manifest_sha256": str(sealed_runtime["runtime_manifest_sha256"]),
        "runtime_provenance": _official_runtime_provenance(
            sha256=runtime_archive_sha256
        ),
        "publisher_probe_path": str(runtime_publisher_probe_path),
        "publisher_probe_sha256": str(publisher_probe["sha256"]),
        "publisher_probe_contract": PUBLISHER_PROBE_CONTRACT,
        "publisher_probe_status": "PENDING",
        "archive_digests": {
            "cpython": str(runtime_archive_sha256),
            "hermes_install": str(hermes_install_archive_sha256),
        },
        "isolated_probe": {
            "command": [str(python), "-I", str(sealed_runtime["direct_probe_path"])],
            "outcome": "PENDING",
        },
    }
    runtime_attestation_bytes = _json_artifact_bytes(runtime_attestation)
    provenance_bytes, provenance_info = _read_sealed_file_bytes(
        Path(hermes_install_provenance_path),
        max_bytes=_MAX_RUNTIME_FILE_BYTES,
        expected_sha256=hermes_install_provenance_sha256,
    )
    try:
        provenance_document = json.loads(provenance_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Hermes install provenance manifest is invalid JSON") from exc
    if (
        not isinstance(provenance_document, dict)
        or set(provenance_document) != HERMES_INSTALL_PROVENANCE_FIELDS
    ):
        raise ValueError("Hermes install provenance must use the modern source-derived schema")
    if provenance_info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(provenance_info.st_mode) not in {0o444, 0o600, 0o644}:
        raise ValueError("Hermes install provenance manifest ownership or mode is unsafe")
    # Keys are generated once during rendering and carried only by the
    # root-owned payload manifest.  They are never printed by the CLI.
    payload_bytes: dict[str, bytes] = {}
    payload_bytes.update(clients)
    payload_bytes.update({
        str(service_config_path): _json_artifact_bytes(config),
        str(seatbelt_path): seatbelt,
        str(launchd_path): broker_plist,
        str(worker_launchd_path): worker_plist,
        str(entrypoint_path): RUNTIME_ENTRYPOINT_CONTENT.encode("utf-8"),
        str(sealed_runtime["direct_probe_path"]): RUNTIME_DIRECT_PROBE_CONTENT.encode("utf-8"),
        str(remote_policy_path): _json_artifact_bytes(remote_policy),
        str(registration_path): _json_artifact_bytes(registration),
        str(runtime_manifest_path): runtime_manifest_bytes,
            str(runtime_attestation_path): runtime_attestation_bytes,
        str(runtime_publisher_probe_path): _read_sealed_file_bytes(
            Path(publisher_probe_path),
            max_bytes=_MAX_RUNTIME_FILE_BYTES,
            expected_sha256=str(publisher_probe["sha256"]),
        )[0],
        str(dispatcher_routing_config_path): routing_config,
        str(dispatcher_profile_config_path): profile_config,
    })
    for surface in ("controller", "publisher", "operator"):
        payload_bytes[str(surface_keys[surface])] = secrets.token_bytes(32)
        payload_bytes[str(sequence_paths[surface])] = b""
    payload_bytes[str(canary_key_path)] = secrets.token_bytes(32)
    additional_files = [
        {
            "path": str(remote_policy_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o600,
            "kind": "remote_policy",
        },
        {
            "path": str(registration_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "broker_register_request",
        },
        {
            "path": str(runtime_attestation_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "runtime_attestation",
        },
        {
            "path": str(runtime_manifest_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "runtime_manifest",
        },
        {
            "path": str(runtime_hermes_provenance_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o644,
            "kind": "hermes_install_provenance",
        },
        {
            "path": str(runtime_publisher_probe_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o555,
            "kind": "publisher_preflight_script",
        },
        {
            "path": str(dispatcher_routing_config_path),
            "uid": int(config["model_uid"]),
            "gid": int(config["workspace_gid"]),
            "mode": 0o600,
            "kind": "dispatcher_routing_config",
        },
        {
            "path": str(dispatcher_profile_config_path),
            "uid": int(config["model_uid"]),
            "gid": int(config["workspace_gid"]),
            "mode": 0o600,
            "kind": "dispatcher_profile_config",
        },
        {
            "path": str(entrypoint_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o555,
            "kind": "runtime_entrypoint",
        },
        {
            "path": str(sealed_runtime["direct_probe_path"]),
            "uid": 0,
            "gid": 0,
            "mode": 0o555,
            "kind": "runtime_direct_probe",
        },
        {
            "path": str(runtime_python_archive_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o444,
            "kind": "runtime_archive",
        },
        {
            "path": str(runtime_hermes_archive_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o444,
            "kind": "runtime_archive",
        },
    ]
    filesystem_plan = render_filesystem_provision_plan(
        config=config,
        service_config_path=service_config_path,
        seatbelt_profile_path=seatbelt_path,
        launchd_plist_path=launchd_path,
        worker_launchd_plist_path=worker_launchd_path,
        client_config_paths=client_paths,
        sequence_paths=sequence_paths,
        runtime_assets=runtime_assets,
        sealed_runtime_plan=sealed_runtime,
        additional_files=additional_files,
        additional_directories=[
            {"path": str(runtime_input_root), "uid": 0, "gid": 0, "mode": 0o700},
            {"path": str(sealed_runtime_root), "uid": 0, "gid": 0, "mode": 0o711},
            {"path": str(entrypoint_path.parent), "uid": 0, "gid": 0, "mode": 0o711},
            # The model owns the profile document, but the profile directory
            # is a root-owned immutable activation boundary.  This lets a
            # root writer replace the model-owned document without granting
            # the model authority to swap the parent or its routing target.
            {"path": str(Path(config["worker_hermes_root"]) / "profiles"), "uid": 0, "gid": 0, "mode": 0o555},
            {"path": str(Path(config["worker_hermes_root"]) / "profiles" / dispatcher_profile), "uid": 0, "gid": 0, "mode": 0o555},
        ],
    )
    filesystem_plan["sealed_runtime"]["archive_destinations"] = [
        {"path": str(runtime_python_archive_path), "sha256": str(runtime_archive_sha256),
         "size": int(python_archive.stat().st_size)},
        {"path": str(runtime_hermes_archive_path), "sha256": str(hermes_install_archive_sha256),
         "size": int(hermes_archive.stat().st_size)},
    ]
    filesystem_plan["sealed_runtime"]["runtime_manifest_path"] = str(runtime_manifest_path)
    # Bind every non-directory payload to the exact filesystem plan digest.
    for item in filesystem_plan["files"]:
        path = str(item["path"])
        content = payload_bytes.get(path)
        if content is None and str(item.get("kind")) in {"runtime_archive", "hermes_install_provenance"}:
            content = b""
        if content is None:
            raise ValueError(f"filesystem plan payload is missing for {path}")
        item["sha256"] = hashlib.sha256(content).hexdigest()
        item["size"] = len(content)
        item["secret"] = str(item.get("kind", "")).endswith("_key") or item.get("kind") == "canary_key"
    external_payloads = [
        {
            "path": str(runtime_python_archive_path),
            "source_path": str(python_archive),
            "sha256": str(runtime_archive_sha256),
            "size": int(sealed_runtime["archives"][0]["size"]),
        },
        {
            "path": str(runtime_hermes_archive_path),
            "source_path": str(hermes_archive),
            "sha256": str(hermes_install_archive_sha256),
            "size": int(sealed_runtime["archives"][1]["size"]),
        },
        {
            "path": str(runtime_hermes_provenance_path),
            "source_path": str(hermes_install_provenance_path),
            "sha256": str(hermes_install_provenance_sha256),
            "size": len(provenance_bytes),
        },
    ]
    for item in filesystem_plan["files"]:
        if item.get("kind") in {"runtime_archive", "hermes_install_provenance"}:
            external = next(ref for ref in external_payloads if ref["path"] == item["path"])
            item["sha256"] = str(external["sha256"])
            item["size"] = int(external["size"])
    payload_manifest = {
        "contract": ASSET_PAYLOAD_CONTRACT,
        "schema_version": 1,
        # Keep the complete provenance as a bounded external payload.  This
        # compact seal record lets root sealing bind the exact modern schema
        # without duplicating a multi-megabyte recursive entry list in capped
        # payloads.json.
        "hermes_install_provenance": {
            "contract": HERMES_INSTALL_PROVENANCE_CONTRACT,
            "schema_version": 1,
            "fields": sorted(HERMES_INSTALL_PROVENANCE_FIELDS),
            "hermes_source_sha": str(provenance_document["hermes_source_sha"]),
            "install_archive_sha256": str(provenance_document["install_archive_sha256"]),
            "provenance_sha256": str(hermes_install_provenance_sha256),
            "entry_count": len(provenance_document["entries"]),
            "locked_package_count": len(provenance_document["locked_packages"]),
            "installed_distribution_count": len(provenance_document["installed_distributions"]),
        },
        "files": [
            {
                "path": str(item["path"]),
                "sha256": str(item["sha256"]),
                "size": int(item["size"]),
                "secret": bool(item.get("secret", False)),
            }
            for item in filesystem_plan["files"]
        ],
        "payloads": {
            path: base64.b64encode(payload_bytes[path]).decode("ascii")
            for path in sorted(payload_bytes)
            if any(str(item["path"]) == path and item.get("kind") not in {"runtime_archive", "hermes_install_provenance"}
                   for item in filesystem_plan["files"])
        },
        "external_payloads": external_payloads,
    }
    if len(_json_artifact_bytes(payload_manifest)) > 4 * 1024 * 1024:
        raise ValueError("asset payload manifest exceeds the plan size limit")
    artifacts: list[dict[str, object]] = []
    for path, uid, gid, mode, kind, content in (
        (identity_path, 0, 0, 0o600, "identity_plan", _json_artifact_bytes(identity_plan)),
        (filesystem_path, 0, 0, 0o600, "filesystem_plan", _json_artifact_bytes(filesystem_plan)),
        (payloads_path, 0, 0, 0o600, "asset_payload_manifest", _json_artifact_bytes(payload_manifest)),
    ):
        artifacts.append({"path": str(path), "uid": uid, "gid": gid, "mode": mode, "kind": kind, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
    artifacts.extend({
        key: value for key, value in item.items() if key != "secret"
    } for item in filesystem_plan["files"])
    for item in artifacts:
        item.setdefault("sha256", None)
        item.setdefault("size", 32 if item.get("kind") in {"canary_key", "controller_key", "publisher_key", "operator_key"} else 0)
    artifacts.sort(key=lambda item: str(item["path"]))
    return {
        "contract": BROKER_INSTALL_PLAN_CONTRACT,
        "schema_version": 1,
        "install_root": str(root),
        "dispatcher_profile": dispatcher_profile,
        "hermes_source_sha": hermes_commit_sha,
        "radulator_source_path": str(radulator_checkout),
        "radulator_source_sha": source_sha,
        "identity_plan_path": str(identity_path),
        "filesystem_plan_path": str(filesystem_path),
        "payload_manifest_path": str(payloads_path),
        "service_config_path": str(service_config_path),
        "identity_plan": identity_plan,
        "filesystem_plan": filesystem_plan,
        "asset_payload_manifest": payload_manifest,
        "service_config": config,
        "remote_policy": remote_policy,
        "broker_register_request": registration,
        "runtime": {
            "python_executable": str(python),
            "python_sha256": config["python_sha256"],
            "git_executable": str(git),
            "git_sha256": config["git_sha256"],
            "package_root": str(package_root),
            "package_manifest_sha256": runtime_assets["package_manifest_sha256"],
            "runtime_manifest_sha256": sealed_runtime["runtime_manifest_sha256"],
            "python_version": OFFICIAL_RUNTIME_VERSION,
            "entrypoint_path": str(entrypoint_path),
            "entrypoint_mode": 0o555,
            "package_root_mode": 0o555,
            "package_file_mode": 0o444,
            "sealed_runtime": sealed_runtime,
            "archive_destinations": [str(runtime_python_archive_path), str(runtime_hermes_archive_path)],
            "attestation_path": str(runtime_attestation_path),
            "runtime_manifest_path": str(runtime_manifest_path),
            "runtime_provenance": _official_runtime_provenance(
                sha256=runtime_archive_sha256
            ),
            "hermes_pyproject_lock_sha256": str(sealed_runtime["hermes_pyproject_lock_sha256"]),
            "hermes_provenance_sha256": str(sealed_runtime["hermes_provenance_sha256"]),
            "publisher_probe_path": str(runtime_publisher_probe_path),
            "publisher_probe_sha256": str(publisher_probe["sha256"]),
        },
        "artifacts": artifacts,
    }


def _assert_safe_output_parent(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise ValueError("broker plan output contains a symlink component")
        except OSError as exc:
            raise ValueError("broker plan output cannot be inspected") from exc


def _atomic_artifact_write(path: Path, content: bytes, *, mode: int, uid: int, gid: int) -> None:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("broker plan artifact path is unsafe")
    _ensure_directory_tree(
        path.parent, mode=0o711, uid=os.geteuid(), gid=os.getegid(), apply_final=False
    )
    parent_fd = _open_directory_fd(path.parent)
    parent_before = os.fstat(parent_fd)
    if (
        not stat.S_ISDIR(parent_before.st_mode)
        or parent_before.st_uid != os.geteuid()
        or stat.S_IMODE(parent_before.st_mode) & 0o022
    ):
        os.close(parent_fd)
        raise ValueError("broker plan output parent owner or mode is unsafe")
    name = path.name
    try:
        try:
            existing_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing_info = None
        if existing_info is not None:
            if (not stat.S_ISREG(existing_info.st_mode) or existing_info.st_nlink != 1
                    or stat.S_IMODE(existing_info.st_mode) != int(mode)):
                raise ValueError("broker plan output target is unsafe")
            if existing_info.st_uid != int(uid) or existing_info.st_gid != int(gid):
                raise ValueError("broker plan output target owner is unsafe")
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            try:
                opened_info = os.fstat(fd)
                if (opened_info.st_dev, opened_info.st_ino) != (
                    existing_info.st_dev, existing_info.st_ino
                ):
                    raise ValueError("broker plan output target changed during read")
                chunks: list[bytes] = []
                remaining = len(content) + 1
                while remaining > 0:
                    chunk = os.read(fd, remaining)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                existing = b"".join(chunks)
                closed_info = os.fstat(fd)
                if (opened_info.st_dev, opened_info.st_ino, opened_info.st_size,
                        opened_info.st_mtime_ns) != (
                    closed_info.st_dev, closed_info.st_ino, closed_info.st_size,
                    closed_info.st_mtime_ns
                ):
                    raise ValueError("broker plan output target changed during read")
            finally:
                os.close(fd)
            if existing != content:
                raise ValueError("existing broker plan artifact differs from plan")
            parent_after = os.fstat(parent_fd)
            if (parent_before.st_dev, parent_before.st_ino) != (
                parent_after.st_dev, parent_after.st_ino
            ):
                raise ValueError("broker plan output parent changed during read")
            return
        temporary_name = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            int(mode),
            dir_fd=parent_fd,
        )
        try:
            os.fchown(fd, int(uid), int(gid))
            os.fchmod(fd, int(mode))
            view = memoryview(content)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
            raise ValueError("broker plan output parent changed during write")
        os.replace(temporary_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            written = os.read(fd, len(content) + 1)
        finally:
            os.close(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != int(mode)
                or info.st_uid != int(uid) or info.st_gid != int(gid)
                or written != content):
            raise ValueError("broker plan artifact ownership, mode, or digest is unsafe")
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except (NameError, FileNotFoundError, OSError):
            pass
        raise
    finally:
        os.close(parent_fd)


def _update_runtime_attestation(
    config: dict[str, object],
    *,
    service_config_path: Path,
    active: bool,
    revoked: bool,
    isolated_probe: dict[str, object] | None = None,
    publisher_probe_status: str | None = None,
    service_config_sha256: str | None = None,
) -> None:
    """Publish only sanitized runtime state; never include keys or credentials."""
    raw_path = config.get("runtime_attestation_path")
    if raw_path is None:
        return
    path = Path(str(raw_path))
    # The configured path is never opened directly.  This descriptor-relative
    # reader checks every parent component with O_NOFOLLOW and records the
    # target inode before/after reading, closing the final-path race window.
    raw, info = _read_sealed_file_bytes(path, max_bytes=1024 * 1024)
    if (
        info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o644
    ):
        raise ValueError("runtime attestation ownership or mode is unsafe")
    try:
        attestation = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime attestation is invalid JSON") from exc
    required = {
        "contract", "schema_version", "active", "revoked", "service_config_sha256",
        "hermes_source_sha", "hermes_install_archive_sha256", "hermes_pyproject_lock_sha256",
        "hermes_provenance_sha256", "radulator_source_sha",
        "runtime_root", "runtime_manifest_path", "python_executable", "python_version", "python_sha256",
        "runtime_manifest_sha256", "runtime_provenance", "publisher_probe_path",
        "publisher_probe_sha256", "publisher_probe_contract", "publisher_probe_status",
        "archive_digests", "isolated_probe",
    }
    if not isinstance(attestation, dict) or set(attestation) != required:
        raise ValueError("runtime attestation fields are not exact")
    if (
        not isinstance(attestation["active"], bool)
        or not isinstance(attestation["revoked"], bool)
        or attestation["active"] == attestation["revoked"]
        or not isinstance(attestation["archive_digests"], dict)
        or set(attestation["archive_digests"]) != {"cpython", "hermes_install"}
        or any(
            re.fullmatch(r"[0-9a-f]{64}", str(value)) is None
            for value in attestation["archive_digests"].values()
        )
        or attestation["archive_digests"]["cpython"] != OFFICIAL_RUNTIME_ARCHIVE_SHA256
        or attestation.get("runtime_provenance") != _official_runtime_provenance(
            sha256=attestation["archive_digests"]["cpython"]
        )
        or attestation.get("publisher_probe_contract") != PUBLISHER_PROBE_CONTRACT
        or attestation.get("publisher_probe_status") not in {"PASS", "PENDING"}
        or not isinstance(attestation["isolated_probe"], dict)
        or set(attestation["isolated_probe"]) != {"command", "outcome"}
        or attestation["isolated_probe"]["outcome"] not in {"PASS", "PENDING"}
        or not isinstance(attestation["isolated_probe"]["command"], list)
    ):
        raise ValueError("runtime attestation evidence is not exact")
    updated = dict(attestation)
    updated["active"] = bool(active)
    updated["revoked"] = bool(revoked)
    if isolated_probe is not None:
        updated["isolated_probe"] = dict(isolated_probe)
    if publisher_probe_status is not None:
        updated["publisher_probe_status"] = publisher_probe_status
    if (
        not isinstance(updated.get("isolated_probe"), dict)
        or set(updated["isolated_probe"]) != {"command", "outcome"}
        or not isinstance(updated["isolated_probe"].get("command"), list)
        or updated["isolated_probe"].get("outcome") not in {"PASS", "PENDING"}
    ):
        raise ValueError("runtime attestation isolated probe evidence is invalid")
    if bool(active) and updated["isolated_probe"].get("outcome") != "PASS":
        raise ValueError("runtime attestation cannot activate before the isolated probe passes")
    if updated.get("publisher_probe_status") not in {"PASS", "PENDING"}:
        raise ValueError("runtime attestation publisher probe status is invalid")
    if bool(active) and updated.get("publisher_probe_status") != "PASS":
        raise ValueError("runtime attestation cannot activate before the publisher probe passes")
    _validated_hex_sha(updated["hermes_source_sha"], field="Hermes source SHA", length=40)
    _validated_hex_sha(
        updated["hermes_install_archive_sha256"],
        field="Hermes install archive SHA256",
        length=64,
    )
    _validated_hex_sha(updated["radulator_source_sha"], field="Radulator source SHA", length=40)
    _validated_hex_sha(updated["python_sha256"], field="Python SHA256", length=64)
    _validated_hex_sha(
        updated["hermes_pyproject_lock_sha256"],
        field="Hermes pyproject/lock SHA256",
        length=64,
    )
    _validated_hex_sha(
        updated["hermes_provenance_sha256"],
        field="Hermes provenance SHA256",
        length=64,
    )
    _validated_hex_sha(
        updated["publisher_probe_sha256"],
        field="publisher preflight script SHA256",
        length=64,
    )
    _validated_hex_sha(
        updated["runtime_manifest_sha256"], field="runtime manifest SHA256", length=64
    )
    if updated["python_version"] != OFFICIAL_RUNTIME_VERSION:
        raise ValueError("runtime attestation Python version is unsupported")
    _read_runtime_manifest_file(
        Path(str(updated["runtime_manifest_path"])),
        expected_sha256=str(updated["runtime_manifest_sha256"]),
        expected_runtime_root=Path(str(updated["runtime_root"])),
        expected_python_executable=Path(str(updated["python_executable"])),
        expected_python_version=OFFICIAL_RUNTIME_VERSION,
    )
    configured_probe = config.get("publisher_probe_path")
    if configured_probe is not None and (
        updated.get("publisher_probe_path") != configured_probe
        or updated.get("publisher_probe_contract") != PUBLISHER_PROBE_CONTRACT
    ):
        raise ValueError("runtime attestation publisher binding differs from service config")
    if configured_probe is not None:
        probe = Path(str(configured_probe))
        probe_info = probe.lstat()
        if (
            stat.S_ISLNK(probe_info.st_mode)
            or not stat.S_ISREG(probe_info.st_mode)
            or probe_info.st_uid != 0
            or probe_info.st_gid != 0
            or probe_info.st_nlink != 1
            or stat.S_IMODE(probe_info.st_mode) != 0o555
            or _safe_file_sha256(probe) != updated.get("publisher_probe_sha256")
        ):
            raise ValueError("runtime attestation publisher script binding is unsafe")
    if service_config_sha256 is None:
        service_digest = _safe_file_sha256(Path(service_config_path))
    else:
        service_digest = _validated_hex_sha(
            service_config_sha256, field="service config SHA256", length=64
        )
    updated["service_config_sha256"] = service_digest
    _atomic_artifact_write(path, _json_artifact_bytes(updated), mode=0o644, uid=0, gid=0)


def _set_dispatcher_profile_activation(config: dict[str, object], *, enabled: bool) -> None:
    """Atomically update the named profile's real routing configuration.

    The profile is model-owned, so the broker never edits it through a model
    process or an ambient absolute-path open.  The descriptor-bound read and
    writer ensure activation cannot silently replace a symlinked profile.
    """
    raw_path = config.get("dispatcher_profile_config_path")
    if raw_path is None:
        return
    path = Path(str(raw_path))
    expected_owner = int(config["model_uid"])
    expected_group = int(config["workspace_gid"])
    raw, info = _read_sealed_file_bytes(path, max_bytes=1024 * 1024)
    if (
        info.st_uid != expected_owner
        or info.st_gid != expected_group
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise ValueError("dispatcher profile config ownership or mode is unsafe")
    parent = path.parent
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise ValueError("dispatcher profile parent is unavailable") from exc
    if (
        stat.S_ISLNK(parent_info.st_mode)
        or not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != 0
        or parent_info.st_gid != 0
        or stat.S_IMODE(parent_info.st_mode) != 0o555
    ):
        raise ValueError("dispatcher profile parent ownership or mode is unsafe")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("dispatcher profile config is not UTF-8") from exc
    lines = text.splitlines(keepends=True)
    if not lines or lines[0] != "kanban:\n":
        raise ValueError("dispatcher profile config contract is invalid")
    updates = {
        "  dedicated_broker_enabled: ": "true" if enabled else "false",
        "  trusted_publisher_enabled: ": "true" if enabled else "false",
    }
    seen: set[str] = set()
    # Retain the YAML document's root key while replacing only the two
    # activation flags below it.
    result: list[str] = [lines[0]]
    for line in lines[1:]:
        newline = "\n" if line.endswith("\n") else ""
        body = line[:-1] if newline else line
        matched = False
        for prefix, value in updates.items():
            if body.startswith(prefix):
                if body[len(prefix):] not in {"true", "false"} or prefix in seen:
                    raise ValueError("dispatcher profile config flags are invalid")
                body = prefix + value
                seen.add(prefix)
                matched = True
                break
        result.append(body + newline)
    if seen != set(updates):
        raise ValueError("dispatcher profile config flags are incomplete")
    replacement = "".join(result).encode("utf-8")
    # _atomic_artifact_write intentionally refuses to replace a pre-existing
    # immutable plan artifact.  Activation is the one reviewed transition
    # that must replace this model-owned document; perform that replacement
    # descriptor-relatively beneath the root-owned 0555 parent.
    parent_fd = _open_directory_fd(parent)
    parent_before = os.fstat(parent_fd)
    temporary_name = f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            os.fchown(fd, expected_owner, expected_group)
            os.fchmod(fd, 0o600)
            view = memoryview(replacement)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        parent_after = os.fstat(parent_fd)
        if (parent_before.st_dev, parent_before.st_ino) != (parent_after.st_dev, parent_after.st_ino):
            raise ValueError("dispatcher profile parent changed during activation")
        os.replace(temporary_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=parent_fd)
        except (FileNotFoundError, OSError):
            pass
        raise
    finally:
        os.close(parent_fd)
    reread, read_info = _read_sealed_file_bytes(path, max_bytes=1024 * 1024)
    if (
        reread != replacement
        or read_info.st_uid != expected_owner
        or read_info.st_gid != expected_group
        or stat.S_IMODE(read_info.st_mode) != 0o600
    ):
        raise ValueError("dispatcher profile config activation readback failed")


def validate_runtime_attestation_state(config: dict[str, object]) -> None:
    """Require the service's durable runtime attestation to agree with flags."""
    raw_path = config.get("runtime_attestation_path")
    if raw_path is None:
        return
    path = Path(str(raw_path))
    raw, info = _read_sealed_file_bytes(path, max_bytes=1024 * 1024)
    if (
        info.st_uid != 0
        or info.st_gid != 0
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o644
    ):
        raise ValueError("runtime attestation ownership or mode is unsafe")
    try:
        attestation = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("runtime attestation is invalid JSON") from exc
    if not isinstance(attestation, dict):
        raise ValueError("runtime attestation is not an object")
    trusted = config.get("trusted_publisher_enabled") is True
    if (
        attestation.get("active") is not trusted
        or attestation.get("revoked") is not (not trusted)
        or (trusted and attestation.get("publisher_probe_status") != "PASS")
        or (trusted and not isinstance(attestation.get("isolated_probe"), dict))
        or attestation.get("runtime_root") != str(config.get("python_executable", "")).rsplit("/bin/", 1)[0]
        or attestation.get("runtime_manifest_path") != config.get("runtime_manifest_path")
        or attestation.get("runtime_manifest_sha256") != config.get("runtime_manifest_sha256")
    ):
        raise ValueError("runtime attestation does not authorize service state")
    configured_service_path = config.get("service_config_path")
    if configured_service_path is not None:
        service_bytes, _service_info = _read_sealed_file_bytes(
            Path(str(configured_service_path)), max_bytes=1024 * 1024
        )
        if attestation.get("service_config_sha256") != hashlib.sha256(service_bytes).hexdigest():
            raise ValueError("runtime attestation service config digest does not match")


def _rebase_path_string(value: object, *, source_root: Path, output_root: Path) -> object:
    if isinstance(value, str):
        prefix = str(source_root)
        if value == prefix:
            return str(output_root)
        if value.startswith(prefix + "/"):
            return str(output_root) + value[len(prefix):]
    if isinstance(value, list):
        return [_rebase_path_string(item, source_root=source_root, output_root=output_root) for item in value]
    if isinstance(value, dict):
        rebased: dict[object, object] = {}
        for key, item in value.items():
            rebased_key = (
                _rebase_path_string(key, source_root=source_root, output_root=output_root)
                if isinstance(key, str) else key
            )
            rebased[rebased_key] = _rebase_path_string(
                item, source_root=source_root, output_root=output_root
            )
        return rebased
    return value


def _validate_plan_artifact_record(item: object, *, directory: bool) -> dict[str, object]:
    if not isinstance(item, dict):
        raise ValueError("broker filesystem artifact entry is malformed")
    expected = {"path", "uid", "gid", "mode"}
    if not directory:
        expected |= {"kind", "sha256", "size", "secret"}
    if set(item) != expected:
        raise ValueError("broker filesystem artifact fields are not exact")
    if not isinstance(item["path"], str) or not item["path"]:
        raise ValueError("broker filesystem artifact path is invalid")
    for field in ("uid", "gid"):
        value = item[field]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= (2**31 - 2):
            raise ValueError("broker filesystem artifact identity is invalid")
    mode = item["mode"]
    allowed_modes = {0o444, 0o555, 0o600, 0o640, 0o644, 0o700, 0o710, 0o711, 0o755}
    if isinstance(mode, bool) or not isinstance(mode, int) or mode not in allowed_modes:
        raise ValueError("broker filesystem artifact mode is invalid")
    if not directory:
        if not isinstance(item["kind"], str) or not item["kind"]:
            raise ValueError("broker filesystem artifact kind is invalid")
        if not isinstance(item["sha256"], str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise ValueError("broker filesystem artifact digest is invalid")
        if isinstance(item["size"], bool) or not isinstance(item["size"], int) or item["size"] < 0:
            raise ValueError("broker filesystem artifact size is invalid")
        if not isinstance(item["secret"], bool):
            raise ValueError("broker filesystem artifact secret marker is invalid")
    return item


def write_broker_installation_plan(plan: dict[str, object], *, output_root: Path) -> dict[str, str]:
    """Write only offline plan documents; final service assets belong to apply."""
    if not isinstance(plan, dict) or plan.get("contract") != BROKER_INSTALL_PLAN_CONTRACT:
        raise ValueError("unsupported broker installation plan")
    source_root = _validated_install_path(
        str(plan.get("install_root") or ""),
        field="plan install root",
        allow_root=True,
    )
    if source_root == Path(source_root.anchor):
        raise ValueError("plan install root must be bounded")
    destination_root = _validated_install_path(output_root, field="plan output root", allow_root=True)
    if destination_root == Path(destination_root.anchor):
        raise ValueError("plan output root must be bounded")
    try:
        destination_info = destination_root.lstat()
    except FileNotFoundError:
        destination_info = None
    if destination_info is not None and (
        stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(destination_info.st_mode)
    ):
        raise ValueError("plan output root must be a real directory")
    filesystem = plan.get("filesystem_plan")
    manifest = plan.get("asset_payload_manifest")
    if not isinstance(filesystem, dict) or not isinstance(manifest, dict):
        raise ValueError("broker installation plan is incomplete")
    if filesystem.get("contract") != "hermes.kanban_broker_filesystem_plan.v1" or manifest.get("contract") != ASSET_PAYLOAD_CONTRACT:
        raise ValueError("broker installation subplans are unsupported")
    raw_directories = filesystem.get("directories")
    raw_files = filesystem.get("files")
    raw_manifest_files = manifest.get("files")
    raw_payloads = manifest.get("payloads")
    raw_external = manifest.get("external_payloads", [])
    if (
        not isinstance(raw_directories, list)
        or not isinstance(raw_files, list)
        or not isinstance(raw_manifest_files, list)
        or not isinstance(raw_payloads, dict)
        or not isinstance(raw_external, list)
    ):
        raise ValueError("broker asset payload manifest is malformed")
    directories = [_validate_plan_artifact_record(item, directory=True) for item in raw_directories]
    files = [_validate_plan_artifact_record(item, directory=False) for item in raw_files]
    paths = [str(item["path"]) for item in [*directories, *files]]
    if len(paths) != len(set(paths)):
        raise ValueError("broker filesystem plan contains duplicate paths")
    file_paths = set(str(item["path"]) for item in files)
    manifest_paths: set[str] = set()
    for item in raw_manifest_files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size", "secret"}:
            raise ValueError("broker asset payload manifest file fields are not exact")
        path = item.get("path")
        if not isinstance(path, str) or path in manifest_paths:
            raise ValueError("broker asset payload manifest has duplicate paths")
        if not isinstance(item.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None:
            raise ValueError("broker asset payload manifest digest is invalid")
        if isinstance(item.get("size"), bool) or not isinstance(item.get("size"), int) or item["size"] < 0:
            raise ValueError("broker asset payload manifest size is invalid")
        if not isinstance(item.get("secret"), bool):
            raise ValueError("broker asset payload manifest secret marker is invalid")
        manifest_paths.add(path)
    external_paths: set[str] = set()
    for item in raw_external:
        if not isinstance(item, dict) or set(item) != {"path", "source_path", "sha256", "size"}:
            raise ValueError("broker external payload fields are not exact")
        path = item.get("path")
        source = item.get("source_path")
        if (not isinstance(path, str) or not isinstance(source, str)
                or path in external_paths or not Path(path).is_absolute()
                or not Path(source).is_absolute()):
            raise ValueError("broker external payload path is invalid")
        _validated_install_path(path, field="broker external destination")
        source_path = _validated_install_path(source, field="broker external source")
        digest = _validated_hex_sha(item.get("sha256"), field="external payload SHA256", length=64)
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > _MAX_RUNTIME_ARCHIVE_BYTES:
            raise ValueError("broker external payload size is invalid")
        _read_sealed_file_bytes(
            source_path,
            max_bytes=_MAX_RUNTIME_ARCHIVE_BYTES,
            expected_size=size,
            expected_sha256=digest,
        )
        external_paths.add(path)
    if manifest_paths != file_paths or set(raw_payloads) | external_paths != file_paths or set(raw_payloads) & external_paths:
        raise ValueError("broker asset payload manifest does not match filesystem plan")
    file_by_path = {str(item["path"]): item for item in files}
    for item in raw_manifest_files:
        file_item = file_by_path[str(item["path"])]
        if (
            item["sha256"] != file_item["sha256"]
            or item["size"] != file_item["size"]
            or item["secret"] is not file_item["secret"]
        ):
            raise ValueError("broker asset payload manifest metadata differs from filesystem plan")
    payloads: dict[str, bytes] = {}
    for raw_path, encoded in raw_payloads.items():
        if not isinstance(raw_path, str) or not isinstance(encoded, str):
            raise ValueError("broker asset payload entry is malformed")
        try:
            payloads[raw_path] = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("broker asset payload is not valid base64") from exc
    for item in files:
        raw_path = str(item["path"])
        if raw_path in external_paths:
            ext = next(ref for ref in raw_external if ref["path"] == raw_path)
            if int(item["size"]) != int(ext["size"]) or str(item["sha256"]) != str(ext["sha256"]):
                raise ValueError("broker external payload metadata does not match filesystem plan")
        else:
            content = payloads[raw_path]
            if len(content) != int(item["size"]) or hashlib.sha256(content).hexdigest() != str(item["sha256"]):
                raise ValueError("broker asset payload metadata does not match filesystem plan")
    rebased_filesystem = cast(
        dict[str, object],
        _rebase_path_string(filesystem, source_root=source_root, output_root=destination_root),
    )
    rebased_manifest = cast(
        dict[str, object],
        _rebase_path_string(manifest, source_root=source_root, output_root=destination_root),
    )
    rebased_payloads = rebased_manifest["payloads"]
    if not isinstance(rebased_payloads, dict):
        raise ValueError("rebased broker asset payload manifest is malformed")
    original_external_sources = {
        str(item["path"]): str(item["source_path"])
        for item in raw_external
    }
    original_registration_sources: dict[str, str] = {}
    for raw_path, encoded in raw_payloads.items():
        if not isinstance(raw_path, str) or not raw_path.endswith("/broker-register.json"):
            continue
        try:
            registration = json.loads(base64.b64decode(encoded, validate=True))
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("broker registration payload is invalid JSON") from exc
        if not isinstance(registration, dict) or not isinstance(
            registration.get("source_path"), str
        ):
            raise ValueError("broker registration payload has no source checkout")
        original_registration_sources[raw_path] = registration["source_path"]
    source_prefix = str(source_root).encode("utf-8")
    destination_prefix = str(destination_root).encode("utf-8")
    for raw_path, encoded in list(rebased_payloads.items()):
        if not isinstance(raw_path, str) or not isinstance(encoded, str):
            raise ValueError("rebased broker asset payload entry is malformed")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("rebased broker asset payload is not valid base64") from exc
        # Service/config/plist/manifest payloads are embedded bytes in the
        # manifest.  Rebase those bytes too, then refresh every bound digest;
        # otherwise output-root plans would name one tree while carrying bytes
        # for another.
        content = content.replace(source_prefix, destination_prefix)
        rebased_payloads[raw_path] = base64.b64encode(content).decode("ascii")
    # External inputs are intentionally not copied into the offline output
    # tree.  Restore their original source paths after generic path rebasing;
    # only their destination keys are rooted at the requested output root.
    for original_path, source_path in original_external_sources.items():
        rebased_path = _rebase_path_string(
            original_path, source_root=source_root, output_root=destination_root
        )
        for item in cast(list[dict[str, object]], rebased_manifest["external_payloads"]):
            if item.get("path") == rebased_path:
                item["source_path"] = source_path
                break
        else:
            raise ValueError("rebased external payload metadata is incomplete")
    for original_path, source_path in original_registration_sources.items():
        rebased_path = _rebase_path_string(
            original_path, source_root=source_root, output_root=destination_root
        )
        encoded = rebased_payloads.get(rebased_path)
        if not isinstance(encoded, str):
            raise ValueError("rebased broker registration payload is missing")
        registration = json.loads(base64.b64decode(encoded, validate=True))
        if not isinstance(registration, dict):
            raise ValueError("rebased broker registration payload is malformed")
        registration["source_path"] = source_path
        rebased_payloads[rebased_path] = base64.b64encode(
            _json_artifact_bytes(registration)
        ).decode("ascii")
    rebased_sealed = rebased_filesystem.get("sealed_runtime")
    original_sealed = filesystem.get("sealed_runtime")
    if isinstance(rebased_sealed, dict) and isinstance(original_sealed, dict):
        original_archives = original_sealed.get("archives")
        rebased_archives = rebased_sealed.get("archives")
        if isinstance(original_archives, list) and isinstance(rebased_archives, list):
            if len(original_archives) != len(rebased_archives):
                raise ValueError("rebased sealed runtime archive metadata is incomplete")
            for original_archive, rebased_archive in zip(original_archives, rebased_archives):
                if isinstance(original_archive, dict) and isinstance(rebased_archive, dict):
                    rebased_archive["path"] = original_archive.get("path")
    # The attestation binds the exact service bytes.  Rebasing changes those
    # bytes, so refresh that binding before the payload/filesystem digests are
    # finalized; otherwise an output-root plan would carry a stale attestation
    # and fail closed at activation.
    service_paths = [
        path for path in rebased_payloads
        if path.endswith("/config/service.json")
    ]
    attestation_paths = [
        path for path in rebased_payloads
        if path.endswith("/runtime-attestation.json")
    ]
    if service_paths and attestation_paths:
        if len(service_paths) != 1 or len(attestation_paths) != 1:
            raise ValueError("rebased broker service attestation paths are ambiguous")
        service_path = service_paths[0]
        attestation_path = attestation_paths[0]
        try:
            attestation = json.loads(
                base64.b64decode(rebased_payloads[attestation_path], validate=True)
            )
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("rebased runtime attestation is invalid JSON") from exc
        if not isinstance(attestation, dict) or "service_config_sha256" not in attestation:
            raise ValueError("rebased runtime attestation is missing its service binding")
        service_bytes = base64.b64decode(rebased_payloads[service_path], validate=True)
        attestation["service_config_sha256"] = hashlib.sha256(service_bytes).hexdigest()
        rebased_payloads[attestation_path] = base64.b64encode(
            _json_artifact_bytes(attestation)
        ).decode("ascii")
    rebased_files = rebased_filesystem.get("files")
    rebased_manifest_files = rebased_manifest.get("files")
    if not isinstance(rebased_files, list) or not isinstance(rebased_manifest_files, list):
        raise ValueError("rebased broker asset metadata is malformed")
    rebased_payload_map = cast(dict[str, str], rebased_payloads)
    manifest_by_path = {
        str(item["path"]): item for item in rebased_manifest_files
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    for item in rebased_files:
        if not isinstance(item, dict):
            raise ValueError("rebased broker filesystem artifact is malformed")
        path = str(item["path"])
        if path in rebased_payload_map:
            content = base64.b64decode(rebased_payload_map[path], validate=True)
            item["sha256"] = hashlib.sha256(content).hexdigest()
            item["size"] = len(content)
            manifest_item = manifest_by_path.get(path)
            if manifest_item is None:
                raise ValueError("rebased broker payload metadata is incomplete")
            manifest_item["sha256"] = item["sha256"]
            manifest_item["size"] = item["size"]
    def target(raw_path: str) -> Path:
        original = _validated_install_path(
            raw_path,
            field="plan artifact",
            install_root=source_root,
            allow_root=True,
        )
        return destination_root / original.relative_to(source_root)
    # Rendering is an offline action.  In particular it must never materialize
    # service JSON, launchd plists, keys, or a runtime archive into the target
    # install root.  The root-only provision-assets edge consumes these plans.
    plan_files = (
        ("identity_plan_path", "identity_plan"),
        ("filesystem_plan_path", "filesystem_plan"),
        ("payload_manifest_path", "asset_payload_manifest"),
    )
    for path_key, value_key in plan_files:
        raw_path = str(plan[path_key])
        if value_key == "filesystem_plan":
            value = rebased_filesystem
        elif value_key == "asset_payload_manifest":
            value = rebased_manifest
        else:
            value = _rebase_path_string(
                plan[value_key], source_root=source_root, output_root=destination_root
            )
        content = _json_artifact_bytes(value)
        owner_uid = os.geteuid()
        owner_gid = os.getegid()
        _atomic_artifact_write(target(raw_path), content, mode=0o600, uid=owner_uid, gid=owner_gid)
    return {"contract": BROKER_INSTALL_PLAN_CONTRACT, "output_root": str(destination_root)}


def seal_broker_installation_plan(*, input_root: Path, output_root: Path) -> dict[str, str]:
    """Re-emit an offline render as root-owned apply inputs.

    Rendering intentionally remains usable by an unprivileged reviewer.  The
    apply edge must consume a separate root seal so no undocumented chown or
    ownership assumption can turn reviewer-controlled JSON into an installer
    authority document.
    """
    if os.geteuid() != 0:
        raise PermissionError("broker plan sealing requires root")
    source_root = _validated_install_path(
        input_root, field="offline plan input root", allow_root=True
    )
    if source_root == Path(source_root.anchor):
        raise ValueError("offline plan input root must be bounded")
    destination_root = _validated_install_path(
        output_root, field="sealed plan output root", allow_root=True
    )
    if destination_root == Path(destination_root.anchor):
        raise ValueError("sealed plan output root must be bounded")
    try:
        destination_info = destination_root.lstat()
    except FileNotFoundError:
        destination_info = None
    if destination_info is not None and (
        stat.S_ISLNK(destination_info.st_mode) or not stat.S_ISDIR(destination_info.st_mode)
    ):
        raise ValueError("sealed plan output root must be a real directory")
    if destination_info is not None:
        os.chown(destination_root, 0, 0)
        os.chmod(destination_root, 0o700)
    identity = _read_root_json(
        source_root / "install/identities.json",
        contract="hermes.kanban_broker_identity_plan.v1",
        allow_unprivileged_owner=True,
    )
    filesystem = _read_root_json(
        source_root / "install/filesystem.json",
        contract="hermes.kanban_broker_filesystem_plan.v1",
        allow_unprivileged_owner=True,
    )
    payloads = _read_root_json(
        source_root / "install/payloads.json",
        contract=ASSET_PAYLOAD_CONTRACT,
        allow_unprivileged_owner=True,
    )
    embedded_provenance = payloads.get("hermes_install_provenance")
    if (
        not isinstance(embedded_provenance, dict)
        or set(embedded_provenance) != HERMES_INSTALL_PROVENANCE_SEAL_FIELDS
        or embedded_provenance.get("contract") != HERMES_INSTALL_PROVENANCE_CONTRACT
        or embedded_provenance.get("schema_version") != 1
        or embedded_provenance.get("fields") != sorted(HERMES_INSTALL_PROVENANCE_FIELDS)
    ):
        raise ValueError(
            "offline plan is missing the complete modern Hermes provenance contract"
        )
    outer = {
        "contract": BROKER_INSTALL_PLAN_CONTRACT,
        "schema_version": 1,
        "install_root": str(source_root),
        "identity_plan_path": str(source_root / "install/identities.json"),
        "filesystem_plan_path": str(source_root / "install/filesystem.json"),
        "payload_manifest_path": str(source_root / "install/payloads.json"),
        "identity_plan": identity,
        "filesystem_plan": filesystem,
        "asset_payload_manifest": payloads,
    }
    result = write_broker_installation_plan(outer, output_root=output_root)
    destination = Path(result["output_root"])
    os.chown(destination, 0, 0)
    os.chmod(destination, 0o700)
    for path in (
        destination / "install/identities.json",
        destination / "install/filesystem.json",
        destination / "install/payloads.json",
    ):
        info = path.lstat()
        if (
            info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("sealed broker plan ownership readback failed")
    return result


if __name__ == "__main__":
    raise SystemExit(main())

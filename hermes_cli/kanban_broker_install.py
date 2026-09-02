"""Render the disabled-first macOS launchd broker service definition."""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import hmac
import json
import os
import plistlib
import pwd
import re
import secrets
import stat
import subprocess
import tempfile
import time
from pathlib import Path
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
    "model_terminal_denied",
    "computer_use_denied_by_uid",
)
_ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
_MAX_POSIX_ID = 2**31 - 2
_MAX_RUNTIME_FILE_BYTES = 4 * 1024 * 1024
_MAX_RUNTIME_PACKAGE_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_PACKAGE_ENTRIES = 4096

# These contracts describe the reviewed, data-only provisioning edge.  The
# existing v1 identity/filesystem/service contracts remain the apply boundary;
# this outer plan binds them together without changing the service lifecycle.
BROKER_INSTALL_PLAN_CONTRACT = "hermes.kanban_broker_install_plan.v1"
HOST_IDENTITY_INVENTORY_CONTRACT = "hermes.kanban_broker_host_inventory.v1"
DESIRED_IDENTITIES_CONTRACT = "hermes.kanban_broker_desired_identities.v1"
REMOTE_POLICY_CONTRACT = "hermes.github_repository.v1"
ASSET_PAYLOAD_CONTRACT = "hermes.kanban_broker_asset_payloads.v1"
RUNTIME_ENTRYPOINT_CONTENT = """#!/usr/bin/python3
\"\"\"Self-contained Hermes broker runtime entrypoint.\"\"\"
from __future__ import annotations

import importlib
import runpy
import sys
from pathlib import Path


def main() -> int:
    # The entrypoint is invoked as ``python3 -I entrypoint -m module ...``.
    # -I removes PYTHONPATH and the ambient checkout; this explicit sibling
    # path is the root-owned, immutable runtime selected by the plan.
    runtime_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(runtime_root))
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-import":
        importlib.import_module(sys.argv[2])
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


def render_broker_service_config(
    *,
    install_root: Path,
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
    worker_client_config_path: Path | None = None,
    worker_sequence_path: Path | None = None,
    install_nonce: str | None = None,
) -> str:
    """Render install-time broker assets in the mandatory disabled state."""
    validate_identity_separation(
        broker_uid=broker_uid,
        model_uid=model_uid,
        controller_uid=controller_uid,
        publisher_uid=publisher_uid,
    )
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
    if worker_client_config_path is not None:
        worker_client_config_path = Path(worker_client_config_path)
    if worker_sequence_path is not None:
        worker_sequence_path = Path(worker_sequence_path)
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
        *([worker_client_config_path] if worker_client_config_path is not None else []),
        *([worker_sequence_path] if worker_sequence_path is not None else []),
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
        *([worker_client_config_path] if worker_client_config_path is not None else []),
        *([worker_sequence_path] if worker_sequence_path is not None else []),
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
        "python_sha256": _safe_file_sha256(python_executable),
        "git_executable": str(git_executable),
        "git_sha256": _safe_file_sha256(git_executable),
        "package_root": str(package_root),
        "package_manifest_sha256": str(package_manifest_sha256),
        "canary_key_path": str(canary_key_path),
        "seatbelt_profile_path": str(seatbelt_profile_path),
        "launchd_plist_path": str(launchd_plist_path),
        "worker_launchd_plist_path": str(worker_launchd_plist_path),
    }
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
    if worker_client_config_path is not None:
        payload["worker_client_config_path"] = str(worker_client_config_path)
    if worker_sequence_path is not None:
        payload["worker_sequence_path"] = str(worker_sequence_path)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def _safe_file_sha256(path: Path) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(Path(path), flags)
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
        return digest.hexdigest()
    finally:
        os.close(fd)


def runtime_package_manifest(
    package_root: Path, *, expected_owner_uid: int
) -> dict[str, object]:
    """Hash a symlink-free, owner-pinned immutable Python package tree."""

    root = Path(package_root)
    root_info = root.lstat()
    if (
        stat.S_ISLNK(root_info.st_mode)
        or not stat.S_ISDIR(root_info.st_mode)
        or root_info.st_uid != int(expected_owner_uid)
        or stat.S_IMODE(root_info.st_mode) & 0o022
    ):
        raise ValueError("runtime package root is mutable or unsafe")
    entries: list[dict[str, object]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for child in sorted(directory.iterdir(), key=lambda value: value.name):
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != int(expected_owner_uid):
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
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or not stat.S_IMODE(info.st_mode) & 0o111
        ):
            raise ValueError(f"{name} runtime is mutable or unsafe")
        digest = _safe_file_sha256(path)
        if digest != config.get(f"{name}_sha256"):
            raise ValueError(f"{name} runtime digest changed")
        identities[f"{name}_executable"] = str(path)
        identities[f"{name}_sha256"] = digest
    package_root = Path(config["package_root"])
    required_modules = {
        "__init__.py",
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
    )
    if package["sha256"] != config.get("package_manifest_sha256"):
        raise ValueError("runtime package manifest changed")
    identities["package_root"] = str(package_root)
    identities["package_manifest_sha256"] = str(package["sha256"])
    entrypoint_value = config.get("runtime_entrypoint_path")
    if entrypoint_value is not None:
        entrypoint = Path(entrypoint_value)
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


def _validate_host_identity_inventory(value: object) -> dict[str, list[dict[str, object]]]:
    if not isinstance(value, dict) or set(value) != {"contract", "accounts", "groups"}:
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
    return {"accounts": accounts, "groups": groups}


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
    inventory: dict[str, list[dict[str, object]]], desired: dict[str, dict[str, object]]
) -> None:
    accounts = inventory["accounts"]
    groups = inventory["groups"]
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
    groups = [
        [names["broker_user"], int(broker_gid)],
        [names["controller_group"], int(controller_gid)],
        [names["publisher_group"], int(publisher_gid)],
        [names["workspace_group"], int(workspace_gid)],
    ]
    users = [
        [names["broker_user"], int(broker_uid), int(broker_gid)],
        [names["controller_user"], int(controller_uid), int(controller_gid)],
        [names["publisher_user"], int(publisher_uid), int(publisher_gid)],
        [names["model_user"], int(model_uid), int(workspace_gid)],
    ]
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
        if int(account.pw_uid) != int(uid):
            raise ValueError(f"{role} identity readback failed")
    for name, gid in plan.get("groups", []):
        if int(grp.getgrnam(name).gr_gid) != int(gid):
            raise ValueError(f"group {name} readback failed")
    memberships = system_group_memberships({
        int(value[1]) for value in expected.values()
    })
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
    worker_client_config_path: Path | None = None,
    worker_sequence_path: Path | None = None,
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
        *([Path(worker_client_config_path)] if worker_client_config_path is not None else []),
        *([Path(worker_sequence_path)] if worker_sequence_path is not None else []),
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
    if worker_client_config_path is not None or worker_sequence_path is not None:
        if worker_client_config_path is None or worker_sequence_path is None:
            raise ValueError("worker client config and sequence must be paired")
        worker_uid = int(config["model_uid"])
        worker_gid = workspace_gid
        directories.extend([
            {
                "path": str(Path(worker_client_config_path).parent),
                "uid": worker_uid,
                "gid": worker_gid,
                "mode": 0o700,
            },
            {
                "path": str(Path(worker_sequence_path).parent),
                "uid": worker_uid,
                "gid": worker_gid,
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
    if worker_client_config_path is not None and worker_sequence_path is not None:
        files.extend([
            {
                "path": str(Path(worker_client_config_path)),
                "uid": int(config["model_uid"]),
                "gid": workspace_gid,
                "mode": 0o600,
                "kind": "worker_client_config",
            },
            {
                "path": str(Path(worker_sequence_path)),
                "uid": int(config["model_uid"]),
                "gid": workspace_gid,
                "mode": 0o600,
                "kind": "worker_sequence",
            },
        ])
    files.extend(additional_files or [])
    return {
        "contract": "hermes.kanban_broker_filesystem_plan.v1",
        "directories": sorted(deduplicated.values(), key=lambda item: item["path"]),
        "files": sorted(files, key=lambda item: item["path"]),
    }


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
    finally:
        os.close(parent_fd)


def _provision_file_asset(item: dict, payload: bytes | None) -> None:
    path = Path(item["path"])
    parent_fd = _open_directory_fd(path.parent)
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
                os.write(fd, payload)
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
            existing = os.read(fd, 1024 * 1024 + 1)
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
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def provision_filesystem_plan(
    plan: dict,
    *,
    payloads: dict[str, bytes],
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
    paths = [str(item.get("path")) for item in [*directories, *files]]
    if len(paths) != len(set(paths)):
        raise ValueError("broker filesystem plan contains duplicate paths")
    for item in sorted(directories, key=lambda value: len(Path(value["path"]).parts)):
        _provision_directory_asset(item)
    for item in files:
        _provision_file_asset(item, payloads.get(str(item["path"])))


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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("broker service config must be a real file") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != int(expected_owner_uid)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise ValueError("broker service config must be a real file mode 0600")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise ValueError("broker service config exceeds the size limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError("broker service config changed during read")
    finally:
        os.close(fd)
    try:
        config = json.loads(b"".join(chunks))
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
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(Path(path), flags)
    try:
        return hashlib.sha256(os.read(fd, 1024 * 1024 + 1)).hexdigest()
    finally:
        os.close(fd)


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
    parent_before = parent.lstat()
    if (
        stat.S_ISLNK(parent_before.st_mode)
        or not stat.S_ISDIR(parent_before.st_mode)
        or stat.S_IMODE(parent_before.st_mode) & 0o022
    ):
        raise ValueError("broker config parent must not be group/world writable")
    encoded = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    temporary = parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        os.write(fd, encoded)
        os.fchown(fd, int(original.st_uid), int(original.st_gid))
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        parent_after = parent.lstat()
        if (parent_after.st_dev, parent_after.st_ino) != (
            parent_before.st_dev,
            parent_before.st_ino,
        ):
            raise ValueError("broker config parent changed during update")
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
            raise ValueError("broker service config changed during update")
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)
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
    reread = _replace_service_config(path, original=original, payload=activated)
    if (
        reread.get("enabled") is not True
        or reread.get("trusted_publisher_enabled") is not True
    ):
        raise ValueError("broker activation readback failed")
    return reread


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
    return reread


def verify_service_disabled(path: Path, *, expected_owner_uid: int) -> bool:
    config, _info = _read_service_config_file(
        Path(path), expected_owner_uid=expected_owner_uid
    )
    return bool(
        config.get("enabled") is False
        and config.get("trusted_publisher_enabled") is False
    )


def _read_root_json(path: Path, *, contract: str) -> dict:
    path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError(
            "broker installer input must be a real root-owned file"
        ) from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ValueError("broker installer input must be root-owned mode 0600")
        raw = os.read(fd, 4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("broker installer input exceeds size limit")
    finally:
        os.close(fd)
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
    render.add_argument("--runtime-source-root", type=Path, default=Path(__file__).resolve().parent)
    render.add_argument("--source-sha", "--radulator-source-sha", required=True)
    render.add_argument("--dispatcher-profile", required=True)
    render.add_argument("--python", type=Path, default=Path("/usr/bin/python3"))
    render.add_argument("--git", type=Path, default=Path("/usr/bin/git"))
    render.add_argument("--install-nonce")
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
            path = Path(path)
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(path, flags)
            except OSError as exc:
                raise ValueError("broker plan input is unavailable") from exc
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid not in {0, os.geteuid()}
                    or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    raise ValueError("broker plan input must be owner-only mode 0600")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > 4 * 1024 * 1024:
                        raise ValueError("broker plan input exceeds size limit")
                    chunks.append(chunk)
            finally:
                os.close(fd)
            raw = b"".join(chunks)
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("broker plan input is invalid JSON") from exc
            if not isinstance(value, dict) or value.get("contract") != expected:
                raise ValueError("broker plan input contract is unsupported")
            return value
        plan = render_broker_installation_plan(
            host_inventory=read_input(args.inventory, HOST_IDENTITY_INVENTORY_CONTRACT),
            desired_identities=read_input(args.desired_identities, DESIRED_IDENTITIES_CONTRACT),
            install_root=args.install_root,
            runtime_source_root=args.runtime_source_root,
            radulator_source_sha=args.source_sha,
            dispatcher_profile=args.dispatcher_profile,
            python_executable=args.python,
            git_executable=args.git,
            install_nonce=args.install_nonce,
        )
        write_broker_installation_plan(
            plan,
            output_root=args.output_root if args.output_root is not None else args.install_root,
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
        if not isinstance(raw_payloads, dict):
            raise ValueError("broker asset payload manifest is malformed")
        payloads: dict[str, bytes] = {}
        for path, value in raw_payloads.items():
            if not isinstance(path, str) or not isinstance(value, str):
                raise ValueError("broker asset payload entry is malformed")
            try:
                payloads[path] = base64.b64decode(value, validate=True)
            except ValueError as exc:
                raise ValueError("broker asset payload is not valid base64") from exc
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
) -> str:
    """Return a launchd plist with no credentials and no activation flag."""
    profile_path = (
        Path(sandbox_profile) if sandbox_profile else Path(state_dir) / "broker.sb"
    )
    if package_root is None or not Path(package_root).is_absolute():
        raise ValueError("broker launchd package root must be absolute")
    if runtime_entrypoint_path is not None and not Path(runtime_entrypoint_path).is_absolute():
        raise ValueError("broker runtime entrypoint must be absolute")
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
    if not re.fullmatch(r"[0-9a-f]{64}", str(python_sha256)) or not re.fullmatch(
        r"[0-9a-f]{64}", str(package_manifest_sha256)
    ):
        raise ValueError("worker launchd runtime digests are invalid")
    payload = {
        "Label": "ai.hermes.kanban-worker",
        "ProgramArguments": [
            str(Path(python_executable)),
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
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")


def render_runtime_entrypoint_asset(*, entrypoint_path: Path, package_root: Path) -> dict[str, object]:
    """Describe the tiny -I bootstrap that imports only the installed package."""
    entrypoint = Path(entrypoint_path)
    package = Path(package_root)
    if not entrypoint.is_absolute() or not package.is_absolute():
        raise ValueError("runtime entrypoint and package paths must be absolute")
    if entrypoint.parent.parent != package.parent:
        raise ValueError("runtime entrypoint must be next to the installed package")
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
    module: str = "hermes_cli.kanban_broker_client",
    runner=subprocess.run,
) -> None:
    """Prove an installed runtime imports without PYTHONPATH or a checkout."""
    if not module or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", module) is None:
        raise ValueError("runtime import module is invalid")
    result = runner(
        [str(Path(python_executable)), "-I", str(Path(entrypoint_path)), "--verify-import", module],
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
    runtime_source_root: Path,
    radulator_source_sha: str | None,
    dispatcher_profile: str,
    python_executable: Path = Path("/usr/bin/python3"),
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
    runtime_source = Path(runtime_source_root)
    if not runtime_source.is_absolute():
        raise ValueError("runtime source root must be absolute")
    _validated_install_path(runtime_source, field="runtime source root", allow_root=True)
    if runtime_source.is_symlink():
        raise ValueError("runtime source root must not be a symlink")
    runtime_source = runtime_source.resolve(strict=True)
    if not runtime_source.is_dir() or runtime_source.is_symlink():
        raise ValueError("runtime source root must be a real directory")
    python = Path(python_executable)
    git = Path(git_executable)
    for executable, field in ((python, "Python executable"), (git, "Git executable")):
        if not executable.is_absolute() or ".." in executable.parts:
            raise ValueError(f"{field} path is invalid")
        _safe_file_sha256(executable)

    state_dir = root / "state"
    workspace_root = root / "workspaces"
    worker_home = root / "worker-home"
    handoff_root = root / "publisher-handoffs"
    socket_root = root / "sockets"
    key_root = root / "keys"
    client_root = root / "clients"
    sequence_root = root / "sequences"
    package_root = root / "runtime" / "hermes_cli"
    entrypoint_path = root / "runtime" / "bin" / "hermes-python"
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
    worker_client_path = client_root / "worker" / "client.json"
    worker_sequence_path = sequence_root / "worker" / "client.sequence"
    worker_socket = socket_root / "worker" / "worker.sock"

    if install_nonce is None:
        install_nonce = hashlib.sha256(
            _canonical_json_bytes({
                "inventory": inventory,
                "desired": desired,
                "install_root": str(root),
                "source_sha": source_sha,
                "dispatcher_profile": dispatcher_profile,
            })
        ).hexdigest()
    if not isinstance(install_nonce, str) or re.fullmatch(r"[0-9a-f]{64}", install_nonce) is None:
        raise ValueError("install nonce must be 64 lowercase hexadecimal characters")

    runtime_assets = render_runtime_package_assets(
        source_root=runtime_source,
        destination_root=package_root,
    )
    runtime_entrypoint = render_runtime_entrypoint_asset(
        entrypoint_path=entrypoint_path,
        package_root=package_root,
    )
    runtime_payloads = cast(dict[str, bytes], runtime_assets["payloads"])
    runtime_files = cast(list[dict[str, object]], runtime_assets["files"])
    runtime_files.append({key: value for key, value in runtime_entrypoint.items() if key != "content"})
    runtime_payloads[str(entrypoint_path)] = cast(bytes, runtime_entrypoint["content"])
    runtime_assets["files"] = runtime_files

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
        "host_inventory_sha256": hashlib.sha256(_canonical_json_bytes(host_inventory)).hexdigest(),
        "desired_identities_sha256": hashlib.sha256(_canonical_json_bytes(desired_identities)).hexdigest(),
    })
    config = json.loads(render_broker_service_config(
        install_root=root,
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
        git_executable=git,
        package_root=package_root,
        package_manifest_sha256=str(runtime_assets["package_manifest_sha256"]),
        canary_key_path=canary_key_path,
        seatbelt_profile_path=seatbelt_path,
        launchd_plist_path=launchd_path,
        worker_launchd_plist_path=worker_launchd_path,
        runtime_entrypoint_path=entrypoint_path,
        runtime_entrypoint_sha256=str(runtime_entrypoint["sha256"]),
        remote_policy_path=remote_policy_path,
        remote_policy_source_sha=source_sha,
        dispatcher_profile=dispatcher_profile,
        worker_client_config_path=worker_client_path,
        worker_sequence_path=worker_sequence_path,
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
    clients[str(worker_client_path)] = _json_artifact_bytes({
        "contract": "hermes.kanban_worker_client_config.v1",
        "surface": "worker",
        "socket_path": str(worker_socket),
        "sequence_path": str(worker_sequence_path),
        "expected_broker_uid": int(ids["broker"]["uid"]),
    })
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
    ).encode("utf-8")
    # Keys are generated once during rendering and carried only by the
    # root-owned payload manifest.  They are never printed by the CLI.
    payload_bytes: dict[str, bytes] = dict(runtime_payloads)
    payload_bytes.update(clients)
    payload_bytes.update({
        str(service_config_path): _json_artifact_bytes(config),
        str(seatbelt_path): seatbelt,
        str(launchd_path): broker_plist,
        str(worker_launchd_path): worker_plist,
        str(remote_policy_path): _json_artifact_bytes(remote_policy),
    })
    for surface in ("controller", "publisher", "operator"):
        payload_bytes[str(surface_keys[surface])] = secrets.token_bytes(32)
        payload_bytes[str(sequence_paths[surface])] = b""
    payload_bytes[str(worker_sequence_path)] = b""
    payload_bytes[str(canary_key_path)] = secrets.token_bytes(32)
    additional_files = [
        {
            "path": str(remote_policy_path),
            "uid": 0,
            "gid": 0,
            "mode": 0o600,
            "kind": "remote_policy",
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
        worker_client_config_path=worker_client_path,
        worker_sequence_path=worker_sequence_path,
        additional_files=additional_files,
        additional_directories=[
            {"path": str(entrypoint_path.parent), "uid": 0, "gid": 0, "mode": 0o555},
        ],
    )
    # Bind every non-directory payload to the exact filesystem plan digest.
    for item in filesystem_plan["files"]:
        path = str(item["path"])
        content = payload_bytes.get(path)
        if content is None:
            raise ValueError(f"filesystem plan payload is missing for {path}")
        item["sha256"] = hashlib.sha256(content).hexdigest()
        item["size"] = len(content)
        item["secret"] = str(item.get("kind", "")).endswith("_key") or item.get("kind") == "canary_key"
    payload_manifest = {
        "contract": ASSET_PAYLOAD_CONTRACT,
        "schema_version": 1,
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
            if any(str(item["path"]) == path for item in filesystem_plan["files"])
        },
    }
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
        "runtime": {
            "python_executable": str(python),
            "python_sha256": config["python_sha256"],
            "git_executable": str(git),
            "git_sha256": config["git_sha256"],
            "package_root": str(package_root),
            "package_manifest_sha256": runtime_assets["package_manifest_sha256"],
            "entrypoint_path": str(entrypoint_path),
            "entrypoint_mode": 0o555,
            "package_root_mode": 0o555,
            "package_file_mode": 0o444,
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
    _assert_safe_output_parent(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing_info = path.lstat()
    except FileNotFoundError:
        existing_info = None
    if existing_info is not None:
        if (
            stat.S_ISLNK(existing_info.st_mode)
            or not stat.S_ISREG(existing_info.st_mode)
            or existing_info.st_nlink != 1
            or stat.S_IMODE(existing_info.st_mode) != int(mode)
        ):
            raise ValueError("broker plan output target is unsafe")
        if os.geteuid() == 0 and (
            existing_info.st_uid != int(uid) or existing_info.st_gid != int(gid)
        ):
            raise ValueError("broker plan output target owner is unsafe")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags)
        try:
            existing = os.read(fd, len(content) + 1)
        finally:
            os.close(fd)
        if existing != content:
            raise ValueError("existing broker plan artifact differs from plan")
        return
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, int(mode))
        if os.geteuid() == 0:
            os.fchown(fd, int(uid), int(gid))
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        os.replace(temporary_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != int(mode) or info.st_nlink != 1:
        raise ValueError("broker plan artifact ownership or mode is unsafe")
    if os.geteuid() == 0 and (info.st_uid != int(uid) or info.st_gid != int(gid)):
        raise ValueError("broker plan artifact owner is unsafe")


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
        return {key: _rebase_path_string(item, source_root=source_root, output_root=output_root) for key, item in value.items()}
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
    """Atomically write one rendered plan and its root-owned apply inputs."""
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
    if (
        not isinstance(raw_directories, list)
        or not isinstance(raw_files, list)
        or not isinstance(raw_manifest_files, list)
        or not isinstance(raw_payloads, dict)
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
    if manifest_paths != file_paths or set(raw_payloads) != file_paths:
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
        content = payloads[raw_path]
        if len(content) != int(item["size"]) or hashlib.sha256(content).hexdigest() != str(item["sha256"]):
            raise ValueError("broker asset payload metadata does not match filesystem plan")
    def target(raw_path: str) -> Path:
        original = _validated_install_path(
            raw_path,
            field="plan artifact",
            install_root=source_root,
            allow_root=True,
        )
        return destination_root / original.relative_to(source_root)
    # Build the complete directory tree before applying immutable modes.  A
    # package directory is intentionally 0555 in the final tree, but applying
    # that mode before creating its children would make a fresh staging tree
    # unwritable even for a later child creation step.
    directory_items = sorted(directories, key=lambda row: len(Path(str(row["path"])).parts))
    for item in directory_items:
        if not isinstance(item, dict):
            raise ValueError("filesystem directory entry is malformed")
        directory = target(str(item["path"]))
        try:
            info = directory.lstat()
        except FileNotFoundError:
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            info = directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ValueError("broker plan directory is not a safe directory")
        # Keep the staging tree writable until every file has been atomically
        # replaced.  This is only an intermediate staging mode; the reviewed
        # immutable modes are applied in the final pass below.
        os.chmod(directory, 0o700)
    for item in files:
        raw_path = str(item["path"])
        content = payloads.get(raw_path)
        if content is None:
            raise ValueError(f"broker asset payload is missing for {raw_path}")
        expected = str(item.get("sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or hashlib.sha256(content).hexdigest() != expected:
            raise ValueError("broker asset payload digest does not match plan")
        _atomic_artifact_write(target(raw_path), content, mode=int(item["mode"]), uid=int(item["uid"]), gid=int(item["gid"]))
    plan_files = (
        ("identity_plan_path", "identity_plan"),
        ("filesystem_plan_path", "filesystem_plan"),
        ("payload_manifest_path", "asset_payload_manifest"),
    )
    for path_key, value_key in plan_files:
        raw_path = str(plan[path_key])
        value = _rebase_path_string(plan[value_key], source_root=source_root, output_root=destination_root)
        content = _json_artifact_bytes(value)
        _atomic_artifact_write(target(raw_path), content, mode=0o600, uid=0, gid=0)
    for item in directory_items:
        directory = target(str(item["path"]))
        os.chmod(directory, int(item["mode"]))
        if os.geteuid() == 0:
            os.chown(directory, int(item["uid"]), int(item["gid"]))
    runtime = plan.get("runtime")
    if isinstance(runtime, dict) and runtime.get("entrypoint_path"):
        entrypoint = target(str(runtime["entrypoint_path"]))
        verify_isolated_runtime_import(
            python_executable=Path(str(runtime["python_executable"])),
            entrypoint_path=entrypoint,
        )
    return {"contract": BROKER_INSTALL_PLAN_CONTRACT, "output_root": str(destination_root)}


if __name__ == "__main__":
    raise SystemExit(main())

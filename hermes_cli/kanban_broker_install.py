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
    for runtime_path in (
        python_executable,
        git_executable,
        install_root,
        package_root,
        canary_key_path,
        seatbelt_profile_path,
        launchd_plist_path,
        worker_launchd_plist_path,
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

    source = Path(source_root).resolve(strict=True)
    destination = Path(destination_root)
    if not destination.is_absolute():
        raise ValueError("runtime package destination must be absolute")
    directories = [{"path": str(destination), "uid": 0, "gid": 0, "mode": 0o555}]
    files: list[dict[str, object]] = []
    payloads: dict[str, bytes] = {}
    manifest_entries: list[dict[str, object]] = []
    for item in sorted(source.rglob("*"), key=lambda value: value.as_posix()):
        relative = item.relative_to(source)
        if "__pycache__" in relative.parts or item.suffix in {".pyc", ".pyo"}:
            continue
        info = item.lstat()
        target = destination.joinpath(*relative.parts)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("runtime source package contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            directories.append({"path": str(target), "uid": 0, "gid": 0, "mode": 0o555})
            manifest_entries.append({"path": relative.as_posix() + "/", "mode": 0o555})
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("runtime source package contains a special file")
        content = item.read_bytes()
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
    return identities


def _validated_account_name(value: str) -> str:
    if not isinstance(value, str) or not _ACCOUNT_NAME_RE.fullmatch(value):
        raise ValueError("broker account or group name is invalid")
    return value


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

    if surface not in {"controller", "publisher", "operator"}:
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
) -> str:
    """Return a launchd plist with no credentials and no activation flag."""
    profile_path = (
        Path(sandbox_profile) if sandbox_profile else Path(state_dir) / "broker.sb"
    )
    if package_root is None or not Path(package_root).is_absolute():
        raise ValueError("broker launchd package root must be absolute")
    payload = {
        "Label": "ai.hermes.kanban-broker",
        "ProgramArguments": [
            "/usr/bin/sandbox-exec",
            "-f",
            str(profile_path),
            str(Path(python_executable)),
            "-m",
            "hermes_cli.kanban_broker_service",
            "serve",
            "--config",
            str(Path(config_path)),
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
            "PYTHONPATH": str(Path(package_root).parent),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
    }
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
    if not re.fullmatch(r"[0-9a-f]{64}", str(python_sha256)) or not re.fullmatch(
        r"[0-9a-f]{64}", str(package_manifest_sha256)
    ):
        raise ValueError("worker launchd runtime digests are invalid")
    payload = {
        "Label": "ai.hermes.kanban-worker",
        "ProgramArguments": [
            str(Path(python_executable)),
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
            "PYTHONPATH": str(Path(package_root).parent),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": os.devnull,
            "GIT_SSH_COMMAND": "/usr/bin/false",
        },
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=True).decode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())

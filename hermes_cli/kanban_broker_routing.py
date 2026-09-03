"""Default-off production routes into the dedicated Kanban broker.

These helpers never fall back to the legacy same-UID authority after the exact
capability is enabled.  Each caller must run under its separately provisioned
controller, publisher, or operator identity and possess that surface's client
config/key by Unix ownership.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from hermes_cli.kanban_broker_client import BrokerRPCClient, load_broker_client

ROUTING_OVERLAY_ENV = "HERMES_KANBAN_ROUTING_CONFIG"
ROUTING_OVERLAY_KEYS = frozenset({
    "dedicated_broker_enabled",
    "trusted_publisher_enabled",
    "dedicated_broker_controller_client_config",
    "dedicated_broker_publisher_client_config",
    "dedicated_broker_operator_client_config",
    "dedicated_broker_registration_file",
    "dedicated_broker_expected_source_sha",
    "dedicated_broker_dispatcher_profile",
})
_ROUTING_OVERLAY_FLAGS = frozenset({"dedicated_broker_enabled", "trusted_publisher_enabled"})
_MAX_ROUTING_OVERLAY_BYTES = 64 * 1024


class DedicatedBrokerRouteError(RuntimeError):
    """The explicit dedicated broker route was absent or invalid."""


def load_trusted_routing_overlay(
    path: Path, *, expected_owner_uid: int = 0
) -> dict[str, Any]:
    """Load the dispatcher-provisioned routing overlay and nothing else.

    The model identity owns its Hermes profile home, so a routing document
    stored there is never authority: the model could rewrite it.  A worker
    that names an overlay only accepts a regular, non-symlink, owner-pinned,
    non-writable ``kanban:`` document beneath an owner-pinned immutable
    directory.  Any other state fails closed instead of falling back to the
    profile's own configuration.
    """
    target = Path(path)
    if not target.is_absolute() or ".." in target.parts:
        raise DedicatedBrokerRouteError("routing overlay path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_info = target.parent.lstat()
        fd = os.open(target, flags)
    except OSError as exc:
        raise DedicatedBrokerRouteError("routing overlay is unavailable") from exc
    try:
        info = os.fstat(fd)
        if (
            stat.S_ISLNK(parent_info.st_mode)
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != int(expected_owner_uid)
            or stat.S_IMODE(parent_info.st_mode) & 0o022
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != int(expected_owner_uid)
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise DedicatedBrokerRouteError("routing overlay ownership or mode is unsafe")
        raw = os.read(fd, _MAX_ROUTING_OVERLAY_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_ROUTING_OVERLAY_BYTES:
        raise DedicatedBrokerRouteError("routing overlay exceeds the size limit")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise DedicatedBrokerRouteError("routing overlay is not UTF-8") from exc
    if not lines or lines[0] != "kanban:":
        raise DedicatedBrokerRouteError("routing overlay contract is invalid")
    values: dict[str, str] = {}
    for line in lines[1:]:
        if not line.startswith("  ") or ": " not in line:
            raise DedicatedBrokerRouteError("routing overlay line is invalid")
        key, value = line[2:].split(": ", 1)
        if key in values or key not in ROUTING_OVERLAY_KEYS:
            raise DedicatedBrokerRouteError("routing overlay key is invalid")
        values[key] = value
    if set(values) != ROUTING_OVERLAY_KEYS:
        raise DedicatedBrokerRouteError("routing overlay keys are incomplete")
    result: dict[str, Any] = {}
    for key, value in values.items():
        if key in _ROUTING_OVERLAY_FLAGS:
            if value not in {"true", "false"}:
                raise DedicatedBrokerRouteError("routing overlay flag is invalid")
            result[key] = value == "true"
        else:
            result[key] = value
    return result


def _kanban_config() -> dict[str, Any]:
    overlay = os.environ.get(ROUTING_OVERLAY_ENV)
    if overlay:
        # A dispatched worker routes only through the root-owned overlay the
        # dispatcher provisioned; its model-owned profile is never consulted.
        return load_trusted_routing_overlay(Path(overlay))
    from hermes_cli.config import load_config_readonly

    config = load_config_readonly() or {}
    kanban = config.get("kanban") if isinstance(config, dict) else None
    return kanban if isinstance(kanban, dict) else {}


def dedicated_broker_enabled() -> bool:
    return _kanban_config().get("dedicated_broker_enabled") is True


def _client_for(surface: str) -> BrokerRPCClient:
    config = _kanban_config()
    if config.get("dedicated_broker_enabled") is not True:
        raise DedicatedBrokerRouteError("dedicated Kanban broker is not enabled")
    if config.get("trusted_publisher_enabled") is not True:
        raise DedicatedBrokerRouteError(
            "dedicated broker trusted publisher opt-in is not enabled"
        )
    key = f"dedicated_broker_{surface}_client_config"
    raw_path = config.get(key)
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise DedicatedBrokerRouteError(
            f"dedicated broker {surface} client config is unavailable"
        )
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        raise DedicatedBrokerRouteError(
            f"dedicated broker {surface} client config must be absolute"
        )
    return load_broker_client(path, expected_surface=surface)


def trusted_create(request: dict[str, Any]) -> dict[str, Any]:
    return _client_for("controller").call("trusted_create", request)


def request_publish_correction(request: dict[str, Any]) -> dict[str, Any]:
    return _client_for("controller").call("request_publish_correction", request)


def dispatch_task(*, task_id: str, operation_id: str) -> dict[str, Any]:
    return _client_for("controller").call(
        "dispatch_task",
        {"task_id": str(task_id), "operation_id": str(operation_id)},
    )


def dispatch_status(*, operation_id: str) -> dict[str, Any]:
    return _client_for("controller").call(
        "dispatch_status",
        {"operation_id": str(operation_id)},
    )


def verify_receipt(*, receipt_id: str, payload_sha256: str) -> dict[str, Any]:
    return _client_for("publisher").call(
        "verify_receipt",
        {"receipt_id": str(receipt_id), "payload_sha256": str(payload_sha256)},
    )


def list_publish_obligations(query: dict[str, Any]) -> dict[str, Any]:
    return _client_for("publisher").call("list_publish_obligations", query)


def export_bundle(*, receipt_id: str, payload_sha256: str) -> dict[str, Any]:
    return _client_for("publisher").call(
        "export_bundle",
        {"receipt_id": str(receipt_id), "payload_sha256": str(payload_sha256)},
    )


def acknowledge_publish(acknowledgement: dict[str, Any]) -> dict[str, Any]:
    return _client_for("publisher").call("ack_publish", acknowledgement)


def verify_completion(*, completion_id: str, payload_sha256: str) -> dict[str, Any]:
    return _client_for("publisher").call(
        "verify_completion",
        {
            "completion_id": str(completion_id),
            "payload_sha256": str(payload_sha256),
        },
    )


def list_completion_obligations(query: dict[str, Any]) -> dict[str, Any]:
    return _client_for("publisher").call("list_completion_obligations", query)


def refresh_repository_base(
    *, repository_id: str, expected_old_base_sha: str
) -> dict[str, Any]:
    return _client_for("operator").call(
        "refresh_repository_base",
        {
            "repository_id": str(repository_id),
            "expected_old_base_sha": str(expected_old_base_sha),
        },
    )


def register_repository(request: dict[str, Any]) -> dict[str, Any]:
    return _client_for("operator").call("register_repository", request)

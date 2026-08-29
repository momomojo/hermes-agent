"""Default-off production routes into the dedicated Kanban broker.

These helpers never fall back to the legacy same-UID authority after the exact
capability is enabled.  Each caller must run under its separately provisioned
controller, publisher, or operator identity and possess that surface's client
config/key by Unix ownership.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hermes_cli.kanban_broker_client import BrokerRPCClient, load_broker_client


class DedicatedBrokerRouteError(RuntimeError):
    """The explicit dedicated broker route was absent or invalid."""


def _kanban_config() -> dict[str, Any]:
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

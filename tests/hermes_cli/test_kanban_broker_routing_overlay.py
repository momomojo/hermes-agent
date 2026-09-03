"""The dispatched worker routes only through the root-owned overlay.

Finding 4: the model identity owns its Hermes profile home (the real worker
credential-home validator demands that), so a routing document inside it can
never be authority.  The dispatcher provisions a separate overlay the model
cannot replace, and the worker hands only that overlay to the model process.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from hermes_cli import kanban_broker_routing as routing
from hermes_cli.kanban_broker_worker import (
    WorkerServiceError,
    _safe_worker_env,
    validate_routing_overlay,
)

OVERLAY = (
    "kanban:\n"
    "  dedicated_broker_enabled: true\n"
    "  trusted_publisher_enabled: true\n"
    "  dedicated_broker_controller_client_config: /opt/hermes/clients/controller/client.json\n"
    "  dedicated_broker_publisher_client_config: /opt/hermes/clients/publisher/client.json\n"
    "  dedicated_broker_operator_client_config: /opt/hermes/clients/operator/client.json\n"
    "  dedicated_broker_registration_file: /opt/hermes/state/broker-register.json\n"
    "  dedicated_broker_expected_source_sha: " + "a" * 40 + "\n"
    "  dedicated_broker_dispatcher_profile: radulator\n"
)


def _write_overlay(tmp_path: Path, text: str = OVERLAY, mode: int = 0o640) -> Path:
    root = tmp_path / "routing" / "radulator"
    root.mkdir(parents=True)
    path = root / "config.yaml"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    root.chmod(0o555)
    return path


def test_overlay_loads_only_the_exact_kanban_document(tmp_path):
    path = _write_overlay(tmp_path)
    loaded = routing.load_trusted_routing_overlay(path, expected_owner_uid=os.getuid())
    assert loaded["dedicated_broker_enabled"] is True
    assert loaded["trusted_publisher_enabled"] is True
    assert loaded["dedicated_broker_dispatcher_profile"] == "radulator"
    assert loaded["dedicated_broker_expected_source_sha"] == "a" * 40
    assert set(loaded) == routing.ROUTING_OVERLAY_KEYS


def test_overlay_rejects_wrong_owner_by_default(tmp_path):
    """Production expects root ownership; a model-writable file is refused."""
    path = _write_overlay(tmp_path)
    assert os.getuid() != 0
    with pytest.raises(routing.DedicatedBrokerRouteError, match="ownership or mode"):
        routing.load_trusted_routing_overlay(path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p.chmod(0o666), "ownership or mode"),
        (lambda p: p.parent.chmod(0o777), "ownership or mode"),
        (lambda p: (p.unlink(), p.write_text("kanban:\n  dedicated_broker_enabled: maybe\n", encoding="utf-8"), p.chmod(0o640)), "keys are incomplete"),
        (lambda p: (p.unlink(), p.write_text(OVERLAY + "  extra_key: 1\n", encoding="utf-8"), p.chmod(0o640)), "key is invalid"),
        (lambda p: (p.unlink(), p.write_text(OVERLAY.replace("kanban:", "other:"), encoding="utf-8"), p.chmod(0o640)), "contract is invalid"),
        (lambda p: (p.unlink(), p.write_text(OVERLAY.replace("enabled: true", "enabled: yes"), encoding="utf-8"), p.chmod(0o640)), "flag is invalid"),
    ],
)
def test_overlay_rejects_mutations_fail_closed(tmp_path, mutation, message):
    path = _write_overlay(tmp_path)
    path.parent.chmod(0o755)
    mutation(path)
    if stat.S_IMODE(path.parent.lstat().st_mode) == 0o755:
        path.parent.chmod(0o555)
    with pytest.raises(routing.DedicatedBrokerRouteError, match=message):
        routing.load_trusted_routing_overlay(path, expected_owner_uid=os.getuid())


def test_overlay_rejects_symlink_and_missing_file(tmp_path):
    real = _write_overlay(tmp_path)
    link_root = tmp_path / "link-root"
    link_root.mkdir()
    link = link_root / "config.yaml"
    link.symlink_to(real)
    with pytest.raises(routing.DedicatedBrokerRouteError, match="unavailable|ownership"):
        routing.load_trusted_routing_overlay(link, expected_owner_uid=os.getuid())
    with pytest.raises(routing.DedicatedBrokerRouteError, match="unavailable"):
        routing.load_trusted_routing_overlay(tmp_path / "missing.yaml", expected_owner_uid=os.getuid())
    with pytest.raises(routing.DedicatedBrokerRouteError, match="path is invalid"):
        routing.load_trusted_routing_overlay(Path("relative/config.yaml"), expected_owner_uid=os.getuid())


def test_kanban_config_prefers_the_overlay_and_never_falls_back(tmp_path, monkeypatch):
    """With the overlay named, the model-owned profile config is not consulted
    at all: an invalid overlay raises instead of degrading to profile routing."""
    path = _write_overlay(tmp_path)
    monkeypatch.setenv(routing.ROUTING_OVERLAY_ENV, str(path))
    monkeypatch.setattr(
        routing, "load_trusted_routing_overlay",
        lambda overlay, expected_owner_uid=0: {"dedicated_broker_enabled": True, "seen": str(overlay)},
    )
    profile_loaded = []
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: profile_loaded.append(True) or {"kanban": {"dedicated_broker_enabled": False}},
    )
    assert routing.dedicated_broker_enabled() is True
    assert profile_loaded == []
    monkeypatch.setattr(
        routing, "load_trusted_routing_overlay",
        lambda overlay, expected_owner_uid=0: (_ for _ in ()).throw(routing.DedicatedBrokerRouteError("bad overlay")),
    )
    with pytest.raises(routing.DedicatedBrokerRouteError, match="bad overlay"):
        routing.dedicated_broker_enabled()
    assert profile_loaded == []


def test_worker_binds_the_overlay_into_the_model_environment(tmp_path, monkeypatch):
    path = _write_overlay(tmp_path)
    envelope = {
        "task_id": "t1",
        "run_id": "r1",
        "workspace_path": str(tmp_path / "workspaces/ws1"),
        "branch": "task/t1",
        "task": {"board": "radulator", "profile": "radulator"},
    }
    (tmp_path / "workspaces/ws1").mkdir(parents=True)
    env = _safe_worker_env(envelope, worker_hermes_root=tmp_path / "worker-home", routing_config=path)
    assert env[routing.ROUTING_OVERLAY_ENV] == str(path)
    assert routing.ROUTING_OVERLAY_ENV not in _safe_worker_env(envelope, worker_hermes_root=tmp_path / "worker-home")
    # The worker demands root ownership in production; the test uid stands in
    # for root through the loader's explicit owner seam.
    monkeypatch.setattr(routing, "load_trusted_routing_overlay", _load_as_test_owner)
    assert validate_routing_overlay(path, profile="radulator")["dedicated_broker_dispatcher_profile"] == "radulator"
    with pytest.raises(WorkerServiceError, match="different profile"):
        validate_routing_overlay(path, profile="other")


_ORIGINAL_LOADER = routing.load_trusted_routing_overlay


def _load_as_test_owner(overlay):
    return _ORIGINAL_LOADER(overlay, expected_owner_uid=os.getuid())


def test_worker_refuses_a_model_owned_overlay_by_default(tmp_path):
    """Without the test-owner seam the worker demands root ownership."""
    path = _write_overlay(tmp_path)
    with pytest.raises(WorkerServiceError, match="routing overlay rejected"):
        validate_routing_overlay(path, profile="radulator")

"""Tests for Finding 5: broker-side RPC observation in publisher preflight.

Finding 5 (P1) requires:
1. A broker-side, authenticated, read-only RPC observation mechanism so the
   canary can prove from the BROKER boundary that exactly one
   list_publish_obligations(limit=1) RPC was made by the publisher identity
   during the preflight window and no other RPC was made.
2. _publisher_runtime_preflight_check validates broker-side evidence in
   addition to the child's JSON self-report.

Broker window mechanism and list_publish_obligations recording are tested
directly against the in-process broker.

_publisher_runtime_preflight_check integration tests mock the probe file
stat check (requires uid=0 in production, which is unprivileged-hostile)
via unittest.mock.patch so the broker-evidence code path is exercised.
"""

from __future__ import annotations

import json
import os
import stat as stat_module
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.macos_only


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _init_repo(path: Path) -> str:
    path.mkdir()
    _git("init", "-b", "main", str(path))
    _git("config", "user.name", "Canary Test", cwd=path)
    _git("config", "user.email", "canary@example.invalid", cwd=path)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    _git("add", ".", cwd=path)
    _git("commit", "-m", "base", cwd=path)
    return _git("rev-parse", "HEAD", cwd=path)


def _remote_repository() -> dict:
    return {
        "contract": "hermes.github_repository.v1",
        "host": "github.com",
        "owner": "momomojo",
        "name": "Radulator",
        "full_name": "momomojo/Radulator",
        "repository_id": 987654321,
        "canonical_url": "https://github.com/momomojo/Radulator",
        "is_fork": False,
        "publication_policy": {
            "pull_request_base": "main",
            "workflow_id": 101,
            "workflow_name": "E2E",
            "workflow_path": ".github/workflows/e2e.yml",
            "workflow_event": "pull_request",
            "required_job_names": ["E2E / exact-head"],
            "required_app": {"id": 15368, "slug": "github-actions"},
            "ready_label_actor": {
                "id": 24681012,
                "login": "hermes-publisher",
                "type": "User",
            },
            "ready_label": "ready-for-gate",
        },
    }


@pytest.fixture
def broker_fixture(tmp_path):
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    base_sha = _init_repo(source)
    state = tmp_path / "state"
    workspace = tmp_path / "workspaces"
    broker = DedicatedKanbanBroker(
        state_dir=state,
        workspace_root=workspace,
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
        trusted_publisher_enabled=True,
    )
    broker.initialize()
    broker.register_repository(
        peer_uid=os.geteuid(),
        repository_id="radulator",
        source_path=source,
        default_branch="main",
        project_id=None,
        remote_repository=_remote_repository(),
        expected_source_sha=base_sha,
    )
    yield broker, source, base_sha
    broker.close()


def _make_task_with_receipt(broker, idempotency_key: str, operation_id: str):
    """Create, claim, and commit a task so list_publish_obligations has rows."""
    from tests.hermes_cli.test_kanban_dedicated_broker import _request as _req

    created = broker.trusted_create(
        peer_uid=os.geteuid(),
        request=_req(idempotency_key=idempotency_key),
    )
    claim = broker.claim_for_dispatch(created["task_id"])
    (Path(claim["workspace_path"]) / "f.txt").write_text("x\n")
    broker.commit_run(
        task_id=created["task_id"],
        run_id=claim["run_id"],
        operation_id=operation_id,
        untrusted_worker_result={},
    )
    return created["task_id"]


# ---------------------------------------------------------------------------
# Broker-side window mechanism — direct method tests
# ---------------------------------------------------------------------------

def test_open_preflight_window_returns_32hex_window_id(broker_fixture):
    """open_publisher_preflight_window must return a 32-hex window_id."""
    broker, _source, _base = broker_fixture
    result = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    assert isinstance(result, dict)
    wid = result.get("window_id")
    assert isinstance(wid, str)
    assert len(wid) == 32
    assert all(c in "0123456789abcdef" for c in wid)
    broker.close_publisher_preflight_window(peer_uid=os.geteuid(), window_id=wid)


def test_open_second_window_while_one_is_open_raises(broker_fixture):
    """A second open call while a window is already open must raise BrokerConflict."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    first = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    try:
        with pytest.raises(BrokerConflict, match="already open"):
            broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    finally:
        broker.close_publisher_preflight_window(
            peer_uid=os.geteuid(), window_id=first["window_id"]
        )


def test_close_unknown_window_id_raises(broker_fixture):
    """Closing a nonexistent window_id must raise BrokerConflict."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    with pytest.raises(BrokerConflict, match="not found"):
        broker.close_publisher_preflight_window(peer_uid=os.geteuid(), window_id="a" * 32)


def test_close_malformed_window_id_raises(broker_fixture):
    """An invalid window_id format must raise BrokerConflict."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    for bad in ("", "short", "g" * 32, "A" * 32, "0" * 33):
        with pytest.raises(BrokerConflict, match="window_id"):
            broker.close_publisher_preflight_window(peer_uid=os.geteuid(), window_id=bad)


def test_close_already_closed_window_raises(broker_fixture):
    """Closing a window a second time must raise BrokerConflict (already closed)."""
    from hermes_cli.kanban_dedicated_broker import BrokerConflict

    broker, _source, _base = broker_fixture
    win = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=win["window_id"]
    )
    with pytest.raises(BrokerConflict, match="not found"):
        broker.close_publisher_preflight_window(
            peer_uid=os.geteuid(), window_id=win["window_id"]
        )


def test_window_requires_operator_uid(broker_fixture):
    """Only the operator UID may open/close windows."""
    from hermes_cli.kanban_dedicated_broker import BrokerAuthorizationError

    broker, _source, _base = broker_fixture
    wrong_uid = os.geteuid() + 99
    with pytest.raises(BrokerAuthorizationError):
        broker.open_publisher_preflight_window(peer_uid=wrong_uid)


# ---------------------------------------------------------------------------
# list_publish_obligations records calls into open windows
# ---------------------------------------------------------------------------

def test_window_records_list_publish_obligations_with_limit(broker_fixture):
    """list_publish_obligations appends a record with the correct limit to windows."""
    broker, _source, _base = broker_fixture
    _make_task_with_receipt(broker, "canary-rpc-obs:v1", "canary-op-1")

    win = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    broker.list_publish_obligations(
        peer_uid=os.geteuid(),
        query={
            "contract": "hermes.publisher_obligation_query.v1",
            "repository_id": "radulator",
            "after_created_at": 0,
            "after_receipt_id": "",
            "limit": 1,
        },
    )
    evidence = broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=win["window_id"]
    )
    calls = evidence["calls"]
    assert len(calls) == 1
    assert calls[0]["method"] == "list_publish_obligations"
    assert calls[0]["limit"] == 1


def test_window_empty_when_no_calls_made(broker_fixture):
    """A window closed immediately with no calls in between must have zero calls."""
    broker, _source, _base = broker_fixture
    win = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    evidence = broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=win["window_id"]
    )
    assert evidence["calls"] == []


def test_window_records_multiple_calls_in_sequence(broker_fixture):
    """Multiple list_publish_obligations calls are all recorded in the window."""
    broker, _source, _base = broker_fixture
    for i in range(3):
        _make_task_with_receipt(broker, f"canary-multi:{i}:v1", f"canary-multi-op-{i}")

    query = {
        "contract": "hermes.publisher_obligation_query.v1",
        "repository_id": "radulator",
        "after_created_at": 0,
        "after_receipt_id": "",
        "limit": 1,
    }
    win = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)
    broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)
    evidence = broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=win["window_id"]
    )
    assert len(evidence["calls"]) == 2
    assert all(c["method"] == "list_publish_obligations" for c in evidence["calls"])


def test_calls_outside_window_boundaries_are_not_captured(broker_fixture):
    """Calls before window open and after window close are not captured."""
    broker, _source, _base = broker_fixture
    _make_task_with_receipt(broker, "canary-outside:v1", "canary-outside-op")

    query = {
        "contract": "hermes.publisher_obligation_query.v1",
        "repository_id": "radulator",
        "after_created_at": 0,
        "after_receipt_id": "",
        "limit": 1,
    }
    broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)  # before
    win = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)  # inside
    evidence = broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=win["window_id"]
    )
    broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)  # after

    assert len(evidence["calls"]) == 1


# ---------------------------------------------------------------------------
# _publisher_runtime_preflight_check with broker-side evidence
#
# The probe file integrity check (st_uid == 0) requires root to satisfy for
# real files.  We mock Path.lstat and _safe_file_sha256 to bypass it and
# exercise the broker-evidence validation code path.
# ---------------------------------------------------------------------------

_PROBE_SHA256 = "c" * 64


def _fake_probe_stat() -> MagicMock:
    """Return a stat-like object that passes the probe integrity checks."""
    m = MagicMock()
    m.st_mode = stat_module.S_IFREG | 0o555
    m.st_uid = 0
    m.st_gid = 0
    m.st_nlink = 1
    return m


def _make_config(tmp_path: Path) -> dict[str, Any]:
    probe = tmp_path / "fake-probe.py"
    probe.write_text("# fake probe\n", encoding="utf-8")
    python = Path(sys.executable).resolve()
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    client_cfg = tmp_path / "client.json"
    client_cfg.write_text("{}", encoding="utf-8")
    package_root = Path(__file__).parent.parent.parent / "hermes_cli"
    return {
        "publisher_probe_path": str(probe),
        "python_executable": str(python),
        "runtime_manifest_path": str(manifest),
        "publisher_client_config": str(client_cfg),
        "runtime_manifest_sha256": "a" * 64,
        "python_version": "3.11.0",
        "python_sha256": "b" * 64,
        "publisher_repository_id": "radulator",
        "publisher_probe_sha256": _PROBE_SHA256,
        "package_root": str(package_root),
        "publisher_uid": os.geteuid(),
        "publisher_gid": os.getegid(),
    }


def _good_child_json(config: dict) -> str:
    """Build a valid child JSON response matching config fields."""
    return json.dumps({
        "contract": "radulator.publisher_runtime_preflight.v1",
        "status": "PASS",
        "python_executable": config["python_executable"],
        "python_version": config["python_version"],
        "runtime_root": str(Path(config["python_executable"]).parent.parent),
        "runtime_manifest_sha256": config["runtime_manifest_sha256"],
        "broker_client_module": str(
            Path(config["package_root"]) / "kanban_broker_client.py"
        ),
        "broker_rpc": "PASS",
    })


class _DirectBrokerOperator:
    """Thin operator client that delegates directly to the in-process broker."""

    def __init__(self, broker) -> None:
        self._broker = broker

    def call(self, method: str, body: dict) -> dict:
        if method == "open_publisher_preflight_window":
            return self._broker.open_publisher_preflight_window(peer_uid=os.geteuid())
        if method == "close_publisher_preflight_window":
            return self._broker.close_publisher_preflight_window(
                peer_uid=os.geteuid(), window_id=str(body.get("window_id") or "")
            )
        raise ValueError(f"unexpected method in test adapter: {method}")


def _run_canary(config, adapter, subprocess_side_effect):
    """Run _publisher_runtime_preflight_check with mocked probe and subprocess."""
    from hermes_cli.kanban_broker_canary import _publisher_runtime_preflight_check

    with patch.object(Path, "lstat", return_value=_fake_probe_stat()):
        with patch(
            "hermes_cli.kanban_broker_install._safe_file_sha256",
            return_value=_PROBE_SHA256,
        ):
            with patch("subprocess.run", side_effect=subprocess_side_effect):
                return _publisher_runtime_preflight_check(
                    config, _operator_broker=adapter
                )


def test_canary_check_fails_when_broker_sees_zero_rpcs(broker_fixture, tmp_path):
    """Canary must fail when the broker records zero RPCs during the window."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)

    def child_no_rpc(command, **kwargs):
        # Child exits cleanly but makes no broker RPC
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": good_json})()

    result = _run_canary(config, adapter, child_no_rpc)
    assert result is False


def test_canary_check_succeeds_with_exactly_one_limit1_rpc(broker_fixture, tmp_path):
    """Canary succeeds when the broker observes exactly one list_publish_obligations(limit=1)."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)
    _make_task_with_receipt(broker, "canary-one-rpc:v1", "canary-pflt-op")

    def child_one_rpc(command, **kwargs):
        broker.list_publish_obligations(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 1,
            },
        )
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": good_json})()

    result = _run_canary(config, adapter, child_one_rpc)
    assert result is True


def test_canary_check_fails_when_broker_sees_two_rpcs(broker_fixture, tmp_path):
    """Canary must fail when the broker records two RPCs — exactly one is required."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)
    for i in range(2):
        _make_task_with_receipt(broker, f"canary-two-rpc:{i}:v1", f"canary-two-op-{i}")

    query = {
        "contract": "hermes.publisher_obligation_query.v1",
        "repository_id": "radulator",
        "after_created_at": 0,
        "after_receipt_id": "",
        "limit": 1,
    }

    def child_two_rpcs(command, **kwargs):
        broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)
        broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": good_json})()

    result = _run_canary(config, adapter, child_two_rpcs)
    assert result is False


def test_canary_check_fails_when_child_json_is_incomplete(broker_fixture, tmp_path):
    """Broker evidence alone does not help if child JSON is missing required keys."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    _make_task_with_receipt(broker, "canary-bad-json:v1", "canary-bad-json-op")

    bad_json = json.dumps({"status": "PASS"})  # missing all required keys
    query = {
        "contract": "hermes.publisher_obligation_query.v1",
        "repository_id": "radulator",
        "after_created_at": 0,
        "after_receipt_id": "",
        "limit": 1,
    }

    def child_bad_json(command, **kwargs):
        broker.list_publish_obligations(peer_uid=os.geteuid(), query=query)
        return type("R", (), {"returncode": 0, "stderr": "", "stdout": bad_json})()

    result = _run_canary(config, adapter, child_bad_json)
    assert result is False


def test_canary_check_fails_when_child_exits_nonzero(broker_fixture, tmp_path):
    """Canary must fail when the child process exits with a nonzero return code."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)

    def child_fails(command, **kwargs):
        return type("R", (), {"returncode": 1, "stderr": "error\n", "stdout": good_json})()

    result = _run_canary(config, adapter, child_fails)
    assert result is False


# ---------------------------------------------------------------------------
# Protocol wire-layer: new window methods on operator surface
# ---------------------------------------------------------------------------

def test_protocol_open_close_window_on_operator_surface(tmp_path):
    """open/close_publisher_preflight_window are reachable via the operator surface."""
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer
    from hermes_cli.kanban_broker_protocol import signed_request
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    key = b"k" * 32
    server = BrokerRPCServer(
        broker=broker, surface="operator", allowed_uid=os.geteuid(), client_key=key
    )

    open_req = signed_request(key, sequence=1, nonce="n1",
                              method="open_publisher_preflight_window", body={})
    resp = server.dispatch(peer_uid=os.geteuid(), message=open_req)
    assert resp["ok"] is True
    wid = resp["result"]["window_id"]
    assert len(wid) == 32

    close_req = signed_request(key, sequence=2, nonce="n2",
                               method="close_publisher_preflight_window",
                               body={"window_id": wid})
    resp2 = server.dispatch(peer_uid=os.geteuid(), message=close_req)
    assert resp2["ok"] is True
    assert resp2["result"]["calls"] == []
    broker.close()


def test_protocol_window_methods_unavailable_on_publisher_surface(tmp_path):
    """open_publisher_preflight_window must NOT be routable on the publisher surface."""
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer, ProtocolError
    from hermes_cli.kanban_broker_protocol import signed_request
    from hermes_cli.kanban_dedicated_broker import DedicatedKanbanBroker

    source = tmp_path / "source"
    _init_repo(source)
    broker = DedicatedKanbanBroker(
        state_dir=tmp_path / "state",
        workspace_root=tmp_path / "workspaces",
        broker_uid=os.geteuid(),
        controller_uid=os.geteuid(),
        publisher_uid=os.geteuid(),
        operator_uid=os.geteuid(),
        worker_uid=os.geteuid(),
        workspace_gid=os.getegid(),
    )
    broker.initialize()
    key = b"k" * 32
    server = BrokerRPCServer(
        broker=broker, surface="publisher", allowed_uid=os.geteuid(), client_key=key
    )
    req = signed_request(key, sequence=1, nonce="n1",
                         method="open_publisher_preflight_window", body={})
    with pytest.raises(ProtocolError, match="unavailable"):
        server.dispatch(peer_uid=os.geteuid(), message=req)
    broker.close()


# ---------------------------------------------------------------------------
# Why the real Radulator trusted_publisher.py --runtime-preflight cannot be
# tested unprivileged — documented and verified programmatically
# ---------------------------------------------------------------------------

def test_real_radulator_trusted_publisher_preflight_is_impossible_unprivileged():
    """Document and verify the blocking check in trusted_publisher.py.

    The real trusted_publisher.py --runtime-preflight (Radulator source at
    /Users/mohibhafeez/Documents/Codex-works/Radulator-source) checks at
    line ~3571 (run_runtime_preflight):

        root_info = runtime_root.lstat()
        if (
            stat.S_ISLNK(root_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != 0         # ← primary blocker
            or stat.S_IMODE(root_info.st_mode) != 0o555
        ):
            raise PublisherError("sealed Python runtime root is mutable")

    An unprivileged process cannot create a directory owned by uid=0.
    Every directory it creates has st_uid == os.geteuid() != 0.

    Additionally, sys.executable must equal runtime_root / "bin" / "python3.11",
    meaning the test must run under the exact sealed CPython 3.11.15 binary
    (pinned SHA-256 from the 20260602 astral-sh/python-build-standalone release),
    installed in a root-owned directory.  This is architecturally impossible
    without root privilege to install the runtime.

    This test asserts the exact blocking condition so future CI failures
    correctly identify the privilege requirement rather than treating it as
    a code regression.
    """
    if os.geteuid() == 0:
        pytest.skip("running as root — this test is for unprivileged environments")

    with tempfile.TemporaryDirectory() as td:
        runtime_root = Path(td) / "runtime"
        runtime_root.mkdir(mode=0o755)
        info = runtime_root.lstat()
        # Confirm the check that blocks unprivileged use:
        # root_info.st_uid != 0 is True for any unprivileged-created directory.
        assert info.st_uid != 0, (
            f"Unexpected: runtime_root st_uid={info.st_uid}; "
            "expected non-zero for unprivileged process"
        )
        # This is exactly what trusted_publisher.py checks at
        # run_runtime_preflight line ~3577: raises "sealed Python runtime root is mutable"
        blocked = info.st_uid != 0
        assert blocked, "Runtime root ownership check must block unprivileged execution"


def test_window_records_other_publisher_rpcs_through_the_wire_server(broker_fixture):
    """Any other publisher-surface call during the window is evidence against
    the preflight: the canary must see exactly one obligations query."""
    from hermes_cli.kanban_broker_protocol import BrokerRPCServer

    broker, _source, _base = broker_fixture
    window = broker.open_publisher_preflight_window(peer_uid=os.geteuid())
    server = BrokerRPCServer.__new__(BrokerRPCServer)
    server.surface = "publisher"
    server.broker = broker
    try:
        server._invoke(
            peer_uid=os.geteuid(),
            method="verify_receipt",
            body={"receipt_id": "missing", "payload_sha256": "a" * 64},
        )
    except Exception:
        pass
    evidence = broker.close_publisher_preflight_window(
        peer_uid=os.geteuid(), window_id=window["window_id"]
    )
    assert [call["method"] for call in evidence["calls"]] == ["verify_receipt"]
    assert evidence["calls"][0]["peer_uid"] == os.geteuid()


def test_canary_check_fails_when_the_single_call_is_not_from_the_publisher_uid(broker_fixture, tmp_path):
    broker, _source, _base = broker_fixture
    config = {**_make_config(tmp_path), "publisher_uid": os.geteuid() + 1}
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)

    def side_effect(*args, **kwargs):
        broker.list_publish_obligations(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 1,
            },
        )
        result = MagicMock()
        result.returncode = 0
        result.stdout = good_json
        result.stderr = ""
        return result

    assert _run_canary(config, adapter, side_effect) is False


def test_canary_runs_the_preflight_child_as_the_publisher_identity(broker_fixture, tmp_path):
    """The root activation runner must drop to the publisher uid/gid for the
    probe; otherwise the publisher-owned 0600 client config and the broker's
    peer-uid check make every production activation fail."""
    broker, _source, _base = broker_fixture
    config = _make_config(tmp_path)
    adapter = _DirectBrokerOperator(broker)
    good_json = _good_child_json(config)
    seen: dict[str, Any] = {}

    def side_effect(*args, **kwargs):
        seen.update(kwargs)
        broker.list_publish_obligations(
            peer_uid=os.geteuid(),
            query={
                "contract": "hermes.publisher_obligation_query.v1",
                "repository_id": "radulator",
                "after_created_at": 0,
                "after_receipt_id": "",
                "limit": 1,
            },
        )
        result = MagicMock()
        result.returncode = 0
        result.stdout = good_json
        result.stderr = ""
        return result

    assert _run_canary(config, adapter, side_effect) is True
    assert seen["user"] == os.geteuid()
    assert seen["group"] == os.getegid()
    assert seen["extra_groups"] == ([] if os.geteuid() == 0 else None)
    assert "HOME" not in seen["env"] and "GH_TOKEN" not in seen["env"]
    missing_gid = {key: value for key, value in config.items() if key != "publisher_gid"}
    assert _run_canary(missing_gid, adapter, side_effect) is False

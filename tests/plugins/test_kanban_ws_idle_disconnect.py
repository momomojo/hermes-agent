"""Regression: kanban events WS must notice client disconnect on an idle board.

Before the fix (#77833), ``stream_events`` only awaited ``asyncio.sleep``
between DB polls, so a disconnect was detected solely when ``send_json``
raised — which never happens on a board with no new events. Every closed
dashboard tab therefore left a zombie poll task querying SQLite forever.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest


def _load_plugin_module():
    repo_root = Path(__file__).resolve().parents[2]
    plugin_file = repo_root / "plugins" / "kanban" / "dashboard" / "plugin_api.py"
    assert plugin_file.exists(), f"plugin file missing: {plugin_file}"
    spec = importlib.util.spec_from_file_location(
        "hermes_dashboard_plugin_kanban_ws_test", plugin_file,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class _IdleDisconnectingWebSocket:
    """Accepts, then reports a client disconnect on the first receive()."""

    def __init__(self):
        self.accepted = False
        self.sent: list[dict] = []
        self.query_params: dict[str, str] = {}
        self.receive_calls = 0

    async def accept(self):
        self.accepted = True

    async def receive(self):
        self.receive_calls += 1
        return {"type": "websocket.disconnect"}

    async def send_json(self, payload):
        self.sent.append(payload)

    async def close(self, code=None):
        self.closed_with = code


@pytest.mark.asyncio
async def test_stream_events_exits_on_idle_disconnect(monkeypatch, tmp_path):
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)
    monkeypatch.setattr(mod, "_event_stream_id", lambda board: f"{board}:x")

    class _Cursor:
        def fetchone(self):
            return (0,)

    class _Connection:
        def execute(self, statement):
            assert "MAX(id)" in statement
            return _Cursor()

        def close(self):
            pass

    monkeypatch.setattr(mod.kanban_db, "connect", lambda board=None: _Connection())

    ws = _IdleDisconnectingWebSocket()

    # The disconnect must terminate the handler even though the board is idle
    # and no event is ever sent. Before the fix this call never returned
    # (the loop only slept between polls), so bound it with a timeout.
    await asyncio.wait_for(mod.stream_events(ws), timeout=5)

    assert ws.accepted
    assert ws.receive_calls == 1
    assert ws.sent == []  # returned before any poll, no zombie loop


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "since, stream, expected_cursor, opening_frame",
    [
        (None, None, 0, False),  # older clients keep the historical full replay
        ("0", None, 0, False),
        ("latest", None, 42, True),  # opt-in: start at the current event, no backlog
        ("5", "default:7", 5, False),  # resume on the same board database
        ("5", "other:1", 42, True),  # cursor from another database: start fresh
        ("50", "default:7", 42, True),  # cursor ahead of a restored sequence: start fresh
    ],
)
async def test_stream_events_start_and_resume(monkeypatch, since, stream, expected_cursor, opening_frame):
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)
    monkeypatch.setattr(mod, "_EVENT_POLL_SECONDS", 0.001)
    monkeypatch.setattr(mod, "_event_stream_id", lambda board: "default:7")
    queried_after: list[int] = []

    class _Cursor:
        def __init__(self, row=None):
            self.row = row

        def fetchone(self):
            return self.row

        def fetchall(self):
            return []

    class _Connection:
        def execute(self, statement, params=()):
            if "MAX(id)" in statement:
                return _Cursor((42,))
            queried_after.append(params[0])
            return _Cursor()

        def close(self):
            pass

    monkeypatch.setattr(mod.kanban_db, "connect", lambda board=None: _Connection())

    class _OnePollWebSocket(_IdleDisconnectingWebSocket):
        async def receive(self):
            self.receive_calls += 1
            if self.receive_calls == 1:
                await asyncio.sleep(0.01)
            return {"type": "websocket.disconnect"}

    ws = _OnePollWebSocket()
    if since is not None:
        ws.query_params["since"] = since
    if stream is not None:
        ws.query_params["stream"] = stream

    await asyncio.wait_for(mod.stream_events(ws), timeout=5)

    assert ws.accepted
    assert queried_after == [expected_cursor]
    # A client starting fresh learns where its stream starts and which board
    # database it reads, so a reconnect can resume with ?since=&stream=. A
    # client resuming on the same database, or a legacy one, gets no extra frame.
    if opening_frame:
        assert ws.sent == [{"events": [], "cursor": 42, "stream": "default:7"}]
    else:
        assert ws.sent == []


def _board_tracking_stubs(monkeypatch, mod, boards_seen):
    """kanban_db.connect stub that records the board every poll reads."""

    class _Cursor:
        def fetchone(self):
            return (0,)

        def fetchall(self):
            return []

    class _Connection:
        def execute(self, statement, params=()):
            return _Cursor()

        def close(self):
            pass

    def _connect(board=None):
        boards_seen.append(board)
        return _Connection()

    monkeypatch.setattr(mod.kanban_db, "connect", _connect)
    monkeypatch.setattr(mod, "_event_stream_id", lambda board: f"{board}:x")


class _PollingWebSocket(_IdleDisconnectingWebSocket):
    """Stays connected for a few polls, then disconnects."""

    polls = 3

    async def receive(self):
        self.receive_calls += 1
        if self.receive_calls <= self.polls:
            await asyncio.sleep(0.01)
        return {"type": "websocket.disconnect"}


@pytest.mark.asyncio
async def test_alias_stream_pins_its_board_and_ends_when_the_alias_moves(monkeypatch):
    """Without ?board=, the current-board alias is resolved once and every poll
    reads that board; when another surface switches boards, the stream ends
    (1012) so the client re-subscribes to the board its REST calls now read."""
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)
    monkeypatch.setattr(mod, "_EVENT_POLL_SECONDS", 0.001)
    current = {"slug": "a", "calls": 0}

    def _current():
        current["calls"] += 1
        return current["slug"] if current["calls"] <= 2 else "b"

    monkeypatch.setattr(mod.kanban_db, "get_current_board", _current)
    boards_seen: list = []
    _board_tracking_stubs(monkeypatch, mod, boards_seen)

    ws = _PollingWebSocket()
    ws.query_params["since"] = "0"
    await asyncio.wait_for(mod.stream_events(ws), timeout=5)

    assert boards_seen and set(boards_seen) == {"a"}
    assert ws.closed_with == 1012


@pytest.mark.asyncio
async def test_explicit_board_stream_ignores_alias_moves(monkeypatch):
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)
    monkeypatch.setattr(mod, "_EVENT_POLL_SECONDS", 0.001)
    monkeypatch.setattr(mod.kanban_db, "get_current_board", lambda: "elsewhere")
    boards_seen: list = []
    _board_tracking_stubs(monkeypatch, mod, boards_seen)

    ws = _PollingWebSocket()
    ws.query_params.update({"board": "ops", "since": "0"})
    await asyncio.wait_for(mod.stream_events(ws), timeout=5)

    assert boards_seen and set(boards_seen) == {"ops"}
    assert getattr(ws, "closed_with", None) is None


def test_event_stream_id_is_a_persisted_database_incarnation(monkeypatch, tmp_path):
    mod = _load_plugin_module()
    real_connect = mod.kanban_db.connect
    paths = {"a": tmp_path / "a" / "kanban.db", "b": tmp_path / "b" / "kanban.db"}
    for path in paths.values():
        path.parent.mkdir()
    monkeypatch.setattr(mod.kanban_db, "connect", lambda board=None: real_connect(db_path=paths[board]))

    first = mod._event_stream_id("a")
    assert first.startswith("a:")
    assert mod._event_stream_id("a") == first  # stable across connections
    assert mod._event_stream_id("b") != first  # another board database
    # Deleting and recreating a board database always mints a new id, even
    # if the filesystem reuses the inode.
    for sidecar in paths["a"].parent.iterdir():
        sidecar.rename(tmp_path / f"retired-{sidecar.name}")
    assert mod._event_stream_id("a") != first

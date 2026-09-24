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
        pass


@pytest.mark.asyncio
async def test_stream_events_exits_on_idle_disconnect(monkeypatch, tmp_path):
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)

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
    # Only the opening cursor frame; returned before any poll, no zombie loop.
    assert ws.sent == [{"events": [], "cursor": 0}]


@pytest.mark.asyncio
@pytest.mark.parametrize("since, expected_cursor", [(None, 42), ("0", 0)])
async def test_stream_events_baselines_only_when_since_is_omitted(monkeypatch, since, expected_cursor):
    mod = _load_plugin_module()
    monkeypatch.setattr(mod, "_ws_upgrade_authorized", lambda ws: True)
    monkeypatch.setattr(mod, "_EVENT_POLL_SECONDS", 0.001)
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

    await asyncio.wait_for(mod.stream_events(ws), timeout=5)

    assert ws.accepted
    assert queried_after == [expected_cursor]
    # A cursorless client learns where its stream starts, so a reconnect can
    # resume with ?since= instead of skipping events raised while it was down.
    # A client that sent its own cursor already knows it.
    if since is None:
        assert ws.sent == [{"events": [], "cursor": 42}]
    else:
        assert ws.sent == []

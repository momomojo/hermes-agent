"""Regression coverage for coherent watchdog activity snapshots."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import run_agent
from agent.iteration_budget import IterationBudget
from tools.environments.base import _get_activity_callback, set_activity_callback


class _InterleavingLock:
    """Run a writer immediately after a reader releases its snapshot lock."""

    def __init__(self, after_release):
        self._lock = threading.RLock()
        self._after_release = after_release
        self._fired = False

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._lock.release()
        if not self._fired:
            self._fired = True
            self._after_release()


def _make_agent(*, wall=10.0, monotonic=10.0, desc="old activity", tool="web_search"):
    """Build only the state used by the real AIAgent activity methods."""
    agent = object.__new__(run_agent.AIAgent)
    agent._activity_lock = threading.Lock()
    agent._last_activity_ts = wall
    agent._last_activity_monotonic = monotonic
    agent._last_activity_desc = desc
    agent._current_tool = tool
    agent._activity_sequence = 7
    agent._api_call_count = 3
    agent.max_iterations = 90
    agent.iteration_budget = IterationBudget(90)
    return agent


def test_summary_never_combines_old_idle_with_newer_activity_fields(monkeypatch):
    """A real writer forced between snapshot read and elapsed calculation stays coherent."""
    clock = {"wall": 100.0, "monotonic": 100.0}
    monkeypatch.setattr(run_agent.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(run_agent.time, "monotonic", lambda: clock["monotonic"])
    agent = _make_agent(wall=10.0, monotonic=10.0)

    def writer():
        clock.update(wall=100.0, monotonic=100.0)
        agent._touch_activity("terminal command running", current_tool="terminal")

    agent._activity_lock = _InterleavingLock(writer)
    summary = agent.get_activity_summary()

    # The writer ran before get_activity_summary returned, but the returned
    # snapshot remains entirely pre-writer rather than an impossible hybrid.
    assert summary["last_activity_ts"] == 10.0
    assert summary["last_activity_desc"] == "old activity"
    assert summary["current_tool"] == "web_search"
    assert summary["activity_sequence"] == 7
    assert summary["seconds_since_activity"] == 90.0


def test_terminal_activity_callback_refreshes_before_tiny_watchdog_boundary(monkeypatch):
    """The actual terminal callback path refreshes the watchdog's monotonic clock."""
    clock = {"wall": 0.0, "monotonic": 0.0}
    monkeypatch.setattr(run_agent.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(run_agent.time, "monotonic", lambda: clock["monotonic"])
    agent = _make_agent(wall=0.0, monotonic=0.0, desc="executing tool: terminal", tool="terminal")

    set_activity_callback(agent._touch_activity)
    try:
        clock.update(wall=0.09, monotonic=0.09)
        callback = _get_activity_callback()
        assert callback is not None
        callback("terminal command running")
        clock.update(wall=0.11, monotonic=0.11)
        assert agent.get_activity_summary()["seconds_since_activity"] < 0.1
    finally:
        set_activity_callback(None)


def test_stale_current_tool_without_heartbeat_still_exceeds_watchdog_limit(monkeypatch):
    """A label alone does not refresh activity or suppress a real timeout."""
    monkeypatch.setattr(run_agent.time, "monotonic", lambda: 30.0)
    agent = _make_agent(monotonic=0.0, desc="executing tool: web_search", tool="web_search")

    summary = agent.get_activity_summary()

    assert summary["current_tool"] == "web_search"
    assert summary["seconds_since_activity"] == 30.0
    assert summary["seconds_since_activity"] >= 1.0


def test_elapsed_is_clamped_when_monotonic_clock_is_adjusted_backwards(monkeypatch):
    monkeypatch.setattr(run_agent.time, "monotonic", lambda: 9.0)
    agent = _make_agent(monotonic=10.0)

    assert agent.get_activity_summary()["seconds_since_activity"] == 0.0


def test_cached_turn_reset_uses_activity_api_when_available():
    from gateway.run import GatewayRunner

    calls = []
    agent = SimpleNamespace(
        _activity_lock=threading.Lock(),
        _api_call_count=5,
        _last_flushed_db_idx=2,
        _touch_activity=lambda desc, **kwargs: calls.append((desc, kwargs)),
    )

    GatewayRunner._init_cached_agent_for_turn(agent, interrupt_depth=0)

    assert calls == [("starting new turn (cached)", {"current_tool": None})]
    assert agent._api_call_count == 0
    assert agent._last_flushed_db_idx == 0

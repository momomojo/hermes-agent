"""Behavioral coverage for lazy TUI slash-worker allocation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_init_session_does_not_allocate_worker_before_slash_use(monkeypatch):
    from tui_gateway import server

    sid = "lazy-worker-session"
    server._sessions.pop(sid, None)
    monkeypatch.setattr(server, "_get_db", lambda: None)
    monkeypatch.setattr(server, "_register_session_cwd", lambda _session: None)
    monkeypatch.setattr(server, "_wire_callbacks", lambda _sid: None)
    monkeypatch.setattr(server, "_notify_session_boundary", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_session_info", lambda *_a, **_k: {"model": "test"})
    monkeypatch.setattr(server, "_emit", lambda *_a, **_k: None)

    agent = MagicMock(model="test/model")
    with patch.object(server, "_SlashWorker") as worker_cls:
        server._init_session(sid, "durable-session-key", agent, [])

    assert server._sessions[sid]["slash_worker"] is None
    worker_cls.assert_not_called()
    server._sessions.pop(sid, None)


def test_restart_preserves_lazy_state_until_worker_has_been_used():
    from tui_gateway import server

    session = {
        "session_key": "durable-session-key",
        "agent": MagicMock(model="test/model"),
        "slash_worker": None,
    }
    with patch.object(server, "_SlashWorker") as worker_cls:
        server._restart_slash_worker("lazy-worker-session", session)

    assert session["slash_worker"] is None
    worker_cls.assert_not_called()


def test_restart_replaces_an_existing_worker(monkeypatch):
    from tui_gateway import server

    old_worker = MagicMock()
    new_worker = MagicMock()
    session = {
        "session_key": "durable-session-key",
        "agent": MagicMock(model="test/model"),
        "slash_worker": old_worker,
    }
    monkeypatch.setattr(
        server,
        "_attach_worker",
        lambda _sid, current, worker: current.__setitem__("slash_worker", worker),
    )
    with patch.object(server, "_SlashWorker", return_value=new_worker) as worker_cls:
        server._restart_slash_worker("lazy-worker-session", session)

    old_worker.close.assert_called_once_with()
    worker_cls.assert_called_once()
    assert session["slash_worker"] is new_worker

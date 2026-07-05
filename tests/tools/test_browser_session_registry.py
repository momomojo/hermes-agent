from __future__ import annotations

from tools import browser_session_registry as registry


def _isolated_registry(monkeypatch, tmp_path, profile: str = "codex-coding") -> None:
    monkeypatch.setattr(registry, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_PROFILE", profile)


def test_sessions_are_keyed_by_profile_backend_and_domain(monkeypatch, tmp_path):
    _isolated_registry(monkeypatch, tmp_path)

    registry.upsert_session(
        domain="https://Example.com/login",
        backend="cdp",
        session_id="cdp-1",
        ttl_seconds=60,
        now=100,
    )
    registry.upsert_session(
        domain="https://other.example/path",
        backend="cdp",
        session_id="cdp-2",
        ttl_seconds=60,
        now=101,
    )
    registry.upsert_session(
        domain="https://example.com/dashboard",
        backend="browser-local",
        session_id="local-1",
        ttl_seconds=60,
        now=102,
    )

    cdp_example = registry.get_reusable_session(
        domain="https://example.com/settings",
        backend="cdp",
        now=103,
    )
    assert cdp_example is not None
    assert cdp_example.session_id == "cdp-1"

    cdp_other = registry.get_reusable_session(
        domain="other.example",
        backend="cdp",
        now=103,
    )
    assert cdp_other is not None
    assert cdp_other.session_id == "cdp-2"

    local_example = registry.get_reusable_session(
        domain="example.com",
        backend="browser-local",
        now=103,
    )
    assert local_example is not None
    assert local_example.session_id == "local-1"


def test_ttl_expiry_filters_and_purges_sessions(monkeypatch, tmp_path):
    _isolated_registry(monkeypatch, tmp_path)
    registry.upsert_session(
        domain="https://example.com",
        backend="cdp",
        session_id="short-lived",
        ttl_seconds=10,
        now=100,
    )

    assert registry.list_sessions(now=109)[0].session_id == "short-lived"
    assert registry.list_sessions(now=110) == []
    assert registry.list_sessions(include_expired=True, now=110)[0].session_id == "short-lived"

    purged = registry.purge_expired(now=111)
    assert [record.session_id for record in purged] == ["short-lived"]
    assert registry.list_sessions(include_expired=True, now=111) == []


def test_auth_needed_state_excludes_reusable_session(monkeypatch, tmp_path):
    _isolated_registry(monkeypatch, tmp_path)
    registry.upsert_session(
        domain="https://example.com",
        backend="browser-local",
        session_id="needs-login",
        ttl_seconds=60,
        now=100,
    )

    assert registry.get_reusable_session(
        domain="example.com",
        backend="browser-local",
        now=101,
    ).session_id == "needs-login"

    updated = registry.mark_auth_needed("needs-login")
    assert len(updated) == 1
    assert updated[0].auth_needed is True
    assert (
        registry.get_reusable_session(
            domain="example.com",
            backend="browser-local",
            now=102,
        )
        is None
    )

    registry.mark_auth_needed("needs-login", auth_needed=False)
    assert registry.get_reusable_session(
        domain="example.com",
        backend="browser-local",
        now=103,
    ).session_id == "needs-login"


def test_close_sessions_removes_matching_session(monkeypatch, tmp_path):
    _isolated_registry(monkeypatch, tmp_path)
    registry.upsert_session(
        domain="https://example.com",
        backend="cdp",
        session_id="gone",
        ttl_seconds=60,
        now=100,
    )

    closed = registry.close_sessions(session_id="gone")
    assert [record.session_id for record in closed] == ["gone"]
    assert registry.list_sessions(include_expired=True) == []

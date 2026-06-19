from __future__ import annotations

import argparse
import json

from hermes_cli import browser_sessions
from tools import browser_session_registry as registry


def test_browser_sessions_cli_marks_auth_needed_json(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(registry, "get_hermes_home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_PROFILE", "codex-coding")
    registry.upsert_session(
        domain="https://example.com",
        backend="cdp",
        session_id="cdp-1",
        ttl_seconds=60,
        now=100,
    )

    browser_sessions.browser_sessions_command(
        argparse.Namespace(
            browser_sessions_command="mark-auth-needed",
            session_id="cdp-1",
            profile=None,
            domain=None,
            backend=None,
            clear=False,
            json=True,
        )
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["updated"][0]["session_id"] == "cdp-1"
    assert payload["updated"][0]["auth_needed"] is True

    browser_sessions.browser_sessions_command(
        argparse.Namespace(
            browser_sessions_command="list",
            profile=None,
            domain=None,
            backend=None,
            include_expired=False,
            usable_only=True,
            json=True,
        )
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["sessions"] == []

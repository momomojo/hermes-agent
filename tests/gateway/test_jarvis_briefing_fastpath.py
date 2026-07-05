"""Tests for the Jarvis BRIEFING API fast path."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import gateway.platforms.api_server as api_server
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter


class _FakeSessionDB:
    def __init__(self) -> None:
        self.messages = []

    def append_message(self, session_id, role, text, **kwargs):
        self.messages.append((session_id, role, text, kwargs))


def _adapter_with_db(db: _FakeSessionDB) -> APIServerAdapter:
    adapter = APIServerAdapter(PlatformConfig(enabled=True))
    adapter._ensure_session_db = lambda: db  # type: ignore[method-assign]
    return adapter


def test_jarvis_briefing_match_is_narrow() -> None:
    assert APIServerAdapter._is_jarvis_briefing_request("jarvis", "BRIEFING") is True
    assert APIServerAdapter._is_jarvis_briefing_request(" jarvis ", "what needs me?") is True
    assert APIServerAdapter._is_jarvis_briefing_request("telegram", "BRIEFING") is False
    assert APIServerAdapter._is_jarvis_briefing_request("jarvis", "approve the first item") is False
    assert APIServerAdapter._is_jarvis_briefing_request("jarvis", "details on briefing") is False


@pytest.mark.asyncio
async def test_jarvis_briefing_fastpath_runs_helper_and_persists_turn(monkeypatch, tmp_path: Path) -> None:
    hermes_home = tmp_path / ".hermes"
    scripts = hermes_home / "scripts"
    scripts.mkdir(parents=True)
    helper = scripts / "jarvis_briefing_queue.py"
    helper.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "assert '--spoken' in sys.argv\n"
        "print('One bounded briefing item. Your call.')\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(api_server.Path, "home", classmethod(lambda cls: tmp_path))
    db = _FakeSessionDB()
    adapter = _adapter_with_db(db)

    result = await adapter._run_jarvis_briefing_fastpath(
        session_id="jarvis-latency-current-briefing-test",
        user_message="BRIEFING",
        gateway_session_key="jarvis",
    )

    assert result is not None
    payload, usage = result
    assert payload == {
        "session_id": "jarvis-latency-current-briefing-test",
        "final_response": "One bounded briefing item. Your call.",
    }
    assert usage == {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "fast_path": "jarvis_briefing"}
    assert db.messages[0][:3] == ("jarvis-latency-current-briefing-test", "user", "BRIEFING")
    assert db.messages[1][:3] == (
        "jarvis-latency-current-briefing-test",
        "assistant",
        "One bounded briefing item. Your call.",
    )
    assert db.messages[1][3]["finish_reason"] == "jarvis_briefing_fastpath"


@pytest.mark.asyncio
async def test_jarvis_briefing_fastpath_falls_back_when_helper_missing(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api_server.Path, "home", classmethod(lambda cls: tmp_path))
    adapter = _adapter_with_db(_FakeSessionDB())

    assert await adapter._run_jarvis_briefing_fastpath(
        session_id="jarvis-missing-helper",
        user_message="BRIEFING",
        gateway_session_key="jarvis",
    ) is None


@pytest.mark.asyncio
async def test_jarvis_briefing_fastpath_ignores_non_jarvis_session(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api_server.Path, "home", classmethod(lambda cls: tmp_path))
    adapter = _adapter_with_db(_FakeSessionDB())

    assert await adapter._run_jarvis_briefing_fastpath(
        session_id="ordinary-session",
        user_message="BRIEFING",
        gateway_session_key="telegram",
    ) is None

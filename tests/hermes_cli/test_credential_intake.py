from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import pytest

from hermes_cli.credential_intake import (
    CredentialIntakeError,
    CredentialIntakeExpired,
    CredentialIntakeStore,
    CredentialIntakeUsed,
    build_local_intake_url,
    parse_token_reference,
    parse_ttl,
)


def _store(tmp_path, now):
    return CredentialIntakeStore(tmp_path / "tokens.json", now=lambda: now[0])


def test_create_stores_hash_not_bearer_token(tmp_path):
    now = [datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)]
    store = _store(tmp_path, now)

    created = store.create(
        label="OpenAI key",
        destination={"adapter": "profile-env", "key": "OPENAI_API_KEY"},
        ttl_seconds=60,
    )

    raw = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert created.request_id in raw
    assert created.token not in raw
    assert "token_hash" in raw
    assert "OPENAI_API_KEY" in raw


def test_consume_is_single_use_and_never_persists_secret(tmp_path, caplog):
    now = [datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)]
    store = _store(tmp_path, now)
    created = store.create(
        label="Provider key",
        destination={"adapter": "profile-env", "key": "ANTHROPIC_API_KEY"},
        ttl_seconds=60,
    )
    secret = "sk-test-secret-value-that-must-not-appear"

    caplog.set_level(logging.INFO, logger="hermes_cli.credential_intake")
    receipt = store.consume(created.token, secret)

    assert receipt.request_id == created.request_id
    assert receipt.stored is False
    raw = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert secret not in raw
    assert secret not in caplog.text
    assert json.loads(raw)["requests"][0]["status"] == "used"
    with pytest.raises(CredentialIntakeUsed):
        store.consume(created.token, "second-value")


def test_expired_token_cannot_be_consumed(tmp_path):
    now = [datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)]
    store = _store(tmp_path, now)
    created = store.create(
        label="Expired",
        destination={"adapter": "profile-env", "key": "OPENAI_API_KEY"},
        ttl_seconds=1,
    )

    now[0] += timedelta(seconds=2)

    with pytest.raises(CredentialIntakeExpired):
        store.consume(created.token, "secret-value")
    assert store.get_request(created.request_id)["status"] == "expired"


def test_adapter_receipt_cannot_echo_secret(tmp_path):
    class BadAdapter:
        def store_secret(self, *, request, secret):
            return {"adapter": "profile-env", "target": "X", "stored": False, "echo": secret}

    now = [datetime(2026, 6, 18, 12, 0, tzinfo=timezone.utc)]
    store = _store(tmp_path, now)
    created = store.create(
        label="Bad",
        destination={"adapter": "profile-env", "key": "OPENAI_API_KEY"},
        ttl_seconds=60,
    )
    secret = "plain-secret-not-a-known-prefix"

    with pytest.raises(CredentialIntakeError):
        store.consume(created.token, secret, adapter=BadAdapter())
    raw = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert secret not in raw
    assert json.loads(raw)["requests"][0]["status"] == "used"


def test_local_url_uses_fragment_and_rejects_remote_hosts():
    url = build_local_intake_url("http://127.0.0.1:8765", "ci_abc", "hci_token")

    assert "#token=hci_token" in url
    assert parse_token_reference(url) == "hci_token"
    with pytest.raises(ValueError):
        build_local_intake_url("https://example.com", "ci_abc", "hci_token")
    with pytest.raises(ValueError):
        parse_token_reference("http://127.0.0.1:8765/credential-intake/ci_abc?token=hci_token")


def test_ttl_parser():
    assert parse_ttl("30") == 30
    assert parse_ttl("15m") == 900
    assert parse_ttl("2h") == 7200
    assert parse_ttl("1d") == 86400
    with pytest.raises(ValueError):
        parse_ttl("0")

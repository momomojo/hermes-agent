"""Regression tests for terminal-free delivery webhook forwarding."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml


PROFILE_HOME = Path("/Users/agent/.hermes/profiles/home-assistant")
SCRIPTS_DIR = PROFILE_HOME / "scripts"
PUSH_ADAPTER_PATH = SCRIPTS_DIR / "gmail_pubsub_push_adapter.py"
ROOT_SUBSCRIPTIONS_PATH = Path("/Users/agent/.hermes/webhook_subscriptions.json")
PROFILE_SUBSCRIPTIONS_PATH = PROFILE_HOME / "webhook_subscriptions.json"
ROOT_CONFIG_PATH = Path("/Users/agent/.hermes/config.yaml")


def _load_push_adapter():
    sys.path.insert(0, str(SCRIPTS_DIR))
    spec = importlib.util.spec_from_file_location(
        "delivery_pubsub_push_adapter_under_test",
        PUSH_ADAPTER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def push_adapter():
    return _load_push_adapter()


def _bridge_config(push_adapter, tmp_path):
    return push_adapter.BridgeConfig(
        state_path=tmp_path / "state.json",
        log_path=tmp_path / "events.jsonl",
        webhook_url="http://127.0.0.1:8648/webhooks/delivery-agent",
        webhook_secret="test-secret",
    )


def test_actionable_delivery_hook_output_posts_alert_payload(push_adapter, monkeypatch, tmp_path):
    posted: list[dict] = []

    monkeypatch.setattr(
        push_adapter,
        "run_delivery_hook_entrypoint",
        lambda payload: "Amazon Fresh delivered - perishables need fridge check now.",
    )

    def fake_post_webhook(payload, config):
        posted.append(payload)
        return {"status_code": 202, "body": "accepted"}

    monkeypatch.setattr(push_adapter, "post_webhook", fake_post_webhook)

    source_payload = {
        "event": "gmail",
        "source": "gmail_pubsub_delivery_bridge",
        "history_id": "7225232",
        "email_address": "person@example.test",
        "messages": [
            {
                "id": "msg-1",
                "threadId": "thread-1",
                "from": "Amazon Fresh <store-news@amazon.com>",
                "subject": "Your Amazon Fresh order was delivered",
                "date": "Tue, 09 Jun 2026 20:00:00 -0700",
                "snippet": "Door code 123456 should not be forwarded",
                "labels": ["INBOX"],
            }
        ],
    }

    result = push_adapter.post_actionable_delivery_webhook(
        source_payload,
        _bridge_config(push_adapter, tmp_path),
    )

    assert result["status_code"] == 202
    assert result["forwarded"] is True
    assert result["delivery_action"] == "alert_forwarded"
    assert len(posted) == 1

    alert_payload = posted[0]
    assert alert_payload["event_type"] == "delivery"
    assert alert_payload["alert_text"] == (
        "Amazon Fresh delivered - perishables need fridge check now."
    )
    assert alert_payload["context"]["history_id"] == "7225232"
    assert alert_payload["context"]["messages"][0]["id"] == "msg-1"
    serialized = json.dumps(alert_payload)
    assert "snippet" not in serialized
    assert "123456" not in serialized


def test_quiet_delivery_hook_output_does_not_post_webhook(push_adapter, monkeypatch, tmp_path):
    posted: list[dict] = []
    monkeypatch.setattr(push_adapter, "run_delivery_hook_entrypoint", lambda payload: "")
    monkeypatch.setattr(
        push_adapter,
        "post_webhook",
        lambda payload, config: posted.append(payload) or {"status_code": 200},
    )

    result = push_adapter.post_actionable_delivery_webhook(
        {"messages": [{"id": "quiet-1", "subject": "Your package shipped"}]},
        _bridge_config(push_adapter, tmp_path),
    )

    assert result == {
        "status_code": 204,
        "body": "quiet delivery event",
        "forwarded": False,
        "delivery_action": "quiet",
    }
    assert posted == []


def test_bridge_counts_quiet_post_func_as_processed_not_forwarded(push_adapter, tmp_path):
    import gmail_pubsub_delivery_bridge as bridge

    class FakeGmail:
        def list_history(self, history_id):
            return [{"messagesAdded": [{"message": {"id": "msg-quiet"}}]}]

        def get_message(self, message_id):
            return {
                "id": message_id,
                "threadId": "thread-quiet",
                "from": "Amazon Fresh <store-news@amazon.com>",
                "subject": "Your Amazon Fresh order was delivered",
                "date": "Tue, 09 Jun 2026 20:00:00 -0700",
                "snippet": "Delivered",
                "labels": ["INBOX"],
            }

    result = bridge.process_pubsub_events(
        [bridge.PubSubEvent(ack_id="push", message_id="pubsub-quiet", history_id="h1")],
        gmail=FakeGmail(),
        post_func=lambda payload, config: {"status_code": 204, "forwarded": False},
        config=_bridge_config(push_adapter, tmp_path),
    )

    assert result.notifications == 1
    assert result.message_ids == 1
    assert result.forwarded == 0
    assert result.filtered == 0

    state = json.loads((tmp_path / "state.json").read_text())
    assert state["processed_pubsub_message_ids"] == ["pubsub-quiet"]
    assert state["seen_gmail_message_ids"] == ["msg-quiet"]

    event_row = json.loads((tmp_path / "events.jsonl").read_text().splitlines()[0])
    assert event_row["forwarded"] == 0
    assert event_row["post_result"]["forwarded"] is False


def test_delivery_subscription_and_platform_config_are_terminal_free():
    for path in [ROOT_SUBSCRIPTIONS_PATH, PROFILE_SUBSCRIPTIONS_PATH]:
        route = json.loads(path.read_text())["delivery-agent"]
        prompt = route["prompt"].lower()
        assert route["deliver_only"] is True
        assert route["deliver"] == "telegram"
        assert "terminal" not in prompt
        assert "local command" not in prompt
        assert "delivery_hook_entrypoint" not in prompt

    config = yaml.safe_load(ROOT_CONFIG_PATH.read_text())
    assert "terminal" not in config["platform_toolsets"].get("webhook", [])

from hermes_cli.gateway import _runtime_health_lines


def test_runtime_health_lines_include_fatal_platform_and_startup_reason(monkeypatch):
    monkeypatch.setattr(
        "gateway.status.read_runtime_status",
        lambda: {
            "gateway_state": "startup_failed",
            "exit_reason": "telegram conflict",
            "platforms": {
                "telegram": {
                    "state": "fatal",
                    "error_message": "another poller is active",
                }
            },
        },
    )

    lines = _runtime_health_lines()

    assert any(
        line.startswith("⚠ telegram: fatal — another poller is active")
        for line in lines
    )
    assert "⚠ Last startup issue: telegram conflict" in lines


def test_runtime_health_lines_include_connected_and_retrying_platforms(monkeypatch):
    monkeypatch.setattr(
        "gateway.status.read_runtime_status",
        lambda: {
            "gateway_state": "running",
            "platforms": {
                "telegram": {
                    "state": "connected",
                    "updated_at": "2026-06-09T00:00:37+00:00",
                },
                "api_server": {
                    "state": "retrying",
                    "error_code": "bind_failed",
                    "error_message": "port busy",
                    "updated_at": "2026-06-09T00:00:38+00:00",
                },
            },
        },
    )

    lines = _runtime_health_lines()

    assert any(line.startswith("✓ telegram: connected") for line in lines)
    assert any(
        line.startswith("⏳ api_server: retrying — bind_failed: port busy")
        for line in lines
    )

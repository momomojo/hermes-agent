from cron.timeouts import (
    DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS,
    configured_cron_inactivity_timeout_seconds,
    resolve_cron_inactivity_timeout_seconds,
)


def test_configured_timeout_defaults_when_missing_or_invalid():
    assert configured_cron_inactivity_timeout_seconds({}) == 600.0
    assert configured_cron_inactivity_timeout_seconds(
        {"cron": {"inactivity_timeout_seconds": -1}}
    ) == DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS
    assert configured_cron_inactivity_timeout_seconds(
        {"cron": {"inactivity_timeout_seconds": "not-a-number"}}
    ) == DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS


def test_configured_timeout_accepts_bounded_and_unlimited_values():
    assert configured_cron_inactivity_timeout_seconds(
        {"cron": {"inactivity_timeout_seconds": 900}}
    ) == 900.0
    assert configured_cron_inactivity_timeout_seconds(
        {"cron": {"inactivity_timeout_seconds": 0}}
    ) == 0.0


def test_environment_override_has_precedence():
    cfg = {"cron": {"inactivity_timeout_seconds": 900}}
    assert resolve_cron_inactivity_timeout_seconds(cfg, {}) == 900.0
    assert resolve_cron_inactivity_timeout_seconds(
        cfg, {"HERMES_CRON_TIMEOUT": "1200"}
    ) == 1200.0
    assert resolve_cron_inactivity_timeout_seconds(
        cfg, {"HERMES_CRON_TIMEOUT": "0"}
    ) == 0.0


def test_invalid_environment_override_falls_back_to_config():
    cfg = {"cron": {"inactivity_timeout_seconds": 900}}
    assert resolve_cron_inactivity_timeout_seconds(
        cfg, {"HERMES_CRON_TIMEOUT": "invalid"}
    ) == 900.0

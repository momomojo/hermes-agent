import pytest

from cron.timeouts import (
    DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS,
    configured_cron_inactivity_timeout_seconds,
    resolve_cron_inactivity_timeout_seconds,
)


@pytest.mark.parametrize(
    "configured",
    [
        -1,
        "not-a-number",
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        [],
        {},
        (),
    ],
)
def test_configured_timeout_defaults_when_missing_or_invalid(configured):
    assert configured_cron_inactivity_timeout_seconds({}) == 600.0
    assert (
        configured_cron_inactivity_timeout_seconds({
            "cron": {"inactivity_timeout_seconds": configured}
        })
        == DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS
    )


def test_configured_timeout_accepts_bounded_and_unlimited_values():
    assert (
        configured_cron_inactivity_timeout_seconds({
            "cron": {"inactivity_timeout_seconds": 900}
        })
        == 900.0
    )
    assert (
        configured_cron_inactivity_timeout_seconds({
            "cron": {"inactivity_timeout_seconds": 0}
        })
        == 0.0
    )


def test_environment_override_has_precedence():
    config = {"cron": {"inactivity_timeout_seconds": 900}}
    assert resolve_cron_inactivity_timeout_seconds(config, {}) == 900.0
    assert (
        resolve_cron_inactivity_timeout_seconds(config, {"HERMES_CRON_TIMEOUT": "1200"})
        == 1200.0
    )
    assert (
        resolve_cron_inactivity_timeout_seconds(config, {"HERMES_CRON_TIMEOUT": "0"})
        == 0.0
    )


@pytest.mark.parametrize(
    "override",
    ["invalid", "-1", "nan", "inf", "-inf", "[]", "{}", True, False, [], {}],
)
def test_invalid_environment_override_falls_back_to_config(override):
    config = {"cron": {"inactivity_timeout_seconds": 900}}
    assert (
        resolve_cron_inactivity_timeout_seconds(
            config, {"HERMES_CRON_TIMEOUT": override}
        )
        == 900.0
    )


def test_scheduler_and_oneshot_recovery_follow_profile_config(tmp_path, monkeypatch):
    """The live regression: config said 900 but the scheduler only read the env
    var, which launchd never set, so every job ran with the 600s default."""
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "config.yaml").write_text(
        "cron:\n  inactivity_timeout_seconds: 900\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.delenv("HERMES_CRON_TIMEOUT", raising=False)

    from cron import jobs, scheduler

    assert scheduler._cron_inactivity_seconds() == 900.0
    assert jobs._oneshot_run_claim_ttl_seconds() == max(
        900.0 * jobs._ONESHOT_RUN_CLAIM_TTL_HEADROOM,
        float(jobs.ONESHOT_RUN_CLAIM_TTL_SECONDS),
    )

    # The environment stays the highest-precedence escape hatch; 0 = unlimited.
    monkeypatch.setenv("HERMES_CRON_TIMEOUT", "0")
    assert scheduler._cron_inactivity_seconds() == 0.0
    assert jobs._oneshot_run_claim_ttl_seconds() == float(
        jobs.ONESHOT_RUN_CLAIM_TTL_SECONDS
    )


def test_oversized_integer_falls_back_instead_of_raising():
    # float(10**400) raises OverflowError; it must fall back like other bad input.
    assert configured_cron_inactivity_timeout_seconds(
        {"cron": {"inactivity_timeout_seconds": 10**400}}
    ) == 600.0


def test_invalid_value_warns_once(caplog):
    from cron import timeouts

    timeouts._WARNED_INVALID.clear()
    config = {"cron": {"inactivity_timeout_seconds": "not-a-number-once"}}
    with caplog.at_level("WARNING", logger="cron.timeouts"):
        for _ in range(3):
            configured_cron_inactivity_timeout_seconds(config)
    assert sum("not-a-number-once" in r.getMessage() for r in caplog.records) == 1

"""Tests for the Home Assistant gateway adapter.

Tests real logic: state change formatting, event filtering pipeline,
cooldown behavior, config integration, and adapter initialization.
"""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import (
    GatewayConfig,
    Platform,
    PlatformConfig,
)
from plugins.platforms.homeassistant.adapter import (
    HomeAssistantAdapter,
    check_ha_requirements,
)


# ---------------------------------------------------------------------------
# check_ha_requirements
# ---------------------------------------------------------------------------


class TestCheckRequirements:
    def test_returns_false_without_token(self, monkeypatch):
        monkeypatch.delenv("HASS_TOKEN", raising=False)
        assert check_ha_requirements() is False

    def test_returns_true_with_token(self, monkeypatch):
        monkeypatch.setenv("HASS_TOKEN", "test-token")
        assert check_ha_requirements() is True

    @patch("plugins.platforms.homeassistant.adapter.AIOHTTP_AVAILABLE", False)
    def test_returns_false_without_aiohttp(self, monkeypatch):
        monkeypatch.setenv("HASS_TOKEN", "test-token")
        assert check_ha_requirements() is False


# ---------------------------------------------------------------------------
# _format_state_change - pure function, all domain branches
# ---------------------------------------------------------------------------


class TestFormatStateChange:
    @staticmethod
    def fmt(entity_id, old_state, new_state):
        return HomeAssistantAdapter._format_state_change(entity_id, old_state, new_state)

    def test_climate_includes_temperatures(self):
        msg = self.fmt(
            "climate.thermostat",
            {"state": "off"},
            {"state": "heat", "attributes": {
                "friendly_name": "Main Thermostat",
                "current_temperature": 21.5,
                "temperature": 23,
            }},
        )
        assert "Main Thermostat" in msg
        assert "'off'" in msg and "'heat'" in msg
        assert "21.5" in msg and "23" in msg

    def test_sensor_includes_unit(self):
        msg = self.fmt(
            "sensor.temperature",
            {"state": "22.5"},
            {"state": "25.1", "attributes": {
                "friendly_name": "Living Room Temp",
                "unit_of_measurement": "C",
            }},
        )
        assert "22.5C" in msg and "25.1C" in msg
        assert "Living Room Temp" in msg

    def test_sensor_without_unit(self):
        msg = self.fmt(
            "sensor.count",
            {"state": "5"},
            {"state": "10", "attributes": {"friendly_name": "Counter"}},
        )
        assert "5" in msg and "10" in msg

    def test_binary_sensor_on(self):
        msg = self.fmt(
            "binary_sensor.motion",
            {"state": "off"},
            {"state": "on", "attributes": {"friendly_name": "Hallway Motion"}},
        )
        assert "triggered" in msg
        assert "Hallway Motion" in msg

    def test_binary_sensor_off(self):
        msg = self.fmt(
            "binary_sensor.door",
            {"state": "on"},
            {"state": "off", "attributes": {"friendly_name": "Front Door"}},
        )
        assert "cleared" in msg

    def test_light_turned_on(self):
        msg = self.fmt(
            "light.bedroom",
            {"state": "off"},
            {"state": "on", "attributes": {"friendly_name": "Bedroom Light"}},
        )
        assert "turned on" in msg

    def test_switch_turned_off(self):
        msg = self.fmt(
            "switch.heater",
            {"state": "on"},
            {"state": "off", "attributes": {"friendly_name": "Heater"}},
        )
        assert "turned off" in msg

    def test_fan_domain_uses_light_switch_branch(self):
        msg = self.fmt(
            "fan.ceiling",
            {"state": "off"},
            {"state": "on", "attributes": {"friendly_name": "Ceiling Fan"}},
        )
        assert "turned on" in msg

    def test_alarm_panel(self):
        msg = self.fmt(
            "alarm_control_panel.home",
            {"state": "disarmed"},
            {"state": "armed_away", "attributes": {"friendly_name": "Home Alarm"}},
        )
        assert "Home Alarm" in msg
        assert "armed_away" in msg and "disarmed" in msg

    def test_generic_domain_includes_entity_id(self):
        msg = self.fmt(
            "automation.morning",
            {"state": "off"},
            {"state": "on", "attributes": {"friendly_name": "Morning Routine"}},
        )
        assert "automation.morning" in msg
        assert "Morning Routine" in msg

    def test_same_state_returns_none(self):
        assert self.fmt(
            "sensor.temp",
            {"state": "22"},
            {"state": "22", "attributes": {"friendly_name": "Temp"}},
        ) is None

    def test_empty_new_state_returns_none(self):
        assert self.fmt("light.x", {"state": "on"}, {}) is None

    def test_no_old_state_uses_unknown(self):
        msg = self.fmt(
            "light.new",
            None,
            {"state": "on", "attributes": {"friendly_name": "New Light"}},
        )
        assert msg is not None
        assert "New Light" in msg

    def test_uses_entity_id_when_no_friendly_name(self):
        msg = self.fmt(
            "sensor.unnamed",
            {"state": "1"},
            {"state": "2", "attributes": {}},
        )
        assert "sensor.unnamed" in msg


# ---------------------------------------------------------------------------
# Adapter initialization from config
# ---------------------------------------------------------------------------


class TestAdapterInit:
    def test_url_and_token_from_config_extra(self, monkeypatch):
        monkeypatch.delenv("HASS_URL", raising=False)
        monkeypatch.delenv("HASS_TOKEN", raising=False)

        config = PlatformConfig(
            enabled=True,
            token="config-token",
            extra={"url": "http://192.168.1.50:8123"},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._hass_token == "config-token"
        assert adapter._hass_url == "http://192.168.1.50:8123"

    def test_url_fallback_to_env(self, monkeypatch):
        monkeypatch.setenv("HASS_URL", "http://env-host:8123")
        monkeypatch.setenv("HASS_TOKEN", "env-tok")

        config = PlatformConfig(enabled=True, token="env-tok")
        adapter = HomeAssistantAdapter(config)
        assert adapter._hass_url == "http://env-host:8123"

    def test_trailing_slash_stripped(self):
        config = PlatformConfig(
            enabled=True, token="t",
            extra={"url": "http://ha.local:8123/"},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._hass_url == "http://ha.local:8123"

    def test_watch_filters_parsed(self):
        config = PlatformConfig(
            enabled=True, token="***",
            extra={
                "watch_domains": ["climate", "binary_sensor"],
                "watch_entities": ["sensor.special"],
                "ignore_entities": ["sensor.uptime", "sensor.cpu"],
                "cooldown_seconds": 120,
            },
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._watch_domains == {"climate", "binary_sensor"}
        assert adapter._watch_entities == {"sensor.special"}
        assert adapter._ignore_entities == {"sensor.uptime", "sensor.cpu"}
        assert adapter._watch_all is False
        assert adapter._cooldown_seconds == 120

    def test_watch_all_parsed(self):
        config = PlatformConfig(
            enabled=True, token="***",
            extra={"watch_all": True},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._watch_all is True

    def test_defaults_when_no_extra(self, monkeypatch):
        monkeypatch.setenv("HASS_TOKEN", "tok")
        config = PlatformConfig(enabled=True, token="***")
        adapter = HomeAssistantAdapter(config)
        assert adapter._watch_domains == set()
        assert adapter._watch_entities == set()
        assert adapter._ignore_entities == set()
        assert adapter._watch_all is False
        assert adapter._cooldown_seconds == 30


# ---------------------------------------------------------------------------
# Event filtering pipeline (_handle_ha_event)
#
# We mock handle_message (not our code, it's the base class pipeline) to
# capture the MessageEvent that _handle_ha_event produces.
# ---------------------------------------------------------------------------


def _make_adapter(**extra) -> HomeAssistantAdapter:
    config = PlatformConfig(enabled=True, token="tok", extra=extra)
    adapter = HomeAssistantAdapter(config)
    adapter.handle_message = AsyncMock()
    return adapter


def _make_event(entity_id, old_state, new_state, old_attrs=None, new_attrs=None):
    return {
        "data": {
            "entity_id": entity_id,
            "old_state": {"state": old_state, "attributes": old_attrs or {}},
            "new_state": {"state": new_state, "attributes": new_attrs or {"friendly_name": entity_id}},
        }
    }


class TestEventFilteringPipeline:
    @pytest.mark.asyncio
    async def test_ignored_entity_not_forwarded(self):
        adapter = _make_adapter(watch_all=True, ignore_entities=["sensor.uptime"])
        await adapter._handle_ha_event(_make_event("sensor.uptime", "100", "101"))
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_unwatched_domain_not_forwarded(self):
        adapter = _make_adapter(watch_domains=["climate"])
        await adapter._handle_ha_event(_make_event("light.bedroom", "off", "on"))
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_watched_domain_forwarded(self):
        adapter = _make_adapter(watch_domains=["climate"], cooldown_seconds=0)
        await adapter._handle_ha_event(
            _make_event("climate.thermostat", "off", "heat",
                        new_attrs={"friendly_name": "Thermostat", "current_temperature": 20, "temperature": 22})
        )
        adapter.handle_message.assert_called_once()

        # Verify the actual MessageEvent text content
        msg_event = adapter.handle_message.call_args[0][0]
        assert "Thermostat" in msg_event.text
        assert "heat" in msg_event.text
        assert msg_event.source.platform == Platform.HOMEASSISTANT
        assert msg_event.source.chat_id == "ha_events"

    @pytest.mark.asyncio
    async def test_watched_entity_forwarded(self):
        adapter = _make_adapter(watch_entities=["sensor.important"], cooldown_seconds=0)
        await adapter._handle_ha_event(
            _make_event("sensor.important", "10", "20",
                        new_attrs={"friendly_name": "Important Sensor", "unit_of_measurement": "W"})
        )
        adapter.handle_message.assert_called_once()
        msg_event = adapter.handle_message.call_args[0][0]
        assert "10W" in msg_event.text and "20W" in msg_event.text

    @pytest.mark.asyncio
    async def test_no_filters_blocks_everything(self):
        """Without watch_domains, watch_entities, or watch_all, events are dropped."""
        adapter = _make_adapter(cooldown_seconds=0)
        await adapter._handle_ha_event(_make_event("cover.blinds", "closed", "open"))
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_watch_all_passes_everything(self):
        """With watch_all=True and no specific filters, all events pass through."""
        adapter = _make_adapter(watch_all=True, cooldown_seconds=0)
        await adapter._handle_ha_event(_make_event("cover.blinds", "closed", "open"))
        adapter.handle_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_same_state_not_forwarded(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=0)
        await adapter._handle_ha_event(_make_event("light.x", "on", "on"))
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_empty_entity_id_skipped(self):
        adapter = _make_adapter(watch_all=True)
        await adapter._handle_ha_event({"data": {"entity_id": ""}})
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_message_event_has_correct_source(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=0)
        await adapter._handle_ha_event(
            _make_event("light.test", "off", "on",
                        new_attrs={"friendly_name": "Test Light"})
        )
        msg_event = adapter.handle_message.call_args[0][0]
        assert msg_event.source.user_name == "Home Assistant"
        assert msg_event.source.chat_type == "channel"
        assert msg_event.message_id.startswith("ha_light.test_")


# ---------------------------------------------------------------------------
# Cooldown behavior
# ---------------------------------------------------------------------------


class TestCooldown:
    @pytest.mark.asyncio
    async def test_cooldown_blocks_rapid_events(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=60)

        event = _make_event("sensor.temp", "20", "21",
                            new_attrs={"friendly_name": "Temp"})
        await adapter._handle_ha_event(event)
        assert adapter.handle_message.call_count == 1

        # Second event immediately after should be blocked
        event2 = _make_event("sensor.temp", "21", "22",
                             new_attrs={"friendly_name": "Temp"})
        await adapter._handle_ha_event(event2)
        assert adapter.handle_message.call_count == 1  # Still 1

    @pytest.mark.asyncio
    async def test_cooldown_expires(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=1)

        event = _make_event("sensor.temp", "20", "21",
                            new_attrs={"friendly_name": "Temp"})
        await adapter._handle_ha_event(event)
        assert adapter.handle_message.call_count == 1

        # Simulate time passing beyond cooldown
        adapter._last_event_time["sensor.temp"] = time.time() - 2

        event2 = _make_event("sensor.temp", "21", "22",
                             new_attrs={"friendly_name": "Temp"})
        await adapter._handle_ha_event(event2)
        assert adapter.handle_message.call_count == 2

    @pytest.mark.asyncio
    async def test_different_entities_independent_cooldowns(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=60)

        await adapter._handle_ha_event(
            _make_event("sensor.a", "1", "2", new_attrs={"friendly_name": "A"})
        )
        await adapter._handle_ha_event(
            _make_event("sensor.b", "3", "4", new_attrs={"friendly_name": "B"})
        )
        # Both should pass - different entities
        assert adapter.handle_message.call_count == 2

        # Same entity again - should be blocked
        await adapter._handle_ha_event(
            _make_event("sensor.a", "2", "3", new_attrs={"friendly_name": "A"})
        )
        assert adapter.handle_message.call_count == 2  # Still 2

    @pytest.mark.asyncio
    async def test_zero_cooldown_passes_all(self):
        adapter = _make_adapter(watch_all=True, cooldown_seconds=0)

        for i in range(5):
            await adapter._handle_ha_event(
                _make_event("sensor.temp", str(i), str(i + 1),
                            new_attrs={"friendly_name": "Temp"})
            )
        assert adapter.handle_message.call_count == 5


# ---------------------------------------------------------------------------
# Significance filter
# ---------------------------------------------------------------------------
#
# _is_significant_event classifies events as significant (-> agent route)
# or routine (-> silently dropped).  The filter inspects domain, device_class,
# state values, and entity_id keywords.
# ---------------------------------------------------------------------------


def _sig_entity(entity_id, old="off", new="on", old_attrs=None, new_attrs=None):
    """Shorthand: call _is_significant_event on an entity change."""
    adapter = _make_adapter(significance_filter=True, watch_all=True, cooldown_seconds=0)
    return adapter._is_significant_event(
        entity_id,
        old_state=old,
        new_state=new,
        old_attrs=old_attrs or {},
        new_attrs=new_attrs or {},
    )


class TestSignificanceFilter:
    """Each test calls _is_significant_event directly (pure method)."""

    # -- Unavailable / unknown (always significant) --

    def test_unavailable_transition(self):
        assert _sig_entity("sensor.temp", old="22", new="unavailable")

    def test_from_unavailable(self):
        assert _sig_entity("light.x", old="unavailable", new="on")

    def test_unknown_transition(self):
        assert _sig_entity("binary_sensor.x", old="unknown", new="on")

    # -- Security / safety domains --

    def test_alarm_control_panel(self):
        assert _sig_entity("alarm_control_panel.home", old="disarmed", new="armed_away")

    def test_lock_state_change(self):
        assert _sig_entity("lock.front_door", old="locked", new="unlocked")

    # -- Binary sensor by device_class --

    def test_smoke_detected(self):
        assert _sig_entity("binary_sensor.smoke", new_attrs={"device_class": "smoke"})

    def test_co_detected(self):
        assert _sig_entity("binary_sensor.co", new_attrs={"device_class": "co"})

    def test_gas_detected(self):
        assert _sig_entity("binary_sensor.gas", new_attrs={"device_class": "gas"})

    def test_motion_detected(self):
        assert _sig_entity("binary_sensor.hallway_motion",
                           new_attrs={"device_class": "motion"})

    def test_door_sensor(self):
        assert _sig_entity("binary_sensor.front_door",
                           new_attrs={"device_class": "door"})

    def test_window_sensor(self):
        assert _sig_entity("binary_sensor.living_window",
                           new_attrs={"device_class": "window"})

    def test_presence_sensor(self):
        assert _sig_entity("binary_sensor.living_presence",
                           new_attrs={"device_class": "presence"})

    def test_battery_low_binary_sensor(self):
        assert _sig_entity("binary_sensor.sensor_battery",
                           new_attrs={"device_class": "battery"})

    def test_connectivity_binary_sensor(self):
        assert _sig_entity("binary_sensor.router_online",
                           new_attrs={"device_class": "connectivity"})

    def test_plug_binary_sensor(self):
        assert _sig_entity("binary_sensor.plug",
                           new_attrs={"device_class": "plug"})

    def test_routine_binary_sensor_no_device_class(self):
        assert not _sig_entity("binary_sensor.routine",
                               old="off", new="on",
                               new_attrs={"friendly_name": "Routine Sensor"})

    def test_routine_binary_sensor_unknown_device_class(self):
        assert not _sig_entity("binary_sensor.carbon_dioxide",
                               new_attrs={"device_class": "carbon_dioxide"})

    # -- Person zone changes --

    def test_person_state_change(self):
        assert _sig_entity("person.mohib", old="home", new="away")

    # -- Update availability --

    def test_update_available(self):
        assert _sig_entity("update.ha_core", old="off", new="on",
                           new_attrs={"friendly_name": "Home Assistant Core Update"})

    def test_update_no_update(self):
        assert not _sig_entity("update.ha_core", old="on", new="off")

    # -- User-action domains --

    def test_light_on(self):
        assert _sig_entity("light.living_room", old="off", new="on")

    def test_switch_off(self):
        assert _sig_entity("switch.plug", old="on", new="off")

    def test_fan_speed_change(self):
        assert _sig_entity("fan.ceiling", old="off", new="on")

    def test_cover_open(self):
        assert _sig_entity("cover.blinds", old="closed", new="open")

    def test_climate_mode_change(self):
        assert _sig_entity("climate.thermostat", old="off", new="heat")

    # -- Media player --

    def test_media_player_turned_on(self):
        assert _sig_entity("media_player.tv", old="off", new="on")

    # -- Sensor keywords --

    def test_backup_sensor(self):
        assert _sig_entity("sensor.last_backup", old="yesterday", new="today")

    def test_wan_sensor(self):
        assert _sig_entity("sensor.wan_status", old="down", new="up")

    def test_alert_sensor(self):
        assert _sig_entity("sensor.alert_count", old="3", new="4")

    def test_alarm_sensor(self):
        assert _sig_entity("sensor.alarm_panel", old="disarmed", new="armed")

    def test_security_sensor(self):
        assert _sig_entity("sensor.security_status", old="ok", new="intrusion")

    def test_presence_sensor_keyword(self):
        assert _sig_entity("sensor.presence_status", old="away", new="home")

    def test_critical_sensor_keyword(self):
        assert _sig_entity("sensor.critical_alerts", old="0", new="1")

    def test_outage_sensor(self):
        assert _sig_entity("sensor.outage_count", old="0", new="1")

    def test_firmware_sensor(self):
        assert _sig_entity("sensor.firmware_version", old="1.0", new="1.1")

    # -- Battery percentage thresholds --

    def test_battery_crosses_20_pct(self):
        assert _sig_entity("sensor.device_battery", old="25", new="19")

    def test_battery_crosses_10_pct(self):
        assert _sig_entity("sensor.device_battery", old="12", new="9")

    def test_battery_crosses_5_pct(self):
        assert _sig_entity("sensor.device_battery", old="6", new="4")

    def test_battery_stays_above_20(self):
        assert not _sig_entity("sensor.device_battery", old="75", new="72")

    def test_battery_goes_from_21_to_20_not_significant(self):
        assert not _sig_entity("sensor.device_battery", old="21", new="20")

    def test_battery_low_state(self):
        assert _sig_entity("sensor.device_battery", old="15", new="low")

    def test_battery_critical_state(self):
        assert _sig_entity("sensor.device_battery", old="low", new="critical")

    # -- Routine sensor updates (dropped) --

    def test_routine_sensor_numeric(self):
        assert not _sig_entity("sensor.temperature", old="22.5", new="23.1")

    def test_routine_sensor_no_keyword(self):
        assert not _sig_entity("sensor.uptime", old="100000", new="100001")

    # -- Unknown domain (passed through) --

    def test_unknown_domain(self):
        assert _sig_entity("automation.morning_routine", old="off", new="on")


# ---------------------------------------------------------------------------
# End-to-end: significance filter wired into _handle_ha_event
#
# These tests mock handle_message (same pattern as TestEventFilteringPipeline)
# and verify the full pipeline with significance_filter enabled.
# ---------------------------------------------------------------------------


class TestSignificancePipeline:
    @pytest.mark.asyncio
    async def test_significance_blocks_routine_sensor(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("sensor.temperature", "22", "23",
                        new_attrs={"friendly_name": "Temp"})
        )
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_significance_passes_light_on(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("light.bedroom", "off", "on",
                        new_attrs={"friendly_name": "Bedroom Light"})
        )
        adapter.handle_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_significance_passes_unavailable(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("sensor.temp", "22", "unavailable",
                        new_attrs={"friendly_name": "Temp"})
        )
        adapter.handle_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_significance_passes_smoke_sensor(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("binary_sensor.smoke_alarm", "off", "on",
                        new_attrs={"friendly_name": "Smoke",
                                   "device_class": "smoke"})
        )
        adapter.handle_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_significance_blocks_routine_update_off(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("update.ha_core", "on", "off",
                        new_attrs={"friendly_name": "HA Core Update"})
        )
        adapter.handle_message.assert_not_called()

    @pytest.mark.asyncio
    async def test_significance_passes_update_available(self):
        adapter = _make_adapter(
            significance_filter=True, watch_all=True, cooldown_seconds=0,
        )
        await adapter._handle_ha_event(
            _make_event("update.ha_core", "off", "on",
                        new_attrs={"friendly_name": "HA Core Update"})
        )
        adapter.handle_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_significance_disabled_by_default(self):
        """Without significance_filter: true, the filter is skipped."""
        adapter = _make_adapter(watch_all=True, cooldown_seconds=0)
        await adapter._handle_ha_event(
            _make_event("sensor.temp", "22", "23",
                        new_attrs={"friendly_name": "Temp"})
        )
        adapter.handle_message.assert_called_once()  # passes through


# ---------------------------------------------------------------------------
# Significance filter config parsing
# ---------------------------------------------------------------------------


class TestSignificanceConfig:
    def test_significance_filter_default_false(self):
        config = PlatformConfig(enabled=True, token="tok")
        adapter = HomeAssistantAdapter(config)
        assert adapter._significance_filter is False

    def test_significance_filter_enabled(self):
        config = PlatformConfig(
            enabled=True, token="tok",
            extra={"significance_filter": True},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._significance_filter is True

    def test_significance_filter_string_true(self):
        config = PlatformConfig(
            enabled=True, token="tok",
            extra={"significance_filter": "true"},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._significance_filter is True

    def test_significance_filter_string_false(self):
        """String false must not accidentally enable the filter."""
        config = PlatformConfig(
            enabled=True, token="tok",
            extra={"significance_filter": "false"},
        )
        adapter = HomeAssistantAdapter(config)
        assert adapter._significance_filter is False
# ---------------------------------------------------------------------------


class TestConfigIntegration:
    def test_env_override_creates_ha_platform(self, monkeypatch):
        monkeypatch.setenv("HASS_TOKEN", "env-token")
        monkeypatch.setenv("HASS_URL", "http://10.0.0.5:8123")
        # Clear other platform tokens
        for v in ["TELEGRAM_BOT_TOKEN", "DISCORD_BOT_TOKEN", "SLACK_BOT_TOKEN"]:
            monkeypatch.delenv(v, raising=False)

        from gateway.config import load_gateway_config
        config = load_gateway_config()

        assert Platform.HOMEASSISTANT in config.platforms
        ha = config.platforms[Platform.HOMEASSISTANT]
        assert ha.enabled is True
        assert ha.token == "env-token"
        assert ha.extra["url"] == "http://10.0.0.5:8123"

    def test_no_env_no_platform(self, monkeypatch):
        for v in ["HASS_TOKEN", "HASS_URL", "TELEGRAM_BOT_TOKEN",
                   "DISCORD_BOT_TOKEN", "SLACK_BOT_TOKEN"]:
            monkeypatch.delenv(v, raising=False)

        from gateway.config import load_gateway_config
        config = load_gateway_config()
        assert Platform.HOMEASSISTANT not in config.platforms

    def test_config_roundtrip_preserves_extra(self):
        config = GatewayConfig(
            platforms={
                Platform.HOMEASSISTANT: PlatformConfig(
                    enabled=True,
                    token="tok",
                    extra={
                        "url": "http://ha:8123",
                        "watch_domains": ["climate"],
                        "cooldown_seconds": 45,
                    },
                ),
            },
        )
        d = config.to_dict()
        restored = GatewayConfig.from_dict(d)

        ha = restored.platforms[Platform.HOMEASSISTANT]
        assert ha.enabled is True
        assert ha.token == "tok"
        assert ha.extra["watch_domains"] == ["climate"]
        assert ha.extra["cooldown_seconds"] == 45

# ---------------------------------------------------------------------------
# send() via REST API
# ---------------------------------------------------------------------------


class TestSendViaRestApi:
    """send() uses REST API (not WebSocket) to avoid race conditions."""

    @staticmethod
    def _mock_aiohttp_session(response_status=200, response_text="OK"):
        """Build a mock aiohttp session + response for async-with patterns.

        aiohttp.ClientSession() is a sync constructor whose return value
        is used as ``async with session:``.  ``session.post(...)`` returns a
        context-manager (not a coroutine), so both layers use MagicMock for
        the call and AsyncMock only for ``__aenter__`` / ``__aexit__``.
        """
        mock_response = MagicMock()
        mock_response.status = response_status
        mock_response.text = AsyncMock(return_value=response_text)
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=False)

        mock_session = MagicMock()
        mock_session.post = MagicMock(return_value=mock_response)
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=False)

        return mock_session

    @pytest.mark.asyncio
    async def test_send_success(self):
        adapter = _make_adapter()
        mock_session = self._mock_aiohttp_session(200)

        with patch("plugins.platforms.homeassistant.adapter.aiohttp") as mock_aiohttp:
            mock_aiohttp.ClientSession = MagicMock(return_value=mock_session)
            mock_aiohttp.ClientTimeout = lambda total: total

            result = await adapter.send("ha_events", "Test notification")

        assert result.success is True
        # Verify the REST API was called with correct payload
        call_args = mock_session.post.call_args
        assert "/api/services/persistent_notification/create" in call_args[0][0]
        assert call_args[1]["json"]["title"] == "Hermes Agent"
        assert call_args[1]["json"]["message"] == "Test notification"
        assert "Bearer tok" in call_args[1]["headers"]["Authorization"]

    @pytest.mark.asyncio
    async def test_send_http_error(self):
        adapter = _make_adapter()
        mock_session = self._mock_aiohttp_session(401, "Unauthorized")

        with patch("plugins.platforms.homeassistant.adapter.aiohttp") as mock_aiohttp:
            mock_aiohttp.ClientSession = MagicMock(return_value=mock_session)
            mock_aiohttp.ClientTimeout = lambda total: total

            result = await adapter.send("ha_events", "Test")

        assert result.success is False
        assert "401" in result.error

    @pytest.mark.asyncio
    async def test_send_truncates_long_message(self):
        adapter = _make_adapter()
        mock_session = self._mock_aiohttp_session(200)
        long_message = "x" * 10000

        with patch("plugins.platforms.homeassistant.adapter.aiohttp") as mock_aiohttp:
            mock_aiohttp.ClientSession = MagicMock(return_value=mock_session)
            mock_aiohttp.ClientTimeout = lambda total: total

            await adapter.send("ha_events", long_message)

        sent_message = mock_session.post.call_args[1]["json"]["message"]
        assert len(sent_message) == 4096

    @pytest.mark.asyncio
    async def test_send_does_not_use_websocket(self):
        """send() must use REST API, not the WS connection (race condition fix)."""
        adapter = _make_adapter()
        adapter._ws = AsyncMock()  # Simulate an active WS
        mock_session = self._mock_aiohttp_session(200)

        with patch("plugins.platforms.homeassistant.adapter.aiohttp") as mock_aiohttp:
            mock_aiohttp.ClientSession = MagicMock(return_value=mock_session)
            mock_aiohttp.ClientTimeout = lambda total: total

            await adapter.send("ha_events", "Test")

        # WS should NOT have been used for sending
        adapter._ws.send_json.assert_not_called()
        adapter._ws.receive_json.assert_not_called()


# ---------------------------------------------------------------------------
# Toolset integration
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# WebSocket URL construction
# ---------------------------------------------------------------------------


class TestWsUrlConstruction:
    def test_http_to_ws(self):
        config = PlatformConfig(enabled=True, token="t", extra={"url": "http://ha:8123"})
        adapter = HomeAssistantAdapter(config)
        ws_url = adapter._hass_url.replace("http://", "ws://").replace("https://", "wss://")
        assert ws_url == "ws://ha:8123"

    def test_https_to_wss(self):
        config = PlatformConfig(enabled=True, token="t", extra={"url": "https://ha.example.com"})
        adapter = HomeAssistantAdapter(config)
        ws_url = adapter._hass_url.replace("http://", "ws://").replace("https://", "wss://")
        assert ws_url == "wss://ha.example.com"

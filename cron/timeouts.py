"""Shared cron timeout resolution.

The gateway, scheduler, and one-shot claim recovery must agree on the same
inactivity budget.  Historically only ``HERMES_CRON_TIMEOUT`` carried this
value, which encouraged operators to hand-edit service definitions.  Those
edits are lost whenever launchd/systemd units are regenerated.  Keep the
environment variable as the highest-precedence escape hatch, but make the
durable ``cron.inactivity_timeout_seconds`` config field authoritative when
the environment is unset.
"""

from __future__ import annotations

import logging
import math
import os
from collections.abc import Mapping
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS = 600.0


def _coerce_timeout(value: Any, source: str) -> float | None:
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        logger.warning("Invalid %s=%r; using the next cron timeout source", source, value)
        return None
    if not math.isfinite(timeout) or timeout < 0:
        logger.warning("Invalid %s=%r; using the next cron timeout source", source, value)
        return None
    return timeout


def configured_cron_inactivity_timeout_seconds(
    config: Mapping[str, Any] | None = None,
) -> float:
    """Return the durable config value, falling back to the safe default.

    ``0`` intentionally means unlimited.  Invalid or negative values fail
    back to the bounded default rather than accidentally disabling the guard.
    """
    if config is None:
        try:
            from hermes_cli.config import load_config_readonly

            loaded = load_config_readonly()
            config = loaded if isinstance(loaded, Mapping) else {}
        except Exception as exc:  # pragma: no cover - defensive startup path
            logger.debug("Failed to load cron inactivity timeout config: %s", exc)
            config = {}

    cron_cfg = config.get("cron", {}) if isinstance(config, Mapping) else {}
    configured = (
        cron_cfg.get("inactivity_timeout_seconds")
        if isinstance(cron_cfg, Mapping)
        else None
    )
    if configured is None:
        return DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS
    parsed = _coerce_timeout(configured, "cron.inactivity_timeout_seconds")
    return (
        parsed
        if parsed is not None
        else DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS
    )


def resolve_cron_inactivity_timeout_seconds(
    config: Mapping[str, Any] | None = None,
    environ: Mapping[str, str] | None = None,
) -> float:
    """Resolve env override -> durable config -> bounded default."""
    env = os.environ if environ is None else environ
    raw = str(env.get("HERMES_CRON_TIMEOUT", "")).strip()
    if raw:
        parsed = _coerce_timeout(raw, "HERMES_CRON_TIMEOUT")
        if parsed is not None:
            return parsed
    return configured_cron_inactivity_timeout_seconds(config)

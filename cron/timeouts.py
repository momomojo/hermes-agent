"""Shared cron inactivity-timeout resolution.

The gateway, scheduler, and one-shot claim recovery must agree on the same
inactivity budget.  Keep ``HERMES_CRON_TIMEOUT`` as the highest-precedence
escape hatch, but use the profile-scoped
``cron.inactivity_timeout_seconds`` setting when the environment is unset.
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
    # bool is an int subclass: accepting it would turn true into a one-second
    # timeout and false into the explicit unlimited sentinel.
    if isinstance(value, bool):
        logger.warning(
            "Invalid %s=%r; using the next cron timeout source", source, value
        )
        return None
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        logger.warning(
            "Invalid %s=%r; using the next cron timeout source", source, value
        )
        return None
    if not math.isfinite(timeout) or timeout < 0:
        logger.warning(
            "Invalid %s=%r; using the next cron timeout source", source, value
        )
        return None
    return timeout


def configured_cron_inactivity_timeout_seconds(
    config: Mapping[str, Any] | None = None,
) -> float:
    """Return the profile config value, or the safe bounded default.

    ``0`` intentionally means unlimited. Invalid values fall back to 600
    seconds instead of accidentally disabling the inactivity guard.
    """
    if config is None:
        try:
            from hermes_cli.config import load_config_readonly

            loaded = load_config_readonly()
            config = loaded if isinstance(loaded, Mapping) else {}
        except Exception as exc:  # pragma: no cover - defensive startup path
            logger.debug("Failed to load cron inactivity timeout config: %s", exc)
            config = {}

    cron_config = config.get("cron", {}) if isinstance(config, Mapping) else {}
    configured = (
        cron_config.get("inactivity_timeout_seconds")
        if isinstance(cron_config, Mapping)
        else None
    )
    if configured is None:
        return DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS
    parsed = _coerce_timeout(configured, "cron.inactivity_timeout_seconds")
    return parsed if parsed is not None else DEFAULT_CRON_INACTIVITY_TIMEOUT_SECONDS


def resolve_cron_inactivity_timeout_seconds(
    config: Mapping[str, Any] | None = None,
    environ: Mapping[str, Any] | None = None,
) -> float:
    """Resolve environment override, then profile config, then 600 seconds."""
    env = os.environ if environ is None else environ
    raw = env.get("HERMES_CRON_TIMEOUT", "")
    if isinstance(raw, str):
        raw = raw.strip()
    if raw not in ("", None):
        parsed = _coerce_timeout(raw, "HERMES_CRON_TIMEOUT")
        if parsed is not None:
            return parsed
    return configured_cron_inactivity_timeout_seconds(config)

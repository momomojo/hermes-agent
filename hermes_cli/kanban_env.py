"""Kanban environment isolation helpers.

The dispatcher injects task lifecycle variables into real worker processes.
Those variables must not leak into independent child sessions launched by a
worker, because their mere presence enables task-scoped lifecycle tools and
defaults them to the parent task.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping


KANBAN_LIFECYCLE_ENV_VARS: frozenset[str] = frozenset(
    {
        "HERMES_KANBAN_TASK",
        "HERMES_KANBAN_RUN",
        "HERMES_KANBAN_RUN_ID",
        "HERMES_KANBAN_WORKSPACE",
        "HERMES_KANBAN_BRANCH",
        "HERMES_KANBAN_CLAIM_LOCK",
        "HERMES_KANBAN_GOAL_MODE",
        "HERMES_KANBAN_GOAL_MAX_TURNS",
        "HERMES_KANBAN_MODEL",
        "HERMES_KANBAN_REASONING_EFFORT",
    }
)


def strip_kanban_lifecycle_env(env: MutableMapping[str, str] | None = None) -> tuple[str, ...]:
    """Remove dispatcher-only Kanban lifecycle variables from *env*.

    Board/config pins such as ``HERMES_KANBAN_DB``, ``HERMES_KANBAN_BOARD``,
    and ``HERMES_KANBAN_WORKSPACES_ROOT`` are intentionally preserved: cron
    scripts and orchestrator sessions may need them to address the right board
    without being task-scoped workers.
    """

    target = os.environ if env is None else env
    removed: list[str] = []
    for key in sorted(KANBAN_LIFECYCLE_ENV_VARS):
        if key in target:
            target.pop(key, None)
            removed.append(key)
    return tuple(removed)

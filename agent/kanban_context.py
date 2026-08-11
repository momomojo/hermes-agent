"""Context-local lifecycle binding for dispatcher Kanban workers.

A Kanban worker's lifecycle identity arrives through process environment because
its own tool calls and dispatcher heartbeat need it.  Nested scheduler work is
not a worker, though: an inline cron run must be able to retain the profile and
board pins without inheriting the caller's task/run/claim binding.  This module
uses a ContextVar rather than mutating ``os.environ`` so concurrently running
scheduler jobs and background threads cannot observe each other's scope.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator, Optional


_LIFECYCLE_TASK_SUPPRESSED: ContextVar[bool] = ContextVar(
    "kanban_lifecycle_task_suppressed", default=False
)


def get_lifecycle_task_id() -> Optional[str]:
    """Return the dispatcher task binding for this execution context, if any.

    Board/profile pin variables intentionally remain in ``os.environ``.  Only
    the task lifecycle binding is hidden for nested scheduler work.
    """
    if _LIFECYCLE_TASK_SUPPRESSED.get():
        return None
    task_id = (os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    return task_id or None


def has_lifecycle_task() -> bool:
    """Whether this execution context is a dispatcher-bound task worker."""
    return get_lifecycle_task_id() is not None


def lifecycle_task_suppressed() -> bool:
    """Whether nested scheduler work must omit worker lifecycle env bindings."""
    return _LIFECYCLE_TASK_SUPPRESSED.get()


@contextmanager
def cron_scheduler_context() -> Iterator[None]:
    """Run nested cron work without inheriting a caller's Kanban lifecycle.

    The mask is context-local and exception-safe.  It deliberately does not
    alter process-global environment state, so other scheduler threads retain
    their own context and the caller's worker env is restored by construction.
    """
    token = _LIFECYCLE_TASK_SUPPRESSED.set(True)
    try:
        yield
    finally:
        _LIFECYCLE_TASK_SUPPRESSED.reset(token)


__all__ = [
    "cron_scheduler_context",
    "get_lifecycle_task_id",
    "has_lifecycle_task",
    "lifecycle_task_suppressed",
]

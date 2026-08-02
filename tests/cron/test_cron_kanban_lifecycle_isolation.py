"""Regression coverage for cron isolation from a caller's Kanban worker lifecycle.

An agent-backed cron force-run may execute inline in a dispatcher worker process.
The scheduler must retain board/profile pins while treating the cron agent and its
background review as an independent, unscoped scheduler session.
"""
from __future__ import annotations

import json
import os
import shlex
import sys
from unittest.mock import patch

import pytest


_LIFECYCLE_ENV = {
    "HERMES_KANBAN_TASK": "t_parent_worker",
    "HERMES_KANBAN_RUN_ID": "42",
    "HERMES_KANBAN_WORKSPACE": "/tmp/parent-workspace",
    "HERMES_KANBAN_BRANCH": "wt/t_parent_worker",
    "HERMES_KANBAN_CLAIM_LOCK": "parent-claim",
}
_PIN_ENV = {
    "HERMES_KANBAN_DB": "/tmp/pinned-kanban.db",
    "HERMES_KANBAN_BOARD": "pinned-board",
    "HERMES_KANBAN_WORKSPACES_ROOT": "/tmp/pinned-workspaces",
}
_PROFILE_ENV = {"HERMES_PROFILE": "parent-worker-profile"}


@pytest.fixture
def parent_worker_env(monkeypatch, tmp_path):
    for name, value in _LIFECYCLE_ENV.items():
        monkeypatch.setenv(name, value)
    for name, value in _PIN_ENV.items():
        monkeypatch.setenv(name, value)
    for name, value in _PROFILE_ENV.items():
        monkeypatch.setenv(name, value)
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return monkeypatch


def test_scheduler_context_hides_parent_lifecycle_but_preserves_board_pins(parent_worker_env):
    """Tool registration and the stop guard cannot see a parent worker task."""
    from agent.kanban_context import cron_scheduler_context
    from agent.kanban_stop import build_kanban_stop_nudge
    from model_tools import _clear_tool_defs_cache, get_tool_definitions

    _clear_tool_defs_cache()
    with cron_scheduler_context():
        _clear_tool_defs_cache()
        tools = get_tool_definitions(enabled_toolsets=["terminal"], quiet_mode=True)
        names = {tool["function"]["name"] for tool in tools}
        assert not any(name.startswith("kanban_") for name in names)
        assert build_kanban_stop_nudge(messages=[]) is None
        assert os.environ["HERMES_KANBAN_DB"] == _PIN_ENV["HERMES_KANBAN_DB"]
        assert os.environ["HERMES_KANBAN_BOARD"] == _PIN_ENV["HERMES_KANBAN_BOARD"]
        assert os.environ["HERMES_KANBAN_WORKSPACES_ROOT"] == _PIN_ENV["HERMES_KANBAN_WORKSPACES_ROOT"]

    assert {name: os.environ.get(name) for name in _LIFECYCLE_ENV} == _LIFECYCLE_ENV
    assert build_kanban_stop_nudge(messages=[]) is not None


def test_run_job_enters_scheduler_context_for_direct_scheduler_call(parent_worker_env):
    """Scheduled fires get the same isolation even outside cronjob(action='run')."""
    from agent.kanban_context import get_lifecycle_task_id
    from cron import scheduler

    with patch.object(
        scheduler,
        "_run_job_in_scheduler_context",
        side_effect=lambda *_args, **_kwargs: (get_lifecycle_task_id(), "", "", None),
    ):
        result = scheduler.run_job({"id": "scheduled-cron"})

    assert result[0] is None
    assert get_lifecycle_task_id() == _LIFECYCLE_ENV["HERMES_KANBAN_TASK"]


def test_scheduler_context_restores_parent_lifecycle_after_exception(parent_worker_env):
    """Context-local masking is restored after exceptions without env mutation."""
    from agent.kanban_context import cron_scheduler_context, get_lifecycle_task_id

    with pytest.raises(RuntimeError, match="boom"):
        with cron_scheduler_context():
            assert get_lifecycle_task_id() is None
            raise RuntimeError("boom")

    assert get_lifecycle_task_id() == _LIFECYCLE_ENV["HERMES_KANBAN_TASK"]
    assert {name: os.environ.get(name) for name in _LIFECYCLE_ENV} == _LIFECYCLE_ENV


def test_scheduler_context_strips_parent_lifecycle_from_local_subprocesses(parent_worker_env):
    """Nested cron children cannot reacquire the parent worker lifecycle."""
    from agent.kanban_context import cron_scheduler_context
    from tools.environments.local import (
        LocalEnvironment,
        _make_run_env,
        _sanitize_subprocess_env,
        hermes_subprocess_env,
    )

    child_program = "\n".join((
        "import json, os",
        "from tools.kanban_tools import _handle_block, _handle_complete, _handle_heartbeat",
        f"names = {tuple(_LIFECYCLE_ENV)!r}",
        "print(json.dumps({'env': {name: os.environ.get(name) for name in names}, "
        "'heartbeat': _handle_heartbeat({}), "
        "'complete': _handle_complete({'summary': 'should not persist'}), "
        "'block': _handle_block({'reason': 'should not persist'})}))",
    ))
    environment = LocalEnvironment(cwd=os.getcwd(), timeout=10)
    try:
        outside_envs = (
            _make_run_env({}),
            _sanitize_subprocess_env(os.environ.copy()),
            hermes_subprocess_env(),
        )
        for env in outside_envs:
            assert {name: env.get(name) for name in _LIFECYCLE_ENV} == _LIFECYCLE_ENV
            assert env["HERMES_HOME"] == os.environ["HERMES_HOME"]
            assert {name: env.get(name) for name in _PROFILE_ENV} == _PROFILE_ENV
            assert {name: env.get(name) for name in _PIN_ENV} == _PIN_ENV

        with cron_scheduler_context():
            nested_envs = (
                _make_run_env({}),
                _sanitize_subprocess_env(os.environ.copy()),
                hermes_subprocess_env(),
            )
            for env in nested_envs:
                assert not set(_LIFECYCLE_ENV) & set(env)
                assert env["HERMES_HOME"] == os.environ["HERMES_HOME"]
                assert {name: env.get(name) for name in _PROFILE_ENV} == _PROFILE_ENV
                assert {name: env.get(name) for name in _PIN_ENV} == _PIN_ENV

            child = environment._run_bash(
                f"{shlex.quote(sys.executable)} -c {shlex.quote(child_program)}"
            )
            output, _ = child.communicate(timeout=10)

        child_result = json.loads(output)
        assert child_result["env"] == {name: None for name in _LIFECYCLE_ENV}
        for action in ("heartbeat", "complete", "block"):
            assert "task_id is required" in child_result[action]
    finally:
        environment.cleanup()

    assert {name: os.environ.get(name) for name in _LIFECYCLE_ENV} == _LIFECYCLE_ENV


def test_non_kanban_check_fn_cache_is_unchanged_in_scheduler_context():
    """Scheduler isolation does not disturb normal registry availability caching."""
    from agent.kanban_context import cron_scheduler_context
    from tools.registry import _check_fn_cached, invalidate_check_fn_cache

    calls = {"count": 0}

    def check_fn():
        calls["count"] += 1
        return True

    invalidate_check_fn_cache()
    try:
        assert _check_fn_cached(check_fn) is True
        with cron_scheduler_context():
            assert _check_fn_cached(check_fn) is True
        assert calls["count"] == 1
    finally:
        invalidate_check_fn_cache()


def test_inline_force_run_uses_unscoped_scheduler_context(parent_worker_env):
    """cronjob(action='run') hands run_one_job an isolated context inline."""
    from agent.kanban_context import get_lifecycle_task_id
    from tools.cronjob_tools import _execute_job_now

    job = {"id": "inline-cron", "name": "inline cron", "prompt": "brief"}
    observed = {}

    def fake_run_one_job(_job):
        observed["task"] = get_lifecycle_task_id()
        observed["raw_task"] = os.environ.get("HERMES_KANBAN_TASK")
        return True

    with patch("tools.cronjob_tools.claim_job_for_fire", return_value=True), \
         patch("cron.scheduler.run_one_job", side_effect=fake_run_one_job), \
         patch("tools.cronjob_tools.get_job", return_value={"last_status": "ok"}):
        result = _execute_job_now(job)

    assert result["success"] is True
    assert observed == {
        "task": None,
        "raw_task": _LIFECYCLE_ENV["HERMES_KANBAN_TASK"],
    }
    assert {name: os.environ.get(name) for name in _LIFECYCLE_ENV} == _LIFECYCLE_ENV


def test_background_review_target_inherits_scheduler_context(parent_worker_env):
    """The post-response curator cannot reacquire the caller's lifecycle scope."""
    from agent.background_review import spawn_background_review_thread
    from agent.kanban_context import cron_scheduler_context, get_lifecycle_task_id

    observed = []

    class Agent:
        _SKILL_REVIEW_PROMPT = "review"

    with cron_scheduler_context(), \
         patch("agent.background_review._run_review_in_thread", side_effect=lambda *_: observed.append(get_lifecycle_task_id())):
        target, _ = spawn_background_review_thread(Agent(), [], review_skills=True)
        target()

    assert observed == [None]


def test_unscoped_kanban_cron_keeps_explicit_orchestrator_tools(parent_worker_env, tmp_path):
    """A cron job that explicitly enables Kanban remains an unscoped orchestrator."""
    from agent.kanban_context import cron_scheduler_context
    from model_tools import _clear_tool_defs_cache, get_tool_definitions

    # Prime the registry with the parent worker's lifecycle verdict first. The
    # nested cron call below must not reuse that process-wide result.
    _clear_tool_defs_cache()
    parent_tools = get_tool_definitions(enabled_toolsets=["kanban"], quiet_mode=True)
    parent_names = {tool["function"]["name"] for tool in parent_tools}
    assert "kanban_show" in parent_names
    assert "kanban_list" not in parent_names

    home = tmp_path / "orchestrator-home"
    home.mkdir()
    (home / "config.yaml").write_text("toolsets:\n  - kanban\n", encoding="utf-8")
    parent_worker_env.setenv("HERMES_HOME", str(home))

    with cron_scheduler_context():
        _clear_tool_defs_cache()
        tools = get_tool_definitions(enabled_toolsets=["kanban"], quiet_mode=True)
        names = {tool["function"]["name"] for tool in tools}

    assert {"kanban_list", "kanban_show", "kanban_complete", "kanban_block"}.issubset(names)


def test_non_contextual_check_fn_keeps_its_ttl_verdict_in_scheduler_context(parent_worker_env):
    """The ContextVar opt-out does not alter shared cache behavior for other tools."""
    from agent.kanban_context import cron_scheduler_context
    from tools.registry import ToolRegistry, invalidate_check_fn_cache

    calls = {"count": 0}

    def general_check():
        calls["count"] += 1
        return True

    reg = ToolRegistry()
    reg.register(
        name="general_cached_tool",
        toolset="general-cache-test",
        schema={"name": "general_cached_tool", "parameters": {"type": "object"}},
        handler=lambda _args, **_kwargs: "{}",
        check_fn=general_check,
    )

    invalidate_check_fn_cache()
    try:
        assert {tool["function"]["name"] for tool in reg.get_definitions({"general_cached_tool"})} == {
            "general_cached_tool"
        }
        with cron_scheduler_context():
            assert {tool["function"]["name"] for tool in reg.get_definitions({"general_cached_tool"})} == {
                "general_cached_tool"
            }
        # ``general_check`` has no ContextVar opt-out marker, so the scheduler
        # boundary reuses its normal process-wide TTL cache rather than probing
        # it again or altering its cached availability verdict.
        assert calls == {"count": 1}
    finally:
        invalidate_check_fn_cache()

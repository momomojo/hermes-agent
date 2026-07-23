import json
import logging
import os
import sys
import types

from hermes_cli.kanban_env import (
    KANBAN_LIFECYCLE_ENV_VARS,
    strip_kanban_lifecycle_env,
)


BOARD_PIN_ENV = {
    "HERMES_KANBAN_DB": "/tmp/hermes-kanban.db",
    "HERMES_KANBAN_BOARD": "ops",
    "HERMES_KANBAN_WORKSPACES_ROOT": "/tmp/hermes-kanban-workspaces",
    "HERMES_KANBAN_HOME": "/tmp/hermes-kanban-home",
}


def _seed_parent_worker_env(monkeypatch) -> None:
    for key in KANBAN_LIFECYCLE_ENV_VARS:
        monkeypatch.setenv(key, f"parent-{key.lower()}")
    for key, value in BOARD_PIN_ENV.items():
        monkeypatch.setenv(key, value)


def _assert_lifecycle_stripped(env: dict[str, str]) -> None:
    for key in KANBAN_LIFECYCLE_ENV_VARS:
        assert key not in env


def _assert_board_pins_preserved(env: dict[str, str]) -> None:
    for key, value in BOARD_PIN_ENV.items():
        assert env.get(key) == value


def test_strip_kanban_lifecycle_env_preserves_board_pins():
    env = {key: f"value-{key}" for key in KANBAN_LIFECYCLE_ENV_VARS}
    env.update(BOARD_PIN_ENV)

    removed = strip_kanban_lifecycle_env(env)

    assert set(removed) == set(KANBAN_LIFECYCLE_ENV_VARS)
    _assert_lifecycle_stripped(env)
    _assert_board_pins_preserved(env)


def test_terminal_subprocess_env_drops_parent_worker_lifecycle(monkeypatch):
    from tools.environments.local import _make_run_env

    _seed_parent_worker_env(monkeypatch)

    run_env = _make_run_env({})

    _assert_lifecycle_stripped(run_env)
    _assert_board_pins_preserved(run_env)


def test_sanitized_subprocess_env_drops_lifecycle_but_keeps_board_pins():
    from tools.environments.local import _sanitize_subprocess_env

    env = {key: f"value-{key}" for key in KANBAN_LIFECYCLE_ENV_VARS}
    env.update(BOARD_PIN_ENV)

    sanitized = _sanitize_subprocess_env(env)

    _assert_lifecycle_stripped(sanitized)
    _assert_board_pins_preserved(sanitized)


def test_oneshot_scrubs_inherited_worker_lifecycle_before_agent(monkeypatch, capsys):
    import hermes_cli.oneshot as oneshot

    _seed_parent_worker_env(monkeypatch)
    captured: dict[str, dict[str, str]] = {}

    def fake_run_agent(*args, **kwargs):
        captured["env"] = dict(os.environ)
        return "ok", {"final_response": "ok", "completed": True}

    monkeypatch.setattr(oneshot, "_run_agent", fake_run_agent)

    try:
        rc = oneshot.run_oneshot("judge this")
    finally:
        logging.disable(logging.NOTSET)

    assert rc == 0
    assert capsys.readouterr().out == "ok\n"
    _assert_lifecycle_stripped(captured["env"])
    _assert_board_pins_preserved(captured["env"])


def test_cron_agent_run_scrubs_parent_worker_lifecycle(monkeypatch, tmp_path):
    import cron.scheduler as scheduler
    import hermes_cli.env_loader as env_loader
    import hermes_cli.runtime_provider as runtime_provider

    _seed_parent_worker_env(monkeypatch)

    captured: dict[str, dict[str, str]] = {}

    class FakeAIAgent:
        def __init__(self, **kwargs):
            captured["init_env"] = dict(os.environ)

        def run_conversation(self, prompt):
            captured["run_env"] = dict(os.environ)
            return {
                "completed": True,
                "failed": False,
                "final_response": "cron ok",
                "turn_exit_reason": "",
            }

        def get_activity_summary(self):
            return {"seconds_since_activity": 0.0}

        @staticmethod
        def _format_turn_completion_explanation(reason):
            return ""

    fake_run_agent = types.ModuleType("run_agent")
    fake_run_agent.AIAgent = FakeAIAgent
    monkeypatch.setitem(sys.modules, "run_agent", fake_run_agent)

    class FakeSessionDB:
        def set_session_title(self, *args, **kwargs):
            return None

    fake_hermes_state = types.ModuleType("hermes_state")
    fake_hermes_state.SessionDB = FakeSessionDB
    monkeypatch.setitem(sys.modules, "hermes_state", fake_hermes_state)

    monkeypatch.setattr(scheduler, "_get_hermes_home", lambda: tmp_path)
    monkeypatch.setattr(scheduler, "_build_job_prompt", lambda job, prerun_script=None: job["prompt"])
    monkeypatch.setattr(scheduler, "_resolve_origin", lambda job: {})
    monkeypatch.setattr(scheduler, "_resolve_delivery_target", lambda job: None)
    monkeypatch.setattr(scheduler, "_guard_job_credential_exfil", lambda job: None)
    monkeypatch.setattr(scheduler, "_resolve_cron_enabled_toolsets", lambda job, cfg: ["terminal"])
    monkeypatch.setattr(scheduler, "_resolve_cron_disabled_toolsets", lambda cfg: [])
    monkeypatch.setattr(scheduler, "get_fallback_chain", lambda cfg: [])
    monkeypatch.setattr(scheduler, "_record_no_agent_watchdog", lambda *args, **kwargs: "")
    monkeypatch.setattr(env_loader, "reset_secret_source_cache", lambda: None)
    monkeypatch.setattr(env_loader, "load_hermes_dotenv", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        runtime_provider,
        "resolve_runtime_provider",
        lambda **kwargs: {
            "provider": "",
            "api_key": None,
            "base_url": None,
            "api_mode": None,
            "command": None,
            "args": None,
        },
    )

    success, _doc, final_response, error = scheduler.run_job(
        {
            "id": "job_agent",
            "name": "agent cron",
            "prompt": "check the queue",
            "model": "fake-model",
            "schedule_display": "manual",
        }
    )

    assert success is True
    assert error is None
    assert final_response == "cron ok"
    _assert_lifecycle_stripped(captured["init_env"])
    _assert_lifecycle_stripped(captured["run_env"])
    _assert_board_pins_preserved(captured["init_env"])
    _assert_board_pins_preserved(captured["run_env"])


def test_no_agent_cron_script_env_strips_lifecycle_and_keeps_board_pins(
    monkeypatch, tmp_path
):
    import cron.scheduler as scheduler

    _seed_parent_worker_env(monkeypatch)
    hermes_home = tmp_path / "home"
    scripts_dir = hermes_home / "scripts"
    scripts_dir.mkdir(parents=True)
    script = scripts_dir / "show_env.py"
    script.write_text(
        "import json, os\n"
        "keys = [\n"
        "    'HERMES_KANBAN_TASK',\n"
        "    'HERMES_KANBAN_RUN_ID',\n"
        "    'HERMES_KANBAN_DB',\n"
        "    'HERMES_KANBAN_BOARD',\n"
        "    'HERMES_KANBAN_WORKSPACES_ROOT',\n"
        "]\n"
        "print(json.dumps({key: os.environ.get(key) for key in keys}, sort_keys=True))\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(scheduler, "_get_hermes_home", lambda: hermes_home)
    monkeypatch.setattr(scheduler, "_record_no_agent_watchdog", lambda *args, **kwargs: "")

    success, _doc, final_response, error = scheduler.run_job(
        {
            "id": "job_no_agent",
            "name": "no-agent cron",
            "no_agent": True,
            "script": "show_env.py",
            "schedule_display": "manual",
        }
    )

    assert success is True
    assert error is None
    seen = json.loads(final_response)
    assert seen["HERMES_KANBAN_TASK"] is None
    assert seen["HERMES_KANBAN_RUN_ID"] is None
    assert seen["HERMES_KANBAN_DB"] == BOARD_PIN_ENV["HERMES_KANBAN_DB"]
    assert seen["HERMES_KANBAN_BOARD"] == BOARD_PIN_ENV["HERMES_KANBAN_BOARD"]
    assert (
        seen["HERMES_KANBAN_WORKSPACES_ROOT"]
        == BOARD_PIN_ENV["HERMES_KANBAN_WORKSPACES_ROOT"]
    )

"""Model-facing Kanban workers cannot mutate host control-plane state."""

from __future__ import annotations

import json
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.delegation_context import non_dispatcher_owned_context


def _env_config(cwd: Path) -> dict:
    return {
        "env_type": "local",
        "timeout": 180,
        "cwd": str(cwd),
        "host_cwd": None,
        "modal_mode": "auto",
        "docker_image": "",
        "singularity_image": "",
        "modal_image": "",
        "daytona_image": "",
    }


@pytest.fixture
def worker(tmp_path, monkeypatch):
    workspace = tmp_path / "repo" / ".worktrees" / "t_safe"
    workspace.mkdir(parents=True)
    (workspace / ".git").write_text(
        "gitdir: ../../.git/worktrees/t_safe\n", encoding="utf-8"
    )
    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HERMES_SESSION_SOURCE", "kanban")
    monkeypatch.setenv("HERMES_KANBAN_TASK", "t_safe")
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", "17")
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", "host:worker:claim")
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", "radulator/t_safe-change")
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_DB", str(tmp_path / "board" / "kanban.db"))
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(tmp_path / "repo"))
    return workspace


def _run_terminal(command: str, workspace: Path, **kwargs):
    from tools.terminal_tool import terminal_tool

    mock_env = MagicMock()
    mock_env.execute.return_value = {"output": "ok", "returncode": 0}
    mock_env.cwd = str(workspace)
    with ExitStack() as stack:
        stack.enter_context(
            patch("tools.terminal_tool._get_env_config", return_value=_env_config(workspace))
        )
        stack.enter_context(patch("tools.terminal_tool._start_cleanup_thread"))
        stack.enter_context(
            patch("tools.terminal_tool._active_environments", {"default": mock_env})
        )
        stack.enter_context(patch("tools.terminal_tool._last_activity", {"default": 0}))
        stack.enter_context(
            patch(
                "tools.terminal_tool._check_all_guards",
                return_value={"approved": True},
            )
        )
        result = json.loads(terminal_tool(command=command, **kwargs))
    return result, mock_env


@pytest.mark.parametrize(
    "command",
    [
        "git add -A",
        "git commit -m worker",
        "git branch sibling",
        "git config core.hooksPath ./hooks",
        "git update-ref refs/heads/main HEAD",
        "git fetch origin",
        "git push origin HEAD",
        "gh pr create --fill",
        "printf attack > .git",
        "printf attack > $HERMES_KANBAN_TRUSTED_REPO_ROOT/.git/config",
    ],
)
def test_dispatcher_worker_terminal_cannot_mutate_git_or_publish(
    worker, command
):
    result, env = _run_terminal(command, worker, force=True)
    assert result["status"] == "blocked"
    assert "trusted Kanban Git broker" in result["error"]
    env.execute.assert_not_called()


@pytest.mark.parametrize("command", ["git status", "git diff", "git branch --show-current"])
def test_dispatcher_worker_allows_read_only_git(worker, command):
    result, env = _run_terminal(command, worker)
    assert result.get("status") != "blocked"
    env.execute.assert_called_once()


def test_cron_context_does_not_inherit_worker_terminal_authority(worker):
    with non_dispatcher_owned_context():
        result, env = _run_terminal("git commit -m cron", worker)
    assert result.get("status") != "blocked"
    env.execute.assert_called_once()


def test_stale_or_worker_supplied_repo_seal_fails_closed(worker, monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(tmp_path / "attacker"))
    result, env = _run_terminal("python -m pytest -q", worker)
    assert result["status"] == "blocked"
    assert "stale/confused-deputy" in result["error"]
    env.execute.assert_not_called()


def test_referenced_shell_script_cannot_hide_git_mutation(worker):
    script = worker / "mutate.sh"
    script.write_text("#!/bin/sh\ngit commit -m hidden\n", encoding="utf-8")
    result, env = _run_terminal("bash mutate.sh", worker)
    assert result["status"] == "blocked"
    assert "trusted Kanban Git broker" in result["error"]
    env.execute.assert_not_called()


def test_model_file_tools_cannot_write_board_or_sibling_paths(worker, tmp_path):
    from tools.file_tools import write_file_tool

    target = tmp_path / "board" / "kanban.db"
    result = json.loads(write_file_tool(str(target), "attacker"))
    assert "outside the assigned Kanban workspace" in result["error"]
    assert not target.exists()


def test_model_file_tools_can_write_normal_task_file(worker):
    from tools.file_tools import write_file_tool

    result = json.loads(write_file_tool("feature.txt", "safe\n"))
    assert not result.get("error")
    assert (worker / "feature.txt").read_text(encoding="utf-8") == "safe\n"


def test_model_file_tools_cannot_replace_worktree_gitfile(worker):
    from tools.file_tools import write_file_tool

    before = (worker / ".git").read_text(encoding="utf-8")
    result = json.loads(write_file_tool(".git", "gitdir: /attacker\n"))
    assert "Git metadata" in result["error"]
    assert (worker / ".git").read_text(encoding="utf-8") == before

"""Model-facing Kanban workers cannot mutate host control-plane state."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent.delegation_context import non_dispatcher_owned_context


def _env_config(cwd: Path, *, env_type: str = "local") -> dict:
    return {
        "env_type": env_type,
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
    from hermes_cli import kanban_db as kb

    db_path = tmp_path / "board" / "kanban.db"
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db_path))
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    conn = kb.connect(db_path=db_path)
    task_id = kb.create_task(
        conn,
        title="safe worker",
        initial_status="blocked",
        workspace_kind="worktree",
        workspace_path=str(tmp_path / "pending"),
        branch_name="wt/pending",
    )
    workspace = tmp_path / "repo" / ".worktrees" / task_id
    workspace.mkdir(parents=True)
    (workspace / ".git").write_text(
        f"gitdir: ../../.git/worktrees/{task_id}\n", encoding="utf-8"
    )
    branch = f"radulator/{task_id}-change"
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET workspace_path = ?, branch_name = ?, status = 'ready' "
            "WHERE id = ?",
            (str(workspace), branch, task_id),
        )
    claimed = kb.claim_task(conn, task_id, claimer="host:worker:claim")
    assert claimed is not None
    conn.close()

    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HERMES_SESSION_SOURCE", "kanban")
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(claimed.claim_lock))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACES_ROOT", str(workspace.parent))
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", branch)
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "")
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(tmp_path / "repo"))
    return workspace


@pytest.fixture
def scratch_worker(tmp_path, monkeypatch):
    """A real claimed scratch task has file/terminal authority but no Git seal."""
    from hermes_cli import kanban_db as kb

    db_path = tmp_path / "board" / "kanban.db"
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db_path))
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    conn = kb.connect(db_path=db_path)
    workspace = tmp_path / "workspaces" / "pending"
    task_id = kb.create_task(
        conn,
        title="scratch worker",
        initial_status="blocked",
        workspace_kind="scratch",
        workspace_path=str(workspace),
    )
    workspace = tmp_path / "workspaces" / task_id
    workspace.mkdir(parents=True)
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET workspace_path = ?, status = 'ready' WHERE id = ?",
            (str(workspace), task_id),
        )
    claimed = kb.claim_task(conn, task_id, claimer="host:scratch:claim")
    assert claimed is not None
    conn.close()

    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HERMES_SESSION_SOURCE", "kanban")
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(claimed.claim_lock))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACES_ROOT", str(workspace.parent))
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    for name in (
        "HERMES_KANBAN_BRANCH",
        "HERMES_KANBAN_PROJECT_ID",
        "HERMES_KANBAN_TRUSTED_REPO_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)
    return workspace


def _claimed_non_git_worker(tmp_path, monkeypatch, *, workspace_kind: str, legacy: bool):
    """Create an exact live non-Git assignment outside the managed task-id root."""
    from hermes_cli import kanban_db as kb

    db_path = tmp_path / "board" / "kanban.db"
    monkeypatch.setenv("HERMES_KANBAN_DB", str(db_path))
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "default")
    conn = kb.connect(db_path=db_path)
    workspace = tmp_path / ("legacy-explicit" if legacy else "durable-dir")
    workspace.mkdir()
    task_id = kb.create_task(
        conn,
        title=f"{workspace_kind} worker",
        initial_status="blocked",
        workspace_kind=workspace_kind,
        workspace_path=str(workspace),
    )
    with kb.write_txn(conn):
        conn.execute("UPDATE tasks SET status = 'ready' WHERE id = ?", (task_id,))
    claimed = kb.claim_task(conn, task_id, claimer=f"host:{workspace_kind}:claim")
    assert claimed is not None
    conn.close()

    monkeypatch.chdir(workspace)
    monkeypatch.setenv("HERMES_SESSION_SOURCE", "kanban")
    monkeypatch.setenv("HERMES_KANBAN_TASK", task_id)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))
    monkeypatch.setenv("HERMES_KANBAN_CLAIM_LOCK", str(claimed.claim_lock))
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(workspace))
    workspaces_root = tmp_path / "workspaces"
    workspaces_root.mkdir()
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACES_ROOT", str(workspaces_root))
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    for name in (
        "HERMES_KANBAN_BRANCH",
        "HERMES_KANBAN_PROJECT_ID",
        "HERMES_KANBAN_TRUSTED_REPO_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)
    return workspace


@pytest.fixture
def dir_worker(tmp_path, monkeypatch):
    return _claimed_non_git_worker(
        tmp_path, monkeypatch, workspace_kind="dir", legacy=False
    )


@pytest.fixture
def legacy_scratch_worker(tmp_path, monkeypatch):
    return _claimed_non_git_worker(
        tmp_path, monkeypatch, workspace_kind="scratch", legacy=True
    )


def _run_terminal(
    command: str,
    workspace: Path,
    *,
    env_type: str = "local",
    **kwargs,
):
    from tools.terminal_tool import terminal_tool

    mock_env = MagicMock()
    observed_boundaries = []

    def _execute(*_args, **_kwargs):
        from tools.kanban_worker_boundary import current_local_sandbox_workspace

        observed_boundaries.append(current_local_sandbox_workspace())
        return {"output": "ok", "returncode": 0}

    mock_env.execute.side_effect = _execute
    mock_env.cwd = str(workspace)
    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "tools.terminal_tool._get_env_config",
                return_value=_env_config(workspace, env_type=env_type),
            )
        )
        stack.enter_context(patch("tools.terminal_tool._start_cleanup_thread"))
        # Unit tests below use a mock LocalEnvironment to assert that the
        # boundary ContextVar surrounds env.execute(). Do not require the CI
        # host itself to have bwrap for that mock-only layer; the dedicated
        # Linux argv test verifies the exact bubblewrap policy, and the macOS
        # integration tests execute the real Seatbelt boundary end to end.
        stack.enter_context(
            patch(
                "tools.kanban_worker_boundary.local_sandbox_argv",
                side_effect=lambda argv, _workspace, **_trusted_options: list(argv),
            )
        )
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
    return result, mock_env, observed_boundaries


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
    result, env, _boundaries = _run_terminal(command, worker, force=True)
    assert result["status"] == "blocked"
    assert "trusted Kanban Git broker" in result["error"]
    env.execute.assert_not_called()


@pytest.mark.parametrize("command", ["git status", "git diff", "git branch --show-current"])
def test_dispatcher_worker_allows_read_only_git(worker, command):
    result, env, boundaries = _run_terminal(command, worker)
    assert result.get("status") != "blocked"
    env.execute.assert_called_once()
    assert boundaries == [worker.resolve()]


def test_cron_context_does_not_inherit_worker_terminal_authority(worker):
    with non_dispatcher_owned_context():
        result, env, boundaries = _run_terminal("git commit -m cron", worker)
    assert result.get("status") != "blocked"
    env.execute.assert_called_once()
    assert boundaries == [None]


def test_stale_or_worker_supplied_repo_seal_fails_closed(worker, monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(tmp_path / "attacker"))
    result, env, _boundaries = _run_terminal("python -m pytest -q", worker)
    assert result["status"] == "blocked"
    assert "stale/confused-deputy" in result["error"]
    env.execute.assert_not_called()


def test_reclaimed_live_claim_revokes_stale_worker_seal(worker):
    from hermes_cli import kanban_db as kb

    task_id = os.environ["HERMES_KANBAN_TASK"]
    old_run_id = int(os.environ["HERMES_KANBAN_RUN_ID"])
    db_path = Path(os.environ["HERMES_KANBAN_DB"])
    conn = kb.connect(db_path=db_path)
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE task_runs SET status = 'reclaimed', outcome = 'reclaimed', "
            "ended_at = 1 WHERE id = ?",
            (old_run_id,),
        )
        conn.execute(
            "UPDATE tasks SET status = 'ready', claim_lock = NULL, "
            "claim_expires = NULL, current_run_id = NULL WHERE id = ?",
            (task_id,),
        )
    successor = kb.claim_task(conn, task_id, claimer="host:successor:claim")
    assert successor is not None
    assert successor.current_run_id != old_run_id
    conn.close()

    result, env, _boundaries = _run_terminal("python -m pytest -q", worker)

    assert result["status"] == "blocked"
    assert "stale/confused-deputy" in result["error"]
    env.execute.assert_not_called()


def test_referenced_shell_script_cannot_hide_git_mutation(worker):
    script = worker / "mutate.sh"
    script.write_text("#!/bin/sh\ngit commit -m hidden\n", encoding="utf-8")
    result, env, _boundaries = _run_terminal("bash mutate.sh", worker)
    assert result["status"] == "blocked"
    assert "trusted Kanban Git broker" in result["error"]
    env.execute.assert_not_called()


def test_model_file_tools_cannot_write_board_or_sibling_paths(worker, tmp_path):
    from tools.file_tools import write_file_tool

    target = tmp_path / "board" / "kanban.db"
    before = target.read_bytes()
    result = json.loads(write_file_tool(str(target), "attacker"))
    assert "outside the assigned Kanban workspace" in result["error"]
    assert target.read_bytes() == before


def test_model_file_tools_can_write_normal_task_file(worker):
    from tools.file_tools import write_file_tool

    result = json.loads(write_file_tool("feature.txt", "safe\n"))
    assert not result.get("error")
    assert (worker / "feature.txt").read_text(encoding="utf-8") == "safe\n"


def test_claimed_scratch_worker_can_write_normal_task_file(scratch_worker):
    from tools.file_tools import write_file_tool

    result = json.loads(write_file_tool("notes.txt", "safe scratch output\n"))

    assert not result.get("error")
    assert (scratch_worker / "notes.txt").read_text(encoding="utf-8") == (
        "safe scratch output\n"
    )


def test_claimed_scratch_worker_can_run_foreground_terminal(scratch_worker):
    result, env, boundaries = _run_terminal("python -m pytest -q", scratch_worker)

    assert result.get("status") != "blocked"
    env.execute.assert_called_once()
    assert boundaries == [scratch_worker.resolve()]


@pytest.mark.parametrize("fixture_name", ["dir_worker", "legacy_scratch_worker"])
def test_durable_nonstandard_workspace_can_write_and_run_terminal(
    fixture_name, request
):
    from tools.file_tools import write_file_tool

    workspace = request.getfixturevalue(fixture_name)
    write_result = json.loads(write_file_tool("result.txt", "durable output\n"))
    terminal_result, env, boundaries = _run_terminal("python -m pytest -q", workspace)

    assert not write_result.get("error")
    assert (workspace / "result.txt").read_text(encoding="utf-8") == "durable output\n"
    assert terminal_result.get("status") != "blocked"
    env.execute.assert_called_once()
    assert boundaries == [workspace.resolve()]


def test_durable_nonstandard_workspace_rejects_worker_supplied_path(
    dir_worker, monkeypatch, tmp_path
):
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    monkeypatch.setenv("HERMES_KANBAN_WORKSPACE", str(attacker))
    monkeypatch.setenv("TERMINAL_CWD", str(attacker))

    result, env, boundaries = _run_terminal("python -m pytest -q", attacker)

    assert result["status"] == "blocked"
    assert "stale/confused-deputy" in result["error"]
    env.execute.assert_not_called()
    assert boundaries == []


@pytest.mark.parametrize("env_type", ["ssh", "docker"])
def test_claimed_scratch_worker_rejects_unverified_terminal_backend(
    scratch_worker, env_type
):
    result, env, boundaries = _run_terminal(
        "python -m pytest -q", scratch_worker, env_type=env_type
    )

    assert result["status"] == "blocked"
    assert "verified local filesystem sandbox" in result["error"]
    env.execute.assert_not_called()
    assert boundaries == []


def test_claimed_scratch_worker_rejects_background_terminal(scratch_worker):
    result, env, _boundaries = _run_terminal(
        "python -m pytest -q", scratch_worker, background=True
    )

    assert result["status"] == "blocked"
    assert "background" in result["error"]
    env.execute_background.assert_not_called()


def test_claimed_scratch_worker_uses_terminal_instead_of_execute_code(scratch_worker):
    from tools.kanban_worker_boundary import execute_code_violation

    violation = execute_code_violation()
    assert violation is not None and "execute_code" in violation


def test_scratch_worker_rejects_stale_worktree_authority(scratch_worker, monkeypatch):
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", "main")
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(scratch_worker.parent))
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "attacker")

    result, env, _boundaries = _run_terminal("python -m pytest -q", scratch_worker)

    assert result["status"] == "blocked"
    assert "stale/confused-deputy" in result["error"]
    env.execute.assert_not_called()


def test_model_file_tools_cannot_replace_worktree_gitfile(worker):
    from tools.file_tools import write_file_tool

    before = (worker / ".git").read_text(encoding="utf-8")
    result = json.loads(write_file_tool(".git", "gitdir: /attacker\n"))
    assert "Git metadata" in result["error"]
    assert (worker / ".git").read_text(encoding="utf-8") == before


def test_model_file_tools_cannot_read_profile_credentials(worker, tmp_path, monkeypatch):
    from tools.file_tools import read_file_tool

    hermes_home = tmp_path / "profiles" / "radulator"
    hermes_home.mkdir(parents=True)
    secret = hermes_home / ".env"
    secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))

    result = json.loads(read_file_tool(str(secret)))

    assert result["error"]
    assert "credential" in result["error"].lower()
    assert "must-not-enter-model" not in result["error"]


def test_dynamic_interpreter_runs_only_inside_os_sandbox(worker):
    command = (
        "python -c \"from pathlib import Path; "
        "Path(chr(46) + 'git/config').write_text('attack')\""
    )
    result, env, boundaries = _run_terminal(command, worker)

    assert result.get("status") != "blocked"
    env.execute.assert_called_once()
    assert boundaries == [worker.resolve()]


@pytest.mark.parametrize(
    "env_type",
    ["docker", "singularity", "modal", "daytona", "vercel_sandbox", "ssh"],
)
def test_dispatcher_worker_rejects_unverified_terminal_backends(worker, env_type):
    result, env, _boundaries = _run_terminal(
        "git status",
        worker,
        env_type=env_type,
    )

    assert result["status"] == "blocked"
    assert "verified local filesystem sandbox" in result["error"]
    env.execute.assert_not_called()


def test_dispatcher_worker_rejects_background_escape(worker):
    result, env, _boundaries = _run_terminal(
        "python -m pytest -q",
        worker,
        background=True,
    )

    assert result["status"] == "blocked"
    assert "background" in result["error"]
    env.execute.assert_not_called()


@pytest.mark.parametrize(
    "env_type",
    ["local", "docker", "singularity", "modal", "daytona", "vercel_sandbox", "ssh"],
)
def test_execute_code_is_disabled_for_dispatcher_worker(
    worker,
    monkeypatch,
    env_type,
):
    from tools.code_execution_tool import execute_code

    monkeypatch.setenv("GH_TOKEN", "must-not-enter-worker")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-worker-either")

    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "tools.terminal_tool._get_env_config",
                return_value=_env_config(worker, env_type=env_type),
            )
        )
        guard = stack.enter_context(
            patch(
                "tools.approval.check_execute_code_guard",
                side_effect=AssertionError("approval guard must not run"),
            )
        )
        result = json.loads(
            execute_code(
                "import os\nos.system('g' + 'it commit -am attack')",
            )
        )

    assert result["status"] == "blocked"
    assert "execute_code" in result["error"]
    guard.assert_not_called()


def test_worker_git_security_boundary_contract_is_pinned():
    from tools.kanban_worker_boundary import WORKER_GIT_SECURITY_BOUNDARY

    assert WORKER_GIT_SECURITY_BOUNDARY == "hermes.worker_git_isolation.v1"


def test_local_worker_subprocess_env_scrubs_publish_credentials(worker, monkeypatch):
    from tools.environments.local import hermes_subprocess_env

    monkeypatch.setenv("GH_TOKEN", "must-not-enter-worker")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-worker-either")

    child_env = hermes_subprocess_env(inherit_credentials=True)

    assert "GH_TOKEN" not in child_env
    assert "GITHUB_TOKEN" not in child_env


def test_local_run_env_never_allows_publish_credential_passthrough(monkeypatch):
    from tools.environments.local import _make_run_env

    monkeypatch.setenv("GH_TOKEN", "must-not-enter-worker")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-worker-either")
    with (
        patch("tools.env_passthrough.is_env_passthrough", return_value=True),
        patch(
            "tools.env_passthrough.resolve_passthrough_value",
            side_effect=lambda _name, value: value,
        ),
    ):
        child_env = _make_run_env({})

    assert "GH_TOKEN" not in child_env
    assert "GITHUB_TOKEN" not in child_env


def test_linux_bubblewrap_is_read_only_except_workspace_and_private_temp(
    worker,
    tmp_path,
    monkeypatch,
):
    from tools.kanban_worker_boundary import local_sandbox_argv

    hermes_home = tmp_path / "profiles" / "radulator"
    hermes_home.mkdir(parents=True)
    (hermes_home / ".env").write_text(
        "GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    with (
        patch("tools.kanban_worker_boundary.platform.system", return_value="Linux"),
        patch("tools.kanban_worker_boundary.shutil.which", return_value="/usr/bin/bwrap"),
    ):
        argv = local_sandbox_argv(
            ["/bin/sh", "-c", "true"], worker, seccomp_fd=71
        )

    joined = "\0".join(argv)
    assert argv[0] == "/usr/bin/bwrap"
    assert "--unshare-net" not in argv
    assert "--unshare-pid" in argv
    assert "--cap-drop\0ALL" in joined
    assert f"--seccomp\0{71}" in joined
    assert f"--ro-bind\0/\0/" not in joined
    assert "--tmpfs\0/run" in joined
    assert "--tmpfs\0/tmp" in joined
    assert "--tmpfs\0/var/tmp" in joined
    # Host / is never bound, so mounting a broad empty $HOME is unnecessary
    # and hides uv-managed interpreter roots that must be re-mounted exactly.
    # Leave the host home absent and expose only the explicit read-only runtime
    # subtrees below it; HOME itself still points at task-private temp.
    tmpfs_targets = {
        Path(argv[index + 1]).resolve(strict=False)
        for index, value in enumerate(argv[:-1])
        if value == "--tmpfs"
    }
    assert Path.home().resolve() not in tmpfs_targets
    assert (
        f"--ro-bind\0{Path.home().resolve()}\0{Path.home().resolve()}"
        not in joined
    )
    assert f"--bind\0{worker.resolve()}\0{worker.resolve()}" in joined
    assert (
        f"--ro-bind\0{(worker / '.git').resolve()}\0{(worker / '.git').resolve()}"
        in joined
    )
    assert f"--ro-bind\0" in joined
    masked_targets = {
        Path(argv[index + 2]).resolve(strict=False)
        for index, value in enumerate(argv[:-2])
        if value == "--ro-bind"
    }
    assert hermes_home.resolve() not in masked_targets


def test_linux_bubblewrap_pins_exact_resolved_python_executable_after_runtime_roots(
    worker,
    tmp_path,
):
    """A uv venv symlink target cannot disappear behind the empty-root view."""
    from tools.kanban_worker_boundary import local_sandbox_argv

    canonical_runtime = tmp_path / "canonical-python" / "cpython-3.11" / "bin"
    canonical_runtime.mkdir(parents=True)
    real_python = canonical_runtime / "python3.11"
    real_python.write_text("runtime", encoding="utf-8")
    lexical_parent = tmp_path / "uv-python-dir"
    lexical_parent.symlink_to(canonical_runtime.parent.parent)
    lexical_runtime = lexical_parent / "cpython-3.11" / "bin"
    lexical_python = lexical_runtime / "python3.11"
    venv_bin = tmp_path / "repo" / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(lexical_python)

    with (
        patch("tools.kanban_worker_boundary.platform.system", return_value="Linux"),
        patch("tools.kanban_worker_boundary.shutil.which", return_value="/usr/bin/bwrap"),
        patch("tools.kanban_worker_boundary.sys.executable", str(venv_python)),
        patch("tools.kanban_worker_boundary.sys.prefix", str(venv_bin.parent)),
        patch(
            "tools.kanban_worker_boundary.sys.base_prefix",
            str(canonical_runtime.parent),
        ),
    ):
        argv = local_sandbox_argv(
            [str(venv_python), "-c", "pass"], worker, seccomp_fd=71
        )

    alias_mount = ["--ro-bind", str(real_python), str(lexical_python)]
    exact_index = next(
        index
        for index in range(len(argv) - 2)
        if argv[index : index + 3] == alias_mount
    )
    runtime_root_mount = [
        "--ro-bind",
        str(canonical_runtime.parent),
        str(lexical_runtime.parent),
    ]
    runtime_index = next(
        index
        for index in range(len(argv) - 2)
        if argv[index : index + 3] == runtime_root_mount
    )
    assert exact_index > runtime_index


def test_linux_bubblewrap_rejects_worker_controlled_python_runtime_alias(worker):
    from tools.kanban_worker_boundary import (
        WorkerSandboxUnavailable,
        local_sandbox_argv,
    )

    runtime = worker / "runtime" / "bin"
    runtime.mkdir(parents=True)
    real_python = runtime / "python3.11"
    real_python.write_text("worker-controlled", encoding="utf-8")
    venv_bin = worker / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    venv_python = venv_bin / "python"
    venv_python.symlink_to(real_python)

    with (
        patch("tools.kanban_worker_boundary.platform.system", return_value="Linux"),
        patch("tools.kanban_worker_boundary.shutil.which", return_value="/usr/bin/bwrap"),
        patch("tools.kanban_worker_boundary.sys.executable", str(venv_python)),
        pytest.raises(WorkerSandboxUnavailable, match="Python runtime alias"),
    ):
        local_sandbox_argv(
            [str(venv_python), "-c", "pass"], worker, seccomp_fd=71
        )


def test_linux_sandbox_fails_closed_without_seccomp_fd(worker):
    from tools.kanban_worker_boundary import (
        WorkerSandboxUnavailable,
        local_sandbox_argv,
    )

    with (
        patch("tools.kanban_worker_boundary.platform.system", return_value="Linux"),
        patch("tools.kanban_worker_boundary.shutil.which", return_value="/usr/bin/bwrap"),
        pytest.raises(WorkerSandboxUnavailable, match="seccomp"),
    ):
        local_sandbox_argv(["/bin/true"], worker)


@pytest.mark.parametrize("machine", ["x86_64", "aarch64"])
def test_linux_network_seccomp_program_denies_socket_and_io_uring(machine):
    from tools.kanban_worker_boundary import (
        _LINUX_NETWORK_SYSCALLS,
        _network_seccomp_instructions,
        _network_seccomp_program,
    )

    instructions = _network_seccomp_instructions(machine)
    errno_action = 0x00050000 | 1
    denied = {
        instruction[3]
        for index, instruction in enumerate(instructions[:-1])
        if instruction[:3] == (0x15, 0, 1)
        and instructions[index + 1] == (0x06, 0, 0, errno_action)
    }
    assert denied == set(_LINUX_NETWORK_SYSCALLS[machine])
    assert instructions[-1] == (0x06, 0, 0, 0x7FFF0000)
    assert len(_network_seccomp_program(machine)) == len(instructions) * 8


def _run_linux_sandbox(command, worker):
    from tools.kanban_worker_boundary import local_sandbox_launch

    with local_sandbox_launch(command, worker) as launch:
        return subprocess.run(
            launch.argv,
            pass_fds=launch.pass_fds,
            capture_output=True,
            text=True,
            timeout=30,
        )


def _linux_socket_denial_probe_code(probes):
    """Return a probe where denial at socket creation or connect is success."""
    literal_probes = tuple((int(family), address) for family, address in probes)
    source = (
        "import socket,sys\n"
        "escaped=False\n"
        f"for family,address in {literal_probes!r}:\n"
        " s=None\n"
        " try:\n"
        "  s=socket.socket(family, socket.SOCK_STREAM); s.settimeout(1)\n"
        "  s.connect(address)\n"
        " except OSError: pass\n"
        " else: escaped=True\n"
        " finally:\n"
        "  if s is not None: s.close()\n"
        "sys.exit(1 if escaped else 0)"
    )
    compile(source, "<linux-socket-denial-probe>", "exec")
    return source


def test_linux_socket_probe_accepts_seccomp_denial_at_socket_creation(monkeypatch):
    fake_socket = MagicMock()
    fake_socket.SOCK_STREAM = socket.SOCK_STREAM
    fake_socket.socket.side_effect = PermissionError(1, "Operation not permitted")
    monkeypatch.setitem(sys.modules, "socket", fake_socket)
    code = _linux_socket_denial_probe_code(((socket.AF_UNIX, "/blocked"),))

    with pytest.raises(SystemExit) as exit_info:
        exec(code, {})

    assert exit_info.value.code == 0


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason="Linux bubblewrap integration",
)
def test_linux_sandbox_executes_exact_active_python_runtime(worker):
    """The exact worker venv and its resolved runtime closure stay executable."""
    executable = shlex.quote(sys.executable)
    script = (
        "set -eu; "
        f"exe={executable}; "
        'printf "exe=%s\\n" "$exe"; '
        'ls -ld "$(dirname "$exe")"; '
        'ls -l "$exe"; '
        'real="$(readlink -f "$exe")"; '
        'printf "real=%s\\n" "$real"; '
        'ls -l "$real"; '
        '"$exe" -c "import sys; assert sys.executable"'
    )

    completed = _run_linux_sandbox(["/bin/sh", "-c", script], worker)

    assert completed.returncode == 0, (
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason="Linux bubblewrap integration",
)
def test_linux_sandbox_cannot_connect_to_host_ip_or_abstract_socket(worker):
    """The inherited seccomp filter must deny IP and abstract AF_UNIX sockets."""

    tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    abstract_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    abstract_address = f"\0hermes-kanban-{os.getpid()}"
    try:
        tcp_listener.bind(("127.0.0.1", 0))
        tcp_listener.listen(1)
        tcp_port = tcp_listener.getsockname()[1]
        abstract_listener.bind(abstract_address)
        abstract_listener.listen(1)
        code = _linux_socket_denial_probe_code(
            (
                (socket.AF_INET, ("127.0.0.1", tcp_port)),
                (socket.AF_UNIX, abstract_address),
            )
        )
        completed = _run_linux_sandbox([sys.executable, "-c", code], worker)
        assert completed.returncode == 0, completed.stderr
    finally:
        abstract_listener.close()
        tcp_listener.close()


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason="Linux bubblewrap integration",
)
@pytest.mark.parametrize(
    "socket_dir",
    [Path("/tmp"), Path("/var/tmp"), Path.home()],
    ids=["tmp", "var-tmp", "home"],
)
def test_linux_sandbox_cannot_connect_to_host_runtime_socket(worker, socket_dir):
    """Host control sockets outside /run must disappear from the worker."""

    if not socket_dir.is_dir() or not os.access(socket_dir, os.W_OK):
        pytest.skip(f"socket fixture directory is not writable: {socket_dir}")
    socket_path = socket_dir / f"hermes-kanban-{os.getpid()}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        listener.listen(1)
        code = _linux_socket_denial_probe_code(
            ((socket.AF_UNIX, str(socket_path)),)
        )
        completed = _run_linux_sandbox([sys.executable, "-c", code], worker)
        assert completed.returncode == 0, completed.stderr
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason="Linux bubblewrap integration",
)
def test_linux_sandbox_cannot_connect_to_host_run_socket(worker):
    """Pathname AF_UNIX sockets require the private /run mount."""

    run_user = Path("/run/user") / str(os.getuid())
    if not run_user.is_dir() or not os.access(run_user, os.W_OK):
        pytest.skip("no writable per-user /run directory for AF_UNIX fixture")
    socket_path = run_user / f"hermes-kanban-{os.getpid()}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        listener.listen(1)
        code = _linux_socket_denial_probe_code(
            ((socket.AF_UNIX, str(socket_path)),)
        )
        completed = _run_linux_sandbox([sys.executable, "-c", code], worker)
        assert completed.returncode == 0, completed.stderr
    finally:
        listener.close()
        socket_path.unlink(missing_ok=True)


@pytest.mark.skipif(
    platform.system() != "Linux" or shutil.which("bwrap") is None,
    reason="Linux bubblewrap integration",
)
def test_linux_sandbox_cannot_connect_to_accessible_container_daemon(worker):
    """Exercise the exact Docker/Podman confused-deputy primitive when present."""

    candidates = (
        Path("/run/docker.sock"),
        Path("/var/run/docker.sock"),
        Path("/run/podman/podman.sock"),
        Path("/run/user") / str(os.getuid()) / "podman" / "podman.sock",
    )
    daemon_socket = None
    for candidate in candidates:
        try:
            if stat.S_ISSOCK(candidate.stat().st_mode) and os.access(
                candidate, os.R_OK | os.W_OK
            ):
                daemon_socket = candidate
                break
        except OSError:
            continue
    if daemon_socket is None:
        pytest.skip("no accessible Docker/Podman control socket on this host")

    code = _linux_socket_denial_probe_code(
        ((socket.AF_UNIX, str(daemon_socket)),)
    )
    completed = _run_linux_sandbox([sys.executable, "-c", code], worker)
    assert completed.returncode == 0, completed.stderr


def test_managed_checkout_under_hermes_root_is_not_masked(
    tmp_path,
    monkeypatch,
):
    from tools.kanban_worker_boundary import _credential_read_paths

    monkeypatch.setenv("HOME", str(tmp_path))
    hermes_root = tmp_path / ".hermes"
    managed_workspace = hermes_root / "hermes-agent" / ".worktrees" / "t_safe"
    managed_workspace.mkdir(parents=True)
    secret = hermes_root / ".env"
    secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes_root))

    masked = _credential_read_paths(managed_workspace)

    assert secret.resolve() in masked
    assert hermes_root.resolve() not in masked
    assert all(path != managed_workspace.resolve() for path in masked)


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_model_path_cannot_read_key_or_mint_trusted_task_but_host_can(
    worker,
):
    """Live same-UID proof of the no-agent authority split on the Mini path."""
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_authority import (
        authority_key_path,
        initialize_authority,
        trusted_create_task,
    )
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    with non_dispatcher_owned_context(), kb.connect_closing() as conn:
        initialized = initialize_authority(conn)
        key_path = authority_key_path(conn)
        authority_db = Path(
            conn.execute("PRAGMA database_list").fetchone()["file"]
        ).resolve()
    assert initialized["contract"] == "hermes.kanban_dispatch_authority.v1"

    from tools.file_tools import read_file_tool

    file_read = json.loads(read_file_tool(str(key_path)))
    assert "credential" in file_read["error"].lower()
    db_read = json.loads(read_file_tool(str(authority_db)))
    assert "credential" in db_read["error"].lower()
    assert key_path.read_bytes()

    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    read_code = (
        "from pathlib import Path; import sys; escaped=False\n"
        f"for candidate in ({str(key_path)!r}, {str(authority_db)!r}):\n"
        " try: Path(candidate).read_bytes()\n"
        " except OSError: pass\n"
        " else: escaped=True\n"
        "sys.exit(1 if escaped else 0)"
    )
    trusted_cli = " ".join(
        (
            "/usr/bin/env",
            "-u HERMES_SESSION_SOURCE",
            "-u HERMES_KANBAN_TASK",
            shlex.quote(sys.executable),
            "-m hermes_cli.main kanban trusted-create forged",
            "--idempotency-key worker:forged-authority:v1 --json",
        )
    )
    try:
        with local_worker_sandbox(worker):
            key_read = environment.execute(
                f"python3 -c {shlex.quote(read_code)}",
                cwd=str(worker),
            )
            forged = environment.execute(trusted_cli, cwd=str(worker))
    finally:
        environment.cleanup()

    assert key_read["returncode"] == 0, key_read.get("output")
    assert forged["returncode"] != 0
    with kb.connect_closing() as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE idempotency_key = ?",
            ("worker:forged-authority:v1",),
        ).fetchone()[0] == 0

    # The separate no-agent host controller can use the same exact API.
    with non_dispatcher_owned_context(), kb.connect_closing() as conn:
        task_id, reused = trusted_create_task(
            conn,
            board="default",
            title="host-created authority canary",
            assignee="radulator",
            created_by="no-agent-test-controller",
            idempotency_key="host:authority-canary:v1",
            initial_status="blocked",
        )
    assert task_id.startswith("t_")
    assert reused is False


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_scratch_terminal_blocks_absolute_credentials_and_host_sockets(
    scratch_worker,
    tmp_path,
    monkeypatch,
):
    """Exercise the actual foreground worker subprocess, not only guard text."""
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    hermes_home = tmp_path / "profiles" / "radulator"
    gh_home = tmp_path / "user-home" / ".config" / "gh"
    hermes_home.mkdir(parents=True)
    gh_home.mkdir(parents=True)
    profile_secret = hermes_home / ".env"
    gh_secret = gh_home / "hosts.yml"
    profile_secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    gh_secret.write_text("oauth_token: must-not-enter-model\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user-home")

    tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_listener.bind(("127.0.0.1", 0))
    tcp_listener.listen(1)
    tcp_port = tcp_listener.getsockname()[1]
    unix_socket_dir = Path(tempfile.mkdtemp(prefix="hkwb-", dir="/tmp"))
    unix_path = unix_socket_dir / "control.sock"
    unix_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unix_listener.bind(str(unix_path))
    unix_listener.listen(1)
    code = (
        "from pathlib import Path; import socket,sys; escaped=False\n"
        f"for p in ({str(profile_secret)!r}, {str(gh_secret)!r}):\n"
        "  try: Path(p).read_text()\n"
        "  except OSError: pass\n"
        "  else: escaped=True\n"
        f"for family,address in ((socket.AF_INET, ('127.0.0.1', {tcp_port})), "
        f"(socket.AF_UNIX, {str(unix_path)!r})):\n"
        "  s=socket.socket(family, socket.SOCK_STREAM); s.settimeout(1)\n"
        "  try: s.connect(address)\n"
        "  except OSError: pass\n"
        "  else: escaped=True\n"
        "  finally: s.close()\n"
        "sys.exit(1 if escaped else 0)"
    )
    environment = LocalEnvironment(
        cwd=str(scratch_worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(scratch_worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(code)}",
                cwd=str(scratch_worker),
            )
    finally:
        environment.cleanup()
        tcp_listener.close()
        unix_listener.close()
        unix_path.unlink(missing_ok=True)
        unix_socket_dir.rmdir()

    assert completed["returncode"] == 0, completed.get("output")


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_sandbox_blocks_obfuscated_git_metadata_write(worker):
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    repo = worker.parents[1]
    common_git = repo / ".git"
    common_git.mkdir()
    protected = common_git / "config"
    protected.write_text("safe\n", encoding="utf-8")
    allowed = worker / "feature.txt"
    code = (
        "from pathlib import Path; "
        f"Path({str(allowed)!r}).write_text('ok'); "
        f"Path({str(protected.parent)!r}, chr(99)+chr(111)+chr(110)+chr(102)+chr(105)+chr(103)).write_text('attack')"
    )
    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(code)}",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()

    assert completed["returncode"] != 0
    assert allowed.read_text(encoding="utf-8") == "ok"
    assert protected.read_text(encoding="utf-8") == "safe\n"


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_sandbox_blocks_obfuscated_worktree_gitfile_replacement(worker):
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    gitfile = worker / ".git"
    before = gitfile.read_text(encoding="utf-8")
    code = (
        "from pathlib import Path; "
        "Path(chr(46) + chr(103) + chr(105) + chr(116)).write_text('attack')"
    )
    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(code)}",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()

    assert completed["returncode"] != 0
    assert gitfile.read_text(encoding="utf-8") == before


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_worker_terminal_never_receives_publish_credentials(
    worker,
    monkeypatch,
):
    from tools.environments.local import LocalEnvironment
    from tools.kanban_worker_boundary import local_worker_sandbox

    monkeypatch.setenv("GH_TOKEN", "must-not-enter-worker")
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-enter-worker-either")
    environment = LocalEnvironment(cwd=str(worker), timeout=30, env={})
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                "test -z \"${GH_TOKEN-}\" && test -z \"${GITHUB_TOKEN-}\"",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()

    assert completed["returncode"] == 0


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_worker_terminal_cannot_read_profile_credentials(
    worker,
    tmp_path,
    monkeypatch,
):
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    hermes_home = tmp_path / "profiles" / "radulator"
    hermes_home.mkdir(parents=True)
    secret = hermes_home / ".env"
    secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(f'open({str(secret)!r}).read()')}",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()

    assert completed["returncode"] != 0
    assert "must-not-enter-model" not in completed["output"]


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_managed_checkout_under_hermes_root_remains_usable(
    tmp_path,
    monkeypatch,
):
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    monkeypatch.setenv("HOME", str(tmp_path))
    hermes_root = tmp_path / ".hermes"
    worker = hermes_root / "hermes-agent" / ".worktrees" / "t_safe"
    worker.mkdir(parents=True)
    (worker / ".git").write_text(
        "gitdir: ../../.git/worktrees/t_safe\n", encoding="utf-8"
    )
    secret = hermes_root / ".env"
    secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    source = worker / "source.txt"
    source.write_text("visible\n", encoding="utf-8")
    output = worker / "result.txt"
    monkeypatch.setenv("HERMES_HOME", str(hermes_root))
    code = (
        "from pathlib import Path; "
        f"data=Path({str(source)!r}).read_text(); "
        f"Path({str(output)!r}).write_text(data); "
        f"Path({str(secret)!r}).read_text()"
    )
    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(code)}",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()

    assert completed["returncode"] != 0
    assert output.read_text(encoding="utf-8") == "visible\n"
    assert "must-not-enter-model" not in completed["output"]


@pytest.mark.skipif(
    platform.system() != "Darwin" or shutil.which("sandbox-exec") is None,
    reason="macOS Seatbelt integration",
)
def test_macos_sandbox_denies_network_for_worker_tests(worker):
    from tools.environments.local import LocalEnvironment, hermes_subprocess_env
    from tools.kanban_worker_boundary import local_worker_sandbox

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    code = (
        "import socket; "
        f"socket.create_connection(('127.0.0.1', {port}), timeout=1)"
    )
    environment = LocalEnvironment(
        cwd=str(worker),
        timeout=30,
        env=hermes_subprocess_env(inherit_credentials=True),
    )
    try:
        with local_worker_sandbox(worker):
            completed = environment.execute(
                f"python3 -c {shlex.quote(code)}",
                cwd=str(worker),
            )
    finally:
        environment.cleanup()
        listener.close()

    assert completed["returncode"] != 0

"""Model-facing Kanban workers cannot mutate host control-plane state."""

from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import socket
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
    monkeypatch.setenv("HERMES_KANBAN_BRANCH", branch)
    monkeypatch.setenv("HERMES_KANBAN_PROJECT_ID", "")
    monkeypatch.setenv("TERMINAL_CWD", str(workspace))
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_REPO_ROOT", str(tmp_path / "repo"))
    return workspace


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
                side_effect=lambda argv, _workspace: list(argv),
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
    secret = hermes_home / ".env"
    secret.write_text("GITHUB_TOKEN=must-not-enter-model\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    with (
        patch("tools.kanban_worker_boundary.platform.system", return_value="Linux"),
        patch("tools.kanban_worker_boundary.shutil.which", return_value="/usr/bin/bwrap"),
    ):
        argv = local_sandbox_argv(["/bin/sh", "-c", "true"], worker)

    joined = "\0".join(argv)
    assert argv[0] == "/usr/bin/bwrap"
    assert "--unshare-net" in argv
    assert "--unshare-pid" in argv
    assert f"--ro-bind\0/\0/" in joined
    assert f"--bind\0{worker.resolve()}\0{worker.resolve()}" in joined
    assert (
        f"--ro-bind\0{(worker / '.git').resolve()}\0{(worker / '.git').resolve()}"
        in joined
    )
    assert f"--ro-bind\0" in joined
    assert f"\0{secret.resolve()}" in joined
    masked_targets = {
        Path(argv[index + 2]).resolve(strict=False)
        for index, value in enumerate(argv[:-2])
        if value == "--ro-bind"
    }
    assert hermes_home.resolve() not in masked_targets


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

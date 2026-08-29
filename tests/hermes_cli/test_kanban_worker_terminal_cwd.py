"""Tests: kanban worker spawn pins TERMINAL_CWD to the task workspace.

Regression coverage for #34619 and #41312 (same root cause): ``_default_spawn``
launched the worker subprocess with ``cwd=workspace`` and set
``HERMES_KANBAN_WORKSPACE``, but did NOT set ``TERMINAL_CWD``. Because
``TERMINAL_CWD`` takes precedence over the process cwd in both
``tools/file_tools.py::_resolve_base_dir`` (relative ``write_file`` paths) and
``agent_init``'s context-file loader (``AGENTS.md`` discovery), workers inherited
the dispatching gateway's cwd — relative writes landed in the gateway user's
home (#41312) and the wrong profile's ``AGENTS.md`` was loaded (#34619).
Pinning ``TERMINAL_CWD`` to the workspace fixes both.
"""

from __future__ import annotations

import subprocess


def _make_task(kb, *, assignee: str = "w"):
    return kb.Task(
        id="t_cwd",
        title="cwd pin",
        body=None,
        assignee=assignee,
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="dir",
        workspace_path=None,
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=1,
    )


def _capture_spawn_env(kb, monkeypatch, workspace: str) -> dict:
    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])

    captured: dict = {}

    class FakeProc:
        pid = 4242

    def fake_popen(cmd, *args, **kwargs):
        captured["cmd"] = list(cmd)
        captured["env"] = dict(kwargs.get("env") or {})
        captured["cwd"] = kwargs.get("cwd")
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    kb._default_spawn(_make_task(kb), workspace)
    return captured


def test_terminal_cwd_pinned_to_workspace(monkeypatch, tmp_path):
    """A real, absolute workspace dir is pinned as TERMINAL_CWD."""
    root = tmp_path / ".hermes"
    (root / "profiles" / "w").mkdir(parents=True)
    (root / "profiles" / "w" / "config.yaml").write_text("toolsets:\n  - kanban\n", encoding="utf-8")
    root.joinpath("config.yaml").write_text("toolsets:\n  - kanban\n", encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv(
        "HERMES_KANBAN_GIT_COMMON_DIR", "/stale/parent/repository/.git"
    )

    from hermes_cli import kanban_db as kb

    workspace = tmp_path / "ws"
    workspace.mkdir()

    captured = _capture_spawn_env(kb, monkeypatch, str(workspace))

    assert captured["env"]["TERMINAL_CWD"] == str(workspace)
    # The subprocess cwd and TERMINAL_CWD must agree — both anchor the workspace.
    assert captured["cwd"] == str(workspace)
    assert captured["env"]["HERMES_KANBAN_WORKSPACE"] == str(workspace)
    assert "HERMES_KANBAN_GIT_COMMON_DIR" not in captured["env"]
    assert "HERMES_KANBAN_TRUSTED_REPO_ROOT" not in captured["env"]


def test_publisher_opt_in_is_pinned_from_dispatcher_before_profile_switch(
    monkeypatch, tmp_path
):
    """A named worker's config cannot override the board dispatcher's opt-in."""
    root = tmp_path / ".hermes"
    profile = root / "profiles" / "w"
    profile.mkdir(parents=True)
    root.joinpath("config.yaml").write_text(
        "kanban:\n  trusted_publisher_enabled: true\n", encoding="utf-8"
    )
    profile.joinpath("config.yaml").write_text(
        "kanban:\n  trusted_publisher_enabled: false\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(root))
    monkeypatch.setenv("HERMES_KANBAN_TRUSTED_PUBLISHER_ENABLED", "stale")

    from hermes_cli import kanban_db as kb

    workspace = tmp_path / "ws"
    workspace.mkdir()
    captured = _capture_spawn_env(kb, monkeypatch, str(workspace))

    assert captured["env"]["HERMES_HOME"] == str(profile)
    assert captured["env"]["HERMES_KANBAN_TRUSTED_PUBLISHER_ENABLED"] == "1"


def test_linked_worktree_spawn_never_exports_git_common_dir(monkeypatch, tmp_path):
    """The model-facing worker never receives shared Git path authority."""
    root = tmp_path / ".hermes"
    (root / "profiles" / "w").mkdir(parents=True)
    (root / "profiles" / "w" / "config.yaml").write_text(
        "toolsets:\n  - kanban\n", encoding="utf-8"
    )
    root.joinpath("config.yaml").write_text(
        "toolsets:\n  - kanban\n", encoding="utf-8"
    )
    monkeypatch.setenv("HERMES_HOME", str(root))

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "Hermes Test"],
        check=True,
    )
    (repo / "README.md").write_text("fixture\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
    workspace = repo / ".worktrees" / "t_git"
    subprocess.run(
        [
            "git", "-C", str(repo), "worktree", "add", "-qb", "wt/t_git",
            str(workspace),
        ],
        check=True,
    )

    from hermes_cli import kanban_db as kb

    monkeypatch.setattr(kb, "_resolve_hermes_argv", lambda: ["hermes"])
    captured: dict = {}
    real_popen = subprocess.Popen

    class FakeProc:
        pid = 4243

    def fake_popen(cmd, *args, **kwargs):
        if cmd and cmd[0] == "git":
            return real_popen(cmd, *args, **kwargs)
        captured["env"] = dict(kwargs.get("env") or {})
        return FakeProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    task = kb.Task(
        id="t_git",
        title="git metadata pin",
        body=None,
        assignee="w",
        status="running",
        priority=0,
        created_by="test",
        created_at=1,
        started_at=None,
        completed_at=None,
        workspace_kind="worktree",
        workspace_path=str(workspace),
        claim_lock="lock",
        claim_expires=None,
        tenant=None,
        current_run_id=1,
        branch_name="wt/t_git",
        project_id="p_radulator",
    )

    kb._default_spawn(task, str(workspace))

    assert "HERMES_KANBAN_GIT_COMMON_DIR" not in captured["env"]
    assert captured["env"]["HERMES_KANBAN_TRUSTED_REPO_ROOT"] == str(repo)
    assert captured["env"]["HERMES_KANBAN_PROJECT_ID"] == "p_radulator"

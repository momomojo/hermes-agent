"""Tests for the optional codex app-server runtime gate.

These are unit tests for the api_mode rewriter and the wire-level transport
module. They do NOT require the `codex` CLI to be installed — that's
covered by a separate live test gated on `codex --version`.
"""

from __future__ import annotations

import pytest

from hermes_cli.runtime_provider import (
    _VALID_API_MODES,
    _maybe_apply_codex_app_server_runtime,
)


class TestApiModeRegistration:
    """The new api_mode must be registered or downstream parsing rejects it."""

    def test_codex_app_server_is_a_valid_api_mode(self) -> None:
        assert "codex_app_server" in _VALID_API_MODES

    def test_existing_api_modes_still_present(self) -> None:
        # Regression guard: don't accidentally delete other api_modes when
        # touching this set.
        for mode in (
            "chat_completions",
            "codex_responses",
            "anthropic_messages",
            "bedrock_converse",
        ):
            assert mode in _VALID_API_MODES


class TestMaybeApplyCodexAppServerRuntime:
    """The opt-in helper that rewrites api_mode → codex_app_server."""

    @pytest.mark.parametrize(
        "model_cfg",
        [
            None,
            {},
            {"openai_runtime": ""},
            {"openai_runtime": "auto"},
            {"openai_runtime": "AUTO"},
            {"other_key": "codex_app_server"},  # wrong key
        ],
    )
    def test_default_off_for_openai(self, model_cfg) -> None:
        """Default behavior is preserved when the flag is unset/auto."""
        got = _maybe_apply_codex_app_server_runtime(
            provider="openai", api_mode="chat_completions", model_cfg=model_cfg
        )
        assert got == "chat_completions"

    def test_opt_in_rewrites_openai(self) -> None:
        got = _maybe_apply_codex_app_server_runtime(
            provider="openai",
            api_mode="chat_completions",
            model_cfg={"openai_runtime": "codex_app_server"},
        )
        assert got == "codex_app_server"

    def test_opt_in_rewrites_openai_codex(self) -> None:
        got = _maybe_apply_codex_app_server_runtime(
            provider="openai-codex",
            api_mode="codex_responses",
            model_cfg={"openai_runtime": "codex_app_server"},
        )
        assert got == "codex_app_server"

    def test_case_insensitive(self) -> None:
        got = _maybe_apply_codex_app_server_runtime(
            provider="openai",
            api_mode="chat_completions",
            model_cfg={"openai_runtime": "Codex_App_Server"},
        )
        assert got == "codex_app_server"

    @pytest.mark.parametrize(
        "provider",
        [
            "anthropic",
            "openrouter",
            "xai",
            "qwen-oauth",
            "google-gemini-cli",
            "opencode-zen",
            "bedrock",
            "",
        ],
    )
    def test_other_providers_never_rerouted(self, provider) -> None:
        """Non-OpenAI providers MUST NOT be rerouted even with the flag set —
        codex's app-server can only run OpenAI/Codex auth flows."""
        got = _maybe_apply_codex_app_server_runtime(
            provider=provider,
            api_mode="anthropic_messages",
            model_cfg={"openai_runtime": "codex_app_server"},
        )
        assert got == "anthropic_messages", (
            f"provider={provider!r} should not be rerouted to codex_app_server"
        )


class TestCodexAppServerModule:
    """Module-surface tests for the JSON-RPC speaker. Don't require codex CLI."""

    def test_module_imports(self) -> None:
        from agent.transports import codex_app_server

        assert codex_app_server.MIN_CODEX_VERSION >= (0, 1, 0)
        assert callable(codex_app_server.parse_codex_version)
        assert callable(codex_app_server.check_codex_binary)

    def test_parse_codex_version_valid(self) -> None:
        from agent.transports.codex_app_server import parse_codex_version

        assert parse_codex_version("codex-cli 0.130.0") == (0, 130, 0)
        assert parse_codex_version("codex-cli 1.2.3 (extra metadata)") == (1, 2, 3)
        assert parse_codex_version("codex 99.0.1\n") == (99, 0, 1)

    def test_parse_codex_version_invalid(self) -> None:
        from agent.transports.codex_app_server import parse_codex_version

        assert parse_codex_version("nope") is None
        assert parse_codex_version("") is None
        assert parse_codex_version(None) is None  # type: ignore[arg-type]

    def test_check_binary_handles_missing_executable(self) -> None:
        from agent.transports.codex_app_server import check_codex_binary

        ok, msg = check_codex_binary(codex_bin="/nonexistent/codex/binary/path")
        assert ok is False
        assert "not found" in msg.lower() or "no such" in msg.lower()

    def test_codex_error_class_is_runtimeerror(self) -> None:
        from agent.transports.codex_app_server import CodexAppServerError

        err = CodexAppServerError(code=-32600, message="boom")
        assert isinstance(err, RuntimeError)
        assert "boom" in str(err)
        assert "-32600" in str(err)


class TestSpawnEnvIsolation:
    """The codex spawn must NOT rewrite HOME — codex's shell tool spawns
    subprocesses (gh, git, npm, aws, gcloud, ...) that need to find their
    config in the real user $HOME. CODEX_HOME isolates codex's own state,
    HOME stays unchanged.

    OpenClaw hit this footgun (openclaw/openclaw#81562) — they were
    rewriting HOME to a synthetic per-agent dir alongside CODEX_HOME,
    and then `gh auth status` / git config / etc. all broke inside codex
    shell calls. We avoid the same bug by only overlaying CODEX_HOME and
    RUST_LOG on top of os.environ.copy().
    """

    def test_spawn_env_preserves_HOME(self, monkeypatch):
        """The spawn env must contain the parent process's HOME unchanged.
        Verifies via a subprocess-monkey-patch."""
        import subprocess
        from agent.transports import codex_app_server as cas

        captured = {}

        class FakePopen:
            def __init__(self, cmd, *args, **kwargs):
                captured["env"] = kwargs.get("env", {}).copy()
                # Provide minimal Popen surface so __init__ doesn't crash
                # on attribute access during construction.
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        monkeypatch.setattr(subprocess, "Popen", FakePopen)
        monkeypatch.setenv("HOME", "/users/alice")

        client = cas.CodexAppServerClient(codex_bin="codex")
        client._closed = True  # so close() is a no-op

        # The spawn env must have HOME=/users/alice unchanged
        assert captured["env"].get("HOME") == "/users/alice", (
            f"HOME got rewritten in codex spawn env: "
            f"{captured['env'].get('HOME')!r}. Codex's shell tool's "
            "subprocesses (gh, git, aws, npm) need the user's real HOME."
        )

    def test_spawn_env_sets_CODEX_HOME_when_provided(self, monkeypatch):
        """CODEX_HOME isolation must still work — that's the whole point
        of the codex_home arg."""
        import subprocess
        from agent.transports import codex_app_server as cas

        captured = {}

        class FakePopen:
            def __init__(self, cmd, *args, **kwargs):
                captured["env"] = kwargs.get("env", {}).copy()
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        monkeypatch.setattr(subprocess, "Popen", FakePopen)
        monkeypatch.setenv("HOME", "/users/alice")

        client = cas.CodexAppServerClient(
            codex_bin="codex", codex_home="/tmp/profile/codex"
        )
        client._closed = True

        assert captured["env"].get("CODEX_HOME") == "/tmp/profile/codex"
        # And HOME still passes through unchanged
        assert captured["env"].get("HOME") == "/users/alice"

    def test_kanban_worker_adds_only_kanban_writable_root(self, monkeypatch):
        """Codex-runtime Kanban workers need to write board state outside
        their scratch/worktree workspace, but should not fall back to
        danger-full-access. Hermes passes a narrow app-server config override
        for the Kanban root only.
        """
        import subprocess
        from agent.transports import codex_app_server as cas

        captured = {}

        class FakePopen:
            def __init__(self, cmd, *args, **kwargs):
                captured["cmd"] = list(cmd)
                captured["env"] = kwargs.get("env", {}).copy()
                captured["preexec_fn"] = kwargs.get("preexec_fn")
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = None

            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

            def kill(self):
                pass

        monkeypatch.setattr(subprocess, "Popen", FakePopen)
        monkeypatch.setenv("HOME", "/users/alice")
        monkeypatch.setenv("HERMES_HOME", "/users/alice/.hermes/profiles/backend-worker")
        monkeypatch.setenv("HERMES_KANBAN_TASK", "t_smoke")
        monkeypatch.setenv(
            "HERMES_KANBAN_DB",
            "/users/alice/.hermes/kanban/boards/smoke/kanban.db",
        )

        client = cas.CodexAppServerClient(codex_bin="codex")
        client._closed = True

        cmd = captured["cmd"]
        assert cmd[:2] == ["codex", "app-server"]
        assert 'sandbox_mode="workspace-write"' in cmd
        assert (
            'sandbox_workspace_write.writable_roots=["/users/alice/.hermes/kanban/boards/smoke"]'
            in cmd
        )
        assert "sandbox_workspace_write.network_access=false" in cmd
        assert all("danger" not in part for part in cmd)
        # preexec_fn=os.setsid isolates codex + its sandbox children into a
        # dedicated process group so close() can killpg the entire tree.
        import os
        assert captured["preexec_fn"] is os.setsid, (
            f"expected os.setsid as preexec_fn, got {captured['preexec_fn']!r}"
        )


class TestCodexAppServerCleanup:
    """Regression: orphan sandbox processes when codex is killed.

    During the 2026-06-11 rc=0 protocol-violation burst, ~50 SkyComputerUse
    sandbox processes were orphaned to pid 1 because CodexAppServerClient.close()
    sent SIGKILL to the codex parent only. The fix isolates codex in its own
    process group (preexec_fn=os.setsid) and uses os.killpg() to kill the whole
    tree.
    """

    def test_close_kills_process_group_on_timeout(self, monkeypatch):
        """close() must escalate from SIGTERM to SIGKILL on the process
        group when the subprocess doesn't exit in time."""
        import os as real_os
        import subprocess
        import signal
        from agent.transports import codex_app_server as cas

        killpg_calls = []
        monkeypatch.setattr(real_os, "killpg", lambda pgid, sig: killpg_calls.append((pgid, sig)))
        monkeypatch.setattr(real_os, "getpgid", lambda pid: 42)

        class SlowPopen:
            """Mimics a codex subprocess that doesn't respond to SIGTERM."""

            def __init__(self, cmd=None, *args, **kwargs):
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = None

            def poll(self):
                return None  # alive

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired(cmd="codex", timeout=timeout or 3.0)

            def terminate(self):
                pass

            def kill(self):
                pass

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: SlowPopen())
        client = cas.CodexAppServerClient(codex_bin="codex")
        client._closed = False
        client._proc = SlowPopen()  # ensure real poll() path

        client.close(timeout=0.01)

        # Must have sent both SIGTERM and SIGKILL to the process group
        assert len(killpg_calls) == 2, (
            f"expected 2 killpg calls (SIGTERM then SIGKILL), got {killpg_calls}"
        )
        assert killpg_calls[0] == (42, signal.SIGTERM), (
            f"first killpg should be SIGTERM, got {killpg_calls[0]}"
        )
        assert killpg_calls[1] == (42, signal.SIGKILL), (
            f"second killpg should be SIGKILL, got {killpg_calls[1]}"
        )

    def test_close_skips_kill_on_dead_process(self, monkeypatch):
        """close() is a no-op when the subprocess has already exited."""
        import os as real_os
        import subprocess
        from agent.transports import codex_app_server as cas

        killpg_calls = []
        monkeypatch.setattr(real_os, "killpg", lambda pgid, sig: killpg_calls.append((pgid, sig)))

        class DeadPopen:
            def __init__(self, cmd=None, *args, **kwargs):
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = 0

            def poll(self):
                return 0  # already dead

            def wait(self, timeout=None):
                return 0

            def terminate(self):
                pass

            def kill(self):
                pass

        monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: DeadPopen())
        client = cas.CodexAppServerClient(codex_bin="codex")
        client._closed = False
        client._proc = DeadPopen()

        client.close(timeout=0.01)
        assert len(killpg_calls) == 0, (
            f"expected no killpg calls for already-dead process, got {killpg_calls}"
        )

    def test_preexec_fn_is_os_setsid(self, monkeypatch):
        """subprocess.Popen must receive preexec_fn=os.setsid so codex and
        its sandbox children run in an isolated process group."""
        import os as real_os
        import subprocess
        from agent.transports import codex_app_server as cas

        captured = {}

        class PopenChecker:
            def __init__(self, cmd, *args, **kwargs):
                captured["preexec_fn"] = kwargs.get("preexec_fn")
                self.stdin = None
                self.stdout = None
                self.stderr = None
                self.pid = 1
                self.returncode = None

            def poll(self):
                return None

        monkeypatch.setattr(subprocess, "Popen", PopenChecker)
        client = cas.CodexAppServerClient(codex_bin="codex")
        client._closed = True

        assert captured["preexec_fn"] is real_os.setsid, (
            f"expected os.setsid as preexec_fn, got {captured['preexec_fn']!r}"
        )

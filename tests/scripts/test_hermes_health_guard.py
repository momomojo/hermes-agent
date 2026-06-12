"""Tests for scripts/hermes_health_guard.py."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _load_health_guard_module():
    repo = Path(__file__).resolve().parents[2]
    script = repo / "scripts" / "hermes_health_guard.py"
    spec = importlib.util.spec_from_file_location("hermes_health_guard_for_test", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_ensure_venv_python_reexecs_when_launched_with_system_python(monkeypatch, tmp_path):
    guard = _load_health_guard_module()
    desired = tmp_path / "venv" / "bin" / "python"
    desired.parent.mkdir(parents=True)
    desired.write_text("#!/bin/sh\n", encoding="utf-8")
    desired.chmod(0o755)

    calls = []
    monkeypatch.setattr(guard, "PYTHON", desired)
    monkeypatch.setattr(guard.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(guard, "__file__", str(tmp_path / "hermes_health_guard.py"))
    monkeypatch.delenv("HERMES_HEALTH_GUARD_REEXECED", raising=False)
    monkeypatch.setattr(
        guard.os,
        "execve",
        lambda exe, argv, env: calls.append((exe, argv, env)),
    )

    guard._ensure_venv_python()

    assert len(calls) == 1
    exe, argv, env = calls[0]
    assert exe == str(desired.resolve())
    assert argv[0] == str(desired.resolve())
    assert argv[1].endswith("hermes_health_guard.py")
    assert env["HERMES_HEALTH_GUARD_REEXECED"] == "1"


def test_ensure_venv_python_noops_when_already_in_venv(monkeypatch, tmp_path):
    guard = _load_health_guard_module()
    desired = tmp_path / "venv" / "bin" / "python"
    desired.parent.mkdir(parents=True)
    desired.write_text("#!/bin/sh\n", encoding="utf-8")
    desired.chmod(0o755)

    monkeypatch.setattr(guard, "PYTHON", desired)
    monkeypatch.setattr(guard.sys, "executable", str(desired))
    monkeypatch.setattr(
        guard.os,
        "execve",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unexpected execve")),
    )

    guard._ensure_venv_python()

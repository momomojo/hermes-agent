from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from hermes_cli import project_memory as pm
from hermes_cli.project_memory import project_memory_command
from hermes_cli.subcommands.project_memory import build_project_memory_parser


def _home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    return home


def test_project_memory_safe_name_and_path_helper(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)

    assert pm.normalize_project_id("My IR Project") == "my-ir-project"
    assert pm.memory_path("../My IR Project") == home / "project-memory" / "my-ir-project" / "memory.md"
    with pytest.raises(ValueError):
        pm.normalize_project_id("////")


def test_update_read_list_and_link_metadata(tmp_path, monkeypatch):
    _home(tmp_path, monkeypatch)

    record = pm.update_project_memory(
        "HHFOS Ops",
        title="HHFOS Ops",
        content="# HHFOS Ops\n\nInitial note.\n",
        links={
            "kanban_tasks": ["t_12345678", "t_12345678"],
            "skills": ["hhfos-kanban-workflow"],
            "cron_jobs": ["10f3002b3f31"],
            "artifacts": ["a_demo"],
            "hindsight_entities": ["project:hhfos"],
        },
        now=100,
    )
    assert record.project_id == "hhfos-ops"
    assert record.links["kanban_tasks"] == ["t_12345678"]

    pm.update_project_memory("HHFOS Ops", append="Follow-up note.", now=120)
    updated, content = pm.read_project_memory("hhfos-ops")

    assert "Initial note" in content
    assert "Follow-up note" in content
    assert updated.updated_at == 120
    assert [r.project_id for r in pm.list_project_memories()] == ["hhfos-ops"]


def test_cli_update_and_show_json(tmp_path, monkeypatch, capsys):
    _home(tmp_path, monkeypatch)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    build_project_memory_parser(sub, cmd_project_memory=project_memory_command)

    args = parser.parse_args([
        "project-memory",
        "update",
        "Radulator Launch",
        "--title",
        "Radulator Launch",
        "--content",
        "# Launch\n",
        "--kanban-task",
        "t_launch",
        "--skill",
        "github-operations",
        "--json",
    ])
    args.func(args)
    payload = json.loads(capsys.readouterr().out)
    assert payload["project_id"] == "radulator-launch"
    assert payload["links"]["skills"] == ["github-operations"]

    args = parser.parse_args(["project-memory", "show", "radulator-launch", "--json"])
    args.func(args)
    shown = json.loads(capsys.readouterr().out)
    assert shown["title"] == "Radulator Launch"
    assert shown["content"] == "# Launch\n"

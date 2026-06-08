from __future__ import annotations

import importlib
import json
from pathlib import Path


def test_skill_manage_delete_archives_recoverably(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    skill_dir = home / "skills" / "my-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: my-skill\ndescription: test\n---\nBody.\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    import hermes_constants
    import tools.skill_manager_tool as skill_manager_tool
    import tools.skill_usage as skill_usage

    importlib.reload(hermes_constants)
    importlib.reload(skill_usage)
    skill_manager_tool = importlib.reload(skill_manager_tool)

    result = json.loads(skill_manager_tool.skill_manage("delete", "my-skill"))

    assert result["success"] is True
    assert "archived" in result["message"]
    assert not skill_dir.exists()
    assert (home / "skills" / ".archive" / "my-skill" / "SKILL.md").exists()

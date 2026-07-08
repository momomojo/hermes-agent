from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "hhfos_profile_registry.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hhfos_profile_registry", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_profile(root: Path, name: str, *, dispatch: bool | None = None, soul: str | None = None, kanban_worker: bool = True) -> Path:
    profile_dir = root if name == "default" else root / "profiles" / name
    profile_dir.mkdir(parents=True, exist_ok=True)
    if dispatch is not None:
        (profile_dir / "config.yaml").write_text(f"kanban:\n  dispatch_in_gateway: {'true' if dispatch else 'false'}\n", encoding="utf-8")
    else:
        (profile_dir / "config.yaml").write_text("model:\n  provider: openai-codex\n", encoding="utf-8")
    if soul is not None:
        (profile_dir / "SOUL.md").write_text(soul, encoding="utf-8")
    if kanban_worker:
        skill_dir = profile_dir / "skills" / "devops" / "kanban-worker"
        skill_dir.mkdir(parents=True, exist_ok=True)
        (skill_dir / "SKILL.md").write_text("---\nname: kanban-worker\n---\n", encoding="utf-8")
    return profile_dir


def write_workflow(path: Path) -> Path:
    skill = path / "SKILL.md"
    path.mkdir(parents=True, exist_ok=True)
    skill.write_text(
        """
# HHFOS Kanban Workflow

## Current profile lanes

- `default`: owner/admin orchestrator, broad HHFOS architecture, profile/config/skill governance, ambiguous routing, cross-profile review, owner-only context, Gmail/Google drafting, and board triage.
- `alpha`: repo-scoped code implementation, tests, refactors, debugging, code review prep inside pinned repo/worktree. Do not route NAS admin, private vault retrieval, Home Assistant state changes, or broad operator tasks.
- `missing-lane`: household finance and receipts. Do not route patient identifiers/PHI or personal vault retrieval.

## Board topology invariants
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return skill


def test_registry_detects_unknown_missing_lanes_and_dispatch_mismatches(tmp_path):
    mod = load_module()
    skill = write_workflow(tmp_path / "workflow")
    write_profile(tmp_path, "default", dispatch=False, soul="Default owner admin orchestrator persona.")
    write_profile(tmp_path, "alpha", dispatch=True, soul="Alpha coding implementation persona.")
    write_profile(tmp_path, "surprise", dispatch=False, soul="Unknown lane persona.")

    registry = mod.compile_registry(tmp_path, skill, now="2026-06-18T12:00:00+00:00")

    assert registry["schema_version"] == 1
    assert registry["drift"]["unknown_profiles"] == ["surprise"]
    assert registry["drift"]["missing_lanes"] == ["missing-lane"]
    mismatches = {item["profile"]: (item["actual"], item["expected"]) for item in registry["drift"]["dispatcher_setting_mismatches"]}
    assert mismatches == {"default": (False, True), "alpha": (True, False)}
    assert registry["drift"]["ok"] is False


def test_registry_isolates_temp_root_and_does_not_emit_private_soul_snippets(tmp_path):
    mod = load_module()
    skill = write_workflow(tmp_path / "workflow")
    private_phrase = "PRIVATE_CLINICAL_SNIPPET_DO_NOT_EMIT"
    write_profile(tmp_path, "default", dispatch=True, soul=f"Owner admin. {private_phrase}")
    write_profile(tmp_path, "alpha", dispatch=False, soul="Coding tests refactor persona.", kanban_worker=False)

    registry = mod.compile_registry(tmp_path, skill, now="2026-06-18T12:00:00+00:00")
    rendered = json.dumps(registry, sort_keys=True) + mod.render_markdown(registry)

    assert private_phrase not in rendered
    assert "/Users/agent/.hermes/profiles" not in rendered
    names = [profile["name"] for profile in registry["profiles"]]
    assert names == ["alpha", "default"]
    assert registry["drift"]["missing_kanban_worker_skill"] == ["alpha"]
    default = next(profile for profile in registry["profiles"] if profile["name"] == "default")
    assert default["soul"]["present"] is True
    assert default["soul"]["sha256"]
    assert default["persona_summary"]["privacy"].startswith("No SOUL.md prose")


def test_default_profile_uses_root_not_stale_profiles_default_directory(tmp_path):
    mod = load_module()
    skill = write_workflow(tmp_path / "workflow")
    write_profile(tmp_path, "default", dispatch=True, soul="Root default owner admin persona.")
    stale = tmp_path / "profiles" / "default"
    stale.mkdir(parents=True)
    (stale / "SOUL.md").write_text("STALE_DEFAULT_DIRECTORY_SHOULD_NOT_APPEAR", encoding="utf-8")

    registry = mod.compile_registry(tmp_path, skill, now="2026-06-18T12:00:00+00:00")

    default = next(profile for profile in registry["profiles"] if profile["name"] == "default")
    assert default["profile_dir"] == str(tmp_path.resolve())
    rendered = json.dumps(registry, sort_keys=True) + mod.render_markdown(registry)
    assert "STALE_DEFAULT_DIRECTORY_SHOULD_NOT_APPEAR" not in rendered



def test_cli_writes_json_and_markdown_report(tmp_path):
    skill = write_workflow(tmp_path / "workflow")
    write_profile(tmp_path, "default", dispatch=True, soul="Owner admin governance persona.")
    write_profile(tmp_path, "alpha", dispatch=False, soul="Code implementation tests persona.")
    json_path = tmp_path / "out" / "registry.json"
    report_path = tmp_path / "out" / "report.md"

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--hermes-root",
            str(tmp_path),
            "--workflow-skill",
            str(skill),
            "--json-output",
            str(json_path),
            "--report-output",
            str(report_path),
            "--now",
            "2026-06-18T12:00:00+00:00",
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    payload = json.loads(result.stdout)
    assert payload["json_output"] == str(json_path)
    assert payload["report_output"] == str(report_path)
    assert json_path.exists()
    assert report_path.exists()
    registry = json.loads(json_path.read_text(encoding="utf-8"))
    assert registry["drift"]["missing_lanes"] == ["missing-lane"]
    report = report_path.read_text(encoding="utf-8")
    assert "HHFOS profile/persona registry drift report" in report
    assert "PRIVATE" not in report

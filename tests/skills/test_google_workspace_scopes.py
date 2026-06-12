"""Google Workspace skill scope-regression tests."""

from __future__ import annotations

import ast
from pathlib import Path


EXPECTED_DEFAULT_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]


def _extract_scopes(script: Path) -> list[str]:
    tree = ast.parse(script.read_text(encoding="utf-8"), filename=str(script))
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "SCOPES":
                    return ast.literal_eval(node.value)
    raise AssertionError(f"SCOPES not found in {script}")


def test_google_workspace_shared_scripts_default_to_gmail_modify_only():
    """The bundled setup default should stay least-privilege.

    Profile-specific workflows that need Calendar/Analytics/etc. should issue a
    tailored token for that profile, not expand the shared default for everyone.
    """
    skill_dir = Path(__file__).resolve().parents[2] / "skills" / "productivity" / "google-workspace" / "scripts"

    assert _extract_scopes(skill_dir / "google_api.py") == EXPECTED_DEFAULT_SCOPES
    assert _extract_scopes(skill_dir / "setup.py") == EXPECTED_DEFAULT_SCOPES

from __future__ import annotations

import argparse
import json

from hermes_cli.capability_catalog import (
    capability_catalog_command,
    capability_plan,
    init_catalog,
    load_catalog,
    run_smoke_tests,
    validate_catalog,
)


def test_init_catalog_writes_valid_synthetic_capability(tmp_path):
    written = init_catalog(tmp_path)

    assert written == [tmp_path / "synthetic.echo" / "capability.yaml"]
    manifests, issues = validate_catalog(tmp_path)

    assert [manifest.capability_id for manifest in manifests] == ["synthetic.echo"]
    assert issues == []


def test_synthetic_smoke_test_passes(tmp_path):
    init_catalog(tmp_path)
    manifests = load_catalog(tmp_path)

    results = run_smoke_tests(manifests, capability_id="synthetic.echo")

    assert len(results) == 1
    assert results[0]["passed"] is True
    assert "HERMES_CAPABILITY_SMOKE_OK" in results[0]["stdout"]


def test_validation_rejects_embedded_credentials_and_missing_references(tmp_path):
    cap_dir = tmp_path / "bad.cap"
    cap_dir.mkdir()
    (cap_dir / "capability.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "bad.cap",
                "name": "Bad Capability",
                "version": "0.1.0",
                "description": "invalid on purpose",
                "components": {
                    "skills": [{"name": "missing-skill", "path": "skills/missing/SKILL.md"}],
                    "credentials": [
                        {
                            "name": "api key",
                            "destination": {"adapter": "profile-env", "key": "API_KEY"},
                            "value": "should-not-be-here",
                        }
                    ],
                    "smoke_tests": [{"id": "missing-command", "kind": "python"}],
                },
                "install": {"steps": []},
                "doctor": {"checks": []},
                "remove": {"steps": []},
            }
        ),
        encoding="utf-8",
    )

    _manifests, issues = validate_catalog(tmp_path)

    messages = [issue.message for issue in issues]
    assert any("referenced file does not exist" in message for message in messages)
    assert any("must not embed secret values" in message for message in messages)
    assert any("smoke tests require command" in message for message in messages)


def test_relative_paths_cannot_escape_capability_directory(tmp_path):
    cap_dir = tmp_path / "escape.cap"
    cap_dir.mkdir()
    (cap_dir / "capability.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "id": "escape.cap",
                "name": "Escape Capability",
                "version": "0.1.0",
                "description": "invalid path on purpose",
                "components": {"plugins": [{"name": "escape", "path": "../plugin.py"}]},
                "install": {"steps": []},
                "doctor": {"checks": []},
                "remove": {"steps": []},
            }
        ),
        encoding="utf-8",
    )

    _manifests, issues = validate_catalog(tmp_path)

    assert any("must stay inside the capability directory" in issue.message for issue in issues)


def test_capability_plan_is_non_mutating_scaffold(tmp_path):
    init_catalog(tmp_path)
    manifest = load_catalog(tmp_path)[0]

    plan = capability_plan(manifest, "install")

    assert plan["capability_id"] == "synthetic.echo"
    assert plan["action"] == "install"
    assert "no credentials are installed" in plan["note"]
    assert plan["plan"]["steps"]


def test_cli_smoke_json(tmp_path, capsys):
    init_catalog(tmp_path)
    args = argparse.Namespace(
        capability_action="smoke",
        catalog_dir=str(tmp_path),
        capability_id="synthetic.echo",
        json=True,
    )

    rc = capability_catalog_command(args)

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["results"][0]["passed"] is True


def test_cli_validate_returns_failure_for_invalid_manifest(tmp_path, capsys):
    cap_dir = tmp_path / "invalid"
    cap_dir.mkdir()
    (cap_dir / "capability.json").write_text(json.dumps({"id": "invalid"}), encoding="utf-8")
    args = argparse.Namespace(capability_action="validate", catalog_dir=str(tmp_path), json=True)

    rc = capability_catalog_command(args)

    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert payload["ok"] is False
    assert any(issue["severity"] == "error" for issue in payload["issues"])

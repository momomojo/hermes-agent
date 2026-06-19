"""Hermes capability catalog scaffold.

Capabilities are installable, doctorable bundles that describe the edge surfaces
needed for a user-facing workflow: skills, plugins, MCP servers, cron jobs,
credential requirements, smoke tests, approval gates, and install/remove plans.
The catalog is intentionally a CLI/library scaffold rather than a model tool so
it keeps Hermes's model-facing tool schema narrow.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from hermes_constants import get_hermes_home

try:  # PyYAML is already a Hermes dependency; keep import local-safe for tests.
    import yaml
except Exception:  # pragma: no cover - exercised only in stripped envs
    yaml = None  # type: ignore[assignment]

CATALOG_VERSION = 1
DEFAULT_CATALOG_DIRNAME = "capabilities"
CAPABILITY_FILE_NAMES = ("capability.yaml", "capability.yml", "capability.json")
VALID_COMPONENT_KINDS = {
    "skills",
    "plugins",
    "mcp_servers",
    "cron_jobs",
    "credentials",
    "smoke_tests",
}
VALID_SMOKE_KINDS = {"command", "python"}
SYNTHETIC_CAPABILITY_ID = "synthetic.echo"


class CapabilityCatalogError(ValueError):
    """Raised when a capability catalog or manifest is invalid."""


@dataclass(frozen=True)
class ValidationIssue:
    severity: str
    capability_id: str
    message: str
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        result = {
            "severity": self.severity,
            "capability_id": self.capability_id,
            "message": self.message,
        }
        if self.path:
            result["path"] = self.path
        return result


@dataclass(frozen=True)
class CapabilityManifest:
    path: Path
    data: Mapping[str, Any]

    @property
    def capability_id(self) -> str:
        return str(self.data.get("id") or "<unknown>")

    @property
    def name(self) -> str:
        return str(self.data.get("name") or self.capability_id)

    @property
    def description(self) -> str:
        return str(self.data.get("description") or "")


def default_catalog_dir() -> Path:
    return get_hermes_home() / DEFAULT_CATALOG_DIRNAME


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_serialized(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".json" or yaml is None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return
    path.write_text(yaml.safe_dump(dict(data), sort_keys=False), encoding="utf-8")


def _load_serialized(path: Path) -> Mapping[str, Any]:
    raw = _read_text(path)
    if path.suffix.lower() == ".json":
        loaded = json.loads(raw)
    else:
        if yaml is None:
            raise CapabilityCatalogError("PyYAML is required to read YAML capability manifests")
        loaded = yaml.safe_load(raw)
    if not isinstance(loaded, Mapping):
        raise CapabilityCatalogError(f"{path} must contain a mapping/object")
    return loaded


def find_manifest_files(catalog_dir: Path | None = None) -> list[Path]:
    root = catalog_dir or default_catalog_dir()
    if not root.exists():
        return []
    files: list[Path] = []
    for name in CAPABILITY_FILE_NAMES:
        files.extend(root.glob(f"*/{name}"))
    return sorted(set(files))


def load_manifest(path: Path) -> CapabilityManifest:
    return CapabilityManifest(path=path, data=_load_serialized(path))


def load_catalog(catalog_dir: Path | None = None) -> list[CapabilityManifest]:
    return [load_manifest(path) for path in find_manifest_files(catalog_dir)]


def synthetic_capability_manifest() -> dict[str, Any]:
    """Return a credential-free smoke-test capability used by tests and demos."""

    return {
        "schema_version": CATALOG_VERSION,
        "id": SYNTHETIC_CAPABILITY_ID,
        "name": "Synthetic Echo Capability",
        "version": "0.1.0",
        "description": "Credential-free capability used to verify catalog install/doctor/smoke plumbing.",
        "owner": {"profile": "default", "lane": "test"},
        "approval_gates": ["no external sends", "no production restarts"],
        "components": {
            "skills": [],
            "plugins": [],
            "mcp_servers": [],
            "cron_jobs": [],
            "credentials": [],
            "smoke_tests": [
                {
                    "id": "echo-python",
                    "kind": "python",
                    "description": "Run a local Python one-liner and require a sentinel string.",
                    "command": [
                        sys.executable,
                        "-c",
                        "print('HERMES_CAPABILITY_SMOKE_OK')",
                    ],
                    "expect_stdout_contains": "HERMES_CAPABILITY_SMOKE_OK",
                    "timeout_seconds": 10,
                }
            ],
        },
        "install": {
            "steps": [
                "Validate manifest schema.",
                "Install/copy listed skills and plugins if absent.",
                "Register MCP servers and cron jobs after explicit approval.",
                "Request listed credentials through credential-intake; never embed secrets in the manifest.",
                "Run doctor, then smoke tests.",
            ]
        },
        "doctor": {
            "checks": [
                "Manifest validates.",
                "All referenced local files exist.",
                "Credential requirements are documented but not present in this synthetic capability.",
            ]
        },
        "remove": {
            "steps": [
                "Disable cron jobs owned by the capability.",
                "Remove capability-owned MCP server entries after approval.",
                "Leave shared skills/plugins unless explicitly capability-owned.",
                "Do not delete credentials automatically; print manual cleanup targets.",
            ]
        },
    }


def init_catalog(catalog_dir: Path | None = None, *, include_synthetic: bool = True) -> list[Path]:
    root = catalog_dir or default_catalog_dir()
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if include_synthetic:
        path = root / SYNTHETIC_CAPABILITY_ID / "capability.yaml"
        if not path.exists():
            _write_serialized(path, synthetic_capability_manifest())
        written.append(path)
    return written


def _as_list(value: Any, path: str, issues: list[ValidationIssue], cap_id: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        issues.append(ValidationIssue("error", cap_id, f"{path} must be a list", path))
        return []
    return value


def _manifest_dir(manifest: CapabilityManifest) -> Path:
    return manifest.path.parent


def _check_relative_path(
    *,
    base_dir: Path,
    value: Any,
    issue_path: str,
    issues: list[ValidationIssue],
    cap_id: str,
) -> None:
    if not value:
        return
    if not isinstance(value, str):
        issues.append(ValidationIssue("error", cap_id, f"{issue_path} must be a string", issue_path))
        return
    target = Path(value)
    if target.is_absolute():
        issues.append(ValidationIssue("error", cap_id, f"{issue_path} must be relative, not absolute", issue_path))
        return
    resolved = (base_dir / target).resolve()
    try:
        resolved.relative_to(base_dir.resolve())
    except ValueError:
        issues.append(ValidationIssue("error", cap_id, f"{issue_path} must stay inside the capability directory", issue_path))
        return
    if not resolved.exists():
        issues.append(ValidationIssue("error", cap_id, f"referenced file does not exist: {value}", issue_path))


def _validate_component_references(manifest: CapabilityManifest, issues: list[ValidationIssue]) -> None:
    data = manifest.data
    cap_id = str(data.get("id") or "<unknown>")
    base_dir = _manifest_dir(manifest)
    components = data.get("components") or {}
    if not isinstance(components, Mapping):
        issues.append(ValidationIssue("error", cap_id, "components must be a mapping/object", "components"))
        return
    for key in components:
        if key not in VALID_COMPONENT_KINDS:
            issues.append(ValidationIssue("warning", cap_id, f"unknown component kind: {key}", f"components.{key}"))

    for idx, skill in enumerate(_as_list(components.get("skills"), "components.skills", issues, cap_id)):
        if not isinstance(skill, Mapping):
            issues.append(ValidationIssue("error", cap_id, "skill entries must be objects", f"components.skills[{idx}]"))
            continue
        if not skill.get("name"):
            issues.append(ValidationIssue("error", cap_id, "skill entries require name", f"components.skills[{idx}].name"))
        _check_relative_path(
            base_dir=base_dir,
            value=skill.get("path"),
            issue_path=f"components.skills[{idx}].path",
            issues=issues,
            cap_id=cap_id,
        )

    for idx, plugin in enumerate(_as_list(components.get("plugins"), "components.plugins", issues, cap_id)):
        if not isinstance(plugin, Mapping):
            issues.append(ValidationIssue("error", cap_id, "plugin entries must be objects", f"components.plugins[{idx}]"))
            continue
        if not plugin.get("name"):
            issues.append(ValidationIssue("error", cap_id, "plugin entries require name", f"components.plugins[{idx}].name"))
        _check_relative_path(
            base_dir=base_dir,
            value=plugin.get("path"),
            issue_path=f"components.plugins[{idx}].path",
            issues=issues,
            cap_id=cap_id,
        )

    for idx, server in enumerate(_as_list(components.get("mcp_servers"), "components.mcp_servers", issues, cap_id)):
        if not isinstance(server, Mapping):
            issues.append(ValidationIssue("error", cap_id, "mcp server entries must be objects", f"components.mcp_servers[{idx}]"))
            continue
        if not server.get("name"):
            issues.append(ValidationIssue("error", cap_id, "mcp server entries require name", f"components.mcp_servers[{idx}].name"))
        if not (server.get("command") or server.get("url")):
            issues.append(ValidationIssue("error", cap_id, "mcp server entries require command or url", f"components.mcp_servers[{idx}]"))

    for idx, job in enumerate(_as_list(components.get("cron_jobs"), "components.cron_jobs", issues, cap_id)):
        if not isinstance(job, Mapping):
            issues.append(ValidationIssue("error", cap_id, "cron job entries must be objects", f"components.cron_jobs[{idx}]"))
            continue
        if not job.get("name") or not job.get("schedule"):
            issues.append(ValidationIssue("error", cap_id, "cron job entries require name and schedule", f"components.cron_jobs[{idx}]"))

    for idx, cred in enumerate(_as_list(components.get("credentials"), "components.credentials", issues, cap_id)):
        if not isinstance(cred, Mapping):
            issues.append(ValidationIssue("error", cap_id, "credential entries must be objects", f"components.credentials[{idx}]"))
            continue
        if not cred.get("name") or not cred.get("destination"):
            issues.append(ValidationIssue("error", cap_id, "credential entries require name and destination", f"components.credentials[{idx}]"))
        if cred.get("value") or cred.get("secret"):
            issues.append(ValidationIssue("error", cap_id, "credential manifests must not embed secret values", f"components.credentials[{idx}]"))

    for idx, smoke in enumerate(_as_list(components.get("smoke_tests"), "components.smoke_tests", issues, cap_id)):
        if not isinstance(smoke, Mapping):
            issues.append(ValidationIssue("error", cap_id, "smoke test entries must be objects", f"components.smoke_tests[{idx}]"))
            continue
        kind = smoke.get("kind")
        if kind not in VALID_SMOKE_KINDS:
            issues.append(ValidationIssue("error", cap_id, f"smoke test kind must be one of {sorted(VALID_SMOKE_KINDS)}", f"components.smoke_tests[{idx}].kind"))
        if not smoke.get("id"):
            issues.append(ValidationIssue("error", cap_id, "smoke tests require id", f"components.smoke_tests[{idx}].id"))
        if not smoke.get("command"):
            issues.append(ValidationIssue("error", cap_id, "smoke tests require command", f"components.smoke_tests[{idx}].command"))


def validate_manifest(manifest: CapabilityManifest) -> list[ValidationIssue]:
    data = manifest.data
    cap_id = str(data.get("id") or "<unknown>")
    issues: list[ValidationIssue] = []
    for field in ("schema_version", "id", "name", "version", "description", "components"):
        if field not in data:
            issues.append(ValidationIssue("error", cap_id, f"missing required field: {field}", field))
    if data.get("schema_version") != CATALOG_VERSION:
        issues.append(ValidationIssue("error", cap_id, f"schema_version must be {CATALOG_VERSION}", "schema_version"))
    if not isinstance(data.get("id", ""), str) or not data.get("id"):
        issues.append(ValidationIssue("error", cap_id, "id must be a non-empty string", "id"))
    if not isinstance(data.get("install"), Mapping):
        issues.append(ValidationIssue("error", cap_id, "install plan is required", "install"))
    if not isinstance(data.get("doctor"), Mapping):
        issues.append(ValidationIssue("error", cap_id, "doctor plan is required", "doctor"))
    if not isinstance(data.get("remove"), Mapping):
        issues.append(ValidationIssue("error", cap_id, "remove plan is required", "remove"))
    _validate_component_references(manifest, issues)
    return issues


def validate_catalog(catalog_dir: Path | None = None) -> tuple[list[CapabilityManifest], list[ValidationIssue]]:
    manifests = load_catalog(catalog_dir)
    issues: list[ValidationIssue] = []
    seen: dict[str, Path] = {}
    for manifest in manifests:
        cap_id = manifest.capability_id
        if cap_id in seen:
            issues.append(ValidationIssue("error", cap_id, f"duplicate capability id also defined at {seen[cap_id]}", "id"))
        seen[cap_id] = manifest.path
        issues.extend(validate_manifest(manifest))
    return manifests, issues


def _smoke_tests(manifest: CapabilityManifest) -> list[Mapping[str, Any]]:
    components = manifest.data.get("components") or {}
    if not isinstance(components, Mapping):
        return []
    tests = components.get("smoke_tests") or []
    return [test for test in tests if isinstance(test, Mapping)]


def _resolve_command(command: Any) -> list[str]:
    if isinstance(command, str):
        return [command]
    if isinstance(command, Sequence):
        return [str(part) for part in command]
    raise CapabilityCatalogError("smoke test command must be a string or list")


def run_smoke_tests(
    manifests: Iterable[CapabilityManifest],
    *,
    capability_id: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for manifest in manifests:
        if capability_id and manifest.capability_id != capability_id:
            continue
        for smoke in _smoke_tests(manifest):
            smoke_id = str(smoke.get("id") or "<unknown>")
            timeout = int(smoke.get("timeout_seconds") or 30)
            command = _resolve_command(smoke.get("command"))
            shell = isinstance(smoke.get("command"), str)
            completed = subprocess.run(
                command if not shell else command[0],
                cwd=manifest.path.parent,
                shell=shell,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            expected = str(smoke.get("expect_stdout_contains") or "")
            passed = completed.returncode == 0 and (not expected or expected in completed.stdout)
            results.append(
                {
                    "capability_id": manifest.capability_id,
                    "smoke_id": smoke_id,
                    "passed": passed,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout.strip(),
                    "stderr": completed.stderr.strip(),
                }
            )
    return results


def capability_plan(manifest: CapabilityManifest, action: str) -> dict[str, Any]:
    if action not in {"install", "doctor", "remove"}:
        raise CapabilityCatalogError("action must be install, doctor, or remove")
    plan = manifest.data.get(action) or {}
    if not isinstance(plan, Mapping):
        plan = {}
    return {
        "capability_id": manifest.capability_id,
        "action": action,
        "plan": dict(plan),
        "note": "Scaffold only: no credentials are installed and no production services are restarted.",
    }


def _select_manifest(manifests: Sequence[CapabilityManifest], capability_id: str) -> CapabilityManifest:
    for manifest in manifests:
        if manifest.capability_id == capability_id:
            return manifest
    raise CapabilityCatalogError(f"capability not found: {capability_id}")


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _print_issues(issues: Sequence[ValidationIssue]) -> None:
    if not issues:
        print("✓ capability catalog valid")
        return
    for issue in issues:
        location = f" [{issue.path}]" if issue.path else ""
        print(f"{issue.severity.upper()}: {issue.capability_id}{location}: {issue.message}")


def capability_catalog_command(args: argparse.Namespace) -> int:
    catalog_dir = Path(args.catalog_dir).expanduser() if getattr(args, "catalog_dir", None) else default_catalog_dir()
    action = getattr(args, "capability_action", None) or "list"
    try:
        if action == "init":
            written = init_catalog(catalog_dir, include_synthetic=True)
            if getattr(args, "json", False):
                _print_json({"catalog_dir": str(catalog_dir), "written": [str(path) for path in written]})
            else:
                print(f"Initialized capability catalog at {catalog_dir}")
                for path in written:
                    print(f"  • {path}")
            return 0

        manifests, issues = validate_catalog(catalog_dir)
        if action == "list":
            payload = [
                {
                    "id": manifest.capability_id,
                    "name": manifest.name,
                    "description": manifest.description,
                    "path": str(manifest.path),
                }
                for manifest in manifests
            ]
            if getattr(args, "json", False):
                _print_json(payload)
            else:
                if not payload:
                    print(f"No capabilities found in {catalog_dir}. Run `hermes capabilities init`.")
                for item in payload:
                    print(f"{item['id']} — {item['name']}")
                    if item["description"]:
                        print(f"  {item['description']}")
                    print(f"  {item['path']}")
            return 0

        if action in {"validate", "doctor"}:
            payload = {
                "catalog_dir": str(catalog_dir),
                "capabilities": len(manifests),
                "ok": not any(issue.severity == "error" for issue in issues),
                "issues": [issue.to_dict() for issue in issues],
            }
            if getattr(args, "json", False):
                _print_json(payload)
            else:
                _print_issues(issues)
            return 0 if payload["ok"] else 1

        if action == "smoke":
            if any(issue.severity == "error" for issue in issues):
                if getattr(args, "json", False):
                    _print_json({"ok": False, "issues": [issue.to_dict() for issue in issues]})
                else:
                    _print_issues(issues)
                return 1
            results = run_smoke_tests(manifests, capability_id=getattr(args, "capability_id", None))
            ok = bool(results) and all(item["passed"] for item in results)
            if getattr(args, "json", False):
                _print_json({"ok": ok, "results": results})
            else:
                for result in results:
                    mark = "✓" if result["passed"] else "✗"
                    print(f"{mark} {result['capability_id']}::{result['smoke_id']} rc={result['returncode']}")
                    if result["stdout"]:
                        print(f"  stdout: {result['stdout']}")
                    if result["stderr"]:
                        print(f"  stderr: {result['stderr']}")
                if not results:
                    print("No smoke tests matched.")
            return 0 if ok else 1

        if action == "plan":
            manifest = _select_manifest(manifests, args.capability_id)
            payload = capability_plan(manifest, args.plan_action)
            if getattr(args, "json", False):
                _print_json(payload)
            else:
                print(f"{payload['capability_id']} {payload['action']} plan")
                print(payload["note"])
                for step in payload["plan"].get("steps", payload["plan"].get("checks", [])):
                    print(f"  • {step}")
            return 0

        raise CapabilityCatalogError(f"unknown capabilities action: {action}")
    except (CapabilityCatalogError, OSError, json.JSONDecodeError, TimeoutError, subprocess.TimeoutExpired) as exc:
        if getattr(args, "json", False):
            _print_json({"ok": False, "error": str(exc)})
        else:
            print(f"capabilities error: {exc}", file=sys.stderr)
        return 1

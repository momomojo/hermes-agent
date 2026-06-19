#!/usr/bin/env python3
"""Privacy-safe HHFOS profile/persona registry compiler.

The compiler reads local Hermes profile directories, the HHFOS Kanban workflow
skill, and profile config/SOUL metadata to produce a registry plus drift report.
It intentionally emits only aggregate/persona labels, hashes, booleans, and
workflow-derived lane text; it does not quote SOUL.md or config secret values.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

try:  # pragma: no cover - exercised implicitly when PyYAML is installed
    import yaml  # type: ignore
except Exception:  # pragma: no cover - fallback for minimal installs
    yaml = None

SCHEMA_VERSION = 1
PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
LANE_RE = re.compile(r"^- `(?P<name>[a-z0-9_-]+)`: (?P<summary>.+)$")
SECRET_KEY_RE = re.compile(r"(api[_-]?key|token|secret|password|credential|auth|cookie|client_secret)", re.I)

DOMAIN_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("owner-admin", ("owner", "admin", "orchestrator", "architecture", "board triage", "governance")),
    ("medical-professional", ("medical", "uci", "residency", "onboarding", "schedule", "education")),
    ("radiology-product", ("radulator", "radiology", "calculator", "seo", "launch", "legal")),
    ("finance", ("finance", "pslf", "idr", "receipt", "cash-flow", "subscription")),
    ("nas-ops", ("truenas", "nas", "qdrant", "snapshot", "dataset", "backup", "hindsight")),
    ("home-automation", ("home assistant", "automation", "entity", "service", "device")),
    ("code-implementation", ("repo", "code", "implementation", "tests", "debug", "refactor")),
    ("google-workspace", ("gmail", "google", "calendar", "drive", "docs", "sheets")),
)

SENSITIVE_DATA_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("patient-data/PHI", ("phi", "patient identifier", "patient data")),
    ("credentials/secrets", ("credential", "password", "oauth", "api key", "token", "secret")),
    ("external-sends", ("send", "message", "email", "wife", "claire", "external")),
    ("payments/submissions", ("payment", "purchase", "submission", "upload", "portal")),
    ("destructive/state-changing ops", ("delete", "restart", "state change", "device action", "nas write")),
)


@dataclasses.dataclass(frozen=True)
class LaneSpec:
    name: str
    summary: str
    persona_domains: list[str]
    forbidden_boundaries: list[str]

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ProfileRecord:
    name: str
    profile_dir: str
    exists: bool
    expected_lane: bool
    lane_summary: str | None
    soul: dict[str, Any]
    persona_summary: dict[str, Any]
    data_domain_boundaries: dict[str, Any]
    dispatch: dict[str, Any]
    skills: dict[str, Any]
    config: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def load_yaml_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {"_read_error": True}
    if yaml is not None:
        try:
            loaded = yaml.safe_load(raw) or {}
            return loaded if isinstance(loaded, dict) else {}
        except Exception:
            return {"_parse_error": True}
    # Tiny fallback: parse enough indentation for tests/simple configs.
    result: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, result)]
    for raw_line in raw.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key = key.strip()
        val = val.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if not val:
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            if val.lower() in {"true", "false"}:
                parent[key] = val.lower() == "true"
            else:
                parent[key] = val.strip('"\'')
    return result


def get_nested(mapping: Mapping[str, Any], dotted: str, default: Any = None) -> Any:
    current: Any = mapping
    for part in dotted.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def scrub_config_summary(config: Mapping[str, Any]) -> dict[str, Any]:
    def safe_scalar(value: Any) -> Any:
        if isinstance(value, (bool, int, float)) or value is None:
            return value
        if isinstance(value, str):
            return value if len(value) <= 120 and not SECRET_KEY_RE.search(value) else "<redacted>"
        return f"<{type(value).__name__}>"

    summary: dict[str, Any] = {}
    for dotted in (
        "model.provider",
        "model.default",
        "model.api_mode",
        "kanban.dispatch_in_gateway",
        "kanban.enabled",
        "gateway.enabled",
    ):
        value = get_nested(config, dotted, None)
        if value is not None:
            summary[dotted] = safe_scalar(value)
    return summary


def infer_labels(text: str, *, fallback: Sequence[str] = ()) -> list[str]:
    lowered = text.lower()
    labels = [label for label, words in DOMAIN_KEYWORDS if any(word in lowered for word in words)]
    for label in fallback:
        if label not in labels:
            labels.append(label)
    return labels or ["unspecified"]


def infer_boundaries(text: str) -> list[str]:
    lowered = text.lower()
    return [label for label, words in SENSITIVE_DATA_MARKERS if any(word in lowered for word in words)]


def parse_hhfos_lanes(skill_path: Path) -> dict[str, LaneSpec]:
    text = skill_path.read_text(encoding="utf-8")
    in_section = False
    lanes: dict[str, LaneSpec] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "## Current profile lanes":
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if not in_section:
            continue
        match = LANE_RE.match(stripped)
        if not match:
            continue
        name = match.group("name")
        summary = normalize_space(match.group("summary"))
        lanes[name] = LaneSpec(
            name=name,
            summary=summary,
            persona_domains=infer_labels(summary),
            forbidden_boundaries=infer_boundaries(summary),
        )
    return lanes


def default_skill_path(hermes_root: Path) -> Path:
    candidates = [
        hermes_root / "skills" / "devops" / "hhfos-kanban-workflow" / "SKILL.md",
        hermes_root / "profiles" / "default" / "skills" / "devops" / "hhfos-kanban-workflow" / "SKILL.md",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("hhfos-kanban-workflow/SKILL.md not found; pass --workflow-skill")


def profile_dirs(hermes_root: Path) -> dict[str, Path]:
    profiles: dict[str, Path] = {"default": hermes_root}
    root = hermes_root / "profiles"
    if root.exists():
        for child in sorted(root.iterdir()):
            if child.name == "default":
                # The default profile is the Hermes root itself.  Some installs
                # carry a stale profiles/default helper dir; treating that as
                # authoritative would hide ~/.hermes/SOUL.md and root skills.
                continue
            if child.is_dir() and PROFILE_ID_RE.match(child.name):
                profiles[child.name] = child
    return profiles


def skill_presence(profile_dir: Path) -> dict[str, Any]:
    skills_root = profile_dir / "skills"
    expected = ["kanban-worker", "hhfos-kanban-workflow", "kanban-orchestrator", "hhfos-kanban-orchestrator"]
    found: dict[str, bool] = {name: False for name in expected}
    total_skill_files = 0
    if skills_root.exists():
        for skill_file in skills_root.rglob("SKILL.md"):
            total_skill_files += 1
            text = ""
            try:
                text = skill_file.read_text(encoding="utf-8", errors="replace")[:1000]
            except OSError:
                pass
            name_match = re.search(r"^name:\s*([A-Za-z0-9_-]+)\s*$", text, re.M)
            name = name_match.group(1) if name_match else skill_file.parent.name
            if name in found:
                found[name] = True
    return {"expected_presence": found, "skill_file_count": total_skill_files}


def soul_metadata(profile_dir: Path) -> dict[str, Any]:
    path = profile_dir / "SOUL.md"
    if not path.exists():
        return {"present": False, "sha256": None, "bytes": 0, "line_count": 0, "persona_labels": ["unspecified"]}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"present": True, "read_error": True, "sha256": None, "bytes": 0, "line_count": 0, "persona_labels": ["unreadable"]}
    return {
        "present": True,
        "sha256": sha256_text(text),
        "bytes": len(text.encode("utf-8", errors="replace")),
        "line_count": len(text.splitlines()),
        "persona_labels": infer_labels(text),
        "contains_sensitive_markers": bool(infer_boundaries(text)),
    }


def compile_profile(name: str, path: Path, lanes: Mapping[str, LaneSpec]) -> ProfileRecord:
    config = load_yaml_file(path / "config.yaml")
    lane = lanes.get(name)
    soul = soul_metadata(path)
    lane_labels = lane.persona_domains if lane else []
    persona_labels = list(dict.fromkeys([*soul.get("persona_labels", []), *lane_labels]))
    dispatch_actual = bool(get_nested(config, "kanban.dispatch_in_gateway", False))
    dispatch_expected = name == "default"
    return ProfileRecord(
        name=name,
        profile_dir=str(path),
        exists=path.exists(),
        expected_lane=lane is not None,
        lane_summary=lane.summary if lane else None,
        soul=soul,
        persona_summary={
            "labels": persona_labels or ["unspecified"],
            "source": "SOUL aggregate labels + hhfos-kanban-workflow lane text",
            "privacy": "No SOUL.md prose or config secrets are emitted; use sha256/size for identity checks.",
        },
        data_domain_boundaries={
            "allowed_summary": lane.summary if lane else None,
            "sensitive_boundaries": lane.forbidden_boundaries if lane else [],
        },
        dispatch={
            "kanban.dispatch_in_gateway": dispatch_actual,
            "expected": dispatch_expected,
            "matches_expected": dispatch_actual == dispatch_expected,
        },
        skills=skill_presence(path),
        config=scrub_config_summary(config),
    )


def build_drift(records: Sequence[ProfileRecord], lanes: Mapping[str, LaneSpec]) -> dict[str, Any]:
    names = {record.name for record in records}
    lane_names = set(lanes)
    unknown_profiles = sorted(names - lane_names)
    missing_lanes = sorted(lane_names - names)
    dispatcher_mismatches = [
        {
            "profile": record.name,
            "actual": record.dispatch["kanban.dispatch_in_gateway"],
            "expected": record.dispatch["expected"],
        }
        for record in records
        if not record.dispatch["matches_expected"]
    ]
    missing_kanban_worker = sorted(
        record.name
        for record in records
        if record.expected_lane and not record.skills["expected_presence"].get("kanban-worker")
    )
    return {
        "unknown_profiles": unknown_profiles,
        "missing_lanes": missing_lanes,
        "dispatcher_setting_mismatches": dispatcher_mismatches,
        "missing_kanban_worker_skill": missing_kanban_worker,
        "ok": not (unknown_profiles or missing_lanes or dispatcher_mismatches or missing_kanban_worker),
    }


def compile_registry(hermes_root: Path, workflow_skill: Path | None = None, *, now: str | None = None) -> dict[str, Any]:
    hermes_root = hermes_root.expanduser().resolve()
    workflow_skill = (workflow_skill or default_skill_path(hermes_root)).expanduser().resolve()
    lanes = parse_hhfos_lanes(workflow_skill)
    dirs = profile_dirs(hermes_root)
    records = [compile_profile(name, path, lanes) for name, path in sorted(dirs.items())]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now or utc_now(),
        "hermes_root": str(hermes_root),
        "workflow_skill": str(workflow_skill),
        "expected_lanes": {name: spec.as_dict() for name, spec in sorted(lanes.items())},
        "profiles": [record.as_dict() for record in records],
        "drift": build_drift(records, lanes),
    }


def render_markdown(registry: Mapping[str, Any]) -> str:
    drift = registry["drift"]
    lines = [
        "# HHFOS profile/persona registry drift report",
        "",
        f"Generated: {registry['generated_at']}",
        f"Hermes root: `{registry['hermes_root']}`",
        f"Workflow source: `{registry['workflow_skill']}`",
        "",
        "## Drift summary",
        "",
        f"- Overall OK: `{drift['ok']}`",
        f"- Unknown profiles: {', '.join(drift['unknown_profiles']) if drift['unknown_profiles'] else 'none'}",
        f"- Missing lanes: {', '.join(drift['missing_lanes']) if drift['missing_lanes'] else 'none'}",
        f"- Dispatcher mismatches: {len(drift['dispatcher_setting_mismatches'])}",
        f"- Missing kanban-worker skill: {', '.join(drift['missing_kanban_worker_skill']) if drift['missing_kanban_worker_skill'] else 'none'}",
        "",
        "## Profiles",
        "",
        "| profile | lane? | persona labels | dispatch actual/expected | SOUL | skills |",
        "|---|---:|---|---|---|---|",
    ]
    for profile in registry["profiles"]:
        soul = profile["soul"]
        skills = profile["skills"]["expected_presence"]
        skill_bits = ", ".join(f"{name}={'yes' if value else 'no'}" for name, value in sorted(skills.items()))
        lines.append(
            "| {name} | {lane} | {labels} | {actual}/{expected} | {soul_present}, {bytes}B, sha256:{sha} | {skills} |".format(
                name=profile["name"],
                lane="yes" if profile["expected_lane"] else "no",
                labels=", ".join(profile["persona_summary"]["labels"]),
                actual=profile["dispatch"]["kanban.dispatch_in_gateway"],
                expected=profile["dispatch"]["expected"],
                soul_present="present" if soul.get("present") else "absent",
                bytes=soul.get("bytes", 0),
                sha=(soul.get("sha256") or "none")[:12],
                skills=skill_bits,
            )
        )
    lines.extend(["", "## Privacy note", "", "This report does not emit SOUL.md prose, memory text, .env values, OAuth material, cookies, or config secret fields. Persona summaries are labels inferred from local aggregate text and HHFOS workflow lane descriptions."])
    return "\n".join(lines) + "\n"


def write_outputs(registry: Mapping[str, Any], json_path: Path | None, report_path: Path | None) -> None:
    if json_path is not None:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(render_markdown(registry), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-root", type=Path, default=Path(os.environ.get("HERMES_ROOT", Path.home() / ".hermes")))
    parser.add_argument("--workflow-skill", type=Path, default=None)
    parser.add_argument("--json-output", type=Path, default=None)
    parser.add_argument("--report-output", type=Path, default=None)
    parser.add_argument("--now", default=None)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    registry = compile_registry(args.hermes_root, args.workflow_skill, now=args.now)
    write_outputs(registry, args.json_output, args.report_output)
    print(json.dumps({"summary": registry["drift"], "json_output": str(args.json_output) if args.json_output else None, "report_output": str(args.report_output) if args.report_output else None}, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

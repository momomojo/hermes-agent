"""Shared guardrails for skill references that must survive curation.

The curator, cron scheduler, and Kanban dispatcher all refer to skills by
stable string identifiers.  If a background consolidation archives one of
those names without migrating every reference, downstream workers fail before
they can report a useful block reason.  This module keeps the reference audit
small, import-light, and reusable across those call sites.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable, Optional

from hermes_constants import get_default_hermes_root, get_hermes_home

logger = logging.getLogger(__name__)


RUNTIME_ABI_SKILLS = frozenset(
    {
        "kanban-worker",
        "kanban-orchestrator",
        "hermes-agent",
        "sdlc-review",
    }
)

NON_TERMINAL_KANBAN_STATUSES = (
    "triage",
    "todo",
    "scheduled",
    "ready",
    "running",
    "blocked",
    "review",
)

_PROFILE_DEFAULT_KEYS = (
    "default",
    "defaults",
    "default_skills",
    "preload",
    "preloaded",
    "autoload",
    "auto_load",
)


def normalize_skill_names(skills: Optional[Iterable[Any]]) -> list[str]:
    """Return unique, stripped skill names while preserving order."""
    if skills is None:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in skills:
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
    return out


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        import yaml

        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return data if isinstance(data, dict) else {}
    except Exception as exc:
        logger.debug("failed to read yaml %s: %s", path, exc)
        return {}


def _configured_external_skill_dirs(home: Path) -> list[Path]:
    cfg = _read_yaml(home / "config.yaml")
    skills_cfg = cfg.get("skills") if isinstance(cfg, dict) else None
    if not isinstance(skills_cfg, dict):
        return []
    raw = skills_cfg.get("external_dirs") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        return []
    dirs: list[Path] = []
    for value in raw:
        text = str(value or "").strip()
        if not text:
            continue
        path = Path(text).expanduser()
        if not path.is_absolute():
            path = home / path
        if path.is_dir():
            dirs.append(path)
    return dirs


def _iter_skill_roots(home: Path) -> list[Path]:
    roots = [home / "skills"]
    roots.extend(_configured_external_skill_dirs(home))
    return roots


def _skill_md_names(skill_md: Path) -> set[str]:
    names = {skill_md.parent.name}
    try:
        from agent.skill_utils import parse_frontmatter

        frontmatter, _body = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
        fm_name = frontmatter.get("name") if isinstance(frontmatter, dict) else None
        if isinstance(fm_name, str) and fm_name.strip():
            names.add(fm_name.strip())
    except Exception:
        pass
    return names


def skill_exists_in_home(skill_name: str, home: Path | str) -> bool:
    """Return True when ``skill_name`` resolves as an active skill in ``home``."""
    name = str(skill_name or "").strip()
    if not name:
        return False
    try:
        from agent.skill_utils import is_excluded_skill_path
    except Exception:
        def is_excluded_skill_path(_path: Path) -> bool:  # type: ignore[no-redef]
            return ".archive" in _path.parts

    base = Path(home).expanduser()
    for root in _iter_skill_roots(base):
        if not root.is_dir():
            continue
        direct = root / name / "SKILL.md"
        if direct.is_file() and not is_excluded_skill_path(direct):
            return True
        try:
            for skill_md in root.rglob("SKILL.md"):
                if is_excluded_skill_path(skill_md):
                    continue
                if name in _skill_md_names(skill_md):
                    return True
        except OSError:
            continue
    return False


def profile_home(profile: Optional[str]) -> Path:
    """Resolve a Kanban assignee profile to the HERMES_HOME workers will use."""
    if profile:
        try:
            from hermes_cli.profiles import get_profile_dir

            return get_profile_dir(profile)
        except Exception:
            pass
    return get_hermes_home()


def validate_task_skills_for_profile(
    skills: Optional[Iterable[Any]],
    profile: Optional[str],
    *,
    allow_uninitialized_home: bool = False,
    allow_missing_profile: bool = False,
) -> list[dict[str, Any]]:
    """Return missing skill records for forced task skills in ``profile``.

    ``allow_uninitialized_home`` is for creation-time compatibility with fresh
    test/dev homes that have not seeded ``skills/`` yet.  Dispatch-time callers
    should leave it false so missing references become explicit blocked tasks.
    """
    requested = normalize_skill_names(skills)
    if not requested:
        return []
    home = profile_home(profile)
    if allow_missing_profile and profile and not home.is_dir():
        return []
    if allow_uninitialized_home and not (home / "skills").is_dir():
        return []
    missing: list[dict[str, Any]] = []
    for name in requested:
        if not skill_exists_in_home(name, home):
            missing.append(
                {
                    "name": name,
                    "profile": profile or "default",
                    "home": str(home),
                }
            )
    return missing


def _json_skill_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return normalize_skill_names(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return []
        if isinstance(parsed, list):
            return normalize_skill_names(parsed)
    return []


def kanban_preflight(conn: Any) -> dict[str, Any]:
    """Check every non-terminal Kanban task against its assignee skill home."""
    placeholders = ",".join("?" * len(NON_TERMINAL_KANBAN_STATUSES))
    rows = conn.execute(
        "SELECT id, status, assignee, skills FROM tasks "
        f"WHERE status IN ({placeholders}) "
        "ORDER BY created_at ASC, id ASC",
        NON_TERMINAL_KANBAN_STATUSES,
    ).fetchall()
    missing: list[dict[str, Any]] = []
    checked = 0
    for row in rows:
        skills = _json_skill_list(row["skills"])
        if row["status"] == "review":
            skills = normalize_skill_names([*skills, "sdlc-review"])
        if not skills:
            continue
        checked += 1
        for item in validate_task_skills_for_profile(
            skills,
            row["assignee"],
            allow_uninitialized_home=False,
            allow_missing_profile=True,
        ):
            item.update(
                {
                    "task_id": row["id"],
                    "status": row["status"],
                    "source": "kanban.tasks.skills",
                }
            )
            missing.append(item)
    return {
        "ok": not missing,
        "checked_tasks": checked,
        "missing": missing,
    }


def _collect_kanban_references() -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    try:
        from hermes_cli import kanban_db

        db_path = kanban_db.kanban_db_path()
        if not db_path.exists():
            return refs
        with kanban_db.connect_closing() as conn:
            placeholders = ",".join("?" * len(NON_TERMINAL_KANBAN_STATUSES))
            rows = conn.execute(
                "SELECT id, status, assignee, skills FROM tasks "
                f"WHERE status IN ({placeholders})",
                NON_TERMINAL_KANBAN_STATUSES,
            ).fetchall()
            for row in rows:
                for name in _json_skill_list(row["skills"]):
                    refs.append(
                        {
                            "name": name,
                            "source": "kanban.tasks.skills",
                            "task_id": row["id"],
                            "profile": row["assignee"],
                            "status": row["status"],
                        }
                    )
                if row["status"] == "review":
                    refs.append(
                        {
                            "name": "sdlc-review",
                            "source": "kanban.review.dispatcher",
                            "task_id": row["id"],
                            "profile": row["assignee"],
                            "status": row["status"],
                        }
                    )
    except Exception as exc:
        logger.debug("failed to collect kanban skill references: %s", exc, exc_info=True)
    return refs


def _collect_cron_references() -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    try:
        from cron.jobs import load_jobs

        for job in load_jobs():
            raw_skills = job.get("skills")
            if raw_skills is None and job.get("skill"):
                raw_skills = [job.get("skill")]
            for name in normalize_skill_names(raw_skills or []):
                refs.append(
                    {
                        "name": name,
                        "source": "cron.jobs.skills",
                        "job_id": job.get("id"),
                        "job_name": job.get("name"),
                        "profile": job.get("profile"),
                    }
                )
    except Exception as exc:
        logger.debug("failed to collect cron skill references: %s", exc, exc_info=True)
    return refs


def _extract_profile_skill_defaults(config: dict[str, Any]) -> list[str]:
    skills_cfg = config.get("skills") if isinstance(config, dict) else None
    if not isinstance(skills_cfg, dict):
        return []
    names: list[str] = []
    for key in _PROFILE_DEFAULT_KEYS:
        value = skills_cfg.get(key)
        if isinstance(value, str):
            names.append(value)
        elif isinstance(value, (list, tuple)):
            names.extend(str(v) for v in value)
    return normalize_skill_names(names)


def _collect_profile_default_references() -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    try:
        root = get_default_hermes_root()
    except Exception:
        root = get_hermes_home()
    candidates: list[tuple[str, Path]] = [("default", root)]
    profiles_root = root / "profiles"
    if profiles_root.is_dir():
        try:
            for entry in sorted(profiles_root.iterdir()):
                if entry.is_dir():
                    candidates.append((entry.name, entry))
        except OSError:
            pass
    for profile, home in candidates:
        cfg = _read_yaml(home / "config.yaml")
        for name in _extract_profile_skill_defaults(cfg):
            refs.append(
                {
                    "name": name,
                    "source": "profile.config.skills",
                    "profile": profile,
                    "config": str(home / "config.yaml"),
                }
            )
    return refs


def collect_protected_references() -> dict[str, Any]:
    """Return protected skill names and the live references protecting them."""
    refs: list[dict[str, Any]] = [
        {"name": name, "source": "runtime.abi"}
        for name in sorted(RUNTIME_ABI_SKILLS)
    ]
    refs.extend(_collect_kanban_references())
    refs.extend(_collect_cron_references())
    refs.extend(_collect_profile_default_references())

    by_name: dict[str, list[dict[str, Any]]] = {}
    for ref in refs:
        name = str(ref.get("name") or "").strip()
        if not name:
            continue
        by_name.setdefault(name, []).append(ref)
    return {
        "protected_names": sorted(by_name),
        "references": refs,
        "by_name": by_name,
        "count": len(by_name),
        "reference_count": len(refs),
    }


def summarize_protected_references(
    snapshot: dict[str, Any], *, sample_limit: int = 3, name_limit: int = 25
) -> dict[str, Any]:
    """Return a globally bounded, aggregation-first diagnostic view."""
    limit = max(0, int(sample_limit))
    max_names = max(0, int(name_limit))
    raw_by_name = snapshot.get("by_name")
    if not isinstance(raw_by_name, dict):
        raw_by_name = {}
    all_names = sorted(str(name) for name in raw_by_name)
    ranked_names = sorted(
        all_names,
        key=lambda name: (-len(raw_by_name.get(name) or []), name),
    )
    selected_names = ranked_names[:max_names]
    summaries: dict[str, dict[str, Any]] = {}
    for name in selected_names:
        refs = [ref for ref in (raw_by_name.get(name) or []) if isinstance(ref, dict)]
        by_source: dict[str, int] = {}
        by_status: dict[str, int] = {}
        for ref in refs:
            source = str(ref.get("source") or "unknown")
            by_source[source] = by_source.get(source, 0) + 1
            if ref.get("status"):
                status = str(ref["status"])
                by_status[status] = by_status.get(status, 0) + 1
        samples = [dict(ref) for ref in refs[:limit]]
        summaries[str(name)] = {
            "total": len(refs),
            "by_source": dict(sorted(by_source.items())),
            "by_status": dict(sorted(by_status.items())),
            "samples": samples,
            "omitted": max(0, len(refs) - len(samples)),
        }
    reference_count = sum(
        len([ref for ref in (raw_by_name.get(name) or []) if isinstance(ref, dict)])
        for name in all_names
    )
    sampled_by_name = {
        name: list(item["samples"]) for name, item in summaries.items()
    }
    sampled_references = [
        ref for refs in sampled_by_name.values() for ref in refs
    ]
    return {
        "protected_names": sorted(summaries),
        "references": sampled_references,
        "by_name": sampled_by_name,
        "count": len(all_names),
        "reference_count": reference_count,
        "summary_by_name": summaries,
        "bounded": True,
        "sample_limit": limit,
        "name_limit": max_names,
        "protected_names_truncated": len(all_names) > len(summaries),
        "names_omitted": max(0, len(all_names) - len(summaries)),
        "references_truncated": reference_count > len(sampled_references),
        **({"error": snapshot["error"]} if snapshot.get("error") else {}),
    }


def is_protected_skill(skill_name: str) -> bool:
    """Return True if ``skill_name`` is currently protected from curation."""
    name = str(skill_name or "").strip()
    if not name:
        return False
    return name in set(collect_protected_references().get("protected_names") or [])


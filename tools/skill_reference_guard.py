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


def _strict_json_skill_list(value: Any) -> tuple[list[str], str | None]:
    """Parse persisted Kanban skills without treating corruption as empty."""
    if value in (None, ""):
        return [], None
    if isinstance(value, list):
        return normalize_skill_names(value), None
    if not isinstance(value, str):
        return [], "skills value is not JSON text"
    try:
        parsed = json.loads(value)
    except Exception as exc:
        return [], f"skills JSON malformed: {type(exc).__name__}"
    if not isinstance(parsed, list):
        return [], "skills JSON is not a list"
    return normalize_skill_names(parsed), None


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


def _collect_kanban_references() -> tuple[list[dict[str, Any]], str | None]:
    refs: list[dict[str, Any]] = []
    try:
        from hermes_cli import kanban_db

        db_path = kanban_db.kanban_db_path()
        if not db_path.exists():
            return refs, None
        with kanban_db.connect_closing() as conn:
            placeholders = ",".join("?" * len(NON_TERMINAL_KANBAN_STATUSES))
            rows = conn.execute(
                "SELECT id, status, assignee, skills FROM tasks "
                f"WHERE status IN ({placeholders})",
                NON_TERMINAL_KANBAN_STATUSES,
            ).fetchall()
            for row in rows:
                names, malformed = _strict_json_skill_list(row["skills"])
                if malformed:
                    return refs, f"kanban scan failed: task {row['id']} {malformed}"
                for name in names:
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
        return refs, f"kanban scan failed: {type(exc).__name__}"
    return refs, None


def _collect_cron_references() -> tuple[list[dict[str, Any]], str | None]:
    refs: list[dict[str, Any]] = []
    try:
        from cron.jobs import load_jobs

        for job in load_jobs():
            if not isinstance(job, dict):
                return refs, "cron scan failed: job record is not an object"
            raw_skills = job.get("skills")
            if raw_skills is None and job.get("skill"):
                raw_skills = [job.get("skill")]
            if raw_skills is not None and not isinstance(raw_skills, (str, list, tuple)):
                return refs, "cron scan failed: skills field is malformed"
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
        return refs, f"cron scan failed: {type(exc).__name__}"
    return refs, None


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


def _collect_profile_default_references() -> tuple[list[dict[str, Any]], str | None]:
    refs: list[dict[str, Any]] = []
    try:
        root = get_default_hermes_root()
    except Exception as exc:
        return refs, f"profile scan failed: {type(exc).__name__}"
    candidates: list[tuple[str, Path]] = [("default", root)]
    profiles_root = root / "profiles"
    if profiles_root.is_dir():
        try:
            for entry in sorted(profiles_root.iterdir()):
                if entry.is_dir():
                    candidates.append((entry.name, entry))
        except OSError as exc:
            return refs, f"profile scan failed: {type(exc).__name__}"
    for profile, home in candidates:
        config_path = home / "config.yaml"
        if not config_path.exists():
            cfg = {}
        else:
            try:
                import yaml
                cfg = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
                if not isinstance(cfg, dict):
                    return refs, f"profile scan failed: {profile} config is not a mapping"
            except Exception as exc:
                return refs, f"profile scan failed: {profile} config unreadable ({type(exc).__name__})"
        for name in _extract_profile_skill_defaults(cfg):
            refs.append(
                {
                    "name": name,
                    "source": "profile.config.skills",
                    "profile": profile,
                    "config": str(home / "config.yaml"),
                }
            )
    return refs, None


def collect_protected_references() -> dict[str, Any]:
    """Return a complete safety index and separate diagnostics input.

    A collector failure never means that no references exist. Callers that
    archive skills must reject an incomplete index; reports can compact it via
    :func:`summarize_protected_references` without weakening that safety gate.
    """
    refs: list[dict[str, Any]] = [
        {"name": name, "source": "runtime.abi"}
        for name in sorted(RUNTIME_ABI_SKILLS)
    ]
    collector_errors: dict[str, str] = {}
    for label, collector in (
        ("kanban", _collect_kanban_references),
        ("cron", _collect_cron_references),
        ("profiles", _collect_profile_default_references),
    ):
        collected, error = collector()
        refs.extend(collected)
        if error:
            collector_errors[label] = error

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
        "complete": not collector_errors,
        "collector_errors": collector_errors,
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
        "complete": bool(snapshot.get("complete", True)),
        "collector_errors": dict(snapshot.get("collector_errors") or {}),
        **({"error": snapshot["error"]} if snapshot.get("error") else {}),
    }


def is_protected_skill(skill_name: str) -> bool:
    """Return True if ``skill_name`` is currently protected from curation."""
    name = str(skill_name or "").strip()
    if not name:
        return False
    return name in set(collect_protected_references().get("protected_names") or [])


def _replace_ordered(skills: list[str], old: str, new: str) -> list[str]:
    """Replace one reference while preserving first-seen order and uniqueness."""
    out: list[str] = []
    for skill in skills:
        candidate = new if skill == old else skill
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def migrate_kanban_skill_refs(old: str, new: str) -> dict[str, Any]:
    """Atomically migrate non-terminal Kanban references and audit each row."""
    from hermes_cli import kanban_db
    from hermes_cli.sqlite_util import write_txn

    updates: list[dict[str, Any]] = []
    with kanban_db.connect_closing() as conn, write_txn(conn):
        placeholders = ",".join("?" * len(NON_TERMINAL_KANBAN_STATUSES))
        rows = conn.execute(
            "SELECT id, skills FROM tasks WHERE status IN (" + placeholders + ")",
            NON_TERMINAL_KANBAN_STATUSES,
        ).fetchall()
        for row in rows:
            before, malformed = _strict_json_skill_list(row["skills"])
            if malformed:
                raise ValueError(f"task {row['id']} {malformed}")
            if old not in before:
                continue
            after = _replace_ordered(before, old, new)
            cursor = conn.execute(
                "UPDATE tasks SET skills = ? WHERE id = ? AND COALESCE(skills, '') = ?",
                (json.dumps(after, ensure_ascii=False), row["id"], row["skills"] or ""),
            )
            if cursor.rowcount != 1:
                raise RuntimeError(f"concurrent Kanban update for task {row['id']}")
            kanban_db._append_event(
                conn, row["id"], "skill_reference_migrated",
                {"from": old, "to": new, "before": before, "after": after},
            )
            updates.append({"task_id": row["id"], "before": before, "after": after})
    return {"tasks_updated": len(updates), "updates": updates}


def prepare_skill_archive(name: str, absorbed_into: Optional[str]) -> dict[str, Any]:
    """Run the fail-closed prepare → migrate → verify half of archive saga.

    The caller archives only after this succeeds, so every partial migration
    failure leaves the source active. Retrying is safe because rewrites dedupe.
    """
    source = str(name or "").strip()
    target = str(absorbed_into or "").strip()
    snapshot = collect_protected_references()
    if not snapshot.get("complete", False):
        return {"success": False, "error": "reference safety scan incomplete", "_fail_closed": True}
    refs = list((snapshot.get("by_name") or {}).get(source) or [])
    if not target:
        if refs:
            return {"success": False, "error": f"Skill '{source}' has live references and cannot be pruned.", "_fail_closed": True}
        return {"success": True, "migration": {"cron": {}, "kanban": {}}}
    if source in RUNTIME_ABI_SKILLS:
        return {"success": False, "error": f"Skill '{source}' is a runtime ABI reference and cannot be migrated.", "_fail_closed": True}
    profiles = {str(ref.get("profile") or "") for ref in refs}
    for profile in profiles:
        if not skill_exists_in_home(target, profile_home(profile or None)):
            return {"success": False, "error": f"Target '{target}' is not active for affected profile '{profile or 'default'}'.", "_fail_closed": True}
    try:
        from cron.jobs import rewrite_skill_refs
        cron = rewrite_skill_refs(consolidated={source: target}, pruned=[])
        kanban = migrate_kanban_skill_refs(source, target)
    except Exception as exc:
        logger.warning("skill archive migration failed for %s: %s", source, exc, exc_info=True)
        return {"success": False, "error": f"reference migration failed: {type(exc).__name__}", "_fail_closed": True}
    verified = collect_protected_references()
    if not verified.get("complete", False) or source in set(verified.get("protected_names") or []):
        return {"success": False, "error": "post-migration complete rescan still finds source references", "_fail_closed": True}
    return {"success": True, "migration": {"cron": cron, "kanban": kanban}}


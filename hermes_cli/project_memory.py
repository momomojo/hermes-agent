"""File-backed Hermes Project Memory.

Project Memory is intentionally lightweight: one markdown document plus a JSON
sidecar per project under ``$HERMES_HOME/project-memory/<safe-id>/``. It gives
Kanban/Hindsight/skills/cron/artifact workflows a durable project narrative
without adding prompt-cache weight or a model-facing tool schema.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from hermes_constants import get_hermes_home

SCHEMA_VERSION = 1
PROJECT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
_UNSAFE_RE = re.compile(r"[^a-z0-9._-]+")

LINK_FIELDS = {
    "kanban_tasks": "Kanban task ids",
    "skills": "Hermes skill names",
    "cron_jobs": "Hermes cron job ids",
    "artifacts": "Artifact registry ids or paths",
    "hindsight_entities": "Hindsight/entity references",
}


@dataclass(frozen=True)
class ProjectMemoryRecord:
    project_id: str
    title: str
    memory_path: str
    metadata_path: str
    exists: bool
    created_at: int | None
    updated_at: int | None
    links: dict[str, list[str]]
    bytes: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def project_memory_root() -> Path:
    return get_hermes_home() / "project-memory"


def normalize_project_id(value: str) -> str:
    """Return a safe project id or raise ``ValueError``.

    The normalizer accepts human-ish names but never preserves path separators
    or traversal components. The result is suitable as exactly one path segment.
    """

    raw = (value or "").strip().lower()
    raw = raw.replace("/", "-").replace("\\", "-")
    candidate = _UNSAFE_RE.sub("-", raw).strip(".-_")
    candidate = re.sub(r"[-_.]{2,}", "-", candidate)[:80].strip(".-_")
    if not candidate or candidate in {".", ".."} or not PROJECT_ID_RE.match(candidate):
        raise ValueError(f"invalid project id: {value!r}")
    return candidate


def project_dir(project: str) -> Path:
    pid = normalize_project_id(project)
    return project_memory_root() / pid


def memory_path(project: str) -> Path:
    return project_dir(project) / "memory.md"


def metadata_path(project: str) -> Path:
    return project_dir(project) / "metadata.json"


def _now(now: int | float | None = None) -> int:
    return int(time.time() if now is None else now)


def _empty_links() -> dict[str, list[str]]:
    return {field: [] for field in LINK_FIELDS}


def _load_metadata(project: str) -> dict[str, Any]:
    path = metadata_path(project)
    if not path.exists():
        pid = normalize_project_id(project)
        return {
            "schema_version": SCHEMA_VERSION,
            "project_id": pid,
            "title": pid,
            "created_at": None,
            "updated_at": None,
            "links": _empty_links(),
        }
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        data = {}
    links = _empty_links()
    raw_links = data.get("links") if isinstance(data, dict) else {}
    if isinstance(raw_links, dict):
        for field in LINK_FIELDS:
            values = raw_links.get(field) or []
            if isinstance(values, list):
                links[field] = [str(v) for v in values if str(v).strip()]
    pid = normalize_project_id(str(data.get("project_id") or project)) if isinstance(data, dict) else normalize_project_id(project)
    return {
        "schema_version": SCHEMA_VERSION,
        "project_id": pid,
        "title": str(data.get("title") or pid) if isinstance(data, dict) else pid,
        "created_at": data.get("created_at") if isinstance(data, dict) else None,
        "updated_at": data.get("updated_at") if isinstance(data, dict) else None,
        "links": links,
    }


def _write_metadata(project: str, metadata: dict[str, Any]) -> None:
    path = metadata_path(project)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _dedupe(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def read_project_memory(project: str) -> tuple[ProjectMemoryRecord, str]:
    pid = normalize_project_id(project)
    meta = _load_metadata(pid)
    path = memory_path(pid)
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    stat_size = path.stat().st_size if path.exists() else 0
    return (
        ProjectMemoryRecord(
            project_id=pid,
            title=str(meta.get("title") or pid),
            memory_path=str(path),
            metadata_path=str(metadata_path(pid)),
            exists=path.exists(),
            created_at=meta.get("created_at"),
            updated_at=meta.get("updated_at"),
            links=meta.get("links") or _empty_links(),
            bytes=stat_size,
        ),
        content,
    )


def update_project_memory(
    project: str,
    *,
    content: str | None = None,
    append: str | None = None,
    title: str | None = None,
    links: dict[str, Iterable[str]] | None = None,
    now: int | float | None = None,
) -> ProjectMemoryRecord:
    if content is not None and append is not None:
        raise ValueError("pass either content or append, not both")
    pid = normalize_project_id(project)
    pdir = project_dir(pid)
    pdir.mkdir(parents=True, exist_ok=True)
    path = memory_path(pid)
    ts = _now(now)
    meta = _load_metadata(pid)
    if meta.get("created_at") is None:
        meta["created_at"] = ts
    if title:
        meta["title"] = title.strip()
    if content is not None:
        new_text = content
    elif append is not None:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        separator = "" if not existing or existing.endswith("\n") else "\n"
        new_text = existing + separator + append.rstrip() + "\n"
    elif not path.exists():
        new_text = f"# {meta.get('title') or pid}\n\n"
    else:
        new_text = path.read_text(encoding="utf-8")
    path.write_text(new_text, encoding="utf-8")

    if links:
        merged = meta.get("links") or _empty_links()
        for field, values in links.items():
            if field not in LINK_FIELDS:
                raise ValueError(f"unknown link field: {field}")
            merged[field] = _dedupe([*(merged.get(field) or []), *values])
        meta["links"] = merged
    meta["project_id"] = pid
    meta["schema_version"] = SCHEMA_VERSION
    meta["updated_at"] = ts
    _write_metadata(pid, meta)
    return read_project_memory(pid)[0]


def list_project_memories() -> list[ProjectMemoryRecord]:
    root = project_memory_root()
    if not root.exists():
        return []
    records: list[ProjectMemoryRecord] = []
    for entry in sorted(p for p in root.iterdir() if p.is_dir()):
        try:
            record, _ = read_project_memory(entry.name)
        except ValueError:
            continue
        records.append(record)
    return sorted(records, key=lambda r: (r.updated_at or 0, r.project_id), reverse=True)


def project_memory_command(args) -> None:
    action = getattr(args, "project_memory_action", None) or "list"
    if action in {"list", "ls"}:
        rows = [record.to_dict() for record in list_project_memories()]
        if getattr(args, "json", False):
            print(json.dumps({"projects": rows}, indent=2))
        else:
            for row in rows:
                print(f"{row['project_id']}\t{row['title']}\t{row['memory_path']}")
        return
    if action == "show":
        record, content = read_project_memory(args.project)
        if getattr(args, "json", False):
            payload = record.to_dict()
            payload["content"] = content
            print(json.dumps(payload, indent=2))
        else:
            print(content, end="" if content.endswith("\n") or not content else "\n")
        return
    if action == "path":
        print(memory_path(args.project))
        return
    if action == "update":
        raw_link_updates: dict[str, list[str]] = {
            "kanban_tasks": list(getattr(args, "kanban_task", None) or []),
            "skills": list(getattr(args, "skill", None) or []),
            "cron_jobs": list(getattr(args, "cron_job", None) or []),
            "artifacts": list(getattr(args, "artifact", None) or []),
            "hindsight_entities": list(getattr(args, "hindsight_entity", None) or []),
        }
        link_updates: dict[str, Iterable[str]] = {k: v for k, v in raw_link_updates.items() if v}
        content = args.content
        if args.content_file:
            content = Path(args.content_file).read_text(encoding="utf-8")
        record = update_project_memory(
            args.project,
            content=content,
            append=args.append,
            title=args.title,
            links=link_updates,
        )
        if getattr(args, "json", False):
            print(json.dumps(record.to_dict(), indent=2))
        else:
            print(record.memory_path)
        return
    raise SystemExit(f"unknown project-memory action: {action}")

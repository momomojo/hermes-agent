"""Command handlers for ``hermes artifacts``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hermes_cli import artifact_registry as registry


def _emit(data: Any, *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
        return
    if isinstance(data, registry.ArtifactRecord):
        print(f"{data.id} {data.cleanup_state} {data.source} {data.path}")
        if data.task_id:
            print(f"task: {data.task_id}")
        if data.session_id:
            print(f"session: {data.session_id}")
        if data.expires_at is not None:
            print(f"expires_at: {data.expires_at}")
        return
    print(data)


def _load_metadata(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("--metadata must be a JSON object")
    return parsed


def artifacts_command(args) -> None:  # noqa: ANN001 - argparse namespace
    action = getattr(args, "artifacts_action", None)
    if action in {None, ""}:
        raise SystemExit("usage: hermes artifacts <list|show|register|promote|cleanup>")

    if action == "list":
        records = registry.list_artifacts(
            source=getattr(args, "source", None),
            task_id=getattr(args, "task", None),
            session_id=getattr(args, "session", None),
            cleanup_state=getattr(args, "state", None),
            limit=getattr(args, "limit", 100),
        )
        if getattr(args, "json", False):
            _emit([r.to_dict() for r in records], as_json=True)
            return
        for record in records:
            ttl = f" expires={record.expires_at}" if record.expires_at is not None else ""
            print(f"{record.id} {record.cleanup_state:8s} {record.source:16s} {record.path}{ttl}")
        return

    if action == "show":
        record = registry.get_artifact(args.artifact_id)
        if record is None:
            raise SystemExit(f"artifact not found: {args.artifact_id}")
        _emit(record.to_dict() if getattr(args, "json", False) else record, as_json=getattr(args, "json", False))
        return

    if action == "register":
        ttl_seconds = registry.parse_ttl(getattr(args, "ttl", None))
        record = registry.register_artifact(
            Path(args.path),
            source=args.source,
            source_id=getattr(args, "source_id", None),
            mime_type=getattr(args, "mime", None),
            sensitivity=getattr(args, "sensitivity", "unknown"),
            task_id=getattr(args, "task", None),
            session_id=getattr(args, "session", None),
            board=getattr(args, "board", None),
            ttl_seconds=ttl_seconds,
            metadata=_load_metadata(getattr(args, "metadata", None)),
            owned=getattr(args, "owned", False),
            copy_into_store=getattr(args, "copy", False),
        )
        _emit(record.to_dict() if getattr(args, "json", False) else record, as_json=getattr(args, "json", False))
        return

    if action == "promote":
        ttl_seconds = registry.parse_ttl(getattr(args, "ttl", None))
        record = registry.promote_artifact(
            args.artifact_id,
            ttl_seconds=ttl_seconds,
            permanent=getattr(args, "permanent", False),
        )
        _emit(record.to_dict() if getattr(args, "json", False) else record, as_json=getattr(args, "json", False))
        return

    if action == "cleanup":
        result = registry.cleanup_expired(dry_run=getattr(args, "dry_run", False))
        if getattr(args, "json", False):
            _emit(result, as_json=True)
            return
        print(
            "checked={checked} removed={removed} expired={expired} "
            "missing={missing} retained={retained} dry_run={dry_run}".format(**result)
        )
        return

    raise SystemExit(f"unknown artifacts action: {action}")

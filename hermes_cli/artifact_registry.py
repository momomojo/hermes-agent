"""Durable artifact/file lifecycle registry.

The registry records inbound files and generated artifacts without changing
the retention policy of existing platform caches or Kanban attachments. Only
files copied into the Hermes artifact store are eligible for deletion by
``cleanup_expired``.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Optional

from hermes_constants import get_hermes_home


DEFAULT_TTL_SECONDS = 30 * 24 * 60 * 60
VALID_CLEANUP_STATES = {"active", "expired", "removed", "missing"}


@dataclass(frozen=True)
class ArtifactRecord:
    id: str
    path: str
    original_path: Optional[str]
    source: str
    source_id: Optional[str]
    mime_type: Optional[str]
    sensitivity: str
    filename: Optional[str]
    size: Optional[int]
    sha256: Optional[str]
    task_id: Optional[str]
    session_id: Optional[str]
    board: Optional[str]
    owned: bool
    created_at: int
    updated_at: int
    expires_at: Optional[int]
    promoted_at: Optional[int]
    cleanup_state: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["owned"] = bool(self.owned)
        return data


def registry_root() -> Path:
    """Return the Hermes-local artifact registry directory."""

    return get_hermes_home() / "artifacts"


def registry_db_path() -> Path:
    return registry_root() / "registry.db"


def artifact_store_root() -> Path:
    return registry_root() / "blobs"


def parse_ttl(value: str | int | None) -> Optional[int]:
    """Parse a TTL string. ``none``/``permanent`` returns ``None``."""

    if value is None:
        return DEFAULT_TTL_SECONDS
    if isinstance(value, int):
        if value <= 0:
            raise ValueError("ttl must be positive")
        return value

    raw = str(value).strip().lower()
    if raw in {"", "default"}:
        return DEFAULT_TTL_SECONDS
    if raw in {"none", "permanent", "forever"}:
        return None

    unit = raw[-1]
    number = raw[:-1] if unit.isalpha() else raw
    try:
        amount = int(number)
    except ValueError as exc:
        raise ValueError(f"invalid ttl: {value!r}") from exc
    if amount <= 0:
        raise ValueError("ttl must be positive")

    multipliers = {
        "s": 1,
        "m": 60,
        "h": 60 * 60,
        "d": 24 * 60 * 60,
        "w": 7 * 24 * 60 * 60,
    }
    if unit.isalpha():
        if unit not in multipliers:
            raise ValueError(f"invalid ttl unit: {unit!r}")
        return amount * multipliers[unit]
    return amount


def connect(path: Path | None = None) -> sqlite3.Connection:
    db_path = path or registry_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    init_db(conn)
    return conn


def init_db(conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if conn is None:
        path = registry_db_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path))
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                original_path TEXT,
                source TEXT NOT NULL,
                source_id TEXT,
                mime_type TEXT,
                sensitivity TEXT NOT NULL DEFAULT 'unknown',
                filename TEXT,
                size INTEGER,
                sha256 TEXT,
                task_id TEXT,
                session_id TEXT,
                board TEXT,
                owned INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                expires_at INTEGER,
                promoted_at INTEGER,
                cleanup_state TEXT NOT NULL DEFAULT 'active',
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_expires "
            "ON artifacts(cleanup_state, expires_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_task "
            "ON artifacts(task_id, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_session "
            "ON artifacts(session_id, created_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_artifacts_source "
            "ON artifacts(source, source_id)"
        )
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def _now(now: int | float | None = None) -> int:
    return int(time.time() if now is None else now)


def _artifact_id() -> str:
    return f"a_{secrets.token_hex(8)}"


def _json_dumps(value: dict[str, Any] | None) -> str:
    return json.dumps(value or {}, sort_keys=True, separators=(",", ":"))


def _json_loads(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _digest(path: Path) -> tuple[Optional[int], Optional[str]]:
    try:
        h = sha256()
        size = 0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                size += len(chunk)
                h.update(chunk)
        return size, h.hexdigest()
    except OSError:
        return None, None


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _row_to_record(row: sqlite3.Row) -> ArtifactRecord:
    return ArtifactRecord(
        id=row["id"],
        path=row["path"],
        original_path=row["original_path"],
        source=row["source"],
        source_id=row["source_id"],
        mime_type=row["mime_type"],
        sensitivity=row["sensitivity"],
        filename=row["filename"],
        size=row["size"],
        sha256=row["sha256"],
        task_id=row["task_id"],
        session_id=row["session_id"],
        board=row["board"],
        owned=bool(row["owned"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        expires_at=row["expires_at"],
        promoted_at=row["promoted_at"],
        cleanup_state=row["cleanup_state"],
        metadata=_json_loads(row["metadata_json"]),
    )


def register_artifact(
    path: str | Path,
    *,
    source: str,
    source_id: str | None = None,
    mime_type: str | None = None,
    sensitivity: str = "unknown",
    task_id: str | None = None,
    session_id: str | None = None,
    board: str | None = None,
    ttl_seconds: int | None = DEFAULT_TTL_SECONDS,
    metadata: dict[str, Any] | None = None,
    filename: str | None = None,
    owned: bool = False,
    copy_into_store: bool = False,
    now: int | float | None = None,
    conn: sqlite3.Connection | None = None,
) -> ArtifactRecord:
    """Register a file and return its lifecycle record.

    ``owned=True`` is accepted only for files under ``artifact_store_root``.
    Use ``copy_into_store=True`` when the registry should own cleanup.
    """

    if not source or not source.strip():
        raise ValueError("source is required")

    created_at = _now(now)
    artifact_id = _artifact_id()
    src = Path(path).expanduser()
    try:
        resolved_src = src.resolve(strict=False)
    except OSError:
        resolved_src = src.absolute()
    display_name = filename or resolved_src.name
    guessed_mime = mime_type or mimetypes.guess_type(display_name)[0]

    original_path: str | None = str(resolved_src)
    stored = resolved_src
    final_owned = bool(owned)

    if copy_into_store:
        if not resolved_src.is_file():
            raise FileNotFoundError(str(resolved_src))
        dest_dir = artifact_store_root() / artifact_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        safe_name = display_name.replace("\\", "/").split("/")[-1].lstrip(".").strip()
        safe_name = safe_name or "artifact.bin"
        stored = dest_dir / safe_name
        shutil.copy2(resolved_src, stored)
        final_owned = True

    if final_owned and not _is_under(stored, artifact_store_root()):
        raise ValueError("owned artifacts must live under the Hermes artifact store")

    size, digest = _digest(stored)
    expires_at = None if ttl_seconds is None else created_at + int(ttl_seconds)

    own_conn = conn is None
    db = conn or connect()
    try:
        db.execute(
            """
            INSERT INTO artifacts (
                id, path, original_path, source, source_id, mime_type,
                sensitivity, filename, size, sha256, task_id, session_id,
                board, owned, created_at, updated_at, expires_at, promoted_at,
                cleanup_state, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                str(stored),
                original_path if str(stored) != original_path else None,
                source.strip(),
                source_id,
                guessed_mime,
                sensitivity or "unknown",
                display_name,
                size,
                digest,
                task_id,
                session_id,
                board,
                1 if final_owned else 0,
                created_at,
                created_at,
                expires_at,
                None,
                "active",
                _json_dumps(metadata),
            ),
        )
        db.commit()
        record = get_artifact(artifact_id, conn=db)
        if record is None:
            raise RuntimeError("artifact registration failed")
        return record
    finally:
        if own_conn:
            db.close()


def get_artifact(
    artifact_id: str,
    *,
    conn: sqlite3.Connection | None = None,
) -> ArtifactRecord | None:
    own_conn = conn is None
    db = conn or connect()
    try:
        row = db.execute(
            "SELECT * FROM artifacts WHERE id = ?",
            (artifact_id,),
        ).fetchone()
        return _row_to_record(row) if row else None
    finally:
        if own_conn:
            db.close()


def list_artifacts(
    *,
    source: str | None = None,
    task_id: str | None = None,
    session_id: str | None = None,
    cleanup_state: str | None = None,
    limit: int = 100,
    conn: sqlite3.Connection | None = None,
) -> list[ArtifactRecord]:
    clauses: list[str] = []
    params: list[Any] = []
    if source:
        clauses.append("source = ?")
        params.append(source)
    if task_id:
        clauses.append("task_id = ?")
        params.append(task_id)
    if session_id:
        clauses.append("session_id = ?")
        params.append(session_id)
    if cleanup_state:
        clauses.append("cleanup_state = ?")
        params.append(cleanup_state)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(max(1, min(int(limit), 1000)))

    own_conn = conn is None
    db = conn or connect()
    try:
        rows = db.execute(
            f"SELECT * FROM artifacts {where} ORDER BY created_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [_row_to_record(row) for row in rows]
    finally:
        if own_conn:
            db.close()


def update_metadata(
    artifact_id: str,
    metadata: dict[str, Any],
    *,
    merge: bool = True,
    now: int | float | None = None,
    conn: sqlite3.Connection | None = None,
) -> ArtifactRecord:
    own_conn = conn is None
    db = conn or connect()
    try:
        row = db.execute(
            "SELECT metadata_json FROM artifacts WHERE id = ?",
            (artifact_id,),
        ).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        next_metadata = _json_loads(row["metadata_json"]) if merge else {}
        next_metadata.update(metadata)
        db.execute(
            "UPDATE artifacts SET metadata_json = ?, updated_at = ? WHERE id = ?",
            (_json_dumps(next_metadata), _now(now), artifact_id),
        )
        db.commit()
        record = get_artifact(artifact_id, conn=db)
        if record is None:
            raise KeyError(artifact_id)
        return record
    finally:
        if own_conn:
            db.close()


def promote_artifact(
    artifact_id: str,
    *,
    ttl_seconds: int | None = DEFAULT_TTL_SECONDS,
    permanent: bool = False,
    now: int | float | None = None,
    conn: sqlite3.Connection | None = None,
) -> ArtifactRecord:
    ts = _now(now)
    expires_at = None if permanent or ttl_seconds is None else ts + int(ttl_seconds)
    own_conn = conn is None
    db = conn or connect()
    try:
        cur = db.execute(
            """
            UPDATE artifacts
            SET expires_at = ?, promoted_at = ?, updated_at = ?, cleanup_state = 'active'
            WHERE id = ?
            """,
            (expires_at, ts, ts, artifact_id),
        )
        if cur.rowcount == 0:
            raise KeyError(artifact_id)
        db.commit()
        record = get_artifact(artifact_id, conn=db)
        if record is None:
            raise KeyError(artifact_id)
        return record
    finally:
        if own_conn:
            db.close()


def cleanup_expired(
    *,
    now: int | float | None = None,
    dry_run: bool = False,
    delete_owned: bool = True,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Expire old records and delete only registry-owned blobs."""

    ts = _now(now)
    own_conn = conn is None
    db = conn or connect()
    items: list[dict[str, Any]] = []
    removed = expired = missing = retained = 0
    root = artifact_store_root()
    try:
        rows = db.execute(
            """
            SELECT * FROM artifacts
            WHERE cleanup_state = 'active'
              AND expires_at IS NOT NULL
              AND expires_at <= ?
            ORDER BY expires_at ASC
            """,
            (ts,),
        ).fetchall()
        for row in rows:
            record = _row_to_record(row)
            path = Path(record.path)
            state = "expired"
            action = "retain"
            if record.owned and delete_owned and _is_under(path, root):
                if path.exists():
                    action = "delete"
                    state = "removed"
                    if not dry_run:
                        path.unlink()
                        try:
                            parent = path.parent
                            if _is_under(parent, root) and parent != root:
                                parent.rmdir()
                        except OSError:
                            pass
                    removed += 1
                else:
                    action = "missing"
                    state = "missing"
                    missing += 1
            else:
                expired += 1
                if record.owned:
                    action = "retain-owned-outside-store"
                else:
                    retained += 1
            if not dry_run:
                db.execute(
                    "UPDATE artifacts SET cleanup_state = ?, updated_at = ? WHERE id = ?",
                    (state, ts, record.id),
                )
            items.append({"id": record.id, "path": record.path, "action": action, "state": state})
        if not dry_run:
            db.commit()
        return {
            "checked": len(rows),
            "removed": removed,
            "expired": expired,
            "missing": missing,
            "retained": retained,
            "dry_run": dry_run,
            "items": items,
        }
    finally:
        if own_conn:
            db.close()


def record_kanban_attachment(
    attachment: Any,
    *,
    task_id: str,
    board: str | None = None,
    session_id: str | None = None,
    ttl_seconds: int | None = DEFAULT_TTL_SECONDS,
) -> ArtifactRecord:
    """Register an existing Kanban task attachment without taking ownership."""

    metadata = {
        "kanban_attachment_id": getattr(attachment, "id", None),
        "uploaded_by": getattr(attachment, "uploaded_by", None),
        "created_at": getattr(attachment, "created_at", None),
    }
    return register_artifact(
        getattr(attachment, "stored_path"),
        source="kanban_attachment",
        source_id=str(getattr(attachment, "id", "")) or None,
        mime_type=getattr(attachment, "content_type", None),
        sensitivity="user-provided",
        task_id=task_id,
        session_id=session_id,
        board=board,
        ttl_seconds=ttl_seconds,
        metadata={k: v for k, v in metadata.items() if v is not None},
        filename=getattr(attachment, "filename", None),
        owned=False,
    )


def record_gateway_inbound_files(
    event: Any,
    *,
    session_id: str | None,
    ttl_seconds: int | None = DEFAULT_TTL_SECONDS,
) -> list[ArtifactRecord]:
    """Best-effort helper for gateway adapters after media is cached locally."""

    paths: Iterable[str] = getattr(event, "media_urls", None) or []
    types: list[str] = list(getattr(event, "media_types", None) or [])
    source_obj = getattr(event, "source", None)
    platform = getattr(getattr(source_obj, "platform", None), "value", None) or getattr(
        source_obj, "platform", None
    )
    records: list[ArtifactRecord] = []
    for idx, path in enumerate(paths):
        mime_type = types[idx] if idx < len(types) else None
        source_id_parts = [
            str(platform or "gateway"),
            str(getattr(event, "message_id", "") or ""),
            str(idx),
        ]
        metadata = {
            "platform": str(platform) if platform else None,
            "chat_id": getattr(source_obj, "chat_id", None),
            "thread_id": getattr(source_obj, "thread_id", None),
            "message_id": getattr(event, "message_id", None),
            "message_type": getattr(getattr(event, "message_type", None), "value", None),
            "media_index": idx,
        }
        records.append(
            register_artifact(
                path,
                source="gateway_inbound",
                source_id=":".join(part for part in source_id_parts if part),
                mime_type=mime_type,
                sensitivity="user-provided",
                session_id=session_id,
                ttl_seconds=ttl_seconds,
                metadata={k: v for k, v in metadata.items() if v is not None},
                owned=False,
            )
        )
    return records

"""Persistent result ledger for cron/no-agent watchdog jobs.

The cron scheduler already supports classic watchdog jobs via ``no_agent=True``:
a script runs on a schedule, non-empty stdout is delivered, empty stdout stays
silent, and script failures alert the operator.  This module adds a small
Hermes-native ledger for those watchdogs so scripts and operators can reason
about whether a result is new, repeated, changed, or recovered without adding a
new model-facing tool or prompt surface.

State is stored as one JSON file per cron job under
``$HERMES_HOME/cron/watchdog-ledger/``.  The record intentionally keeps hashes
and short previews for delivered/error payloads rather than unbounded raw
output; silent/suppressed runs store hashes only. Full cron output remains in
``cron/output/{job_id}/``.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

try:  # POSIX advisory locks
    import fcntl  # type: ignore
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None
    try:
        import msvcrt  # type: ignore
    except ImportError:  # pragma: no cover
        msvcrt = None

from hermes_constants import get_hermes_home
from hermes_time import now as _hermes_now
from utils import atomic_replace

LEDGER_DIR_NAME = "watchdog-ledger"
DEFAULT_MAX_HISTORY = 20
DEFAULT_MAX_PREVIEW_CHARS = 500
_VALID_STATUSES = frozenset({"ok", "silent", "error"})

# Cron jobs can run concurrently inside one gateway process.  The scheduler's
# tick lock prevents most cross-process overlap, but an in-process lock still
# protects read→modify→write cycles when parallel no-agent jobs finish at the
# same time.
_ledger_lock = threading.Lock()


def _secure_dir(path: Path) -> None:
    try:
        os.chmod(path, 0o700)
    except (OSError, NotImplementedError):
        pass


def _secure_file(path: Path) -> None:
    try:
        if path.exists():
            os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def _validate_job_id(job_id: str) -> str:
    """Return a safe single-path-component job id or raise ``ValueError``.

    Mirrors the protection in ``cron.jobs._job_output_dir``: job ids are used as
    filesystem path components, so path traversal, nested components, and
    absolute paths must be rejected before resolving a ledger path.
    """
    text = str(job_id or "").strip()
    if not text or text in {".", ".."} or "/" in text or "\\" in text:
        raise ValueError(f"Invalid cron job id for watchdog ledger path: {job_id!r}")
    candidate = Path(text)
    if candidate.is_absolute() or candidate.drive:
        raise ValueError(f"Invalid cron job id for watchdog ledger path: {job_id!r}")
    return text


def watchdog_ledger_dir(*, hermes_home: Path | str | None = None) -> Path:
    """Return the cron watchdog ledger directory, creating it securely."""
    home = Path(hermes_home).expanduser() if hermes_home is not None else get_hermes_home()
    directory = home / "cron" / LEDGER_DIR_NAME
    directory.mkdir(parents=True, exist_ok=True)
    _secure_dir(directory)
    return directory


def watchdog_ledger_path(job_id: str, *, hermes_home: Path | str | None = None) -> Path:
    """Return the per-job ledger path after validating ``job_id``."""
    safe_id = _validate_job_id(job_id)
    return watchdog_ledger_dir(hermes_home=hermes_home) / f"{safe_id}.json"


def _sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def _preview(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    cleaned = (text or "").strip()
    if len(cleaned) <= max_chars:
        return cleaned
    return cleaned[: max_chars - 1].rstrip() + "…"


def _result_hash(*, status: str, output_sha256: str, error_sha256: str | None) -> str:
    payload = json.dumps(
        {"status": status, "output_sha256": output_sha256, "error_sha256": error_sha256},
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_text(payload)


def load_watchdog_record(
    job_id: str,
    *,
    hermes_home: Path | str | None = None,
) -> dict[str, Any] | None:
    """Load a watchdog ledger record.

    Returns ``None`` when no record exists or when the on-disk JSON is corrupt.
    Corrupt records are treated as recoverable because watchdog persistence
    should never break the alerting path.
    """
    path = watchdog_ledger_path(job_id, hermes_home=hermes_home)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _classify_change(previous: Mapping[str, Any] | None, status: str, result_hash: str) -> tuple[bool, str]:
    if not previous:
        return True, "first_seen"

    previous_status = str(previous.get("last_status") or "")
    previous_hash = str(previous.get("last_result_hash") or "")

    if previous_status == "error" and status != "error":
        return True, "recovered"
    if previous_status != status:
        return True, "status_changed"
    if previous_hash != result_hash:
        return True, "output_changed"
    return False, "unchanged"


def _atomic_write_json(path: Path, data: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _secure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.write("\n")
        real_path = Path(atomic_replace(tmp_path, path))
        _secure_file(real_path)
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass


@contextmanager
def _locked_ledger_path(path: Path):
    """Cross-process lock for a ledger read→modify→write cycle."""
    path.parent.mkdir(parents=True, exist_ok=True)
    _secure_dir(path.parent)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, "r+", encoding="utf-8") as lock_file:
        _secure_file(lock_path)
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        elif msvcrt is not None:  # pragma: no cover - Windows only
            getattr(msvcrt, "locking")(lock_file.fileno(), getattr(msvcrt, "LK_LOCK"), 1)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            elif msvcrt is not None:  # pragma: no cover - Windows only
                try:
                    lock_file.seek(0)
                    getattr(msvcrt, "locking")(lock_file.fileno(), getattr(msvcrt, "LK_UNLCK"), 1)
                except OSError:
                    pass


def record_watchdog_result(
    job: Mapping[str, Any],
    *,
    status: str,
    output: str = "",
    error: str | None = None,
    now: datetime | None = None,
    max_history: int = DEFAULT_MAX_HISTORY,
    max_preview_chars: int = DEFAULT_MAX_PREVIEW_CHARS,
    hermes_home: Path | str | None = None,
) -> dict[str, Any]:
    """Record a cron/no-agent watchdog result and return change metadata.

    Args:
        job: Cron job dict. Must include ``id``; ``name`` is copied for operator
            readability only.
        status: One of ``ok``, ``silent``, or ``error``.
        output: Redacted stdout/final message text for hashing/preview.
        error: Optional redacted error text for failed script runs.
        now: Optional timestamp for deterministic tests.
        max_history: Bounded history entries to retain per job.
        max_preview_chars: Max chars of preview text stored in the ledger. Pass
            ``0`` to store hashes only.
        hermes_home: Optional override used by tests.

    Returns:
        A dict with ``changed``, ``reason``, ``current_hash``,
        ``previous_hash``, ``path``, and the updated ``record``.
    """
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid watchdog status {status!r}; expected one of {sorted(_VALID_STATUSES)}")

    job_id = _validate_job_id(str(job.get("id") or ""))
    path = watchdog_ledger_path(job_id, hermes_home=hermes_home)
    timestamp = (now or _hermes_now()).isoformat()
    output_text = output or ""
    error_text = error or ""
    output_sha = _sha256_text(output_text)
    error_sha = _sha256_text(error_text) if error is not None else None
    current_hash = _result_hash(status=status, output_sha256=output_sha, error_sha256=error_sha)

    with _ledger_lock:
        with _locked_ledger_path(path):
            previous = load_watchdog_record(job_id, hermes_home=hermes_home)
            changed, reason = _classify_change(previous, status, current_hash)
            previous_hash = previous.get("last_result_hash") if previous else None
            previous_run_count = int(previous.get("run_count") or 0) if previous else 0
            previous_changed_count = int(previous.get("changed_count") or 0) if previous else 0
            history = list(previous.get("history") or []) if previous else []

            event = {
                "run_at": timestamp,
                "status": status,
                "changed": changed,
                "reason": reason,
                "result_hash": current_hash,
                "output_sha256": output_sha,
            }
            if error_sha is not None:
                event["error_sha256"] = error_sha
            # Silent runs deliberately suppress delivery; keep only hashes for
            # them so the ledger does not create a new persistent copy of
            # diagnostic payloads that were intentionally not surfaced.
            if max_preview_chars > 0 and status != "silent":
                preview_source = error_text if status == "error" and error_text else output_text
                event["preview"] = _preview(preview_source, max_preview_chars)

            history.append(event)
            if max_history < 0:
                max_history = 0
            if max_history:
                history = history[-max_history:]
            else:
                history = []

            first_seen_at = previous.get("first_seen_at") if previous else timestamp
            last_changed_at = timestamp if changed else (previous.get("last_changed_at") if previous else timestamp)

            record = {
                "job_id": job_id,
                "job_name": str(job.get("name") or job.get("prompt") or job_id),
                "first_seen_at": first_seen_at,
                "last_run_at": timestamp,
                "last_changed_at": last_changed_at,
                "last_status": status,
                "last_reason": reason,
                "last_result_hash": current_hash,
                "last_output_sha256": output_sha,
                "last_error_sha256": error_sha,
                "last_preview": event.get("preview", ""),
                "run_count": previous_run_count + 1,
                "changed_count": previous_changed_count + (1 if changed else 0),
                "history": history,
            }
            _atomic_write_json(path, record)

    return {
        "changed": changed,
        "reason": reason,
        "current_hash": current_hash,
        "previous_hash": previous_hash,
        "path": str(path),
        "record": record,
    }


def format_watchdog_metadata(result: Mapping[str, Any]) -> str:
    """Return markdown metadata lines for cron output archives."""
    changed = "true" if result.get("changed") else "false"
    reason = result.get("reason") or "unknown"
    current_hash = result.get("current_hash") or ""
    path = result.get("path") or ""
    return (
        f"**Watchdog Changed:** {changed}\n"
        f"**Watchdog Reason:** {reason}\n"
        f"**Watchdog Result SHA256:** {current_hash}\n"
        f"**Watchdog Ledger:** {path}\n"
    )

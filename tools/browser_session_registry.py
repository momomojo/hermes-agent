"""Persistent browser session registry.

The registry is intentionally a helper, not an agent-facing model tool. It gives
browser, CDP, and computer-use integrations a common place to record reusable
sessions without expanding the core tool schema.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from hermes_constants import get_hermes_home


DEFAULT_BROWSER_SESSION_TTL_SECONDS = 120
REGISTRY_FILENAME = "browser_sessions.json"


@dataclass(frozen=True)
class BrowserSessionRecord:
    """One reusable browser-like session scoped by profile, backend, and domain."""

    profile: str
    domain: str
    backend: str
    session_id: str
    last_used: float
    ttl_seconds: int = DEFAULT_BROWSER_SESSION_TTL_SECONDS
    auth_needed: bool = False

    @property
    def key(self) -> str:
        return registry_key(self.profile, self.domain, self.backend, self.session_id)

    def is_expired(self, now: float | None = None) -> bool:
        if self.ttl_seconds <= 0:
            return False
        if now is None:
            now = time.time()
        return now - self.last_used >= self.ttl_seconds

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def registry_path() -> Path:
    return get_hermes_home() / REGISTRY_FILENAME


def current_profile() -> str:
    return (os.environ.get("HERMES_PROFILE") or "default").strip() or "default"


def normalize_domain(value: str) -> str:
    """Normalize a URL or host into a registry domain key."""

    raw = (value or "").strip()
    if not raw:
        raise ValueError("domain or URL is required")

    if "://" not in raw:
        candidate = f"https://{raw}"
    else:
        candidate = raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError(f"could not determine domain from {value!r}")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass

    port = parsed.port
    default_port = (
        parsed.scheme == "http"
        and port == 80
        or parsed.scheme == "https"
        and port == 443
    )
    if port and not default_port:
        return f"{host}:{port}"
    return host


def registry_key(profile: str, domain: str, backend: str, session_id: str) -> str:
    parts = (profile, normalize_domain(domain), backend.strip().lower(), session_id)
    return "|".join(_escape_key_part(part) for part in parts)


def upsert_session(
    *,
    domain: str,
    backend: str,
    session_id: str,
    profile: str | None = None,
    ttl_seconds: int = DEFAULT_BROWSER_SESSION_TTL_SECONDS,
    auth_needed: bool = False,
    now: float | None = None,
) -> BrowserSessionRecord:
    if now is None:
        now = time.time()
    record = BrowserSessionRecord(
        profile=(profile or current_profile()).strip() or "default",
        domain=normalize_domain(domain),
        backend=backend.strip().lower(),
        session_id=session_id.strip(),
        last_used=float(now),
        ttl_seconds=int(ttl_seconds),
        auth_needed=bool(auth_needed),
    )
    if not record.backend:
        raise ValueError("backend is required")
    if not record.session_id:
        raise ValueError("session_id is required")

    records = _load_records()
    records[record.key] = record
    _save_records(records)
    return record


def touch_session(
    session_id: str,
    *,
    domain: str | None = None,
    backend: str | None = None,
    profile: str | None = None,
    now: float | None = None,
) -> BrowserSessionRecord | None:
    if now is None:
        now = time.time()
    records = _load_records()
    matches = _matching_records(
        records.values(),
        session_id=session_id,
        domain=domain,
        backend=backend,
        profile=profile,
        include_expired=True,
    )
    if not matches:
        return None
    record = matches[0]
    touched = BrowserSessionRecord(
        profile=record.profile,
        domain=record.domain,
        backend=record.backend,
        session_id=record.session_id,
        last_used=float(now),
        ttl_seconds=record.ttl_seconds,
        auth_needed=record.auth_needed,
    )
    records.pop(record.key, None)
    records[touched.key] = touched
    _save_records(records)
    return touched


def list_sessions(
    *,
    profile: str | None = None,
    domain: str | None = None,
    backend: str | None = None,
    include_expired: bool = False,
    include_auth_needed: bool = True,
    now: float | None = None,
) -> list[BrowserSessionRecord]:
    records = _matching_records(
        _load_records().values(),
        profile=profile,
        domain=domain,
        backend=backend,
        include_expired=include_expired,
        include_auth_needed=include_auth_needed,
        now=now,
    )
    return sorted(records, key=lambda rec: rec.last_used, reverse=True)


def get_reusable_session(
    *,
    domain: str,
    backend: str | None = None,
    profile: str | None = None,
    now: float | None = None,
) -> BrowserSessionRecord | None:
    records = list_sessions(
        profile=profile,
        domain=domain,
        backend=backend,
        include_expired=False,
        include_auth_needed=False,
        now=now,
    )
    return records[0] if records else None


def close_sessions(
    *,
    session_id: str | None = None,
    profile: str | None = None,
    domain: str | None = None,
    backend: str | None = None,
    include_expired: bool = True,
) -> list[BrowserSessionRecord]:
    records = _load_records()
    matches = _matching_records(
        records.values(),
        session_id=session_id,
        profile=profile,
        domain=domain,
        backend=backend,
        include_expired=include_expired,
    )
    for record in matches:
        records.pop(record.key, None)
    if matches:
        _save_records(records)
    return matches


def mark_auth_needed(
    session_id: str,
    *,
    auth_needed: bool = True,
    profile: str | None = None,
    domain: str | None = None,
    backend: str | None = None,
) -> list[BrowserSessionRecord]:
    records = _load_records()
    matches = _matching_records(
        records.values(),
        session_id=session_id,
        profile=profile,
        domain=domain,
        backend=backend,
        include_expired=True,
    )
    updated: list[BrowserSessionRecord] = []
    for record in matches:
        replacement = BrowserSessionRecord(
            profile=record.profile,
            domain=record.domain,
            backend=record.backend,
            session_id=record.session_id,
            last_used=record.last_used,
            ttl_seconds=record.ttl_seconds,
            auth_needed=bool(auth_needed),
        )
        records.pop(record.key, None)
        records[replacement.key] = replacement
        updated.append(replacement)
    if updated:
        _save_records(records)
    return updated


def purge_expired(now: float | None = None) -> list[BrowserSessionRecord]:
    if now is None:
        now = time.time()
    records = _load_records()
    expired = [record for record in records.values() if record.is_expired(now)]
    for record in expired:
        records.pop(record.key, None)
    if expired:
        _save_records(records)
    return expired


def _matching_records(
    records: Iterable[BrowserSessionRecord],
    *,
    session_id: str | None = None,
    profile: str | None = None,
    domain: str | None = None,
    backend: str | None = None,
    include_expired: bool = False,
    include_auth_needed: bool = True,
    now: float | None = None,
) -> list[BrowserSessionRecord]:
    normalized_domain = normalize_domain(domain) if domain else None
    normalized_backend = backend.strip().lower() if backend else None
    normalized_profile = (profile or current_profile()).strip() if profile else None
    normalized_session_id = session_id.strip() if session_id else None
    if now is None:
        now = time.time()

    matches: list[BrowserSessionRecord] = []
    for record in records:
        if normalized_session_id and record.session_id != normalized_session_id:
            continue
        if normalized_profile and record.profile != normalized_profile:
            continue
        if normalized_domain and record.domain != normalized_domain:
            continue
        if normalized_backend and record.backend != normalized_backend:
            continue
        if not include_expired and record.is_expired(now):
            continue
        if not include_auth_needed and record.auth_needed:
            continue
        matches.append(record)
    return matches


def _load_records() -> dict[str, BrowserSessionRecord]:
    path = registry_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}

    items = raw.get("sessions", []) if isinstance(raw, dict) else []
    records: dict[str, BrowserSessionRecord] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            record = BrowserSessionRecord(
                profile=str(item["profile"]),
                domain=normalize_domain(str(item["domain"])),
                backend=str(item["backend"]).strip().lower(),
                session_id=str(item["session_id"]),
                last_used=float(item["last_used"]),
                ttl_seconds=int(item.get("ttl_seconds", DEFAULT_BROWSER_SESSION_TTL_SECONDS)),
                auth_needed=bool(item.get("auth_needed", False)),
            )
        except (KeyError, TypeError, ValueError):
            continue
        records[record.key] = record
    return records


def _save_records(records: dict[str, BrowserSessionRecord]) -> None:
    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "sessions": [record.to_dict() for record in sorted(records.values(), key=lambda r: r.key)],
    }
    fd, tmp_name = tempfile.mkstemp(prefix=f".{REGISTRY_FILENAME}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _escape_key_part(part: str) -> str:
    return part.replace("\\", "\\\\").replace("|", "\\|")

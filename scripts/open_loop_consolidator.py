#!/usr/bin/env python3
"""Open-loop consolidator for HHFOS/Jarvis/Kanban signals.

This helper is intentionally local-first and side-effect-light.  It collects
read-only unresolved-loop signals from fixtures or live local stores, merges
those signals with a durable ledger, and emits bounded next-action proposals:

- action_board:add for Mohib-facing decisions/commitments,
- kanban:create for internal/judge/fleet work,
- suppress for delegated/in-flight work that should not page Mohib again.

`--dry-run` never writes.  `--apply` writes only the local consolidator state
ledger so future runs can throttle duplicates and close stale records.  It does
not send messages, change credentials, or create live Kanban tasks.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = 1
DEFAULT_THROTTLE_SECONDS = 18 * 60 * 60
DEFAULT_SESSION_LOOKBACK_SECONDS = 7 * 24 * 60 * 60
TERMINAL_STATUSES = {"done", "archived", "cancelled", "closed"}
ACTIVE_KANBAN_STATUSES = {"ready", "running", "blocked", "todo"}
MOHIB_GATE_RE = re.compile(
    r"\b(mohib|human|approval|credential|oauth|password|external|send|message|email|payment|portal|upload|submission|wife|claire)\b",
    re.IGNORECASE,
)
INTERNAL_GATE_RE = re.compile(
    r"\b(review-required|judge|internal|fleet|config|cron|kanban|test|pr|github|code|runtime|watchdog|health)\b",
    re.IGNORECASE,
)
COMMITMENT_RE = re.compile(
    r"\b(i(?:'ll| will)|we(?:'ll| will)|follow(?:ing)? up|remind(?: me)?|circle back|next step(?: is)?|i need to)\b",
    re.IGNORECASE,
)


@dataclasses.dataclass(frozen=True)
class OpenLoopRecord:
    source: str
    source_id: str
    title: str
    detail: str = ""
    profile: str = "default"
    state: str = "open"
    gate: str = "internal"
    due: str | None = None
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def key(self) -> str:
        raw = f"{self.source}:{self.source_id}"
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
        return f"ol_{digest}"

    @property
    def fingerprint(self) -> str:
        payload = {
            "source": self.source,
            "source_id": self.source_id,
            "title": normalize_space(self.title),
            "detail": normalize_space(self.detail),
            "gate": self.gate,
            "state": self.state,
            "due": self.due,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "source": self.source,
            "source_id": self.source_id,
            "title": self.title,
            "detail": self.detail,
            "profile": self.profile,
            "state": self.state,
            "gate": self.gate,
            "due": self.due,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "fingerprint": self.fingerprint,
            "metadata": self.metadata,
        }


@dataclasses.dataclass(frozen=True)
class ConsolidationDecision:
    key: str
    action: str
    target: str
    title: str
    reason: str
    throttled: bool = False
    record: dict[str, Any] | None = None
    prior: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        data = dataclasses.asdict(self)
        return data


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_ts(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def normalize_space(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def hermes_root() -> Path:
    return Path(os.environ.get("HERMES_ROOT") or os.environ.get("HERMES_HOME") or Path.home() / ".hermes")


def default_state_path(root: Path | None = None) -> Path:
    root = root or hermes_root()
    return root / "state" / "open-loop-consolidator.json"


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_state(path: Path) -> dict[str, Any]:
    state = load_json(path, {"schema_version": SCHEMA_VERSION, "records": {}})
    if not isinstance(state, dict):
        return {"schema_version": SCHEMA_VERSION, "records": {}}
    state.setdefault("schema_version", SCHEMA_VERSION)
    state.setdefault("records", {})
    return state


def classify_gate(text: str, default: str = "internal") -> str:
    if MOHIB_GATE_RE.search(text):
        return "mohib"
    if INTERNAL_GATE_RE.search(text):
        return "internal"
    return default


def choose_action(record: OpenLoopRecord) -> tuple[str, str, str]:
    if record.state == "suppressed":
        return "suppress", "suppressed", "linked work is already delegated/in-flight"
    if record.gate in {"mohib", "external"}:
        return "action_board:add", "action_board", "needs Mohib-facing decision or visibility"
    return "kanban:create", "kanban", "internal unresolved loop should become/reuse a worker card"


def collect_from_action_registry(registry_path: Path, kanban_db: Path | None = None, now_iso: str | None = None) -> list[OpenLoopRecord]:
    data = load_json(registry_path, {"items": []})
    items = data.get("items", data if isinstance(data, list) else [])
    active_task_ids = load_active_kanban_task_ids(kanban_db) if kanban_db else set()
    records: list[OpenLoopRecord] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "pending").lower()
        item_id = str(item.get("id") or item.get("source") or item.get("title") or "unknown")
        title = normalize_space(item.get("title") or item.get("summary") or item_id)
        delegated = normalize_space(item.get("delegated_task_id") or item.get("kanban_task_id"))
        if status in TERMINAL_STATUSES:
            continue
        state = "open"
        detail = normalize_space(item.get("notes") or item.get("context") or "")
        if delegated and (not active_task_ids or delegated in active_task_ids or status == "in-flight"):
            state = "suppressed"
            detail = normalize_space(f"delegated_task_id={delegated}; {detail}")
        gate = classify_gate(f"{title} {detail} {item.get('source', '')}", default="mohib")
        records.append(OpenLoopRecord(
            source="action_registry",
            source_id=item_id,
            title=title,
            detail=detail,
            profile=str(item.get("profile") or "default"),
            state=state,
            gate=gate,
            due=item.get("due"),
            first_seen_at=item.get("created_at") or item.get("first_seen_at"),
            last_seen_at=now_iso,
            metadata={"delegated_task_id": delegated or None, "registry_status": status},
        ))
    return records


def load_active_kanban_task_ids(db_path: Path | None) -> set[str]:
    if not db_path or not db_path.exists():
        return set()
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT id, status FROM tasks").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return set()
    return {str(row["id"]) for row in rows if str(row["status"]).lower() in ACTIVE_KANBAN_STATUSES}


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    except sqlite3.Error:
        return set()


def collect_from_kanban(db_path: Path, now_iso: str | None = None) -> list[OpenLoopRecord]:
    if not db_path.exists():
        return []
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        columns = table_columns(conn, "tasks")
        if not {"id", "status"}.issubset(columns):
            return []
        select_cols = [c for c in ["id", "title", "body", "assignee", "status", "result"] if c in columns]
        rows = conn.execute(f"SELECT {', '.join(select_cols)} FROM tasks WHERE lower(status) IN ('blocked', 'ready', 'running')").fetchall()
    finally:
        conn.close()
    records: list[OpenLoopRecord] = []
    for row in rows:
        data = dict(row)
        task_id = str(data.get("id") or "")
        status = str(data.get("status") or "").lower()
        title = normalize_space(data.get("title") or task_id)
        body = normalize_space(data.get("body") or data.get("result") or "")
        text = f"{title} {body} {status}"
        gate = classify_gate(text, default="internal")
        if status == "blocked" and not body:
            body = "blocked kanban task needs reconciliation"
        records.append(OpenLoopRecord(
            source="kanban",
            source_id=task_id,
            title=title,
            detail=body[:600],
            profile=str(data.get("assignee") or "default"),
            state="open",
            gate=gate,
            last_seen_at=now_iso,
            metadata={"kanban_status": status},
        ))
    return records


def collect_from_watchdog_ledger(path: Path, now_iso: str | None = None) -> list[OpenLoopRecord]:
    if not path.exists():
        return []
    latest: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            job_id = str(row.get("job_id") or row.get("name") or row.get("id") or "unknown")
            latest[job_id] = row
    records: list[OpenLoopRecord] = []
    for job_id, row in latest.items():
        status = str(row.get("status") or row.get("last_status") or row.get("outcome") or "").lower()
        if status in {"", "ok", "success", "silent"}:
            continue
        title = normalize_space(row.get("title") or row.get("name") or f"Watchdog {job_id} unresolved")
        detail = normalize_space(row.get("error") or row.get("summary") or row.get("message") or status)
        records.append(OpenLoopRecord(
            source="watchdog",
            source_id=job_id,
            title=title,
            detail=detail[:600],
            profile=str(row.get("profile") or "default"),
            state="open",
            gate="internal",
            last_seen_at=now_iso,
            metadata={"watchdog_status": status, "ledger_ts": row.get("ts") or row.get("timestamp")},
        ))
    return records


def collect_from_sessions(db_path: Path, now_ts: float | None = None, lookback_seconds: int = DEFAULT_SESSION_LOOKBACK_SECONDS) -> list[OpenLoopRecord]:
    if not db_path.exists():
        return []
    now_ts = now_ts or time.time()
    cutoff = now_ts - lookback_seconds
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cols = table_columns(conn, "messages")
        if not {"id", "role", "text"}.issubset(cols):
            return []
        ts_col = "ts" if "ts" in cols else ("timestamp" if "timestamp" in cols else None)
        sid_col = "sid" if "sid" in cols else ("session_id" if "session_id" in cols else None)
        select = ["id", "role", "text"] + ([ts_col] if ts_col else []) + ([sid_col] if sid_col else [])
        where = "WHERE role = 'assistant'"
        params: list[Any] = []
        if ts_col:
            where += f" AND {ts_col} >= ?"
            params.append(cutoff)
        rows = conn.execute(f"SELECT {', '.join(select)} FROM messages {where} ORDER BY id DESC LIMIT 200", params).fetchall()
    finally:
        conn.close()
    records: list[OpenLoopRecord] = []
    for row in rows:
        text = normalize_space(row["text"])
        if not COMMITMENT_RE.search(text):
            continue
        sid = str(row[sid_col]) if sid_col else "unknown-session"
        source_id = f"{sid}:{row['id']}"
        title = text[:100] + ("…" if len(text) > 100 else "")
        gate = classify_gate(text, default="mohib")
        records.append(OpenLoopRecord(
            source="session",
            source_id=source_id,
            title=title,
            detail=text[:600],
            profile="default",
            state="open",
            gate=gate,
            metadata={"session_id": sid, "message_id": row["id"]},
        ))
    return records


def collect_from_hindsight_json(path: Path, now_iso: str | None = None) -> list[OpenLoopRecord]:
    """Collect unresolved Hindsight-like fixture rows without depending on NAS services."""
    if not path.exists():
        return []
    rows: list[Any]
    if path.suffix == ".jsonl":
        rows = []
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    else:
        payload = load_json(path, [])
        rows = payload.get("items", payload) if isinstance(payload, dict) else payload
    records: list[OpenLoopRecord] = []
    for idx, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or row.get("state") or "open").lower()
        if status in TERMINAL_STATUSES or row.get("resolved") is True:
            continue
        if not (row.get("unresolved") is True or status in {"open", "pending", "blocked"}):
            continue
        source_id = str(row.get("id") or row.get("key") or idx)
        title = normalize_space(row.get("title") or row.get("summary") or row.get("content") or source_id)
        detail = normalize_space(row.get("detail") or row.get("content") or row.get("notes") or "")
        records.append(OpenLoopRecord(
            source="hindsight",
            source_id=source_id,
            title=title[:160],
            detail=detail[:600],
            profile=str(row.get("profile") or "default"),
            state="open",
            gate=classify_gate(f"{title} {detail}", default="internal"),
            last_seen_at=now_iso,
            metadata={"hindsight_status": status},
        ))
    return records


def dedupe_records(records: Iterable[OpenLoopRecord]) -> list[OpenLoopRecord]:
    by_key: dict[str, OpenLoopRecord] = {}
    for record in records:
        existing = by_key.get(record.key)
        if not existing or (existing.state != "open" and record.state == "open"):
            by_key[record.key] = record
    return list(by_key.values())


def consolidate(records: Sequence[OpenLoopRecord], state: dict[str, Any], *, now_iso: str, throttle_seconds: int) -> dict[str, Any]:
    records_by_key = {r.key: r for r in dedupe_records(records)}
    state_records: dict[str, Any] = dict(state.get("records") or {})
    emitted: list[ConsolidationDecision] = []
    throttled: list[ConsolidationDecision] = []
    suppressed: list[ConsolidationDecision] = []
    closed: list[dict[str, Any]] = []
    now_epoch = parse_ts(now_iso) or time.time()

    for key, record in records_by_key.items():
        prior = state_records.get(key, {}) if isinstance(state_records.get(key), dict) else {}
        action, target, reason = choose_action(record)
        prior_emit = parse_ts(prior.get("last_emitted_at"))
        same_fingerprint = prior.get("fingerprint") == record.fingerprint
        is_throttled = bool(prior_emit and same_fingerprint and (now_epoch - prior_emit) < throttle_seconds)
        decision = ConsolidationDecision(
            key=key,
            action=action,
            target=target,
            title=record.title,
            reason=reason,
            throttled=is_throttled,
            record=record.as_dict(),
            prior=prior or None,
        )
        if action == "suppress":
            suppressed.append(decision)
        elif is_throttled:
            throttled.append(decision)
        else:
            emitted.append(decision)

        first_seen = prior.get("first_seen_at") or record.first_seen_at or now_iso
        state_records[key] = {
            "key": key,
            "status": "suppressed" if action == "suppress" else "open",
            "source": record.source,
            "source_id": record.source_id,
            "title": record.title,
            "gate": record.gate,
            "action": action,
            "target": target,
            "first_seen_at": first_seen,
            "last_seen_at": now_iso,
            "last_emitted_at": prior.get("last_emitted_at") if (is_throttled or action == "suppress") else now_iso,
            "fingerprint": record.fingerprint,
            "closure": prior.get("closure"),
            "suppression": {"reason": reason, "at": now_iso} if action == "suppress" else prior.get("suppression"),
        }

    for key, prior in list(state_records.items()):
        if key in records_by_key:
            continue
        if not isinstance(prior, dict):
            continue
        if prior.get("status") in {"closed", "resolved"}:
            continue
        closure = {"closed_at": now_iso, "reason": "source_absent_or_terminal"}
        prior = dict(prior)
        prior["status"] = "closed"
        prior["closure"] = closure
        prior["last_seen_at"] = prior.get("last_seen_at")
        state_records[key] = prior
        closed.append({"key": key, "title": prior.get("title"), "closure": closure})

    new_state = {"schema_version": SCHEMA_VERSION, "updated_at": now_iso, "records": state_records}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso,
        "summary": {
            "records_seen": len(records_by_key),
            "emit_count": len(emitted),
            "throttled_count": len(throttled),
            "suppressed_count": len(suppressed),
            "closed_count": len(closed),
        },
        "actions": [d.as_dict() for d in emitted],
        "throttled": [d.as_dict() for d in throttled],
        "suppressed": [d.as_dict() for d in suppressed],
        "closed": closed,
        "state": new_state,
    }


def collect_all(args: argparse.Namespace, now_iso: str) -> list[OpenLoopRecord]:
    records: list[OpenLoopRecord] = []
    kanban_db = Path(args.kanban_db) if args.kanban_db else None
    if args.registry:
        records.extend(collect_from_action_registry(Path(args.registry), kanban_db=kanban_db, now_iso=now_iso))
    if kanban_db:
        records.extend(collect_from_kanban(kanban_db, now_iso=now_iso))
    if args.watchdog_ledger:
        records.extend(collect_from_watchdog_ledger(Path(args.watchdog_ledger), now_iso=now_iso))
    if args.sessions_db:
        records.extend(collect_from_sessions(Path(args.sessions_db), lookback_seconds=args.session_lookback_seconds))
    if args.hindsight_json:
        records.extend(collect_from_hindsight_json(Path(args.hindsight_json), now_iso=now_iso))
    if args.records_json:
        fixture = load_json(Path(args.records_json), [])
        rows = fixture.get("records", fixture.get("items", fixture)) if isinstance(fixture, dict) else fixture
        for row in rows:
            if isinstance(row, dict):
                records.append(OpenLoopRecord(
                    source=str(row.get("source") or "fixture"),
                    source_id=str(row.get("source_id") or row.get("id") or row.get("title") or len(records)),
                    title=normalize_space(row.get("title") or row.get("summary") or row.get("source_id") or "open loop"),
                    detail=normalize_space(row.get("detail") or row.get("body") or ""),
                    profile=str(row.get("profile") or "default"),
                    state=str(row.get("state") or "open"),
                    gate=str(row.get("gate") or classify_gate(f"{row.get('title', '')} {row.get('detail', '')}")),
                    due=row.get("due"),
                    first_seen_at=row.get("first_seen_at"),
                    last_seen_at=now_iso,
                    metadata=dict(row.get("metadata") or {}),
                ))
    return records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Consolidate unresolved local HHFOS loops into bounded next-action proposals.")
    parser.add_argument("--state", help="Consolidator state path (default: $HERMES_ROOT/state/open-loop-consolidator.json)")
    parser.add_argument("--registry", help="Action registry JSON path")
    parser.add_argument("--kanban-db", help="Kanban sqlite DB path")
    parser.add_argument("--watchdog-ledger", help="Watchdog JSONL ledger path")
    parser.add_argument("--sessions-db", help="Hermes session sqlite DB path")
    parser.add_argument("--hindsight-json", help="Hindsight unresolved fixture JSON/JSONL path")
    parser.add_argument("--records-json", help="Normalized fixture JSON path for tests/dry-runs")
    parser.add_argument("--throttle-seconds", type=int, default=DEFAULT_THROTTLE_SECONDS)
    parser.add_argument("--session-lookback-seconds", type=int, default=DEFAULT_SESSION_LOOKBACK_SECONDS)
    parser.add_argument("--now", help="ISO timestamp for deterministic tests")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Do not write state (default)")
    mode.add_argument("--apply", action="store_true", help="Write the local consolidator state ledger only")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    now_iso = args.now or utc_now()
    state_path = Path(args.state) if args.state else default_state_path()
    state = load_state(state_path)
    records = collect_all(args, now_iso=now_iso)
    result = consolidate(records, state, now_iso=now_iso, throttle_seconds=args.throttle_seconds)
    result["dry_run"] = not args.apply
    result["state_path"] = str(state_path)
    if args.apply:
        atomic_write_json(state_path, result["state"])
    else:
        result.pop("state", None)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

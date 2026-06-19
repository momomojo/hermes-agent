"""CLI wrapper for the browser session registry."""

from __future__ import annotations

import argparse
import json
import time
from typing import Any

from tools import browser_session_registry as registry


def build_parser(subparsers) -> argparse.ArgumentParser:
    parser = subparsers.add_parser(
        "browser-sessions",
        aliases=["browser-session"],
        help="Inspect and manage browser session registry",
        description=(
            "List, close, and mark auth state for reusable browser/CDP/"
            "computer-use sessions tracked by Hermes."
        ),
    )
    session_subparsers = parser.add_subparsers(dest="browser_sessions_command")

    p_list = session_subparsers.add_parser("list", aliases=["ls"], help="List tracked sessions")
    _add_common_filters(p_list)
    p_list.add_argument("--include-expired", action="store_true", help="Show expired sessions")
    p_list.add_argument(
        "--usable-only",
        action="store_true",
        help="Hide sessions marked auth-needed",
    )
    p_list.add_argument("--json", action="store_true", help="Emit JSON")

    p_close = session_subparsers.add_parser("close", help="Remove sessions from registry")
    p_close.add_argument("session_id", nargs="?", help="Session id to remove")
    _add_common_filters(p_close)
    p_close.add_argument("--json", action="store_true", help="Emit JSON")

    p_auth = session_subparsers.add_parser(
        "mark-auth-needed",
        aliases=["auth-needed"],
        help="Mark a session as needing user authentication",
    )
    p_auth.add_argument("session_id", help="Session id to update")
    _add_common_filters(p_auth)
    p_auth.add_argument(
        "--clear",
        action="store_true",
        help="Clear auth-needed instead of setting it",
    )
    p_auth.add_argument("--json", action="store_true", help="Emit JSON")

    p_purge = session_subparsers.add_parser("purge-expired", help="Delete expired sessions")
    p_purge.add_argument("--json", action="store_true", help="Emit JSON")

    parser.set_defaults(func=browser_sessions_command)
    return parser


def browser_sessions_command(args) -> None:
    command = getattr(args, "browser_sessions_command", None)
    if command in {None, ""}:
        command = "list"

    if command in {"list", "ls"}:
        sessions = registry.list_sessions(
            profile=getattr(args, "profile", None),
            domain=getattr(args, "domain", None),
            backend=getattr(args, "backend", None),
            include_expired=getattr(args, "include_expired", False),
            include_auth_needed=not getattr(args, "usable_only", False),
        )
        _print_records(sessions, json_output=getattr(args, "json", False))
        return

    if command == "close":
        if not _has_close_selector(args):
            raise SystemExit("close requires a session_id or at least one filter")
        closed = registry.close_sessions(
            session_id=getattr(args, "session_id", None),
            profile=getattr(args, "profile", None),
            domain=getattr(args, "domain", None),
            backend=getattr(args, "backend", None),
        )
        if getattr(args, "json", False):
            print(json.dumps({"closed": [_record_payload(r) for r in closed]}, indent=2))
        else:
            print(f"Closed {len(closed)} browser session record(s).")
        return

    if command in {"mark-auth-needed", "auth-needed"}:
        updated = registry.mark_auth_needed(
            getattr(args, "session_id"),
            auth_needed=not getattr(args, "clear", False),
            profile=getattr(args, "profile", None),
            domain=getattr(args, "domain", None),
            backend=getattr(args, "backend", None),
        )
        if getattr(args, "json", False):
            print(json.dumps({"updated": [_record_payload(r) for r in updated]}, indent=2))
        else:
            state = "auth-needed" if not getattr(args, "clear", False) else "usable"
            print(f"Marked {len(updated)} browser session record(s) {state}.")
        return

    if command == "purge-expired":
        purged = registry.purge_expired()
        if getattr(args, "json", False):
            print(json.dumps({"purged": [_record_payload(r) for r in purged]}, indent=2))
        else:
            print(f"Purged {len(purged)} expired browser session record(s).")
        return

    raise SystemExit(f"Unknown browser-sessions command: {command}")


def _add_common_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="Filter by Hermes profile")
    parser.add_argument("--domain", help="Filter by domain or URL")
    parser.add_argument("--backend", help="Filter by backend id")


def _has_close_selector(args) -> bool:
    return any(
        getattr(args, name, None)
        for name in ("session_id", "profile", "domain", "backend")
    )


def _print_records(records: list[registry.BrowserSessionRecord], *, json_output: bool) -> None:
    if json_output:
        print(json.dumps({"sessions": [_record_payload(r) for r in records]}, indent=2))
        return
    if not records:
        print("No browser sessions.")
        return
    for record in records:
        state = "auth-needed" if record.auth_needed else "usable"
        expires_in = _expires_in(record)
        print(
            f"{record.session_id}  {record.profile}  {record.backend}  "
            f"{record.domain}  {state}  last_used={int(record.last_used)}  "
            f"ttl={record.ttl_seconds}s  expires_in={expires_in}"
        )


def _record_payload(record: registry.BrowserSessionRecord) -> dict[str, Any]:
    payload = record.to_dict()
    payload["expired"] = record.is_expired()
    return payload


def _expires_in(record: registry.BrowserSessionRecord) -> str:
    if record.ttl_seconds <= 0:
        return "never"
    remaining = int(record.ttl_seconds - (time.time() - record.last_used))
    return f"{max(remaining, 0)}s"

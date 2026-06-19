"""``hermes artifacts`` subcommand parser."""

from __future__ import annotations

from typing import Callable


def build_artifacts_parser(subparsers, *, cmd_artifacts: Callable) -> None:
    """Attach the artifact lifecycle registry command to ``subparsers``."""

    parser = subparsers.add_parser(
        "artifacts",
        help="Inspect and clean up registered artifacts/files",
        description=(
            "Manage the Hermes artifact lifecycle registry. The cleanup command "
            "only deletes files copied into the Hermes artifact store."
        ),
    )
    sub = parser.add_subparsers(dest="artifacts_action", metavar="<subcommand>")

    list_p = sub.add_parser("list", aliases=["ls"], help="List artifact records")
    list_p.add_argument("--source", help="Filter by source")
    list_p.add_argument("--task", help="Filter by Kanban task id")
    list_p.add_argument("--session", help="Filter by session id")
    list_p.add_argument("--state", help="Filter by cleanup state")
    list_p.add_argument("--limit", type=int, default=100, help="Maximum records to show")
    list_p.add_argument("--json", action="store_true", help="Emit JSON")

    show = sub.add_parser("show", help="Show one artifact record")
    show.add_argument("artifact_id")
    show.add_argument("--json", action="store_true", help="Emit JSON")

    register = sub.add_parser("register", help="Register a local file")
    register.add_argument("path")
    register.add_argument("--source", required=True, help="Source system label")
    register.add_argument("--source-id", help="Source-specific id")
    register.add_argument("--mime", help="MIME type override")
    register.add_argument("--sensitivity", default="unknown", help="Sensitivity label")
    register.add_argument("--task", help="Kanban task id")
    register.add_argument("--session", help="Hermes session id")
    register.add_argument("--board", help="Kanban board slug")
    register.add_argument(
        "--ttl",
        default="default",
        help="TTL: seconds, 15m, 2h, 7d, 4w, or permanent",
    )
    register.add_argument("--metadata", help="JSON object metadata")
    register.add_argument(
        "--copy",
        action="store_true",
        help="Copy into the Hermes artifact store so cleanup may delete it later",
    )
    register.add_argument(
        "--owned",
        action="store_true",
        help="Mark already-stored file as registry-owned (must be under artifact store)",
    )
    register.add_argument("--json", action="store_true", help="Emit JSON")

    promote = sub.add_parser("promote", help="Extend or remove an artifact TTL")
    promote.add_argument("artifact_id")
    promote.add_argument(
        "--ttl",
        default="default",
        help="New TTL from now: seconds, 15m, 2h, 7d, 4w, or permanent",
    )
    promote.add_argument("--permanent", action="store_true", help="Clear expiration")
    promote.add_argument("--json", action="store_true", help="Emit JSON")

    cleanup = sub.add_parser("cleanup", help="Expire old records and remove owned blobs")
    cleanup.add_argument("--dry-run", action="store_true", help="Do not modify files or rows")
    cleanup.add_argument("--json", action="store_true", help="Emit JSON")

    parser.set_defaults(func=cmd_artifacts)

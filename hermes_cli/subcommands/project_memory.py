"""``hermes project-memory`` subcommand parser."""

from __future__ import annotations

from typing import Callable


def build_project_memory_parser(subparsers, *, cmd_project_memory: Callable) -> None:
    """Attach the Project Memory command to ``subparsers``."""

    parser = subparsers.add_parser(
        "project-memory",
        aliases=["project-memories", "projects-memory"],
        help="Manage file-backed project memory documents",
        description=(
            "Manage lightweight markdown Project Memory documents linked to "
            "Kanban tasks, Hindsight entities, skills, cron jobs, and artifacts."
        ),
    )
    sub = parser.add_subparsers(dest="project_memory_action", metavar="<subcommand>")

    list_p = sub.add_parser("list", aliases=["ls"], help="List project memories")
    list_p.add_argument("--json", action="store_true", help="Emit JSON")

    show = sub.add_parser("show", help="Show a project memory markdown document")
    show.add_argument("project")
    show.add_argument("--json", action="store_true", help="Emit JSON with metadata and content")

    path = sub.add_parser("path", help="Print the project memory path")
    path.add_argument("project")

    update = sub.add_parser("update", help="Create or update a project memory")
    update.add_argument("project")
    update.add_argument("--title", help="Human-readable project title")
    update.add_argument("--content", help="Replace markdown content")
    update.add_argument("--content-file", help="Read replacement markdown content from a file")
    update.add_argument("--append", help="Append markdown text")
    update.add_argument("--kanban-task", action="append", default=[], help="Link a Kanban task id")
    update.add_argument("--skill", action="append", default=[], help="Link a Hermes skill name")
    update.add_argument("--cron-job", action="append", default=[], help="Link a cron job id")
    update.add_argument("--artifact", action="append", default=[], help="Link an artifact id/path")
    update.add_argument("--hindsight-entity", action="append", default=[], help="Link a Hindsight/entity reference")
    update.add_argument("--json", action="store_true", help="Emit JSON")

    parser.set_defaults(func=cmd_project_memory)

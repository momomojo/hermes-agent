"""``hermes capabilities`` subcommand parser."""

from __future__ import annotations

from typing import Callable


def _add_common(parser) -> None:
    parser.add_argument(
        "--catalog-dir",
        help="Capability catalog directory (default: $HERMES_HOME/capabilities)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON")


def build_capabilities_parser(subparsers, *, cmd_capabilities: Callable) -> None:
    """Attach the ``capabilities`` subcommand to ``subparsers``."""

    parser = subparsers.add_parser(
        "capabilities",
        aliases=["capability"],
        help="Manage local capability manifests",
        description=(
            "Manage Hermes capability manifests: installable scaffolds bundling "
            "skills, plugins, MCP servers, cron jobs, credential requirements, "
            "approval gates, and smoke tests without adding model-facing tools."
        ),
    )
    capability_sub = parser.add_subparsers(
        dest="capability_action",
        metavar="<subcommand>",
    )

    init = capability_sub.add_parser("init", help="Create a catalog with a synthetic smoke capability")
    _add_common(init)

    list_parser = capability_sub.add_parser("list", aliases=["ls"], help="List capabilities")
    _add_common(list_parser)

    validate = capability_sub.add_parser("validate", help="Validate all capability manifests")
    _add_common(validate)

    doctor = capability_sub.add_parser("doctor", help="Alias for validate/doctor checks")
    _add_common(doctor)

    smoke = capability_sub.add_parser("smoke", help="Run declared smoke tests")
    smoke.add_argument("capability_id", nargs="?", help="Optional capability id to smoke-test")
    _add_common(smoke)

    plan = capability_sub.add_parser("plan", help="Print a scaffold install/doctor/remove plan")
    plan.add_argument("capability_id", help="Capability id")
    plan.add_argument("plan_action", choices=["install", "doctor", "remove"], help="Plan to print")
    _add_common(plan)

    parser.set_defaults(func=cmd_capabilities)

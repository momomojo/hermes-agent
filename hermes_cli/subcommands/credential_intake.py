"""``hermes credential-intake`` subcommand parser."""

from __future__ import annotations

from typing import Callable


def build_credential_intake_parser(subparsers, *, cmd_credential_intake: Callable) -> None:
    """Attach ``credential-intake`` subcommand to ``subparsers``."""

    parser = subparsers.add_parser(
        "credential-intake",
        help="Create and consume short-lived local credential intake tokens",
        description=(
            "Create one-time localhost credential-intake links. The scaffold "
            "stores token metadata only; submitted secrets are not persisted."
        ),
    )
    intake_sub = parser.add_subparsers(
        dest="credential_intake_action",
        metavar="<subcommand>",
    )

    create = intake_sub.add_parser("create", help="Create a short-lived intake token")
    create.add_argument("--label", default="", help="Human-readable request label")
    create.add_argument(
        "--adapter",
        required=True,
        choices=["profile-env", "onepassword"],
        help="Placeholder destination adapter",
    )
    create.add_argument("--key", help="profile-env target environment variable")
    create.add_argument("--vault", help="1Password vault label")
    create.add_argument("--item", help="1Password item label")
    create.add_argument("--field", help="1Password field label")
    create.add_argument(
        "--ttl",
        default="15m",
        help="Token lifetime, e.g. 900, 15m, 2h, 1d (default: 15m)",
    )
    create.add_argument(
        "--base-url",
        default="http://127.0.0.1:8765",
        help="Local intake base URL (must be localhost)",
    )
    create.add_argument("--json", action="store_true", help="Emit JSON")

    list_parser = intake_sub.add_parser("list", help="List intake requests")
    list_parser.add_argument("--json", action="store_true", help="Emit JSON")

    show = intake_sub.add_parser("show", help="Show one intake request")
    show.add_argument("request_id")
    show.add_argument("--json", action="store_true", help="Emit JSON")

    submit = intake_sub.add_parser("submit", help="Consume a token once")
    submit.add_argument("token_or_url", help="Raw token or generated local URL")
    submit.add_argument(
        "--value-stdin",
        action="store_true",
        help="Read the credential value from stdin instead of a masked prompt",
    )
    submit.add_argument("--json", action="store_true", help="Emit JSON")

    revoke = intake_sub.add_parser("revoke", help="Revoke an unused intake request")
    revoke.add_argument("request_id")
    revoke.add_argument("--json", action="store_true", help="Emit JSON")

    parser.set_defaults(func=cmd_credential_intake)

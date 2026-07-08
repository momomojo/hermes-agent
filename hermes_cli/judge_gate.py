"""Read-only judge-ledger gate validation.

The judge ledger is append-only operational state, currently stored as
``<hermes-root>/state/judge-ledger.jsonl``.  This module never writes that
file; it only resolves a supplied verdict id (usually the ledger ``ts``) and
checks that it is an APPROVE verdict for the requested title/scope.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


class JudgeGateError(RuntimeError):
    """Raised when a judge verdict does not authorize the requested action."""


@dataclass(frozen=True)
class JudgeVerdict:
    """Validated judge-ledger entry."""

    id: str
    ts: int | None
    title: str
    verdict: str
    detail: str
    future_conditions: tuple[str, ...]
    raw: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ts": self.ts,
            "title": self.title,
            "verdict": self.verdict,
            "detail": self.detail,
            "future_conditions": list(self.future_conditions),
        }


_WS_RE = re.compile(r"\s+")
_CONDITION_LINE_RE = re.compile(r"\bconditions?\b", re.IGNORECASE)
_FUTURE_CONDITION_RE = re.compile(
    r"\b(after|before|when|once|next|first|later|future|scheduled|"
    r"restart|cron|watch|wait|post[- ]?(apply|deploy|restart))\b|"
    r"\b\d{1,2}:\d{2}\b",
    re.IGNORECASE,
)


def default_judge_ledger_path() -> Path:
    """Return the shared judge ledger path for the active Hermes root."""
    from hermes_constants import get_default_hermes_root

    return get_default_hermes_root() / "state" / "judge-ledger.jsonl"


def _normalize_text(value: str) -> str:
    return _WS_RE.sub(" ", str(value or "").strip()).casefold()


def _entry_id(entry: dict[str, Any]) -> str:
    raw_id = entry.get("id")
    if raw_id not in (None, ""):
        return str(raw_id).strip()
    raw_ts = entry.get("ts")
    if raw_ts not in (None, ""):
        return str(raw_ts).strip()
    return ""


def iter_judge_ledger(path: str | Path | None = None) -> Iterable[dict[str, Any]]:
    """Yield JSON objects from the judge ledger, failing closed on corruption."""
    ledger_path = Path(path).expanduser() if path else default_judge_ledger_path()
    try:
        lines = ledger_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise JudgeGateError(f"judge ledger not found: {ledger_path}") from exc
    except OSError as exc:
        raise JudgeGateError(f"could not read judge ledger {ledger_path}: {exc}") from exc

    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JudgeGateError(
                f"judge ledger {ledger_path} has invalid JSON on line {lineno}: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise JudgeGateError(
                f"judge ledger {ledger_path} line {lineno} is not an object"
            )
        yield parsed


def detect_future_conditions(detail: str) -> tuple[str, ...]:
    """Return future-looking condition lines from a verdict detail string."""
    found: list[str] = []
    for raw_line in str(detail or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _CONDITION_LINE_RE.search(line) and _FUTURE_CONDITION_RE.search(line):
            found.append(line)
    return tuple(found)


def resolve_judge_verdict(
    verdict_id: str,
    *,
    expected_title: str | None = None,
    expected_scope: str | None = None,
    ledger_path: str | Path | None = None,
) -> JudgeVerdict:
    """Validate and return an APPROVE verdict for the requested title/scope.

    ``verdict_id`` matches either an explicit ledger ``id`` field or, for the
    current ledger format, the entry ``ts``.  ``expected_title`` is normalized
    exact-match; ``expected_scope`` is a normalized substring match against the
    entry title plus detail.  At least one match constraint is required so a
    stale unrelated APPROVE cannot unlock a different live change.
    """
    wanted = str(verdict_id or "").strip()
    if not wanted:
        raise JudgeGateError("missing judge verdict id; pass --verdict <id-or-ts>")
    if not str(expected_title or "").strip() and not str(expected_scope or "").strip():
        raise JudgeGateError(
            "judge gate requires --title or --scope so the verdict can be tied "
            "to the requested change"
        )

    match: dict[str, Any] | None = None
    for entry in iter_judge_ledger(ledger_path):
        if _entry_id(entry) == wanted:
            match = entry

    if match is None:
        raise JudgeGateError(f"judge verdict {wanted!r} was not found")

    verdict = str(match.get("verdict") or "").strip().upper()
    title = str(match.get("title") or "").strip()
    detail = str(match.get("detail") or "")
    if verdict != "APPROVE":
        raise JudgeGateError(
            f"judge verdict {wanted!r} is {verdict or 'missing'}, not APPROVE"
        )

    if expected_title is not None and str(expected_title).strip():
        if _normalize_text(title) != _normalize_text(expected_title):
            raise JudgeGateError(
                f"judge verdict {wanted!r} title mismatch: expected "
                f"{expected_title!r}, got {title!r}"
            )

    if expected_scope is not None and str(expected_scope).strip():
        haystack = _normalize_text(f"{title}\n{detail}")
        needle = _normalize_text(expected_scope)
        if needle not in haystack:
            raise JudgeGateError(
                f"judge verdict {wanted!r} does not mention required scope "
                f"{expected_scope!r}"
            )

    raw_ts = match.get("ts")
    try:
        ts = int(raw_ts) if raw_ts not in (None, "") else None
    except (TypeError, ValueError):
        ts = None

    return JudgeVerdict(
        id=_entry_id(match),
        ts=ts,
        title=title,
        verdict=verdict,
        detail=detail,
        future_conditions=detect_future_conditions(detail),
        raw=dict(match),
    )


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a judge-ledger APPROVE verdict without mutating state."
    )
    parser.add_argument(
        "--verdict", required=True, help="Judge verdict id or ledger ts"
    )
    parser.add_argument("--title", help="Exact expected ledger title")
    parser.add_argument(
        "--scope",
        help="Required phrase that must appear in the verdict title or detail",
    )
    parser.add_argument("--ledger", help="Override judge-ledger JSONL path")
    parser.add_argument("--json", action="store_true", help="Print JSON result")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    try:
        verdict = resolve_judge_verdict(
            args.verdict,
            expected_title=args.title,
            expected_scope=args.scope,
            ledger_path=args.ledger,
        )
    except JudgeGateError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(verdict.to_dict(), sort_keys=True))
    else:
        print(
            f"APPROVE {verdict.id}: {verdict.title}"
            + (
                f" ({len(verdict.future_conditions)} future condition(s))"
                if verdict.future_conditions
                else ""
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

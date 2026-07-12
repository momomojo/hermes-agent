"""Kanban repair-card automation for GitHub CI webhook events.

This module is intentionally side-effect small: it consumes a single already
authenticated GitHub webhook payload, extracts CI failure evidence, and
creates or updates one Kanban repair card. It does not call GitHub, merge PRs,
or dispatch workers directly; the Kanban dispatcher owns execution.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from hermes_cli import kanban_db as kb

logger = logging.getLogger(__name__)

_PR_URL_RE = re.compile(
    r"https://github\.com/"
    r"(?P<repo>[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)/pull/(?P<number>\d+)"
    r"(?P<suffix>[#/\w.-]*)?"
)
_FAILURE_CONCLUSIONS = {
    "failure",
    "timed_out",
    "cancelled",
    "action_required",
    "startup_failure",
}
_NON_FAILURE_CONCLUSIONS = {"success", "skipped", "neutral"}
_MAX_TAIL_CHARS = 1600


@dataclass
class GitHubCIEvent:
    event_type: str
    repo: str = ""
    repo_url: str = ""
    pr_number: Optional[int] = None
    pr_url: str = ""
    pr_title: str = ""
    head_branch: str = ""
    head_sha: str = ""
    conclusion: str = ""
    status: str = ""
    action: str = ""
    run_urls: list[str] = field(default_factory=list)
    failed_names: list[str] = field(default_factory=list)
    failure_tail: str = ""

    @property
    def is_failure(self) -> bool:
        return self.conclusion.lower() in _FAILURE_CONCLUSIONS

    @property
    def is_terminal_non_failure(self) -> bool:
        return self.conclusion.lower() in _NON_FAILURE_CONCLUSIONS

    @property
    def pr_label(self) -> str:
        if self.pr_number is not None:
            return f"PR #{self.pr_number}"
        if self.head_branch:
            return f"branch {self.head_branch}"
        return "unknown PR"

    @property
    def failure_signature(self) -> str:
        basis = {
            "conclusion": self.conclusion,
            "failed_names": sorted(self.failed_names),
            "tail": self.failure_tail[-600:],
        }
        raw = json.dumps(basis, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @property
    def idempotency_key(self) -> str:
        target = self.pr_number if self.pr_number is not None else self.head_branch or "unknown"
        sha = self.head_sha or "unknown-sha"
        repo = self.repo or "unknown-repo"
        return f"github-ci-repair:{repo}:{target}:{sha}"


def handle_github_ci_repair_webhook(
    *,
    payload: dict[str, Any],
    event_type: str,
    route_config: Optional[dict[str, Any]] = None,
    route_name: str = "",
    delivery_id: str = "",
    profile: Optional[str] = None,
) -> dict[str, Any]:
    """Create or update an idempotent Kanban repair card for failed GitHub CI."""
    route_config = route_config or {}
    event = _extract_github_ci_event(payload, event_type)
    allowed = _route_repositories(route_config)
    if allowed and event.repo not in allowed:
        return {
            "status": "ignored",
            "reason": "repo_not_watched",
            "repo": event.repo,
            "delivery_id": delivery_id,
        }
    if not event.is_failure:
        reason = "ci_not_failed"
        if not event.conclusion:
            reason = "ci_not_completed"
        elif event.is_terminal_non_failure:
            reason = "ci_non_failure"
        return {
            "status": "ignored",
            "reason": reason,
            "repo": event.repo,
            "pr_number": event.pr_number,
            "head_sha": event.head_sha,
            "conclusion": event.conclusion,
            "delivery_id": delivery_id,
        }

    board = _route_value(route_config, "board")
    with kb.connect_closing(board=board) as conn:
        parent_id, handoff_comment_url = _resolve_parent_task(conn, event, route_config)
        existing_id = _find_existing_repair_task(conn, event)
        author = _comment_author(route_name=route_name, profile=profile)

        if existing_id:
            _ensure_idempotency_key(conn, existing_id, event.idempotency_key)
            if parent_id:
                _ensure_parent_link(conn, parent_id=parent_id, child_id=existing_id)
            comment_added = _add_evidence_comment_once(
                conn,
                existing_id,
                author=author,
                event=event,
                parent_id=parent_id,
                handoff_comment_url=handoff_comment_url,
                delivery_id=delivery_id,
            )
            logger.info(
                "github-ci repair card updated task=%s repo=%s pr=%s head=%s",
                existing_id,
                event.repo,
                event.pr_number,
                event.head_sha[:12],
            )
            return {
                "status": "kanban_card_updated",
                "task_id": existing_id,
                "parent_id": parent_id,
                "comment_added": comment_added,
                "idempotency_key": event.idempotency_key,
                "failure_signature": event.failure_signature,
                "delivery_id": delivery_id,
            }

        parent = kb.get_task(conn, parent_id) if parent_id else None
        assignee = (
            _route_value(route_config, "assignee")
            or (parent.assignee if parent else None)
            or _route_value(route_config, "fallback_assignee")
            or profile
        )
        triage = parent_id is None
        if triage:
            assignee = assignee or _route_value(route_config, "triage_assignee")

        task_id = kb.create_task(
            conn,
            title=_build_title(event, unresolved=triage),
            body=_build_body(
                event,
                parent_id=parent_id,
                handoff_comment_url=handoff_comment_url,
                delivery_id=delivery_id,
                unresolved=triage,
            ),
            assignee=assignee,
            created_by=author,
            parents=[parent_id] if parent_id else [],
            priority=_route_int(route_config, "priority", 80),
            workspace_kind=(
                _route_value(route_config, "workspace_kind")
                or (parent.workspace_kind if parent else "scratch")
            ),
            workspace_path=(
                _route_value(route_config, "workspace_path")
                or (parent.workspace_path if parent else None)
            ),
            idempotency_key=event.idempotency_key,
            triage=triage,
            initial_status="running",
        )
        logger.info(
            "github-ci repair card created task=%s repo=%s pr=%s head=%s parent=%s",
            task_id,
            event.repo,
            event.pr_number,
            event.head_sha[:12],
            parent_id,
        )
        return {
            "status": "kanban_card_created",
            "task_id": task_id,
            "parent_id": parent_id,
            "triage": triage,
            "idempotency_key": event.idempotency_key,
            "failure_signature": event.failure_signature,
            "delivery_id": delivery_id,
        }


def _extract_github_ci_event(payload: dict[str, Any], event_type: str) -> GitHubCIEvent:
    subject = _event_subject(payload, event_type)
    repo = _dig(payload, "repository", "full_name") or _dig(subject, "repository", "full_name")
    repo_url = _dig(payload, "repository", "html_url")
    pull_requests = _pull_requests(payload, subject)
    pr = pull_requests[0] if pull_requests else {}
    pr_number = _coerce_int(_dig(payload, "pull_request", "number") or pr.get("number"))
    pr_url = (
        _dig(payload, "pull_request", "html_url")
        or pr.get("html_url")
        or _html_pr_url(repo, pr_number)
    )
    pr_title = _dig(payload, "pull_request", "title") or pr.get("title") or ""

    head_branch = (
        _dig(subject, "head_branch")
        or _dig(payload, "pull_request", "head", "ref")
        or _dig(subject, "head", "ref")
        or ""
    )
    head_sha = (
        _dig(subject, "head_sha")
        or _dig(payload, "pull_request", "head", "sha")
        or _dig(subject, "head", "sha")
        or ""
    )
    conclusion = str(_dig(subject, "conclusion") or "").lower()
    status = str(_dig(subject, "status") or "").lower()
    action = str(payload.get("action") or "").lower()
    run_url = _dig(subject, "html_url") or _dig(subject, "details_url") or ""
    failed_name = (
        _dig(subject, "name")
        or _dig(payload, "workflow", "name")
        or _dig(subject, "app", "name")
        or event_type
    )
    failure_tail = _failure_tail(subject)

    return GitHubCIEvent(
        event_type=event_type,
        repo=str(repo or ""),
        repo_url=str(repo_url or ""),
        pr_number=pr_number,
        pr_url=str(pr_url or ""),
        pr_title=str(pr_title or ""),
        head_branch=str(head_branch or ""),
        head_sha=str(head_sha or ""),
        conclusion=conclusion,
        status=status,
        action=action,
        run_urls=[str(run_url)] if run_url else [],
        failed_names=[str(failed_name)] if failed_name else [],
        failure_tail=failure_tail,
    )


def _event_subject(payload: dict[str, Any], event_type: str) -> dict[str, Any]:
    key = {
        "workflow_run": "workflow_run",
        "check_suite": "check_suite",
        "check_run": "check_run",
        "status": "commit",
    }.get(event_type, "")
    value = payload.get(key) if key else None
    return value if isinstance(value, dict) else payload


def _pull_requests(payload: dict[str, Any], subject: dict[str, Any]) -> list[dict[str, Any]]:
    prs = subject.get("pull_requests")
    if isinstance(prs, list):
        return [p for p in prs if isinstance(p, dict)]
    pr = payload.get("pull_request")
    return [pr] if isinstance(pr, dict) else []


def _failure_tail(subject: dict[str, Any]) -> str:
    output = subject.get("output")
    pieces: list[str] = []
    if isinstance(output, dict):
        for key in ("title", "summary", "text"):
            value = output.get(key)
            if value:
                pieces.append(str(value))
    for key in ("message", "description"):
        value = subject.get(key)
        if value:
            pieces.append(str(value))
    text = "\n\n".join(p.strip() for p in pieces if p and p.strip())
    if len(text) > _MAX_TAIL_CHARS:
        text = text[-_MAX_TAIL_CHARS:]
    return text


def _resolve_parent_task(
    conn: Any,
    event: GitHubCIEvent,
    route_config: dict[str, Any],
) -> tuple[Optional[str], Optional[str]]:
    configured = _route_value(route_config, "parent_task_id") or _route_value(
        route_config, "origin_task_id"
    )
    if configured and kb.get_task(conn, str(configured)):
        return str(configured), _route_value(route_config, "handoff_comment_url")

    candidates: list[tuple[int, str, Optional[str]]] = []
    for task, text in _iter_task_text(conn):
        if not _matches_event_text(text, event):
            continue
        handoff_url = _first_handoff_comment_url(text, event)
        for explicit in _explicit_parent_ids(text):
            if explicit != task.id and kb.get_task(conn, explicit):
                candidates.append((120, explicit, handoff_url))
        score = 30
        if _looks_like_repair_task(task):
            score -= 20
        else:
            score += 25
        if task.status == "done":
            score += 10
        if event.head_sha and event.head_sha in text:
            score += 10
        candidates.append((score, task.id, handoff_url))

    if not candidates:
        return None, _route_value(route_config, "handoff_comment_url")
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1], candidates[0][2] or _route_value(
        route_config, "handoff_comment_url"
    )


def _find_existing_repair_task(conn: Any, event: GitHubCIEvent) -> Optional[str]:
    row = conn.execute(
        "SELECT id FROM tasks WHERE idempotency_key = ? AND status != 'archived' "
        "ORDER BY created_at DESC LIMIT 1",
        (event.idempotency_key,),
    ).fetchone()
    if row:
        return str(row["id"])

    candidates: list[tuple[int, str]] = []
    for task, text in _iter_task_text(conn):
        if not _looks_like_repair_task(task):
            continue
        if not _matches_event_text(text, event):
            continue
        score = 50
        if event.head_sha and event.head_sha in text:
            score += 20
        if event.pr_url and event.pr_url in text:
            score += 15
        candidates.append((score, task.id))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _iter_task_text(conn: Any) -> Iterable[tuple[kb.Task, str]]:
    rows = conn.execute(
        "SELECT * FROM tasks WHERE status != 'archived' ORDER BY created_at ASC"
    ).fetchall()
    comments = conn.execute(
        "SELECT task_id, body FROM task_comments ORDER BY created_at ASC"
    ).fetchall()
    comments_by_task: dict[str, list[str]] = {}
    for row in comments:
        comments_by_task.setdefault(str(row["task_id"]), []).append(str(row["body"] or ""))
    for row in rows:
        task = kb.Task.from_row(row)
        parts = [
            task.title or "",
            task.body or "",
            task.branch_name or "",
            task.idempotency_key or "",
            "\n".join(comments_by_task.get(task.id, [])),
        ]
        yield task, "\n".join(parts)


def _matches_event_text(text: str, event: GitHubCIEvent) -> bool:
    haystack = text.lower()
    pr_terms = [event.pr_url, f"pull/{event.pr_number}" if event.pr_number else ""]
    if event.pr_number is not None:
        pr_terms.extend([f"pr #{event.pr_number}", f"pr {event.pr_number}"])
    pr_match = any(term and term.lower() in haystack for term in pr_terms)
    head_terms = [event.head_sha, event.head_sha[:12], event.head_branch]
    head_match = any(term and term.lower() in haystack for term in head_terms)
    if pr_match and (head_match or not any(head_terms)):
        return True
    return bool(head_match and event.repo and event.repo.lower() in haystack)


def _explicit_parent_ids(text: str) -> list[str]:
    out: list[str] = []
    parent_re = re.compile(
        r"\b(?:parent(?:\s+card)?|origin(?:ating)?(?:\s+parent)?(?:\s+card)?):?"
        r"\s*(`?)(t_[a-f0-9]{6,})\1",
        re.IGNORECASE,
    )
    for match in parent_re.finditer(text):
        out.append(match.group(2).lower())
    return out


def _looks_like_repair_task(task: kb.Task) -> bool:
    text = f"{task.title or ''}\n{task.body or ''}\n{task.idempotency_key or ''}".lower()
    return (
        "github-ci-repair:" in text
        or "repair ci" in text
        or "ci blocker" in text
        or "ci failure" in text
    )


def _ensure_idempotency_key(conn: Any, task_id: str, idempotency_key: str) -> None:
    with kb.write_txn(conn):
        conn.execute(
            "UPDATE tasks SET idempotency_key = ? "
            "WHERE id = ? AND (idempotency_key IS NULL OR idempotency_key = '')",
            (idempotency_key, task_id),
        )


def _ensure_parent_link(conn: Any, *, parent_id: str, child_id: str) -> None:
    if parent_id == child_id:
        return
    try:
        kb.link_tasks(conn, parent_id=parent_id, child_id=child_id)
    except ValueError:
        logger.debug(
            "github-ci repair card parent link skipped parent=%s child=%s",
            parent_id,
            child_id,
        )


def _add_evidence_comment_once(
    conn: Any,
    task_id: str,
    *,
    author: str,
    event: GitHubCIEvent,
    parent_id: Optional[str],
    handoff_comment_url: Optional[str],
    delivery_id: str,
) -> bool:
    marker = f"ci-failure-signature:{event.failure_signature}"
    comments = kb.list_comments(conn, task_id)
    if any(marker in (comment.body or "") for comment in comments):
        return False
    kb.add_comment(
        conn,
        task_id,
        author=author,
        body=_build_evidence_comment(
            event,
            parent_id=parent_id,
            handoff_comment_url=handoff_comment_url,
            delivery_id=delivery_id,
            marker=marker,
        ),
    )
    return True


def _build_title(event: GitHubCIEvent, *, unresolved: bool) -> str:
    repo_name = event.repo.split("/")[-1] if event.repo else "GitHub"
    prefix = "Triage unresolved CI failure for" if unresolved else "Repair CI blockers for"
    return f"{prefix} {repo_name} {event.pr_label}"


def _build_body(
    event: GitHubCIEvent,
    *,
    parent_id: Optional[str],
    handoff_comment_url: Optional[str],
    delivery_id: str,
    unresolved: bool,
) -> str:
    origin = f"`{parent_id}`" if parent_id else "`unresolved-origin`"
    lines = [
        f"GOAL: Repair or correctly route the failing CI blockers for {event.repo} {event.pr_label}.",
        "",
        "Context:",
        f"- Repo: `{event.repo}`",
        f"- PR: {event.pr_url or event.pr_label}",
        f"- PR title: {event.pr_title or '(unknown)'}",
        f"- Head branch: `{event.head_branch or '(unknown)'}`",
        f"- Head SHA: `{event.head_sha or '(unknown)'}`",
        f"- Originating parent card: {origin}",
    ]
    if unresolved:
        lines.append(
            "- Origin resolution: `unresolved-origin` - route safely; do not guess ownership."
        )
    if handoff_comment_url:
        lines.append(f"- PR handoff comment: {handoff_comment_url}")
    lines.extend(
        [
            "",
            "CI evidence:",
            f"- Event: `{event.event_type}` / action `{event.action or '(none)'}` / conclusion `{event.conclusion}`",
            f"- Delivery: `{delivery_id or '(none)'}`",
        ]
    )
    for name in event.failed_names or ["(unknown failed check)"]:
        lines.append(f"- Failed workflow/check: `{name}`")
    for url in event.run_urls:
        lines.append(f"- Failed run URL: {url}")
    if event.failure_tail:
        lines.extend(["", "Failure tail:", "```", event.failure_tail, "```"])
    lines.extend(
        [
            "",
            "Acceptance:",
            "- Classify each failing check as PR-caused, base/pre-existing, or CI infrastructure.",
            "- Push only minimal repair commits needed for PR-caused failures.",
            "- Verify CI is green, or leave exact residual evidence and scoped follow-up cards.",
            "- Update the PR/gate handoff comment with the repair result.",
            "- Comment on the parent card with CI evidence and next action.",
            "",
            "Safety:",
            "- Do not auto-merge.",
            "- Do not broaden PR scope beyond the failing CI repair.",
        ]
    )
    return "\n".join(lines)


def _build_evidence_comment(
    event: GitHubCIEvent,
    *,
    parent_id: Optional[str],
    handoff_comment_url: Optional[str],
    delivery_id: str,
    marker: str,
) -> str:
    lines = [
        f"Automated CI failure evidence update ({marker}).",
        "",
        f"- Repo: `{event.repo}`",
        f"- PR: {event.pr_url or event.pr_label}",
        f"- Head branch: `{event.head_branch or '(unknown)'}`",
        f"- Head SHA: `{event.head_sha or '(unknown)'}`",
        f"- Parent card: `{parent_id}`" if parent_id else "- Parent card: `unresolved-origin`",
        f"- Delivery: `{delivery_id or '(none)'}`",
    ]
    if handoff_comment_url:
        lines.append(f"- PR handoff comment: {handoff_comment_url}")
    for name in event.failed_names:
        lines.append(f"- Failed workflow/check: `{name}`")
    for url in event.run_urls:
        lines.append(f"- Failed run URL: {url}")
    if event.failure_tail:
        lines.extend(["", "Failure tail:", "```", event.failure_tail, "```"])
    return "\n".join(lines)


def _route_repositories(route_config: dict[str, Any]) -> set[str]:
    raw = _route_value(route_config, "repo") or _route_value(route_config, "repository")
    raw = raw or _route_value(route_config, "repositories")
    if not raw:
        return set()
    if isinstance(raw, str):
        return {part.strip() for part in raw.split(",") if part.strip()}
    if isinstance(raw, (list, tuple, set)):
        return {str(part).strip() for part in raw if str(part).strip()}
    return set()


def _route_value(route_config: dict[str, Any], key: str) -> Any:
    for section in (
        route_config.get("github_ci_repair"),
        route_config.get("kanban_ci_repair"),
        route_config.get("kanban"),
        route_config,
    ):
        if isinstance(section, dict) and key in section:
            value = section.get(key)
            if value not in (None, ""):
                return value
    return None


def _route_int(route_config: dict[str, Any], key: str, default: int) -> int:
    raw = _route_value(route_config, key)
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _comment_author(*, route_name: str, profile: Optional[str]) -> str:
    if profile:
        return f"webhook/{profile}"
    if route_name:
        return f"webhook/{route_name}"
    return "webhook"


def _first_handoff_comment_url(text: str, event: GitHubCIEvent) -> Optional[str]:
    for match in _PR_URL_RE.finditer(text):
        url = match.group(0)
        if "#issuecomment-" in url:
            if event.pr_number is None or match.group("number") == str(event.pr_number):
                return url
    return None


def _html_pr_url(repo: str, number: Optional[int]) -> str:
    if not repo or number is None:
        return ""
    return f"https://github.com/{repo}/pull/{number}"


def _dig(obj: Any, *path: str) -> Any:
    cur = obj
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _coerce_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None

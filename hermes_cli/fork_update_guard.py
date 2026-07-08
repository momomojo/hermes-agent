"""Fork-aware update preflight for ``hermes update``.

This module intentionally does not apply updates. It gives fork/device-branch
installs a guarded path to snapshot first, inspect drift against both the fork
and upstream, rehearse the reconcile in a temporary worktree, and leave a
reviewable report before any live checkout mutation happens.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


class ForkUpdatePreflightError(RuntimeError):
    """Raised when the preflight cannot even build a report."""


@dataclass(frozen=True)
class Drift:
    """Ahead/behind counts for ``base..head`` comparisons."""

    ahead: int = -1
    behind: int = -1


@dataclass
class ForkUpdatePreflightResult:
    repo_root: Path
    report_path: Path
    current_branch: str
    target_branch: str
    upstream_branch: str
    current_head: str
    origin_url: Optional[str] = None
    upstream_url: Optional[str] = None
    origin_ref: str = ""
    upstream_ref: str = ""
    origin_head: Optional[str] = None
    upstream_head: Optional[str] = None
    snapshot_id: Optional[str] = None
    snapshot_error: Optional[str] = None
    fetch_errors: list[str] = field(default_factory=list)
    missing_refs: list[str] = field(default_factory=list)
    local_vs_origin: Drift = field(default_factory=Drift)
    local_vs_upstream: Drift = field(default_factory=Drift)
    origin_vs_upstream: Drift = field(default_factory=Drift)
    carried_commits: list[str] = field(default_factory=list)
    rehearsal_strategy: str = "merge"
    rehearsal_command: list[str] = field(default_factory=list)
    rehearsal_status: str = "not-run"
    rehearsal_stdout: str = ""
    rehearsal_stderr: str = ""
    conflict_files: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)

    @property
    def ok_to_live_update(self) -> bool:
        return (
            self.snapshot_error is None
            and not self.fetch_errors
            and not self.missing_refs
            and self.rehearsal_status == "clean"
        )


def _run_git(
    git_cmd: list[str],
    cwd: Path,
    args: list[str],
    *,
    check: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        git_cmd + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
    )


def _git_stdout(git_cmd: list[str], cwd: Path, args: list[str]) -> Optional[str]:
    result = _run_git(git_cmd, cwd, args)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _remote_url(git_cmd: list[str], cwd: Path, remote: str) -> Optional[str]:
    return _git_stdout(git_cmd, cwd, ["remote", "get-url", remote])


def _ref_exists(git_cmd: list[str], cwd: Path, ref: str) -> bool:
    result = _run_git(git_cmd, cwd, ["rev-parse", "--verify", "--quiet", ref])
    return result.returncode == 0


def _rev_parse(git_cmd: list[str], cwd: Path, ref: str) -> Optional[str]:
    return _git_stdout(git_cmd, cwd, ["rev-parse", "--verify", ref])


def _count_between(git_cmd: list[str], cwd: Path, base: str, head: str) -> int:
    raw = _git_stdout(git_cmd, cwd, ["rev-list", "--count", f"{base}..{head}"])
    if raw is None:
        return -1
    try:
        return int(raw)
    except ValueError:
        return -1


def _drift(git_cmd: list[str], cwd: Path, left: str, right: str) -> Drift:
    return Drift(
        ahead=_count_between(git_cmd, cwd, left, right),
        behind=_count_between(git_cmd, cwd, right, left),
    )


def _current_branch(git_cmd: list[str], cwd: Path) -> str:
    branch = _git_stdout(git_cmd, cwd, ["rev-parse", "--abbrev-ref", "HEAD"])
    if not branch:
        raise ForkUpdatePreflightError("could not determine current git branch")
    if branch == "HEAD":
        raise ForkUpdatePreflightError(
            "fork update preflight needs a named branch; detached HEAD is not supported"
        )
    return branch


def _default_report_path() -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    try:
        from hermes_constants import get_hermes_home

        root = get_hermes_home()
    except Exception:
        root = Path(tempfile.gettempdir()) / "hermes"
    return root / "updates" / "reconcile-reports" / f"fork-update-{stamp}.md"


def _create_preflight_snapshot() -> tuple[Optional[str], Optional[str]]:
    try:
        from hermes_cli.backup import create_quick_snapshot

        snapshot_id = create_quick_snapshot(label="pre-fork-update-reconcile", keep=3)
    except Exception as exc:
        return None, str(exc)
    if not snapshot_id:
        return None, "quick snapshot did not return an id"
    return str(snapshot_id), None


def _trim_lines(value: str, *, limit: int = 20) -> str:
    lines = [line.rstrip() for line in value.splitlines() if line.rstrip()]
    if len(lines) <= limit:
        return "\n".join(lines)
    shown = "\n".join(lines[:limit])
    return f"{shown}\n... ({len(lines) - limit} more line(s))"


def _commit_subjects(
    git_cmd: list[str],
    cwd: Path,
    base: str,
    head: str,
    *,
    limit: int = 25,
) -> list[str]:
    result = _run_git(
        git_cmd,
        cwd,
        ["log", "--reverse", f"--max-count={limit}", "--format=%h %s", f"{base}..{head}"],
    )
    if result.returncode != 0:
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def _rehearse_reconcile(
    result: ForkUpdatePreflightResult,
    git_cmd: list[str],
    *,
    strategy: str,
) -> None:
    temp_root = Path(tempfile.mkdtemp(prefix="hermes-fork-update-"))
    worktree = temp_root / "worktree"
    try:
        add_result = _run_git(
            git_cmd,
            result.repo_root,
            ["worktree", "add", "--detach", str(worktree), "HEAD"],
        )
        if add_result.returncode != 0:
            result.rehearsal_status = "failed"
            result.rehearsal_stderr = add_result.stderr.strip()
            return

        if strategy == "merge":
            command = ["merge", "--no-commit", "--no-ff", result.upstream_ref]
        elif strategy == "rebase":
            command = ["rebase", result.upstream_ref]
        else:
            raise ForkUpdatePreflightError(
                f"unknown fork reconcile strategy {strategy!r}; use merge or rebase"
            )

        result.rehearsal_strategy = strategy
        result.rehearsal_command = ["git", *command]
        trial = _run_git(git_cmd, worktree, command)
        result.rehearsal_stdout = trial.stdout.strip()
        result.rehearsal_stderr = trial.stderr.strip()

        if trial.returncode == 0:
            result.rehearsal_status = "clean"
            changed = _git_stdout(git_cmd, worktree, ["diff", "--name-only", "HEAD"])
            if changed:
                result.changed_files = [
                    line for line in changed.splitlines() if line.strip()
                ]
            return

        conflicts = _git_stdout(
            git_cmd,
            worktree,
            ["diff", "--name-only", "--diff-filter=U"],
        )
        result.conflict_files = (
            [line for line in conflicts.splitlines() if line.strip()]
            if conflicts
            else []
        )
        result.rehearsal_status = "conflicts" if result.conflict_files else "failed"
    finally:
        _run_git(git_cmd, result.repo_root, ["worktree", "remove", "--force", str(worktree)])
        _run_git(git_cmd, result.repo_root, ["worktree", "prune"])
        shutil.rmtree(temp_root, ignore_errors=True)


def _render_drift(name: str, drift: Drift, left: str, right: str) -> str:
    if drift.ahead < 0 or drift.behind < 0:
        return f"- {name}: unavailable ({right} vs {left})"
    return f"- {name}: {right} is {drift.ahead} ahead / {drift.behind} behind {left}"


def _render_report(result: ForkUpdatePreflightResult) -> str:
    verdict = "SAFE TO REVIEW FOR LIVE UPDATE" if result.ok_to_live_update else "BLOCKED"
    lines = [
        "# Hermes Fork Update Preflight",
        "",
        f"Verdict: {verdict}",
        "",
        "## Scope",
        "",
        f"- Repository: `{result.repo_root}`",
        f"- Current branch: `{result.current_branch}`",
        f"- Target fork branch: `{result.target_branch}`",
        f"- Upstream branch: `{result.upstream_branch}`",
        f"- Current HEAD: `{result.current_head}`",
        f"- Origin: `{result.origin_url or '(missing)'}`",
        f"- Upstream: `{result.upstream_url or '(missing)'}`",
        "",
        "## Snapshot",
        "",
    ]

    if result.snapshot_id:
        lines.append(f"- Runtime snapshot: `{result.snapshot_id}`")
    elif result.snapshot_error:
        lines.append(f"- Runtime snapshot: FAILED - {result.snapshot_error}")
    else:
        lines.append("- Runtime snapshot: skipped")

    lines.extend(
        [
            "",
            "## Drift",
            "",
            f"- Origin ref: `{result.origin_ref}` -> `{result.origin_head or '(missing)'}`",
            f"- Upstream ref: `{result.upstream_ref}` -> `{result.upstream_head or '(missing)'}`",
            _render_drift("local vs origin", result.local_vs_origin, result.origin_ref, "HEAD"),
            _render_drift(
                "local vs upstream",
                result.local_vs_upstream,
                result.upstream_ref,
                "HEAD",
            ),
            _render_drift(
                "origin vs upstream",
                result.origin_vs_upstream,
                result.upstream_ref,
                result.origin_ref,
            ),
            "",
            "## Carried Commits",
            "",
        ]
    )

    if result.carried_commits:
        lines.extend(f"- {line}" for line in result.carried_commits)
    else:
        lines.append("- None detected or unavailable.")

    lines.extend(["", "## Rehearsal", ""])
    if result.rehearsal_command:
        lines.append(f"- Command: `{' '.join(result.rehearsal_command)}`")
    else:
        lines.append("- Command: not run")
    lines.append(f"- Status: `{result.rehearsal_status}`")

    if result.conflict_files:
        lines.extend(["", "Conflicts:"])
        lines.extend(f"- `{path}`" for path in result.conflict_files)
    if result.changed_files:
        lines.extend(["", "Changed files from clean merge rehearsal:"])
        lines.extend(f"- `{path}`" for path in result.changed_files)

    if result.fetch_errors:
        lines.extend(["", "## Fetch Errors", ""])
        lines.extend(f"- {err}" for err in result.fetch_errors)

    if result.missing_refs:
        lines.extend(["", "## Missing Refs", ""])
        lines.extend(f"- `{ref}`" for ref in result.missing_refs)

    if result.rehearsal_stdout or result.rehearsal_stderr:
        lines.extend(["", "## Rehearsal Output", ""])
        if result.rehearsal_stdout:
            lines.extend(["stdout:", "```", _trim_lines(result.rehearsal_stdout), "```"])
        if result.rehearsal_stderr:
            lines.extend(["stderr:", "```", _trim_lines(result.rehearsal_stderr), "```"])

    lines.extend(
        [
            "",
            "## Review Gate",
            "",
            "- No live update was applied by this preflight.",
            (
                "- If approved, run "
                f"`hermes update --branch {result.target_branch}` "
                "from the live checkout."
            ),
            (
                "- If anything looks wrong, do not run the live update; "
                "reconcile the fork branch in a normal PR first."
            ),
            "",
            "## Rollback Path",
            "",
            f"- Source checkout: `git reset --hard {result.current_head}`",
            (
                "- Runtime state: restore the snapshot listed above with the "
                "normal Hermes snapshot/import flow."
            ),
            "- Gateway: restart only after reviewer approval and a successful live update.",
            "",
        ]
    )
    return "\n".join(lines)


def run_fork_update_preflight(
    repo_root: Path,
    *,
    branch: Optional[str] = None,
    upstream_branch: str = "main",
    strategy: str = "merge",
    fetch: bool = True,
    snapshot: bool = True,
    report_path: Optional[Path] = None,
    git_cmd: Optional[list[str]] = None,
) -> ForkUpdatePreflightResult:
    """Run a fork update preflight and write a reconcile report.

    The live checkout is not pulled, reset, pushed, dependency-installed, or
    restarted. The only git mutation is temporary worktree bookkeeping, which
    is removed before returning.
    """

    repo_root = Path(repo_root).resolve()
    git_cmd = list(git_cmd or ["git"])

    if not (repo_root / ".git").exists():
        raise ForkUpdatePreflightError(f"{repo_root} is not a git checkout")

    current_branch = _current_branch(git_cmd, repo_root)
    target_branch = (branch or current_branch).strip()
    if not target_branch:
        raise ForkUpdatePreflightError("target branch is empty")
    upstream_branch = (upstream_branch or "main").strip() or "main"

    current_head = _rev_parse(git_cmd, repo_root, "HEAD")
    if not current_head:
        raise ForkUpdatePreflightError("could not resolve HEAD")

    snapshot_id = None
    snapshot_error = None
    if snapshot:
        snapshot_id, snapshot_error = _create_preflight_snapshot()

    report = Path(report_path) if report_path else _default_report_path()
    result = ForkUpdatePreflightResult(
        repo_root=repo_root,
        report_path=report,
        current_branch=current_branch,
        target_branch=target_branch,
        upstream_branch=upstream_branch,
        current_head=current_head,
        origin_url=_remote_url(git_cmd, repo_root, "origin"),
        upstream_url=_remote_url(git_cmd, repo_root, "upstream"),
        origin_ref=f"origin/{target_branch}",
        upstream_ref=f"upstream/{upstream_branch}",
        snapshot_id=snapshot_id,
        snapshot_error=snapshot_error,
        rehearsal_strategy=strategy,
    )

    if fetch:
        for remote, ref in (("origin", target_branch), ("upstream", upstream_branch)):
            fetch_result = _run_git(git_cmd, repo_root, ["fetch", remote, ref, "--quiet"])
            if fetch_result.returncode != 0:
                err = fetch_result.stderr.strip() or fetch_result.stdout.strip()
                result.fetch_errors.append(f"git fetch {remote} {ref}: {err or 'failed'}")

    for ref in (result.origin_ref, result.upstream_ref):
        if not _ref_exists(git_cmd, repo_root, ref):
            result.missing_refs.append(ref)

    if not result.missing_refs:
        result.origin_head = _rev_parse(git_cmd, repo_root, result.origin_ref)
        result.upstream_head = _rev_parse(git_cmd, repo_root, result.upstream_ref)
        result.local_vs_origin = _drift(git_cmd, repo_root, result.origin_ref, "HEAD")
        result.local_vs_upstream = _drift(git_cmd, repo_root, result.upstream_ref, "HEAD")
        result.origin_vs_upstream = _drift(
            git_cmd,
            repo_root,
            result.upstream_ref,
            result.origin_ref,
        )
        result.carried_commits = _commit_subjects(
            git_cmd,
            repo_root,
            result.upstream_ref,
            "HEAD",
        )

    if result.fetch_errors or result.missing_refs:
        result.rehearsal_status = "not-run"
    else:
        _rehearse_reconcile(result, git_cmd, strategy=strategy)

    result.report_path.parent.mkdir(parents=True, exist_ok=True)
    result.report_path.write_text(_render_report(result), encoding="utf-8")
    return result


def cmd_fork_update_preflight(args, *, repo_root: Path) -> int:
    """CLI adapter for ``hermes update --fork-preflight``."""

    try:
        result = run_fork_update_preflight(
            repo_root,
            branch=getattr(args, "branch", None),
            upstream_branch=getattr(args, "upstream_branch", "main"),
            strategy=getattr(args, "fork_strategy", "merge"),
            fetch=not bool(getattr(args, "no_fetch", False)),
            snapshot=not bool(getattr(args, "no_snapshot", False)),
            report_path=(
                Path(getattr(args, "report", ""))
                if getattr(args, "report", None)
                else None
            ),
        )
    except ForkUpdatePreflightError as exc:
        print(f"fork update preflight failed: {exc}")
        return 1

    print("Fork update preflight complete.")
    print(f"  Status: {result.rehearsal_status}")
    print(f"  Report: {result.report_path}")
    if result.snapshot_id:
        print(f"  Snapshot: {result.snapshot_id}")
    if result.ok_to_live_update:
        print(
            "  No live update was applied. Review the report, then run "
            f"`hermes update --branch {result.target_branch}` if approved."
        )
        return 0

    print("  Live update remains blocked until the report is reviewed.")
    if result.conflict_files:
        print(f"  Conflicts: {', '.join(result.conflict_files)}")
    if result.fetch_errors:
        print(f"  Fetch errors: {len(result.fetch_errors)}")
    if result.missing_refs:
        print(f"  Missing refs: {', '.join(result.missing_refs)}")
    return 1

import subprocess
from pathlib import Path

from hermes_cli.fork_update_guard import run_fork_update_preflight


def _git(cwd: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
    )


def _init_repo(path: Path) -> None:
    path.mkdir(parents=True)
    _git(path, "init")
    _git(path, "checkout", "-b", "main")
    _git(path, "config", "user.email", "tests@example.com")
    _git(path, "config", "user.name", "Hermes Tests")


def _commit(path: Path, rel: str, text: str, message: str) -> None:
    target = path / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    _git(path, "add", rel)
    _git(path, "commit", "-m", message)


def _clone_bare(src: Path, dest: Path) -> None:
    subprocess.run(
        ["git", "clone", "--bare", str(src), str(dest)],
        capture_output=True,
        text=True,
        check=True,
    )


def _clone(src: Path, dest: Path) -> None:
    subprocess.run(
        ["git", "clone", str(src), str(dest)],
        capture_output=True,
        text=True,
        check=True,
    )
    _git(dest, "config", "user.email", "tests@example.com")
    _git(dest, "config", "user.name", "Hermes Tests")


def _make_fork_layout(tmp_path: Path, *, conflict: bool = False) -> Path:
    seed = tmp_path / "seed"
    _init_repo(seed)
    _commit(seed, "app.txt", "base\n", "base")

    upstream_bare = tmp_path / "upstream.git"
    fork_bare = tmp_path / "fork.git"
    _clone_bare(seed, upstream_bare)
    _clone_bare(seed, fork_bare)

    upstream_work = tmp_path / "upstream-work"
    _clone(upstream_bare, upstream_work)
    if conflict:
        _commit(upstream_work, "app.txt", "upstream\n", "upstream drift")
    else:
        _commit(upstream_work, "upstream.txt", "upstream\n", "upstream drift")
    _git(upstream_work, "push", "origin", "main")

    local = tmp_path / "local"
    _clone(fork_bare, local)
    _git(local, "remote", "add", "upstream", str(upstream_bare))
    _git(local, "checkout", "-b", "mohib/mac-mini-hermes")
    if conflict:
        _commit(local, "app.txt", "local\n", "local carried")
    else:
        _commit(local, "device.txt", "local\n", "local carried")
    _git(local, "push", "-u", "origin", "mohib/mac-mini-hermes")
    return local


def test_fork_preflight_rehearses_clean_merge_without_mutating_live_checkout(tmp_path):
    local = _make_fork_layout(tmp_path)
    head_before = _git(local, "rev-parse", "HEAD").stdout.strip()
    report_path = tmp_path / "report.md"

    result = run_fork_update_preflight(
        local,
        report_path=report_path,
        snapshot=False,
    )

    assert result.ok_to_live_update is True
    assert result.rehearsal_status == "clean"
    assert result.target_branch == "mohib/mac-mini-hermes"
    assert result.local_vs_origin == type(result.local_vs_origin)(ahead=0, behind=0)
    assert result.local_vs_upstream.ahead == 1
    assert result.local_vs_upstream.behind == 1
    assert any("local carried" in line for line in result.carried_commits)

    assert _git(local, "rev-parse", "HEAD").stdout.strip() == head_before
    assert _git(local, "branch", "--show-current").stdout.strip() == "mohib/mac-mini-hermes"
    assert _git(local, "status", "--porcelain").stdout == ""

    report = report_path.read_text(encoding="utf-8")
    assert "SAFE TO REVIEW FOR LIVE UPDATE" in report
    assert "hermes update --branch mohib/mac-mini-hermes" in report
    assert "No live update was applied" in report


def test_fork_preflight_reports_conflicts_and_blocks_live_update(tmp_path):
    local = _make_fork_layout(tmp_path, conflict=True)
    report_path = tmp_path / "conflict-report.md"

    result = run_fork_update_preflight(
        local,
        report_path=report_path,
        snapshot=False,
    )

    assert result.ok_to_live_update is False
    assert result.rehearsal_status == "conflicts"
    assert result.conflict_files == ["app.txt"]
    assert _git(local, "status", "--porcelain").stdout == ""

    report = report_path.read_text(encoding="utf-8")
    assert "Verdict: BLOCKED" in report
    assert "`app.txt`" in report
    assert "do not run the live update" in report

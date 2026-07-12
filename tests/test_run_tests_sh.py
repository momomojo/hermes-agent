"""Integration coverage for the canonical shell test runner."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


def _run_shell_runner(files: list[Path], *extra: str) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env["OPENAI_API_KEY"] = "must-not-leak"
    return subprocess.run(
        [
            str(repo_root / "scripts" / "run_tests.sh"),
            "--files",
            ":".join(str(path) for path in files),
            "-j",
            "1",
            "--file-timeout",
            "30",
            *extra,
        ],
        cwd=repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=90,
        env=env,
    )


def _assert_no_runner_infrastructure_error(output: str) -> None:
    for needle in (
        "NameError",
        "TypeError",
        "Traceback (most recent call last)",
        "runner crashed",
    ):
        assert needle not in output, output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
@pytest.mark.live_system_guard_bypass
def test_files_mode_runs_with_clean_environment(tmp_path: Path) -> None:
    probe = tmp_path / "test_runner_probe.py"
    probe.write_text(
        "import os\n\n"
        "def test_clean_environment():\n"
        "    assert os.environ.get('HERMES_HOME')\n"
        "    assert os.environ.get('OPENAI_API_KEY') in (None, '')\n"
    )
    proc = _run_shell_runner([probe], "-q")
    assert proc.returncode == 0, proc.stdout
    _assert_no_runner_infrastructure_error(proc.stdout)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
@pytest.mark.live_system_guard_bypass
def test_real_test_failure_is_nonzero(tmp_path: Path) -> None:
    probe = tmp_path / "test_runner_failure.py"
    probe.write_text("def test_failure():\n    assert False, 'intentional probe failure'\n")
    proc = _run_shell_runner([probe], "-q")
    assert proc.returncode != 0, proc.stdout
    _assert_no_runner_infrastructure_error(proc.stdout)
    assert "intentional probe failure" in proc.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")
def test_prefers_test_capable_venv_over_broken_dotvenv(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    scripts.mkdir(parents=True)
    source = Path(__file__).resolve().parent.parent / "scripts" / "run_tests.sh"
    runner = scripts / "run_tests.sh"
    runner.write_text(source.read_text())
    runner.chmod(0o755)
    (scripts / "run_tests_parallel.py").write_text(
        "raise AssertionError('fake interpreter should intercept')\n"
    )

    broken = repo / ".venv" / "bin" / "python"
    broken.parent.mkdir(parents=True)
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)

    marker = tmp_path / "selected.txt"
    capable = repo / "venv" / "bin" / "python"
    capable.parent.mkdir(parents=True)
    capable.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = -c ]; then exit 0; fi\n"
        f"printf capable > {str(marker)!r}\n"
    )
    capable.chmod(0o755)

    proc = subprocess.run(
        [str(runner)],
        cwd=repo,
        capture_output=True,
        text=True,
        env={"HOME": str(tmp_path), "PATH": os.environ["PATH"]},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert marker.read_text() == "capable"

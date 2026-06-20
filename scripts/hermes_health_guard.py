#!/usr/bin/env python3
"""Lightweight local health guard for Hermes rescue invariants.

This script is intentionally read-only: it does not start, stop, or repair
services. It records whether the gateway and Kanban invariants are healthy so
operators can tell when drift or adapter trouble returns.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes"))).expanduser()
REPO = Path(os.environ.get("HERMES_REPO", str(HOME / "hermes-agent"))).expanduser()
PYTHON = Path(os.environ.get("HERMES_PYTHON", str(REPO / "venv" / "bin" / "python"))).expanduser()
BASE = HOME / "monitoring" / "hermes_health"
STATE_PATH = BASE / "state.json"
HISTORY_PATH = BASE / "history.jsonl"
HTML_PATH = BASE / "index.html"
LOG_PATH = HOME / "logs" / "hermes_health_guard.log"
LOG_MAX_BYTES = int(os.environ.get("HERMES_HEALTH_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
LAUNCHD_LOG_PATHS = [
    Path(os.environ.get("HERMES_HEALTH_LAUNCHD_STDOUT_PATH", str(HOME / "logs" / "hermes_health_guard.launchd.log"))),
    Path(os.environ.get("HERMES_HEALTH_LAUNCHD_STDERR_PATH", str(HOME / "logs" / "hermes_health_guard.launchd.err"))),
]
NOTIFY_STATE_PATH = BASE / "notify_state.json"
KANBAN_FLOW_STATE_PATH = BASE / "kanban_flow_state.json"
NOTIFY_WEBHOOK_URL = os.environ.get(
    "HERMES_HEALTH_WEBHOOK_URL", "http://127.0.0.1:8648/webhooks/health-guard"
)
NOTIFY_WEBHOOK_NAME = NOTIFY_WEBHOOK_URL.rstrip("/").rsplit("/", 1)[-1]

DEFAULT_EXPECTED_PROFILES = (
    "codex-coding",
    "financial",
    "home-assistant",
    "job-medical",
    "nas-ops",
)
BAD_PLATFORM_STATES = {"fatal", "paused", "retrying", "disconnected"}

# Minimum delay between the latest git HEAD commit time and a gateway's process
# start time before the gateway is flagged as stale (running pre-update code).
# The 30-minute threshold gives the nightly updater (03:31) time to complete
# before alerting, while catching the incident pattern where profile gateways
# ran stale code for 10+ hours after the checkout advanced.
STALENESS_THRESHOLD_MINUTES = 30

# Non-gateway listeners that must stay up; gateway ports are covered via
# each profile's gateway_state.json instead.
CRITICAL_LISTENERS = {"delivery-pubsub-push-adapter": 8663}
BACKUP_LOG = HOME / "logs" / "home-backup.log"
BACKUP_MAX_AGE_HOURS = float(os.environ.get("HERMES_BACKUP_MAX_AGE_HOURS", "36"))

# launchd jobs (NOT hermes crons — the cron sweep can't see them) whose
# nonzero last exit must page: the nightly fork updater failing silently is
# how the M5 went stale for days before the 2026-06-10 review.
CRITICAL_LAUNCHD_JOBS = ("com.hermes.nightly-update-guarded",)

# Provider-health sentinel output (written by the "provider-health-sentinel"
# cron every 15 min). 40 min default = two missed ticks + slack.
PROVIDER_HEALTH_STATE_PATH = HOME / "state" / "provider-health-state.json"
PROVIDER_HEALTH_MAX_AGE_MIN = float(
    os.environ.get("HERMES_PROVIDER_HEALTH_MAX_AGE_MIN", "40.0")
)
PROVIDER_HEALTH_PAGE_STATES = {"down", "critical", "error"}
# Cap per-lane detail in failure lines — sentinel details can embed whole
# tracebacks/HTTP bodies and huge alert strings drown the pager.
PROVIDER_HEALTH_DETAIL_MAX_CHARS = 160

# Managed-layer drift: an uncommitted path in the ~/.hermes git overlay older
# than this survived the 04:15 nightly autocommit, so the autocommit is
# aborting or failing.
MANAGED_DRIFT_MAX_AGE_H = float(os.environ.get("HERMES_MANAGED_DRIFT_MAX_AGE_H", "30.0"))
KANBAN_ZERO_RUNNABLE_HOURS = float(os.environ.get("HERMES_KANBAN_ZERO_RUNNABLE_HOURS", "24.0"))
KANBAN_BLOCKED_BACKLOG_THRESHOLD = int(os.environ.get("HERMES_KANBAN_BLOCKED_BACKLOG_THRESHOLD", "20"))
KANBAN_RUNNABLE_STATUSES = {"triage", "todo", "ready", "running"}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _run(cmd: list[str], *, timeout: float = 20.0) -> dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "cmd": cmd,
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "ok": False,
            "returncode": None,
            "stdout": (exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
            "stderr": f"timeout after {timeout:.0f}s",
        }
    except OSError as exc:
        return {
            "cmd": cmd,
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }


def _parse_json_output(result: dict[str, Any]) -> Any:
    try:
        return json.loads(result.get("stdout") or "")
    except json.JSONDecodeError:
        return None


def _pid_alive(pid: Any) -> bool:
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    try:
        os.kill(value, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _profile_names() -> list[str]:
    configured = os.environ.get("HERMES_HEALTH_PROFILES", "").strip()
    if configured:
        return [p.strip() for p in configured.split(",") if p.strip() and p.strip() != "default"]

    profiles_dir = HOME / "profiles"
    names = [
        p.name
        for p in profiles_dir.iterdir()
        if p.is_dir() and p.name != "default"
    ] if profiles_dir.exists() else []
    found = set(names)
    ordered = [name for name in DEFAULT_EXPECTED_PROFILES if name in found]
    ordered.extend(sorted(found - set(ordered)))
    return ordered


def _profile_home(profile: str | None) -> Path:
    if not profile or profile == "default":
        return HOME
    return HOME / "profiles" / profile


def _hermes_cmd(profile: str | None, *args: str) -> list[str]:
    cmd = [str(PYTHON), "-m", "hermes_cli.main"]
    if profile and profile != "default":
        cmd.extend(["--profile", profile])
    cmd.extend(args)
    return cmd


def _ensure_venv_python() -> None:
    """Re-exec script runs under the Hermes venv when launched directly.

    The LaunchAgent already points at ``venv/bin/python``, but manual runs or
    stale plists can hit macOS/system Python where optional runtime deps such
    as PyYAML are absent.  Re-execing the script (not import-time) keeps unit
    tests safe while making direct/launchd execution use the dependency set
    Hermes itself runs with.
    """
    if os.environ.get("HERMES_HEALTH_GUARD_REEXECED") == "1":
        return
    try:
        desired = PYTHON.expanduser().resolve()
        current = Path(sys.executable).expanduser().resolve()
    except OSError:
        return
    if not desired.exists() or current == desired:
        return
    env = os.environ.copy()
    env["HERMES_HEALTH_GUARD_REEXECED"] = "1"
    os.execve(str(desired), [str(desired), str(Path(__file__).resolve()), *sys.argv[1:]], env)


def _check_kanban_preflight(profile: str | None) -> dict[str, Any]:
    label = profile or "default"
    result = _run(_hermes_cmd(profile, "kanban", "preflight", "--json"), timeout=30)
    payload = _parse_json_output(result)
    ok = bool(result["ok"] and isinstance(payload, dict) and payload.get("ok") is True)
    missing = payload.get("missing") if isinstance(payload, dict) else None
    return {
        "profile": label,
        "ok": ok,
        "missing": missing or [],
        "checked_tasks": payload.get("checked_tasks") if isinstance(payload, dict) else None,
        "error": None if ok else (result.get("stderr") or result.get("stdout") or "invalid preflight output"),
    }


def _load_runtime_state(profile: str | None) -> dict[str, Any] | None:
    path = _profile_home(profile) / "gateway_state.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _disabled_platforms(profile: str | None) -> set[str]:
    """Platforms explicitly disabled in the profile's config.yaml.

    A gateway may still report a disabled platform (e.g. webhook with
    enabled: false) as "disconnected"; that is not a failure.
    """
    config_path = _profile_home(profile) / "config.yaml"
    try:
        import yaml  # available in the hermes venv

        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return set()
    platforms = config.get("platforms")
    if not isinstance(platforms, dict):
        return set()
    return {
        name
        for name, pconf in platforms.items()
        if isinstance(pconf, dict) and pconf.get("enabled") is False
    }


def _launchd_service_pid(profile: str | None) -> int | None:
    """Live pid from launchd for the profile's gateway service, or None."""
    label = "ai.hermes.gateway" if not profile or profile == "default" else f"ai.hermes.gateway-{profile}"
    result = _run(["launchctl", "print", f"gui/{os.getuid()}/{label}"], timeout=10)
    if not result["ok"]:
        return None
    m = re.search(r"^\s*pid = (\d+)", result["stdout"], re.MULTILINE)
    return int(m.group(1)) if m else None


def _check_gateway_state(profile: str | None) -> dict[str, Any]:
    label = profile or "default"
    state = _load_runtime_state(profile)
    if not state:
        return {
            "profile": label,
            "ok": False,
            "pid": None,
            "gateway_state": "missing",
            "platforms": {},
            "errors": ["gateway_state.json missing or invalid"],
        }

    errors: list[str] = []
    notes: list[str] = []
    pid = state.get("pid")
    gateway_state = state.get("gateway_state")
    if gateway_state not in {"running", "degraded"}:
        errors.append(f"gateway_state={gateway_state or 'unknown'}")
    if not _pid_alive(pid):
        # gateway_state.json is only rewritten on platform events, so after a
        # restart it can hold a dead pid for hours (hit twice on 2026-06-10).
        # launchd is the source of truth: if the service's launchd pid is
        # alive, the gateway is up and only the state file is stale.
        launchd_pid = _launchd_service_pid(profile)
        if launchd_pid and _pid_alive(launchd_pid):
            notes.append(
                f"state-file pid {pid} stale; launchd pid {launchd_pid} alive"
            )
        else:
            errors.append(f"pid {pid or 'missing'} is not alive")

    disabled = _disabled_platforms(profile)
    skipped: list[str] = []
    platforms = state.get("platforms") or {}
    if isinstance(platforms, dict):
        for platform, pdata in sorted(platforms.items()):
            if platform in disabled:
                skipped.append(platform)
                continue
            if not isinstance(pdata, dict):
                errors.append(f"{platform}: invalid platform state")
                continue
            platform_state = str(pdata.get("state") or "unknown")
            if platform_state in BAD_PLATFORM_STATES:
                detail = pdata.get("error_message") or pdata.get("error_code") or platform_state
                errors.append(f"{platform}: {platform_state} ({detail})")
    else:
        platforms = {}
        errors.append("platforms field is invalid")

    return {
        "profile": label,
        "ok": not errors,
        "pid": pid,
        "gateway_state": gateway_state,
        "platforms": platforms,
        "skipped_disabled": skipped,
        "notes": notes,
        "updated_at": state.get("updated_at"),
        "errors": errors,
    }


def _check_listener(name: str, port: int) -> dict[str, Any]:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            return {"name": name, "port": port, "ok": True, "error": None}
    except OSError as exc:
        return {"name": name, "port": port, "ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _check_cron_failures(profiles: list[str]) -> list[str]:
    """One failure line per enabled, unpaused cron job whose latest run errored.

    This is what catches a daily no_agent script that starts exiting
    nonzero — previously invisible unless a human read jobs.json.
    """
    failures: list[str] = []
    paths = [(None, HOME / "cron" / "jobs.json")]
    paths += [(p, HOME / "profiles" / p / "cron" / "jobs.json") for p in profiles]
    for profile, path in paths:
        label = profile or "default"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue  # profile without cron jobs is normal
        jobs = data.get("jobs") if isinstance(data, dict) else data
        for job in jobs or []:
            if not isinstance(job, dict):
                continue
            if not job.get("enabled", True) or job.get("paused_at"):
                continue
            if job.get("last_status") == "error":
                name = job.get("name") or job.get("id") or "?"
                detail = job.get("last_error") or "error"
                failures.append(f"cron job failing for {label}: {name}: {detail}")
    return failures


def _check_launchd_jobs() -> list[str]:
    """One failure line per critical launchd job whose last run exited nonzero."""
    failures: list[str] = []
    for job in CRITICAL_LAUNCHD_JOBS:
        result = _run(["launchctl", "print", f"gui/{os.getuid()}/{job}"], timeout=10)
        if not result["ok"]:
            failures.append(f"launchd job missing: {job}")
            continue
        m = re.search(r"last exit code = (-?\d+)", result["stdout"])
        if m and m.group(1) not in ("0",):
            failures.append(f"launchd job failed: {job} (last exit {m.group(1)})")
    return failures


def _provider_sentinel_registered() -> bool:
    """True when an enabled, unpaused "provider-health-sentinel" cron exists.

    Portability guard: clones of this home (e.g. the m5max) carry this
    script but not the sentinel cron — they must never page about a state
    file the sentinel was never going to write.
    """
    path = HOME / "cron" / "jobs.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    jobs = data.get("jobs") if isinstance(data, dict) else data
    for job in jobs or []:
        if not isinstance(job, dict):
            continue
        if not job.get("enabled", True) or job.get("paused_at"):
            continue
        if job.get("name") == "provider-health-sentinel":
            return True
    return False


def _load_provider_health_state() -> dict[str, Any] | None:
    try:
        data = json.loads(PROVIDER_HEALTH_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _provider_health_summary() -> dict[str, str]:
    """Compact {lane: status} map for the payload ({} when not applicable)."""
    if not _provider_sentinel_registered():
        return {}
    state = _load_provider_health_state()
    lanes = state.get("lanes") if state else None
    if not isinstance(lanes, dict):
        return {}
    summary: dict[str, str] = {}
    for lane, ldata in sorted(lanes.items()):
        status = ldata.get("status") if isinstance(ldata, dict) else None
        summary[str(lane)] = str(status or "unknown")
    return summary


def _check_provider_health() -> list[str]:
    """Page when the provider-health sentinel reports a bad lane or goes dark.

    Lanes may include per-profile keys like "codex-provider@radulator" —
    they are treated as ordinary lanes. "warn"/"degraded" lanes do NOT page.
    """
    if not _provider_sentinel_registered():
        return []
    state = _load_provider_health_state()
    if state is None:
        return [
            "provider-health: state file missing/unreadable "
            "(sentinel cron registered but no output)"
        ]

    updated: datetime | None = None
    if isinstance(state.get("updated"), str):
        try:
            updated = datetime.fromisoformat(state["updated"])
        except ValueError:
            updated = None
    if updated is None:
        # No usable timestamp: indistinguishable from no output at all.
        return [
            "provider-health: state file missing/unreadable "
            "(sentinel cron registered but no output)"
        ]

    failures: list[str] = []
    now = datetime.now(updated.tzinfo) if updated.tzinfo else datetime.now()
    age_min = (now - updated).total_seconds() / 60.0
    if age_min > PROVIDER_HEALTH_MAX_AGE_MIN:
        failures.append(
            f"provider-health: state stale ({age_min:.0f} min old; sentinel dead?)"
        )

    lanes = state.get("lanes")
    if isinstance(lanes, dict):
        for lane, ldata in sorted(lanes.items()):
            if not isinstance(ldata, dict):
                continue
            status = str(ldata.get("status") or "unknown").lower()
            if status not in PROVIDER_HEALTH_PAGE_STATES:
                continue
            detail = str(ldata.get("detail") or status)
            if len(detail) > PROVIDER_HEALTH_DETAIL_MAX_CHARS:
                detail = detail[:PROVIDER_HEALTH_DETAIL_MAX_CHARS]
            failures.append(f"provider-health: lane {lane} {status}: {detail}")
    return failures


def _check_managed_layer_drift() -> list[str]:
    """Page when uncommitted ~/.hermes paths survive the nightly autocommit.

    The 04:15 autocommit should sweep the managed layer daily; a dirty path
    older than MANAGED_DRIFT_MAX_AGE_H hours means the autocommit aborted or
    is failing. One consolidated failure line — never one per path.
    """
    if not (HOME / ".git").exists():
        return []
    result = _run(["git", "-C", str(HOME), "status", "--porcelain", "--untracked-files=all"])
    if not result["ok"]:
        return []
    cutoff = time.time() - MANAGED_DRIFT_MAX_AGE_H * 3600.0
    old_paths: list[str] = []
    for line in (result["stdout"] or "").splitlines():
        # Porcelain v1: two status chars, a space, then the path. _run strips
        # the whole stdout, which can eat the first line's leading space —
        # fall back to splitting on the first space in that case.
        if len(line) >= 4 and line[2] == " ":
            rel = line[3:]
        elif " " in line:
            rel = line.split(" ", 1)[1]
        else:
            continue
        if " -> " in rel:  # rename: page on the new path
            rel = rel.split(" -> ", 1)[1]
        rel = rel.strip().strip('"')
        try:
            mtime = (HOME / rel).stat().st_mtime
        except OSError:
            continue  # path no longer exists — nothing to age-check
        if mtime < cutoff:
            old_paths.append(rel)
    if not old_paths:
        return []
    shown = ", ".join(old_paths[:5])
    return [
        f"managed-layer drift: {len(old_paths)} uncommitted path(s) older than "
        f"{MANAGED_DRIFT_MAX_AGE_H:g}h (autocommit aborted/failing?): {shown}"
    ]


def _check_backup_freshness() -> list[str]:
    """Alert when the nightly ~/.hermes -> NAS mirror hasn't succeeded lately."""
    try:
        text = BACKUP_LOG.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [f"home-backup log missing ({BACKUP_LOG})"]
    last: str | None = None
    for m in re.finditer(
        r"=== finished (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) rsync_rc=0/0 ===", text
    ):
        last = m.group(1)
    if last is None:
        return ["home-backup has never succeeded (no rsync_rc=0/0 in log)"]
    age = datetime.now() - datetime.strptime(last, "%Y-%m-%d %H:%M:%S")
    if age > timedelta(hours=BACKUP_MAX_AGE_HOURS):
        hours = age.total_seconds() / 3600
        return [f"home-backup stale: last success {last} ({hours:.0f}h ago)"]
    return []


def _check_hindsight_config(profile: str | None) -> list[str]:
    """Validate hindsight config for a single profile.

    Checks (only for profiles with memory.provider=hindsight):
      1. $HERMES_HOME/hindsight/config.json exists.
      2. api_url points at the NAS service.
      3. recall_types is observation-only by default for precise state recall.
      4. The configured bank_id appears in the NAS banks listing.

    Returns a list of failure strings (empty = all good).
    """
    from importlib import import_module

    label = profile or "default"
    home = _profile_home(profile)
    config_path = home / "config.yaml"
    failures: list[str] = []

    # --- read config.yaml to determine memory provider ---
    try:
        yaml = import_module("yaml")
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        return [f"hindsight [{label}]: cannot read config.yaml: {exc}"]

    memory = config.get("memory", {})
    if not isinstance(memory, dict) or memory.get("provider") != "hindsight":
        return []  # not using hindsight; skip

    # --- check 1: config.json exists ---
    hc_path = home / "hindsight" / "config.json"
    if not hc_path.exists():
        return [f"hindsight [{label}]: hindsight/config.json missing"]

    try:
        hc = json.loads(hc_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"hindsight [{label}]: hindsight/config.json unreadable: {exc}"]

    # --- check 2: api_url points at NAS ---
    api_url = hc.get("api_url", "")
    if not isinstance(api_url, str) or not api_url.strip():
        failures.append(f"hindsight [{label}]: api_url is empty or not a string")
    elif "truenas-scale.tail1339c4.ts.net:8890" not in api_url and "100.113.37.78:8890" not in api_url:
        # Check if the host portion looks like the NAS; allow trailing slashes
        failures.append(f"hindsight [{label}]: api_url={api_url} does not point at NAS service")

    # --- check 3: recall_types ---
    recall_types = hc.get("recall_types")
    if recall_types is None:
        # Provider default is observation-only; absent key is acceptable and
        # keeps state/current-status recalls free of raw experience metadata.
        pass
    elif not isinstance(recall_types, list):
        failures.append(f"hindsight [{label}]: recall_types is not a list")
    elif recall_types != ["observation"]:
        failures.append(
            f"hindsight [{label}]: recall_types={recall_types} should be ['observation'] "
            "for default state recall; use per-call types/tags for broad history searches"
        )

    # --- check 4: bank reachability ---
    bank_id = hc.get("bank_id", "")
    if not bank_id:
        failures.append(f"hindsight [{label}]: bank_id is empty in config")
    elif api_url:
        base = api_url.rstrip("/")
        # Try primary hostname, fallback to Tailscale IP if the URL uses hostname
        hosts_to_try = [base]
        if "truenas-scale.tail1339c4.ts.net:8890" in base:
            hosts_to_try.append(base.replace("truenas-scale.tail1339c4.ts.net:8890", "100.113.37.78:8890"))

        bank_found = False
        last_exc = None
        for url in hosts_to_try:
            try:
                req = urllib.request.Request(f"{url}/v1/default/banks")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    banks_data = data if isinstance(data, dict) else {"banks": data if isinstance(data, list) else []}
                    banks_list = banks_data.get("banks") or []
                    if any(b.get("bank_id") == bank_id for b in banks_list if isinstance(b, dict)):
                        bank_found = True
                        break
                    # bank not found — collect the list for the error message
                    actual_ids = [b.get("bank_id") for b in banks_list if isinstance(b, dict)]
                    last_exc = f"bank '{bank_id}' not found in NAS banks: {actual_ids}"
            except Exception as exc:
                last_exc = f"bank reachability check failed: {exc}"

        if not bank_found and last_exc:
            failures.append(f"hindsight [{label}]: {last_exc}")

    return failures


def _check_hindsight_configs(profiles: list[str]) -> list[str]:
    """Aggregate hindsight config failures across all profiles (incl. default)."""
    failures: list[str] = []
    for profile in [None, *profiles]:
        failures.extend(_check_hindsight_config(profile))
    return failures


def _check_gateway_staleness(profiles: list[str]) -> list[str]:
    """Detect profile gateways running pre-update code.

    Compares each gateway's process start time against the git HEAD commit
    timestamp.  If the HEAD is newer than the gateway's start time by more
    than STALENESS_THRESHOLD_MINUTES, the gateway is considered stale (it
    was started before the latest code update and was never restarted).

    Returns a list of human-readable failure strings (empty = all current).
    """
    failures: list[str] = []

    # Read HEAD commit timestamp as Unix epoch (seconds since 1970) —
    # avoids timezone math entirely.
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        head_epoch = int(result.stdout.strip())
        head_dt = datetime.fromtimestamp(head_epoch)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        failures.append(f"staleness: cannot read HEAD commit time from git: {exc}")
        return failures

    for profile in [None, *profiles]:
        label = profile or "default"
        pid = _launchd_service_pid(profile)
        if pid is None:
            continue

        # Get process start time as Unix epoch via `ps -o etime`
        try:
            ps_result = subprocess.run(
                ["ps", "-o", "lstart=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if ps_result.returncode != 0:
                continue
            lstart = (ps_result.stdout or "").strip()
            if not lstart:
                continue
            # Format: "Thu Jun 11 18:51:18 2026" (local time)
            proc_local = datetime.strptime(lstart, "%a %b %d %H:%M:%S %Y")
            # Convert local → epoch via mktime (respects DST)
            proc_epoch = time.mktime(proc_local.timetuple())
            proc_dt = datetime.fromtimestamp(proc_epoch)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue

        # Staleness condition: HEAD commit is newer than process start + threshold
        gap = (head_dt - proc_dt).total_seconds()
        gap_minutes = gap / 60.0

        if gap_minutes > STALENESS_THRESHOLD_MINUTES:
            failures.append(
                f"gateway stale for {label}: "
                f"process started {proc_dt.strftime('%b %d %H:%M')} "
                f"(~{gap_minutes:.0f} min before HEAD commit "
                f"{datetime.fromtimestamp(head_epoch).strftime('%Y-%m-%d %H:%M')}), "
                f"restart required to pick up new code"
            )
        elif gap_minutes > 0:
            # Gateway started before latest commit but within the threshold —
            # informational, not a failure.  The nightly updater may still be
            # running or about to kickstart gateways.
            pass

    return failures


def _check_kanban_flow() -> dict[str, Any]:
    """Detect a starved Kanban board: blocked backlog but no runnable work."""
    result = _run(_hermes_cmd(None, "kanban", "stats", "--json"), timeout=30)
    payload = _parse_json_output(result)
    if not result["ok"] or not isinstance(payload, dict):
        return {
            "ok": False,
            "failures": [f"kanban flow stats failed: {result.get('stderr') or result.get('stdout') or 'invalid stats output'}"],
            "by_status": {},
        }

    by_status = payload.get("by_status") if isinstance(payload.get("by_status"), dict) else {}
    runnable = sum(int(by_status.get(status) or 0) for status in KANBAN_RUNNABLE_STATUSES)
    blocked = int(by_status.get("blocked") or 0)
    now_ts = time.time()

    try:
        state = json.loads(KANBAN_FLOW_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        state = {}
    if not isinstance(state, dict):
        state = {}

    active = runnable == 0 and blocked >= KANBAN_BLOCKED_BACKLOG_THRESHOLD
    if active:
        first_seen = float(state.get("zero_runnable_since") or now_ts)
    else:
        first_seen = None

    next_state = {
        "updated_at": _now(),
        "zero_runnable_since": first_seen,
        "runnable": runnable,
        "blocked": blocked,
        "by_status": by_status,
    }
    KANBAN_FLOW_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = KANBAN_FLOW_STATE_PATH.with_suffix(KANBAN_FLOW_STATE_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(next_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(KANBAN_FLOW_STATE_PATH)

    failures: list[str] = []
    if active and first_seen is not None:
        age_hours = (now_ts - first_seen) / 3600.0
        if age_hours >= KANBAN_ZERO_RUNNABLE_HOURS:
            failures.append(
                "kanban flow starved: "
                f"0 runnable tasks for {age_hours:.1f}h while {blocked} task(s) remain blocked"
            )

    return {
        "ok": not failures,
        "failures": failures,
        "by_status": by_status,
        "runnable": runnable,
        "blocked": blocked,
        "zero_runnable_since": first_seen,
    }


def collect_health() -> dict[str, Any]:
    profiles = _profile_names()
    preflight_profiles = [None, *profiles]
    gateway_profiles = [None, *profiles]
    preflights = [_check_kanban_preflight(profile) for profile in preflight_profiles]
    gateways = [_check_gateway_state(profile) for profile in gateway_profiles]
    listeners = [_check_listener(name, port) for name, port in sorted(CRITICAL_LISTENERS.items())]
    kanban_flow = _check_kanban_flow()
    failures: list[str] = []

    for item in preflights:
        if not item["ok"]:
            failures.append(f"kanban preflight failed for {item['profile']}: {item['error']}")
    for item in gateways:
        if not item["ok"]:
            failures.append(f"gateway unhealthy for {item['profile']}: {'; '.join(item['errors'])}")
    for item in listeners:
        if not item["ok"]:
            failures.append(f"listener down: {item['name']} (127.0.0.1:{item['port']}): {item['error']}")
    failures.extend(kanban_flow.get("failures") or [])
    failures.extend(_check_cron_failures(profiles))
    failures.extend(_check_backup_freshness())
    failures.extend(_check_launchd_jobs())
    failures.extend(_check_provider_health())
    failures.extend(_check_managed_layer_drift())
    failures.extend(_check_gateway_staleness(profiles))
    hindsight_failures = _check_hindsight_configs(profiles)
    # Consolidate bank-reachability failures when the root cause is shared
    # (e.g. NAS service down — don't spam 7 identical lines).
    bank_conn_failures = [f for f in hindsight_failures if "bank reachability check failed" in f]
    other_hindsight_failures = [f for f in hindsight_failures if "bank reachability check failed" not in f]
    failures.extend(other_hindsight_failures)
    if bank_conn_failures:
        # Extract unique profile names from failure strings like
        # "hindsight [codex-coding]: bank reachability check failed: ..."
        profiles_with_bank_fail: set[str] = set()
        for f in bank_conn_failures:
            match = re.search(r"hindsight \[([^\]]+)\]", f)
            if match:
                profiles_with_bank_fail.add(match.group(1))
        sorted_profiles = sorted(profiles_with_bank_fail, key=str)
        failures.append(
            f"hindsight bank unreachable for {len(sorted_profiles)} profile(s) "
            f"({', '.join(sorted_profiles)}): "
            f"NAS service unreachable on port 8890 (tailscale-down?)"
        )

    level = "ok" if not failures else "critical"
    return {
        "timestamp": _now(),
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "level": level,
        "ok": level == "ok",
        "failures": failures,
        "preflights": preflights,
        "gateways": gateways,
        "listeners": listeners,
        "kanban_flow": kanban_flow,
        "provider_health": _provider_health_summary(),
        "hindsight_checks": _check_hindsight_configs(profiles),
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _append_history(payload: dict[str, Any]) -> None:
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "timestamp": payload["timestamp"],
            "level": payload["level"],
            "failures": payload["failures"],
        }, sort_keys=True) + "\n")


def _html_table(rows: list[dict[str, Any]], kind: str) -> str:
    body = []
    for row in rows:
        status = "OK" if row.get("ok") else "FAIL"
        if kind == "gateway":
            detail = "; ".join(row.get("errors") or []) or f"pid={row.get('pid')}, state={row.get('gateway_state')}"
        else:
            detail = "; ".join(row.get("missing") or []) or f"checked_tasks={row.get('checked_tasks')}"
        body.append(
            "<tr>"
            f"<td>{html.escape(str(row.get('profile')))}</td>"
            f"<td>{status}</td>"
            f"<td>{html.escape(detail)}</td>"
            "</tr>"
        )
    return "\n".join(body)


def _hindsight_table(checks: list[str]) -> str:
    if not checks:
        return "<small>no failures</small>"
    lines = "<br>".join(html.escape(f) for f in checks)
    return f"<pre style=\"color:#e8edf7;margin:0;font-size:12px\">{lines}</pre>"


def _write_html(payload: dict[str, Any]) -> None:
    level = payload["level"].upper()
    failures = payload.get("failures") or ["No active failures."]
    fail_html = "<br>".join(html.escape(str(item)) for item in failures)
    hindsight_checks = payload.get("hindsight_checks") or []
    doc = f"""<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="60">
<title>Hermes Health Guard</title>
<style>
body{{font:14px -apple-system,BlinkMacSystemFont,sans-serif;background:#0b1020;color:#e8edf7;margin:24px}}
.card{{background:#151b2e;border:1px solid #28324d;border-radius:10px;padding:16px;margin:12px 0}}
.pill{{display:inline-block;border-radius:999px;padding:4px 10px;font-weight:700;background:{'#0b7' if payload['ok'] else '#b30'};color:white}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #2b3552;padding:7px;text-align:left;vertical-align:top}}
code,small{{color:#b9d7ff}}
</style>
<h1>Hermes Health Guard</h1>
<div class="card"><span class="pill">{level}</span> <b>Updated:</b> {html.escape(payload["timestamp"])}</div>
<div class="card"><b>Failures:</b><br>{fail_html}</div>
<div class="card"><h2>Hindsight Config</h2>{_hindsight_table(hindsight_checks)}</div>
<div class="card"><h2>Gateway State</h2><table><tr><th>Profile</th><th>Status</th><th>Detail</th></tr>{_html_table(payload["gateways"], "gateway")}</table></div>
<div class="card"><h2>Kanban Preflight</h2><table><tr><th>Profile</th><th>Status</th><th>Detail</th></tr>{_html_table(payload["preflights"], "preflight")}</table></div>
<div class="card"><small>JSON: {html.escape(str(STATE_PATH))}<br>History: {html.escape(str(HISTORY_PATH))}<br>LaunchAgent label: ai.hermes.health-guard</small></div>
"""
    HTML_PATH.parent.mkdir(parents=True, exist_ok=True)
    HTML_PATH.write_text(doc, encoding="utf-8")


def _notify_secret() -> str | None:
    try:
        subs = json.loads((HOME / "webhook_subscriptions.json").read_text(encoding="utf-8"))
        return subs[NOTIFY_WEBHOOK_NAME]["secret"]
    except Exception:
        return None


def _post_alert(alert_text: str, level: str) -> bool:
    secret = _notify_secret()
    if secret is None:
        return False
    body = json.dumps({
        "source": "health-guard",
        "ts": _now(),
        "level": level,
        "alert_text": alert_text,
    }).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(NOTIFY_WEBHOOK_URL, data=body, headers={
        "Content-Type": "application/json",
        "X-Hub-Signature-256": sig,
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except OSError:
        return False


def _notify_if_changed(payload: dict[str, Any]) -> None:
    """Deliver one alert per state change (deliver-only route, zero LLM).

    Silent while the failure set is unchanged; failed deliveries leave
    notify_state untouched so the next 300s tick retries.
    """
    try:
        prev = json.loads(NOTIFY_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        prev = None
    current = {"level": payload["level"], "failures": sorted(payload["failures"])}
    if prev is not None and prev == current:
        return
    if payload["ok"]:
        if prev is None or prev.get("level") == "ok":
            _write_json(NOTIFY_STATE_PATH, current)
            return
        alert_text = "✅ Hermes health guard: all clear (recovered from: " + \
            "; ".join(prev.get("failures") or ["unknown"]) + ")"
    else:
        lines = "\n".join(f"- {f}" for f in current["failures"])
        alert_text = f"🚨 Hermes health guard: {len(current['failures'])} failure(s)\n{lines}"
    if _post_alert(alert_text, payload["level"]):
        _write_json(NOTIFY_STATE_PATH, current)


def _rotate_if_large(path: Path, max_bytes: int = LOG_MAX_BYTES) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size < max_bytes:
        return
    rotated = path.with_suffix(path.suffix + ".1")
    try:
        rotated.unlink(missing_ok=True)
        path.replace(rotated)
    except OSError:
        pass


def _previous_state() -> dict[str, Any] | None:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _same_failure_set(previous: dict[str, Any] | None, payload: dict[str, Any]) -> bool:
    if not previous:
        return False
    return (
        previous.get("level") == payload.get("level")
        and sorted(previous.get("failures") or []) == sorted(payload.get("failures") or [])
    )


def main() -> int:
    previous = _previous_state()
    payload = collect_health()
    unchanged = _same_failure_set(previous, payload)
    _write_json(STATE_PATH, payload)
    _append_history(payload)
    _write_html(payload)
    _notify_if_changed(payload)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _rotate_if_large(LOG_PATH)
    for path in LAUNCHD_LOG_PATHS:
        _rotate_if_large(path)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        suffix = " unchanged" if unchanged and payload["failures"] else ""
        fh.write(f"{payload['timestamp']} {payload['level']} failures={len(payload['failures'])}{suffix}\n")
        if not unchanged:
            for failure in payload["failures"]:
                fh.write(f"  {failure}\n")
    if payload["ok"]:
        print(f"OK Hermes health guard: {STATE_PATH}")
        return 0
    print(f"FAIL Hermes health guard: {STATE_PATH}", file=sys.stderr)
    if unchanged:
        print("- failure set unchanged; see state.json/html for details", file=sys.stderr)
    else:
        for failure in payload["failures"]:
            print(f"- {failure}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    _ensure_venv_python()
    raise SystemExit(main())

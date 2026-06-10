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
import subprocess
import sys
import urllib.request
from datetime import datetime
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
NOTIFY_STATE_PATH = BASE / "notify_state.json"
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
        return [p.strip() for p in configured.split(",") if p.strip()]

    profiles_dir = HOME / "profiles"
    names = [p.name for p in profiles_dir.iterdir() if p.is_dir()] if profiles_dir.exists() else []
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
    pid = state.get("pid")
    gateway_state = state.get("gateway_state")
    if gateway_state not in {"running", "degraded"}:
        errors.append(f"gateway_state={gateway_state or 'unknown'}")
    if not _pid_alive(pid):
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
        "updated_at": state.get("updated_at"),
        "errors": errors,
    }


def collect_health() -> dict[str, Any]:
    profiles = _profile_names()
    preflight_profiles = [None, *profiles]
    gateway_profiles = [None, *profiles]
    preflights = [_check_kanban_preflight(profile) for profile in preflight_profiles]
    gateways = [_check_gateway_state(profile) for profile in gateway_profiles]
    failures: list[str] = []

    for item in preflights:
        if not item["ok"]:
            failures.append(f"kanban preflight failed for {item['profile']}: {item['error']}")
    for item in gateways:
        if not item["ok"]:
            failures.append(f"gateway unhealthy for {item['profile']}: {'; '.join(item['errors'])}")

    level = "ok" if not failures else "critical"
    return {
        "timestamp": _now(),
        "host": os.uname().nodename if hasattr(os, "uname") else "",
        "level": level,
        "ok": level == "ok",
        "failures": failures,
        "preflights": preflights,
        "gateways": gateways,
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


def _write_html(payload: dict[str, Any]) -> None:
    level = payload["level"].upper()
    failures = payload.get("failures") or ["No active failures."]
    fail_html = "<br>".join(html.escape(str(item)) for item in failures)
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


def main() -> int:
    payload = collect_health()
    _write_json(STATE_PATH, payload)
    _append_history(payload)
    _write_html(payload)
    _notify_if_changed(payload)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"{payload['timestamp']} {payload['level']} failures={len(payload['failures'])}\n")
        for failure in payload["failures"]:
            fh.write(f"  {failure}\n")
    if payload["ok"]:
        print(f"OK Hermes health guard: {STATE_PATH}")
        return 0
    print(f"FAIL Hermes health guard: {STATE_PATH}", file=sys.stderr)
    for failure in payload["failures"]:
        print(f"- {failure}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

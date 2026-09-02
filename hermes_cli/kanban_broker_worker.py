"""Model-identity reverse worker endpoint for the dedicated Kanban broker.

The listener runs as the unprivileged model account.  It accepts only the
kernel-authenticated broker UID, receives a broker-selected ``.git``-free
workspace, launches the normal Hermes worker under that same model identity,
and returns no authority-bearing data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable

from hermes_cli.kanban_broker_protocol import peer_uid, receive_frame, send_frame
from hermes_cli.kanban_dedicated_broker import KANBAN_BROKER_SECURITY_BOUNDARY


class WorkerServiceError(RuntimeError):
    """The reverse worker endpoint or sealed envelope was unsafe."""


GITHUB_DENIED_CREDENTIAL_POLICY = "github-denied-v1"
_PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_FORBIDDEN_HOME_SURFACES = (
    Path(".config/gh"),
    Path(".config/gh-copilot"),
    Path(".config/github-copilot"),
    Path(".copilot"),
    Path(".git-credentials"),
    Path(".gitconfig"),
    Path(".authinfo"),
    Path(".curlrc"),
    Path(".docker"),
    Path(".gnupg"),
    Path(".netrc"),
    Path(".npmrc"),
    Path(".ssh"),
    Path("Library/Application Support/gh"),
)
_CONFIG_KEY_RE = re.compile(
    r"^\s*(?:export\s+)?[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]"
)
_GITHUB_CREDENTIAL_MATERIAL_RE = re.compile(
    r"(?i)(?:github_pat_|gh[pousr]_|https?://[^/\s:@]+:[^@\s]+@github\.com)"
)


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise WorkerServiceError("dedicated worker requires a POSIX host")
    return int(getter())


def _is_github_credential_key(name: str) -> bool:
    normalized = str(name).strip().upper().replace("-", "_").replace(".", "_")
    return (
        normalized.startswith("GH_")
        or normalized.startswith("GITHUB_")
        or normalized.startswith("COPILOT_")
        or normalized
        in {
            "GIT_ASKPASS",
            "GIT_CREDENTIAL_HELPER",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "SSH_ASKPASS",
            "SSH_AUTH_SOCK",
        }
    )


def _require_private_owned_directory(path: Path, *, expected_owner_uid: int) -> Path:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise WorkerServiceError("worker credential home is unavailable") from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != int(expected_owner_uid)
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise WorkerServiceError("worker credential home is mutable or unsafe")
    return resolved


def _config_github_credential_finding(path: Path) -> str | None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise WorkerServiceError("worker credential configuration is not a real file")
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = _CONFIG_KEY_RE.match(line)
                if match is not None and _is_github_credential_key(match.group(1)):
                    return "key"
                if _GITHUB_CREDENTIAL_MATERIAL_RE.search(line) is not None:
                    return "material"
    except OSError as exc:
        raise WorkerServiceError("worker credential configuration is unreadable") from exc
    return None


def _path_contains_forbidden_credential_surface(path: Path, *, root: Path) -> bool:
    parts = path.relative_to(root).parts
    for forbidden in _FORBIDDEN_HOME_SURFACES:
        needle = forbidden.parts
        if any(
            tuple(parts[index : index + len(needle)]) == needle
            for index in range(len(parts) - len(needle) + 1)
        ):
            return True
    return False


def validate_worker_credential_home(
    worker_hermes_root: Path,
    *,
    profile: str | None,
    expected_owner_uid: int,
) -> dict[str, str]:
    """Prove the model identity has no GitHub, Git, or SSH credential surface."""

    root = _require_private_owned_directory(
        Path(worker_hermes_root), expected_owner_uid=expected_owner_uid
    )
    for relative in _FORBIDDEN_HOME_SURFACES:
        candidate = root / relative
        if candidate.exists() or candidate.is_symlink():
            raise WorkerServiceError("worker home contains credential authority")

    profile_home: Path | None = None
    if profile is not None:
        normalized = str(profile).strip().lower()
        if not _PROFILE_ID_RE.fullmatch(normalized) or normalized != profile:
            raise WorkerServiceError("sealed worker profile name is invalid")
        profiles_root = _require_private_owned_directory(
            root / "profiles", expected_owner_uid=expected_owner_uid
        )
        profile_home = _require_private_owned_directory(
            profiles_root / normalized, expected_owner_uid=expected_owner_uid
        )

    for candidate in root.rglob("*"):
        if _path_contains_forbidden_credential_surface(candidate, root=root):
            raise WorkerServiceError("worker home contains credential authority")
        try:
            info = candidate.lstat()
        except OSError as exc:
            raise WorkerServiceError("worker credential home changed during scan") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WorkerServiceError("worker credential home contains a symlink")
        if not stat.S_ISREG(info.st_mode):
            continue
        if candidate.name in {".env", ".op.env", "config.yaml", "config.yml"}:
            finding = _config_github_credential_finding(candidate)
            if finding == "key":
                raise WorkerServiceError(
                    "worker profile contains a GitHub credential key"
                )
            if finding == "material":
                raise WorkerServiceError(
                    "worker profile contains GitHub credential material"
                )
    return {
        "worker_hermes_root": str(root),
        "profile_home": str(profile_home) if profile_home is not None else "",
        "credential_policy": GITHUB_DENIED_CREDENTIAL_POLICY,
    }


def validate_worker_runtime(
    *,
    python_executable: Path,
    python_sha256: str,
    package_root: Path,
    package_manifest_sha256: str,
    expected_package_owner_uid: int = 0,
    expected_package_owner_gid: int | None = None,
    expected_python_owner_uid: int = 0,
    runtime_entrypoint_path: Path | None = None,
    runtime_entrypoint_sha256: str | None = None,
    runtime_manifest_path: Path | None = None,
    runtime_manifest_sha256: str | None = None,
) -> dict[str, str]:
    """Bind the model listener to the same immutable installed runtime."""

    from hermes_cli.kanban_broker_install import _read_sealed_file_bytes
    from hermes_cli.kanban_broker_install import _safe_file_sha256
    from hermes_cli.kanban_broker_install import _official_runtime_provenance
    from hermes_cli.kanban_broker_install import OFFICIAL_RUNTIME_ARCHIVE_SHA256
    from hermes_cli.kanban_broker_install import OFFICIAL_RUNTIME_VERSION
    from hermes_cli.kanban_broker_install import _verify_runtime_tree_against_manifest
    from hermes_cli.kanban_broker_install import runtime_package_manifest

    python = Path(python_executable)
    try:
        python_info = python.lstat()
    except OSError as exc:
        raise WorkerServiceError("worker Python runtime is unavailable") from exc
    if (
        stat.S_ISLNK(python_info.st_mode)
        or not stat.S_ISREG(python_info.st_mode)
        or python_info.st_uid != int(expected_python_owner_uid)
        or python_info.st_nlink != 1
        or stat.S_IMODE(python_info.st_mode) & 0o022
        or not stat.S_IMODE(python_info.st_mode) & 0o111
    ):
        raise WorkerServiceError("worker Python runtime is mutable or unsafe")
    try:
        digest = _safe_file_sha256(python)
    except (OSError, ValueError) as exc:
        raise WorkerServiceError("worker Python runtime could not be hashed safely") from exc
    if digest != python_sha256:
        raise WorkerServiceError("worker Python runtime digest changed")
    if runtime_entrypoint_path is not None:
        entrypoint = Path(runtime_entrypoint_path)
        runtime_root = python.parent.parent
        if (
            not entrypoint.is_absolute()
            or ".." in entrypoint.parts
            or entrypoint != runtime_root / "bin/hermes-python"
            or not isinstance(runtime_entrypoint_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", runtime_entrypoint_sha256) is None
        ):
            raise WorkerServiceError("worker runtime entrypoint binding is invalid")
        try:
            entry_info = entrypoint.lstat()
        except OSError as exc:
            raise WorkerServiceError("worker runtime entrypoint is unavailable") from exc
        if (
            stat.S_ISLNK(entry_info.st_mode)
            or not stat.S_ISREG(entry_info.st_mode)
            or entry_info.st_uid != int(expected_python_owner_uid)
            or entry_info.st_nlink != 1
            or stat.S_IMODE(entry_info.st_mode) != 0o555
        ):
            raise WorkerServiceError("worker runtime entrypoint is mutable or unsafe")
        try:
            entry_bytes, _entry_read_info = _read_sealed_file_bytes(
                entrypoint,
                max_bytes=4 * 1024 * 1024,
                expected_sha256=runtime_entrypoint_sha256,
            )
        except (OSError, ValueError) as exc:
            raise WorkerServiceError("worker runtime entrypoint changed during read") from exc
    root = Path(package_root).resolve(strict=True)
    if Path(__file__).resolve(strict=True).parent != root:
        raise WorkerServiceError("worker module is outside the installed package")
    manifest = runtime_package_manifest(
        root,
        expected_owner_uid=expected_package_owner_uid,
        expected_owner_gid=expected_package_owner_gid,
    )
    if manifest["sha256"] != package_manifest_sha256:
        raise WorkerServiceError("worker package manifest changed")
    if runtime_manifest_path is not None:
        if not isinstance(runtime_manifest_sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", runtime_manifest_sha256
        ) is None:
            raise WorkerServiceError("worker runtime manifest digest is invalid")
        manifest_path = Path(runtime_manifest_path)
        if not manifest_path.is_absolute() or ".." in manifest_path.parts:
            raise WorkerServiceError("worker runtime manifest path is invalid")
        try:
            raw, info = _read_sealed_file_bytes(
                manifest_path, max_bytes=4 * 1024 * 1024
            )
            if info.st_uid != int(expected_package_owner_uid) or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
                raise WorkerServiceError("worker runtime manifest ownership is unsafe")
        except (OSError, ValueError) as exc:
            raise WorkerServiceError("worker runtime manifest is unavailable") from exc
        try:
            runtime_manifest = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerServiceError("worker runtime manifest is invalid") from exc
        if (
            not isinstance(runtime_manifest, dict)
            or set(runtime_manifest)
            != {"contract", "schema_version", "runtime_root", "python_executable",
                "python_version", "provenance", "runtime_manifest_sha256", "entries"}
            or runtime_manifest.get("contract") != "hermes.kanban_broker_runtime_manifest.v1"
            or runtime_manifest.get("runtime_root") != str(python.parent.parent)
            or runtime_manifest.get("python_executable") != str(python)
            or runtime_manifest.get("python_version") != OFFICIAL_RUNTIME_VERSION
            or runtime_manifest.get("runtime_manifest_sha256") != runtime_manifest_sha256
            or runtime_manifest.get("provenance") != _official_runtime_provenance(
                sha256=OFFICIAL_RUNTIME_ARCHIVE_SHA256
            )
            or not isinstance(runtime_manifest.get("entries"), list)
        ):
            raise WorkerServiceError("worker runtime manifest fields are not exact")
        encoded = json.dumps(
            runtime_manifest["entries"], sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != runtime_manifest_sha256:
            raise WorkerServiceError("worker runtime manifest digest changed")
        _verify_runtime_tree_against_manifest(
            python.parent.parent,
            runtime_manifest["entries"],
            expected_owner_uid=expected_package_owner_uid,
            expected_owner_gid=0,
        )
    return {
        "python_executable": str(python),
        "python_sha256": digest,
        "package_root": str(root),
        "package_manifest_sha256": str(manifest["sha256"]),
        **(
            {"runtime_manifest_path": str(runtime_manifest_path),
             "runtime_manifest_sha256": str(runtime_manifest_sha256)}
            if runtime_manifest_path is not None else {}
        ),
    }


def _safe_worker_env(
    envelope: dict[str, Any], *, worker_hermes_root: Path
) -> dict[str, str]:
    task = envelope["task"]
    workspace = Path(envelope["workspace_path"])
    allowed_parent_names = {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "TZ",
    }
    env = {
        key: value
        for key, value in os.environ.items()
        if key in allowed_parent_names or key.startswith("LC_")
    }
    home = Path(worker_hermes_root)
    env.update({
        "HOME": str(home),
        "HERMES_HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_DATA_HOME": str(home / ".local/share"),
        "XDG_STATE_HOME": str(home / ".local/state"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "GNUPGHOME": str(home / ".gnupg"),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": os.devnull,
        "GIT_SSH_COMMAND": "/usr/bin/false",
        "HERMES_SESSION_SOURCE": "kanban",
        "HERMES_KANBAN_DEDICATED_BOUNDARY": KANBAN_BROKER_SECURITY_BOUNDARY,
        "HERMES_KANBAN_CREDENTIAL_POLICY": GITHUB_DENIED_CREDENTIAL_POLICY,
        "HERMES_KANBAN_TASK": str(envelope["task_id"]),
        "HERMES_KANBAN_RUN_ID": str(envelope["run_id"]),
        "HERMES_KANBAN_CLAIM_LOCK": (
            f"dedicated:{envelope['task_id']}:{envelope['run_id']}:{workspace.name}"
        ),
        "HERMES_KANBAN_WORKSPACE": str(workspace),
        "HERMES_KANBAN_WORKSPACES_ROOT": str(workspace.parent),
        "HERMES_KANBAN_BOARD": str(task["board"]),
        "HERMES_KANBAN_BRANCH": str(envelope["branch"]),
        "HERMES_KANBAN_PROJECT_ID": str(task.get("project_id") or ""),
        "TERMINAL_CWD": str(workspace),
        "HERMES_PROFILE": str(task["profile"]),
    })
    if task.get("goal_mode") is True:
        env["HERMES_KANBAN_GOAL_MODE"] = "1"
        env["HERMES_KANBAN_GOAL_MAX_TURNS"] = str(task["goal_max_turns"])
    return env


def _validated_envelope(value: Any, *, workspace_root: Path) -> dict[str, Any]:
    required = {
        "contract",
        "broker_boundary",
        "task_id",
        "run_id",
        "claim_generation",
        "workspace_id",
        "workspace_path",
        "repository_id",
        "branch",
        "base_branch",
        "base_sha",
        "target_base_sha",
        "task",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("contract") != "hermes.broker_reverse_worker_dispatch.v1"
        or value.get("broker_boundary") != KANBAN_BROKER_SECURITY_BOUNDARY
        or not isinstance(value.get("task"), dict)
    ):
        raise WorkerServiceError("broker worker envelope fields are not exact")
    root = Path(workspace_root).resolve(strict=True)
    workspace = Path(value["workspace_path"]).resolve(strict=True)
    if workspace.parent != root:
        raise WorkerServiceError("broker worker workspace is outside the sealed root")
    info = workspace.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise WorkerServiceError("broker worker workspace is not a real directory")
    if (workspace / ".git").exists() or (workspace / ".git").is_symlink():
        raise WorkerServiceError("broker worker workspace contains Git metadata")
    task = value["task"]
    if (
        task.get("task_id") != value["task_id"]
        or task.get("workspace_path") != value["workspace_path"]
        or task.get("workspace_id") != value["workspace_id"]
        or task.get("repository_id") != value["repository_id"]
        or task.get("branch_name") != value["branch"]
        or task.get("base_sha") != value["base_sha"]
        or task.get("target_base_sha") != value["target_base_sha"]
    ):
        raise WorkerServiceError("broker worker envelope authority is inconsistent")
    return value


def run_hermes_worker(
    envelope: dict[str, Any],
    *,
    python_executable: Path,
    worker_hermes_root: Path,
    runtime_entrypoint: Path | None = None,
) -> dict[str, Any]:
    """Run the ordinary Hermes worker with only credential-free sealed inputs."""

    task = envelope["task"]
    profile = str(task.get("profile") or "")
    if not profile:
        raise WorkerServiceError("sealed worker profile is unavailable")
    validate_worker_credential_home(
        worker_hermes_root,
        profile=profile,
        expected_owner_uid=_effective_uid(),
    )
    runtime = task.get("max_runtime_seconds")
    if isinstance(runtime, bool) or not isinstance(runtime, int) or runtime <= 0:
        raise WorkerServiceError("sealed worker runtime is invalid")
    prompt = (
        f"Work Kanban task {envelope['task_id']} in the assigned workspace. "
        "Edit and test files only; Git metadata, credentials, publishing, and "
        "task authority remain owned by the host broker."
    )
    command = [str(Path(python_executable))]
    if runtime_entrypoint is not None:
        entrypoint = Path(runtime_entrypoint)
        if not entrypoint.is_absolute() or ".." in entrypoint.parts:
            raise WorkerServiceError("sealed worker runtime entrypoint is invalid")
        command.extend(["-B", "-I", str(entrypoint)])
    command.extend([
        "-m",
        "hermes_cli.main",
        "-p",
        profile,
        "--cli",
    ])
    for skill in task.get("skills") or []:
        if skill:
            command.extend(["--skills", str(skill)])
    model = str(task.get("model_override") or "").strip()
    provider = str(task.get("provider_override") or "").strip()
    if provider and not model:
        raise WorkerServiceError("sealed provider override requires a model override")
    if model:
        command.extend(["-m", model])
        if provider:
            command.extend(["--provider", provider])
    reasoning = str(task.get("reasoning_effort") or "").strip()
    if reasoning:
        command.extend(["--reasoning", reasoning])
    command.extend(["chat", "-q", prompt])
    if task.get("goal_mode") is True:
        command.append("-Q")
    try:
        result = subprocess.run(
            command,
            cwd=envelope["workspace_path"],
            env=_safe_worker_env(
                envelope, worker_hermes_root=Path(worker_hermes_root)
            ),
            capture_output=True,
            text=True,
            check=False,
            timeout=min(int(runtime), 86400),
        )
    finally:
        validate_worker_credential_home(
            worker_hermes_root,
            profile=profile,
            expected_owner_uid=_effective_uid(),
        )
    if result.returncode != 0:
        raise WorkerServiceError(
            "Hermes worker failed: " + (result.stderr or "worker error")[-500:]
        )
    return {
        "contract": "hermes.worker_turn_complete.v1",
        "outcome": "completed",
        "exit_code": 0,
    }


class WorkerSocketService:
    """One bounded Unix listener owned by the unprivileged model identity."""

    def __init__(
        self,
        *,
        socket_path: Path,
        workspace_root: Path,
        broker_uid: int,
        workspace_gid: int,
        handler: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        self.socket_path = Path(socket_path)
        self.workspace_root = Path(workspace_root)
        self.broker_uid = int(broker_uid)
        self.workspace_gid = int(workspace_gid)
        self.handler = handler
        self.listener: socket.socket | None = None

    def start(self) -> None:
        parent = self.socket_path.parent
        info = parent.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != _effective_uid()
            or info.st_gid != self.workspace_gid
            or stat.S_IMODE(info.st_mode) != 0o710
        ):
            raise WorkerServiceError("worker socket parent ownership is unsafe")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise WorkerServiceError("worker socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.socket_path))
        os.chown(self.socket_path, -1, self.workspace_gid)
        self.socket_path.chmod(0o660)
        listener.listen(8)
        self.listener = listener

    def serve_once(self) -> None:
        if self.listener is None:
            raise WorkerServiceError("worker socket service is not started")
        conn, _address = self.listener.accept()
        with conn:
            if peer_uid(conn) != self.broker_uid:
                raise WorkerServiceError("worker socket peer is not the broker UID")
            envelope = _validated_envelope(
                receive_frame(conn), workspace_root=self.workspace_root
            )
            try:
                response = self.handler(envelope)
            except Exception as exc:
                response = {
                    "contract": "hermes.worker_turn_failed.v1",
                    "outcome": "failed",
                    "error_class": type(exc).__name__,
                }
            send_frame(conn, response)

    def close(self) -> None:
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        self.socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hermes_cli.kanban_broker_worker")
    parser.add_argument("serve", nargs="?")
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--broker-uid", type=int, required=True)
    parser.add_argument("--workspace-gid", type=int, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--python-sha256", required=True)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--package-manifest-sha256", required=True)
    parser.add_argument("--worker-hermes-root", type=Path, required=True)
    parser.add_argument("--runtime-entrypoint", type=Path)
    parser.add_argument("--runtime-entrypoint-sha256")
    parser.add_argument("--runtime-manifest-path", type=Path)
    parser.add_argument("--runtime-manifest-sha256")
    args = parser.parse_args(argv)
    validate_worker_runtime(
        python_executable=args.python,
        python_sha256=args.python_sha256,
        package_root=args.package_root,
        package_manifest_sha256=args.package_manifest_sha256,
        runtime_entrypoint_path=args.runtime_entrypoint,
        runtime_entrypoint_sha256=args.runtime_entrypoint_sha256,
        runtime_manifest_path=args.runtime_manifest_path,
        runtime_manifest_sha256=args.runtime_manifest_sha256,
    )
    service = WorkerSocketService(
        socket_path=args.socket,
        workspace_root=args.workspace_root,
        broker_uid=args.broker_uid,
        workspace_gid=args.workspace_gid,
        handler=lambda envelope: run_hermes_worker(
            envelope,
            python_executable=args.python,
            worker_hermes_root=args.worker_hermes_root,
            runtime_entrypoint=args.runtime_entrypoint,
        ),
    )
    service.start()
    try:
        while True:
            service.serve_once()
    finally:
        service.close()


if __name__ == "__main__":
    raise SystemExit(main())

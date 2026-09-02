"""Staging-host canaries for the dedicated broker OS-identity boundary."""

from __future__ import annotations

import json
import os
import plistlib
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable


def _effective_uid() -> int:
    """Return the POSIX effective UID or fail closed on unsupported hosts."""

    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        raise OSError("dedicated broker canaries require a POSIX host")
    return int(getter())


def _read_access_result(path: Path, *, uid: int, gid: int) -> str:
    path = Path(path)
    try:
        path.lstat()
    except FileNotFoundError:
        return "MISSING"
    except OSError as exc:
        return f"ERROR:{type(exc).__name__}"
    read_fd, write_fd = os.pipe()
    pid = os.fork()  # windows-footgun: ok - root-only macOS staging canary
    if pid == 0:
        try:
            os.close(read_fd)
            os.setgroups([])
            os.setgid(int(gid))
            os.setuid(int(uid))
            try:
                path.read_bytes()
            except PermissionError:
                os.write(write_fd, b"DENIED")
            except FileNotFoundError:
                os.write(write_fd, b"MISSING")
            except Exception as exc:
                os.write(
                    write_fd,
                    f"ERROR:{type(exc).__name__}".encode("ascii", "replace"),
                )
            else:
                os.write(write_fd, b"ALLOWED")
        except Exception as exc:
            os.write(
                write_fd,
                f"ERROR:{type(exc).__name__}".encode("ascii", "replace"),
            )
        finally:
            os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 32)
    os.close(read_fd)
    _pid, status = os.waitpid(pid, 0)
    if not os.WIFEXITED(status):
        return "ERROR:child_status"
    return result.decode("ascii", "replace") or "ERROR:no_result"


def cross_uid_read_denied(path: Path, *, model_uid: int, model_gid: int) -> bool:
    """Fork a model-UID reader and report whether Unix ownership denied it.

    This must run as root on a disposable staging host after the broker account
    and files exist.  It intentionally does not use a Hermes regex or sandbox:
    it models Accessibility driving an otherwise unsandboxed Terminal process.
    """
    if _effective_uid() != 0:
        raise PermissionError("cross-UID broker canary requires root")
    result = _read_access_result(path, uid=model_uid, gid=model_gid)
    if result != "DENIED":
        raise RuntimeError(f"expected DENIED, observed {result}")
    return True


def cross_uid_publisher_read_matrix(
    path: Path,
    *,
    model_uid: int,
    model_gid: int,
    publisher_uid: int,
    publisher_gid: int,
) -> bool:
    """Prove the publisher can read a handoff while the model cannot."""
    if _effective_uid() != 0:
        raise PermissionError("cross-UID broker canary requires root")
    model = _read_access_result(path, uid=model_uid, gid=model_gid)
    publisher = _read_access_result(path, uid=publisher_uid, gid=publisher_gid)
    if model != "DENIED" or publisher != "ALLOWED":
        raise RuntimeError(
            f"publisher read matrix mismatch: model={model}, publisher={publisher}"
        )
    return True


def cross_uid_socket_connect_matrix(
    path: Path,
    *,
    model_uid: int,
    model_gid: int,
    client_uid: int,
    client_gid: int,
) -> bool:
    """Prove Unix socket mode/group denies model and permits its client."""
    if _effective_uid() != 0:
        raise PermissionError("cross-UID broker canary requires root")

    try:
        endpoint = Path(path).lstat()
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(endpoint.st_mode) or not stat.S_ISSOCK(endpoint.st_mode):
        raise RuntimeError("socket matrix endpoint is not a real Unix socket")

    def connects(uid: int, gid: int) -> str:
        read_fd, write_fd = os.pipe()
        pid = os.fork()  # windows-footgun: ok - root-only macOS staging canary
        if pid == 0:
            try:
                os.close(read_fd)
                os.setgroups([])
                os.setgid(int(gid))
                os.setuid(int(uid))
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(1.0)
                try:
                    client.connect(str(path))
                except PermissionError:
                    os.write(write_fd, b"DENIED")
                except FileNotFoundError:
                    os.write(write_fd, b"MISSING")
                except OSError as exc:
                    os.write(
                        write_fd,
                        f"ERROR:{type(exc).__name__}".encode("ascii", "replace"),
                    )
                else:
                    os.write(write_fd, b"ALLOWED")
                finally:
                    client.close()
            finally:
                os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 32)
        os.close(read_fd)
        _pid, status = os.waitpid(pid, 0)
        if not os.WIFEXITED(status):
            return "ERROR"
        return result.decode("ascii", "replace") or "ERROR"

    model = connects(model_uid, model_gid)
    client = connects(client_uid, client_gid)
    if model != "DENIED" or client != "ALLOWED":
        raise RuntimeError(f"socket matrix mismatch: denied={model}, client={client}")
    return True


def cross_uid_workspace_edit_proof(
    *, workspace: Path, broker_secret: Path, model_uid: int, model_gid: int
) -> bool:
    """Prove a model UID can edit its workspace but cannot read broker state."""
    if _effective_uid() != 0:
        raise PermissionError("cross-UID broker canary requires root")
    read_fd, write_fd = os.pipe()
    pid = os.fork()  # windows-footgun: ok - root-only macOS staging canary
    if pid == 0:
        try:
            os.close(read_fd)
            os.setgroups([])
            os.setgid(int(model_gid))
            os.setuid(int(model_uid))
            tracked = Path(workspace) / "README.md"
            with tracked.open("a", encoding="utf-8") as stream:
                stream.write("model edit\n")
            (Path(workspace) / "model-created.txt").write_text(
                "model bytes\n", encoding="utf-8"
            )
            try:
                Path(broker_secret).read_bytes()
            except PermissionError:
                os.write(write_fd, b"editable-secret-denied")
            else:
                os.write(write_fd, b"secret-readable")
        except Exception as exc:
            os.write(write_fd, f"error:{type(exc).__name__}".encode("ascii", "replace"))
        finally:
            os._exit(0)
    os.close(write_fd)
    result = os.read(read_fd, 128)
    os.close(read_fd)
    _pid, status = os.waitpid(pid, 0)
    return os.WIFEXITED(status) and result == b"editable-secret-denied"


def _observe(check: Callable[[], bool]) -> dict[str, str]:
    try:
        passed = check()
    except FileNotFoundError as exc:
        return {"outcome": "MISSING", "detail": str(exc)[:240]}
    except Exception as exc:
        return {
            "outcome": "ERROR",
            "detail": f"{type(exc).__name__}:{str(exc)[:200]}",
        }
    return {
        "outcome": "PASS" if passed is True else "FAIL",
        "detail": "observed" if passed is True else "unexpected_result",
    }


def _socket_parent_check(config: dict[str, Any]) -> bool:
    for surface, gid_key in (
        ("controller", "controller_gid"),
        ("publisher", "publisher_gid"),
        ("operator", "operator_gid"),
    ):
        parent = Path(config[f"{surface}_socket"]).parent
        info = parent.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != int(config["broker_uid"])
            or info.st_gid != int(config[gid_key])
            or stat.S_IMODE(info.st_mode) != 0o710
        ):
            return False
    worker = Path(config["worker_socket"]).parent.lstat()
    return bool(
        not stat.S_ISLNK(worker.st_mode)
        and stat.S_ISDIR(worker.st_mode)
        and worker.st_uid == int(config["model_uid"])
        and worker.st_gid == int(config["workspace_gid"])
        and stat.S_IMODE(worker.st_mode) == 0o710
    )


def _network_denied(config: dict[str, Any]) -> bool:
    sandbox = Path("/usr/bin/sandbox-exec")
    profile = Path(config["seatbelt_profile_path"])
    if not sandbox.exists() or not profile.exists():
        raise FileNotFoundError("sandbox executable or profile is missing")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2.0)
    host, port = listener.getsockname()
    code = (
        "import socket; s=socket.socket(); "
        f"s.settimeout(1); s.connect(({host!r},{port})); s.close()"
    )

    def demote() -> None:
        os.setgroups([])
        os.setgid(int(config["broker_gid"]))
        os.setuid(int(config["broker_uid"]))

    result = subprocess.Popen(
        [
            str(sandbox),
            "-f",
            str(profile),
            str(config["python_executable"]),
            "-c",
            code,
        ],
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=demote,
    )
    connected = False
    try:
        conn, _address = listener.accept()
        connected = True
        conn.close()
    except TimeoutError:
        pass
    finally:
        listener.close()
    return bool(result.wait(timeout=3) != 0 and not connected)


def _credential_scrub_check(config: dict[str, Any]) -> bool:
    forbidden = {
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITHUB_PAT",
        "SSH_AUTH_SOCK",
        "AWS_SECRET_ACCESS_KEY",
    }
    for name in ("launchd_plist_path", "worker_launchd_plist_path"):
        with Path(config[name]).open("rb") as stream:
            payload = plistlib.load(stream)
        environment = payload.get("EnvironmentVariables") or {}
        if forbidden & set(environment):
            return False
    from hermes_cli.kanban_broker_worker import _safe_worker_env
    from hermes_cli.kanban_broker_worker import validate_worker_credential_home

    dispatcher_profile = str(config.get("dispatcher_profile") or "")
    # Keep this focused helper usable by legacy unit callers that only test
    # environment scrubbing.  The full activation runner enforces the named
    # profile before it invokes this check.
    if dispatcher_profile:
        validate_worker_credential_home(
            Path(config["worker_hermes_root"]),
            profile=dispatcher_profile,
            expected_owner_uid=int(config["model_uid"]),
        )

    prior = {name: os.environ.get(name) for name in forbidden}
    try:
        for name in forbidden:
            os.environ[name] = "canary-secret"
        safe = _safe_worker_env(
            {
                "task_id": "canary",
                "run_id": 1,
                "workspace_path": str(Path(config["workspace_root"]) / "canary"),
                "branch": "wt/canary",
                "task": {
                    "board": "canary",
                    "project_id": None,
                    "profile": dispatcher_profile,
                    "goal_mode": False,
                },
            },
            worker_hermes_root=Path(config["worker_hermes_root"]),
        )
        return not bool(forbidden & set(safe))
    finally:
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _routing_profile_check(config: dict[str, Any]) -> bool:
    """Load the named dispatcher profile and verify its real client routes."""
    routing_path = Path(str(config.get("dispatcher_routing_config_path") or ""))
    profile = str(config.get("dispatcher_profile") or "")
    if not profile or routing_path.name != "kanban-routing.json":
        return False
    if routing_path.parent.name != profile:
        return False
    expected_profile_root = (
        Path(str(config.get("worker_hermes_root") or ""))
        / "profiles"
        / profile
    )
    if routing_path.parent != expected_profile_root:
        return False
    profile_info = routing_path.parent.lstat()
    if (
        stat.S_ISLNK(profile_info.st_mode)
        or not stat.S_ISDIR(profile_info.st_mode)
        or profile_info.st_uid != int(config["model_uid"])
        or profile_info.st_gid != int(config["workspace_gid"])
        or stat.S_IMODE(profile_info.st_mode) != 0o700
    ):
        return False
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(routing_path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != int(config["model_uid"])
            or info.st_gid != int(config["workspace_gid"])
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            return False
        raw = os.read(fd, 1024 * 1024 + 1)
    finally:
        os.close(fd)
    if len(raw) > 1024 * 1024:
        return False
    try:
        routing = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    required = {
        "contract", "schema_version", "profile", "dedicated_broker_enabled",
        "trusted_publisher_enabled", "controller_client_config",
        "publisher_client_config", "operator_client_config", "registration_file",
        "expected_source_sha",
    }
    if not isinstance(routing, dict) or set(routing) != required:
        return False
    if (
        routing["contract"] != "hermes.kanban_broker_routing.v1"
        or routing["schema_version"] != 1
        or routing["profile"] != profile
        or routing["dedicated_broker_enabled"] is not False
        or routing["trusted_publisher_enabled"] is not False
        or not isinstance(routing["expected_source_sha"], str)
        or len(routing["expected_source_sha"]) != 40
        or routing.get("registration_file") != config.get("registration_file_path")
    ):
        return False
    for surface in ("controller", "publisher", "operator"):
        client_path = Path(str(routing[f"{surface}_client_config"]))
        if not client_path.is_absolute() or ".." in client_path.parts:
            return False
        try:
            client_info = client_path.lstat()
            if (
                stat.S_ISLNK(client_info.st_mode)
                or not stat.S_ISREG(client_info.st_mode)
                or client_info.st_uid != int(config[f"{surface}_uid"])
                or client_info.st_gid != int(config[f"{surface}_gid"])
                or stat.S_IMODE(client_info.st_mode) != 0o600
            ):
                return False
            client = json.loads(client_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        if (
            not isinstance(client, dict)
            or client.get("surface") != surface
            or client.get("socket_path") != config[f"{surface}_socket"]
        ):
            return False
    registration = Path(str(routing["registration_file"]))
    if not registration.is_file() or registration.is_symlink():
        return False
    try:
        request = json.loads(registration.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return bool(
        isinstance(request, dict)
        and request.get("expected_source_sha") == routing["expected_source_sha"]
    )


def _publisher_runtime_preflight_check(config: dict[str, Any]) -> bool:
    """Run Radulator's exact direct isolated publisher preflight contract."""
    probe = Path(str(config.get("publisher_probe_path") or ""))
    python = Path(str(config.get("python_executable") or ""))
    manifest = Path(str(config.get("runtime_manifest_path") or ""))
    if not probe.is_absolute() or not python.is_absolute() or not manifest.is_absolute():
        return False
    command = [
        str(python), "-I", "-B", str(probe),
        "--runtime-root", str(python.parent.parent),
        "--runtime-manifest", str(manifest),
        "--runtime-manifest-sha256", str(config.get("runtime_manifest_sha256") or ""),
        "--runtime-python-version", str(config.get("python_version") or ""),
        "--runtime-python-sha256", str(config.get("python_sha256") or ""),
        "--runtime-preflight",
    ]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
        )
        if result.returncode != 0:
            return False
        response = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    expected = {
        "contract": "radulator.publisher_runtime_preflight.v1",
        "status": "PASS",
        "python_executable": str(python),
        "python_version": str(config["python_version"]),
        "runtime_root": str(python.parent.parent),
        "runtime_manifest_sha256": str(config["runtime_manifest_sha256"]),
        "broker_client_module": None,
        "broker_rpc": "PASS",
    }
    if not isinstance(response, dict) or set(response) != set(expected):
        return False
    module_path = response.get("broker_client_module")
    package_root = Path(str(config["package_root"])).resolve()
    try:
        module_resolved = Path(str(module_path)).resolve()
    except (TypeError, ValueError):
        return False
    expected.update({"broker_client_module": str(module_resolved)})
    return bool(
        response.get("contract") == expected["contract"]
        and response.get("status") == expected["status"]
        and response.get("python_executable") == expected["python_executable"]
        and response.get("python_version") == expected["python_version"]
        and response.get("runtime_root") == expected["runtime_root"]
        and response.get("runtime_manifest_sha256") == expected["runtime_manifest_sha256"]
        and response.get("broker_rpc") == expected["broker_rpc"]
        and module_resolved == package_root / "kanban_broker_client.py"
        and module_resolved.is_file()
    )


def cross_uid_process_read_denied(
    path: Path,
    *,
    model_uid: int,
    model_gid: int,
    accessibility_driven: bool,
) -> bool:
    """Prove a real model-UID process observes file permission denial.

    The Accessibility variant uses ``osascript`` to launch the fixed ``cat``
    process.  Errors opening Apple Events, a missing login session, a missing
    file, or any other infrastructure failure are not accepted as denial.
    """

    if _effective_uid() != 0:
        raise PermissionError("cross-UID process canary requires root")
    target = Path(path)
    target.lstat()
    if accessibility_driven:
        executable = Path("/usr/bin/osascript")
        if not executable.is_file():
            raise FileNotFoundError(executable)
        script = 'do shell script "/bin/cat " & quoted form of ' + json.dumps(
            str(target)
        )
        command = [str(executable), "-e", script]
    else:
        executable = Path("/bin/cat")
        if not executable.is_file():
            raise FileNotFoundError(executable)
        command = [str(executable), str(target)]

    def demote() -> None:
        os.setgroups([])
        os.setgid(int(model_gid))
        os.setuid(int(model_uid))

    result = subprocess.run(
        command,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"},
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
        preexec_fn=demote,
    )
    if result.returncode == 0:
        return False
    detail = (result.stderr or result.stdout or "").lower()
    if "permission denied" in detail and target.name.lower() in detail:
        return True
    raise RuntimeError(
        "model process did not prove target permission denial: " + detail[:200]
    )


def run_activation_canaries(config: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Execute all root-only activation probes; no result is caller-supplied."""

    if _effective_uid() != 0:
        raise PermissionError("activation canary runner requires root")
    dispatcher_profile = str(config.get("dispatcher_profile") or "")
    if not dispatcher_profile:
        raise ValueError("activation canary dispatcher profile is unavailable")
    checks: dict[str, Callable[[], bool]] = {}
    checks["root_execution"] = lambda: _effective_uid() == 0
    checks["identity_separation"] = lambda: (
        len({
            int(config[name])
            for name in (
                "broker_uid",
                "model_uid",
                "controller_uid",
                "publisher_uid",
            )
        })
        == 4
    )

    def group_separation() -> bool:
        from hermes_cli.kanban_broker_install import (
            system_group_memberships,
            validate_group_separation,
        )

        validate_group_separation(
            broker_uid=int(config["broker_uid"]),
            model_uid=int(config["model_uid"]),
            controller_uid=int(config["controller_uid"]),
            controller_gid=int(config["controller_gid"]),
            publisher_uid=int(config["publisher_uid"]),
            publisher_gid=int(config["publisher_gid"]),
            operator_uid=int(config["operator_uid"]),
            operator_gid=int(config["operator_gid"]),
            workspace_gid=int(config["workspace_gid"]),
            memberships=system_group_memberships({
                int(config[name])
                for name in (
                    "broker_uid",
                    "model_uid",
                    "controller_uid",
                    "publisher_uid",
                    "operator_uid",
                )
            }),
        )
        return True

    checks["group_separation"] = group_separation
    checks["socket_parent_traversal"] = lambda: _socket_parent_check(config)
    model = {
        "model_uid": int(config["model_uid"]),
        "model_gid": int(config["workspace_gid"]),
    }
    authority_key = Path(config["state_dir"]) / "authority.key"
    authority_db = Path(config["state_dir"]) / "broker.sqlite3"
    checks["state_denied_model"] = lambda: cross_uid_read_denied(authority_key, **model)
    checks["authority_db_denied_model"] = lambda: cross_uid_read_denied(
        authority_db, **model
    )

    canary_id = f"activation-{os.getpid()}-{time.time_ns()}"
    workspace = Path(config["workspace_root"]) / canary_id
    bundle = Path(config["publisher_handoff_root"]) / f"{canary_id}.bundle"

    def workspace_check() -> bool:
        workspace.mkdir(mode=0o770)
        os.chown(workspace, int(config["broker_uid"]), int(config["workspace_gid"]))
        workspace.chmod(0o2770)
        tracked = workspace / "README.md"
        tracked.write_text("canary\n", encoding="utf-8")
        os.chown(tracked, int(config["broker_uid"]), int(config["workspace_gid"]))
        tracked.chmod(0o660)
        try:
            return cross_uid_workspace_edit_proof(
                workspace=workspace,
                broker_secret=authority_key,
                **model,
            )
        finally:
            for child in workspace.iterdir():
                child.unlink()
            workspace.rmdir()

    checks["workspace_edit_secret_denied"] = workspace_check

    def bundle_check() -> bool:
        bundle.write_bytes(b"canary bundle")
        os.chown(bundle, int(config["broker_uid"]), int(config["publisher_gid"]))
        bundle.chmod(0o640)
        try:
            return cross_uid_publisher_read_matrix(
                bundle,
                **model,
                publisher_uid=int(config["publisher_uid"]),
                publisher_gid=int(config["publisher_gid"]),
            )
        finally:
            bundle.unlink(missing_ok=True)

    checks["publisher_bundle_matrix"] = bundle_check
    for surface, uid_key, gid_key in (
        ("controller", "controller_uid", "controller_gid"),
        ("publisher", "publisher_uid", "publisher_gid"),
        ("operator", "operator_uid", "operator_gid"),
    ):
        checks[f"{surface}_socket_matrix"] = lambda s=surface, u=uid_key, g=gid_key: (
            cross_uid_socket_connect_matrix(
                Path(config[f"{s}_socket"]),
                **model,
                client_uid=int(config[u]),
                client_gid=int(config[g]),
            )
        )
    checks["worker_socket_matrix"] = lambda: cross_uid_socket_connect_matrix(
        Path(config["worker_socket"]),
        model_uid=int(config["publisher_uid"]),
        model_gid=int(config["publisher_gid"]),
        client_uid=int(config["broker_uid"]),
        client_gid=int(config["workspace_gid"]),
    )
    checks["network_denied"] = lambda: _network_denied(config)
    checks["credential_env_scrubbed"] = lambda: _credential_scrub_check(config)
    checks["routing_profile_binding"] = lambda: _routing_profile_check(config)
    checks["publisher_runtime_preflight"] = lambda: _publisher_runtime_preflight_check(config)
    def isolated_runtime_check() -> bool:
        from hermes_cli.kanban_broker_install import verify_isolated_runtime_import

        verify_isolated_runtime_import(
            python_executable=Path(config["python_executable"]),
            entrypoint_path=Path(config["runtime_entrypoint_path"]),
            direct_probe_path=Path(config["python_executable"]).parent.parent
            / "runtime-probe.py",
            module="hermes_cli.kanban_broker_client",
        )
        return True
    checks["isolated_runtime_import"] = isolated_runtime_check
    checks["model_terminal_denied"] = lambda: cross_uid_process_read_denied(
        authority_key, **model, accessibility_driven=False
    )
    checks["computer_use_denied_by_uid"] = lambda: cross_uid_process_read_denied(
        authority_db, **model, accessibility_driven=True
    )
    expected = {
        "root_execution",
        "identity_separation",
        "group_separation",
        "socket_parent_traversal",
        "state_denied_model",
        "authority_db_denied_model",
        "workspace_edit_secret_denied",
        "publisher_bundle_matrix",
        "controller_socket_matrix",
        "publisher_socket_matrix",
        "operator_socket_matrix",
        "worker_socket_matrix",
        "network_denied",
        "credential_env_scrubbed",
        "routing_profile_binding",
        "publisher_runtime_preflight",
        "isolated_runtime_import",
        "model_terminal_denied",
        "computer_use_denied_by_uid",
    }
    if set(checks) != expected:
        raise RuntimeError("activation canary implementation is incomplete")
    return {name: _observe(checks[name]) for name in sorted(expected)}

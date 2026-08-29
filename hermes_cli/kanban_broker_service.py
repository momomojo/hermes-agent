"""Default-off launchd service for the dedicated-identity Kanban broker."""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import json
import os
import selectors
import signal
import socket
import stat
import threading
from pathlib import Path
from typing import Any

from hermes_cli.kanban_broker_install import validate_identity_separation
from hermes_cli.kanban_broker_install import (
    system_group_memberships,
    validate_group_separation,
    validate_runtime_identity,
)
from hermes_cli.kanban_broker_protocol import BrokerRPCServer
from hermes_cli.kanban_broker_protocol import send_frame
from hermes_cli.kanban_dedicated_broker import (
    KANBAN_BROKER_SECURITY_BOUNDARY,
    DedicatedKanbanBroker,
)


SERVICE_CONFIG_CONTRACT = "hermes.kanban_broker_service_config.v1"


class BrokerServiceError(RuntimeError):
    """A dedicated broker service invariant failed."""


class BrokerServiceDisabled(BrokerServiceError):
    """The explicit exact-bool activation flag is not enabled."""


def dedicated_broker_enabled(config: dict[str, Any]) -> bool:
    kanban = config.get("kanban") if isinstance(config, dict) else None
    return isinstance(kanban, dict) and kanban.get("dedicated_broker_enabled") is True


def require_enabled_service_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict) or config.get("enabled") is not True:
        raise BrokerServiceDisabled("dedicated Kanban broker is default-off")
    return config


class BrokerSocketService:
    """Bind reviewed surface handlers to separate Unix sockets."""

    def __init__(
        self,
        *,
        surfaces: dict[str, dict[str, Any]],
        broker_uid: int,
        max_inflight: int = 8,
    ) -> None:
        if int(max_inflight) < 2 or int(max_inflight) > 64:
            raise BrokerServiceError("broker max_inflight must be between 2 and 64")
        self.surfaces = dict(surfaces)
        self.broker_uid = int(broker_uid)
        self._selector = selectors.DefaultSelector()
        self._listeners: dict[str, tuple[socket.socket, Path, int]] = {}
        self._stop = threading.Event()
        self._quiescing = threading.Event()
        self._inflight_lock = threading.Lock()
        self._inflight_by_surface = {surface: 0 for surface in self.surfaces}
        self._mutating_inflight = 0
        self._capacity = threading.BoundedSemaphore(int(max_inflight))
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=int(max_inflight),
            thread_name_prefix="hermes-kanban-broker",
        )
        operator = self.surfaces.get("operator")
        if operator is not None:
            operator["server"].quiesce_callback = self.begin_quiesce
            operator["server"].quiesce_status_callback = self.quiesce_status
        for definition in self.surfaces.values():
            definition["server"].quiescing_callback = self.is_quiescing
            definition["server"].mutation_admission_callback = self.admit_mutation
            definition["server"].mutation_release_callback = self.release_mutation
            if definition["server"].surface == "controller":
                definition[
                    "server"
                ].background_dispatch_callback = self.submit_background_dispatch

    def is_quiescing(self) -> bool:
        return self._quiescing.is_set()

    def begin_quiesce(self) -> dict[str, Any]:
        # The cutoff and admission counter share one lock: every mutation is
        # either durably admitted before the cutoff or rejected after it.
        with self._inflight_lock:
            self._quiescing.set()
        return self.quiesce_status()

    def admit_mutation(self) -> bool:
        with self._inflight_lock:
            if self._quiescing.is_set():
                return False
            self._mutating_inflight += 1
            return True

    def release_mutation(self) -> None:
        with self._inflight_lock:
            if self._mutating_inflight <= 0:
                raise BrokerServiceError("broker mutation admission counter underflow")
            self._mutating_inflight -= 1

    def submit_background_dispatch(
        self, *, operation_id: str, worker_socket: Path
    ) -> None:
        # Transfer the request admission to the durable background operation
        # before the RPC handler releases its own admission.
        with self._inflight_lock:
            self._mutating_inflight += 1

        def run() -> None:
            try:
                controller = self.surfaces["controller"]["server"]
                controller.broker.perform_dispatch(
                    operation_id=operation_id,
                    worker_socket=worker_socket,
                )
            except Exception:
                # The broker journals the exact terminal failure; callers use
                # dispatch_status instead of thread exception state.
                return
            finally:
                self.release_mutation()

        try:
            self._executor.submit(run)
        except Exception:
            controller = self.surfaces["controller"]["server"]
            controller.broker.fail_dispatch_submission(operation_id=operation_id)
            self.release_mutation()
            raise

    def quiesce_status(self) -> dict[str, Any]:
        with self._inflight_lock:
            mutating_inflight = int(self._mutating_inflight)
        return {
            "quiescing": self.is_quiescing(),
            "inflight": mutating_inflight,
        }

    def _serve_connection(self, *, conn: socket.socket, surface: str) -> None:
        try:
            with conn:
                conn.settimeout(30.0)
                self.surfaces[surface]["server"].handle_connection(conn)
        finally:
            with self._inflight_lock:
                self._inflight_by_surface[surface] -= 1
            self._capacity.release()

    def _remove_stale_socket(self, path: Path) -> None:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISSOCK(info.st_mode)
            or info.st_uid != self.broker_uid
        ):
            raise BrokerServiceError("broker socket path is not a broker-owned socket")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(str(path))
        except OSError as exc:
            if exc.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
                raise BrokerServiceError(
                    "broker socket cannot be safely recovered"
                ) from exc
        else:
            raise BrokerServiceError("another broker is already listening")
        finally:
            probe.close()
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise BrokerServiceError("broker socket changed during recovery")
        path.unlink()

    def start(self) -> None:
        if self._listeners:
            raise BrokerServiceError("broker socket service is already started")
        socket_parents = [
            Path(definition["path"]).parent.resolve(strict=True)
            for definition in self.surfaces.values()
        ]
        if len(socket_parents) != len(set(socket_parents)):
            raise BrokerServiceError(
                "each broker surface requires a dedicated socket parent"
            )
        for surface, definition in sorted(self.surfaces.items()):
            path = Path(definition["path"])
            parent_info = path.parent.lstat()
            if (
                stat.S_ISLNK(parent_info.st_mode)
                or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != self.broker_uid
                or parent_info.st_gid != int(definition["gid"])
                or stat.S_IMODE(parent_info.st_mode) != 0o710
            ):
                raise BrokerServiceError(
                    "broker socket parent must be broker-owned, client-group mode 0710"
                )
            if path.exists() or path.is_symlink():
                self._remove_stale_socket(path)
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(path))
                os.chown(path, -1, int(definition["gid"]))
                path.chmod(0o660)
                listener.listen(16)
                listener.setblocking(False)
                info = path.lstat()
                self._selector.register(listener, selectors.EVENT_READ, surface)
                self._listeners[surface] = (listener, path, int(info.st_ino))
            except Exception:
                listener.close()
                path.unlink(missing_ok=True)
                self.close()
                raise

    def serve_forever(self) -> None:
        if not self._listeners:
            raise BrokerServiceError("broker socket service is not started")
        while not self._stop.is_set():
            for key, _events in self._selector.select(timeout=0.1):
                listener = key.fileobj
                if not isinstance(listener, socket.socket):
                    raise BrokerServiceError(
                        "broker selector returned a non-socket listener"
                    )
                try:
                    conn, _address = listener.accept()
                except BlockingIOError:
                    continue
                surface = str(key.data)
                if not self._capacity.acquire(blocking=False):
                    with conn:
                        try:
                            send_frame(
                                conn,
                                {
                                    "ok": False,
                                    "error": "dedicated broker is at bounded capacity",
                                },
                            )
                        except OSError:
                            pass
                    continue
                with self._inflight_lock:
                    self._inflight_by_surface[surface] += 1
                self._executor.submit(
                    self._serve_connection,
                    conn=conn,
                    surface=surface,
                )

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        for listener, path, inode in list(self._listeners.values()):
            try:
                self._selector.unregister(listener)
            except Exception:
                pass
            listener.close()
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISSOCK(info.st_mode) and int(info.st_ino) == inode:
                path.unlink()
        self._listeners.clear()
        self._selector.close()
        self._executor.shutdown(wait=False, cancel_futures=True)


def _read_config(path: Path) -> dict[str, Any]:
    try:
        fd = os.open(
            Path(path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise BrokerServiceError("broker config is unavailable") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid
            != os.geteuid()  # windows-footgun: ok - macOS launchd service only
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > 1024 * 1024
        ):
            raise BrokerServiceError("broker config must be broker-owned mode 0600")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BrokerServiceError("broker config changed during read")
    finally:
        os.close(fd)
    try:
        value = json.loads(b"".join(chunks))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerServiceError("broker config is not valid JSON") from exc
    if (
        not isinstance(value, dict)
        or value.get("contract") != SERVICE_CONFIG_CONTRACT
        or value.get("broker_boundary") != KANBAN_BROKER_SECURITY_BOUNDARY
    ):
        raise BrokerServiceError("unsupported broker service config")
    return require_enabled_service_config(value)


def _read_client_key(path: Path, *, broker_uid: int, client_gid: int) -> bytes:
    try:
        fd = os.open(
            Path(path),
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise BrokerServiceError("broker surface key is unavailable") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != broker_uid
            or before.st_gid != client_gid
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o640
            or before.st_size != 32
        ):
            raise BrokerServiceError("broker surface key ownership or mode is unsafe")
        key = os.read(fd, 33)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BrokerServiceError("broker surface key changed during read")
    finally:
        os.close(fd)
    if len(key) != 32:
        raise BrokerServiceError("broker surface key has invalid length")
    return key


def service_from_config(
    config: dict[str, Any],
) -> tuple[DedicatedKanbanBroker, BrokerSocketService]:
    config = require_enabled_service_config(config)
    if (
        config.get("contract") != SERVICE_CONFIG_CONTRACT
        or config.get("broker_boundary") != KANBAN_BROKER_SECURITY_BOUNDARY
    ):
        raise BrokerServiceError("unsupported broker service config")
    try:
        validate_runtime_identity(config, expected_package_owner_uid=0)
    except (KeyError, OSError, ValueError) as exc:
        raise BrokerServiceError("broker immutable runtime identity failed") from exc
    if Path(__file__).resolve().parent != Path(config["package_root"]).resolve():
        raise BrokerServiceError("broker imported outside the pinned runtime package")
    numeric = {
        name: int(config[name])
        for name in (
            "broker_uid",
            "model_uid",
            "controller_uid",
            "controller_gid",
            "publisher_uid",
            "publisher_gid",
            "operator_uid",
            "operator_gid",
            "workspace_gid",
        )
    }
    current_uid = os.geteuid()  # windows-footgun: ok - macOS launchd service only
    if numeric["broker_uid"] != current_uid:
        raise BrokerServiceError("broker service is running under the wrong UID")
    validate_identity_separation(
        broker_uid=numeric["broker_uid"],
        model_uid=numeric["model_uid"],
        controller_uid=numeric["controller_uid"],
        publisher_uid=numeric["publisher_uid"],
    )
    boundary_uids = {
        numeric["broker_uid"],
        numeric["model_uid"],
        numeric["controller_uid"],
        numeric["publisher_uid"],
        numeric["operator_uid"],
    }
    validate_group_separation(
        broker_uid=numeric["broker_uid"],
        model_uid=numeric["model_uid"],
        controller_uid=numeric["controller_uid"],
        controller_gid=numeric["controller_gid"],
        publisher_uid=numeric["publisher_uid"],
        publisher_gid=numeric["publisher_gid"],
        operator_uid=numeric["operator_uid"],
        operator_gid=numeric["operator_gid"],
        workspace_gid=numeric["workspace_gid"],
        memberships=system_group_memberships(boundary_uids),
    )
    broker = DedicatedKanbanBroker(
        state_dir=Path(config["state_dir"]),
        workspace_root=Path(config["workspace_root"]),
        publisher_handoff_root=Path(config["publisher_handoff_root"]),
        broker_uid=numeric["broker_uid"],
        controller_uid=numeric["controller_uid"],
        publisher_uid=numeric["publisher_uid"],
        operator_uid=numeric["operator_uid"],
        worker_uid=numeric["model_uid"],
        workspace_gid=numeric["workspace_gid"],
        publisher_gid=numeric["publisher_gid"],
        trusted_publisher_enabled=config.get("trusted_publisher_enabled") is True,
    )
    broker.initialize()
    try:
        definitions: dict[str, dict[str, Any]] = {}
        for surface, uid_name, gid_name in (
            ("controller", "controller_uid", "controller_gid"),
            ("publisher", "publisher_uid", "publisher_gid"),
            ("operator", "operator_uid", "operator_gid"),
        ):
            client_key = _read_client_key(
                Path(config[f"{surface}_key_path"]),
                broker_uid=numeric["broker_uid"],
                client_gid=numeric[gid_name],
            )
            definitions[surface] = {
                "path": Path(config[f"{surface}_socket"]),
                "gid": numeric[gid_name],
                "server": BrokerRPCServer(
                    broker=broker,
                    surface=surface,
                    allowed_uid=numeric[uid_name],
                    client_key=client_key,
                    worker_socket=(
                        Path(config["worker_socket"])
                        if surface == "controller"
                        else None
                    ),
                ),
            }
        service = BrokerSocketService(
            surfaces=definitions,
            broker_uid=numeric["broker_uid"],
            max_inflight=int(config.get("max_inflight", 8)),
        )
        return broker, service
    except Exception:
        broker.close()
        raise


def serve_config(path: Path) -> None:
    broker, service = service_from_config(_read_config(path))

    def request_stop(_signum, _frame) -> None:
        service.stop()

    prior_handlers = {
        signum: signal.signal(signum, request_stop)
        for signum in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        service.start()
        service.serve_forever()
    finally:
        service.stop()
        service.close()
        broker.close()
        for signum, handler in prior_handlers.items():
            signal.signal(signum, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hermes_cli.kanban_broker_service")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--config", type=Path, required=True)
    check = subparsers.add_parser("check-config")
    check.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "check-config":
        _read_config(args.config)
        return 0
    serve_config(args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

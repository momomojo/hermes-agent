"""Authenticated fail-closed client for the dedicated Kanban broker."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import secrets
import socket
import stat
import time
from pathlib import Path
from typing import Any

from hermes_cli.kanban_broker_protocol import (
    ProtocolError,
    peer_uid,
    receive_frame,
    send_frame,
    signed_request,
)


class BrokerRPCError(RuntimeError):
    """The dedicated broker was unavailable or rejected an RPC."""


class BrokerRPCClient:
    """One surface-scoped client with a durable monotonic sequence."""

    def __init__(
        self,
        *,
        socket_path: Path,
        expected_broker_uid: int,
        client_key: bytes,
        sequence_path: Path,
        timeout_seconds: float = 30.0,
    ) -> None:
        if len(client_key) != 32:
            raise ValueError("broker client key must be 32 bytes")
        self.socket_path = Path(socket_path)
        self.expected_broker_uid = int(expected_broker_uid)
        self.client_key = bytes(client_key)
        self.sequence_path = Path(sequence_path)
        self.timeout_seconds = float(timeout_seconds)

    def _next_sequence(self) -> int:
        parent = self.sequence_path.parent
        if not parent.is_dir() or parent.is_symlink():
            raise BrokerRPCError(
                "broker client sequence parent is not a real directory"
            )
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.sequence_path, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid
                != os.geteuid()  # windows-footgun: ok - Unix socket client only
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise BrokerRPCError("broker client sequence file is not owner-only")
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.lseek(fd, 0, os.SEEK_SET)
            raw = os.read(fd, 64)
            if raw.strip() and not raw.strip().isdigit():
                raise BrokerRPCError("broker client sequence file is malformed")
            sequence = int(raw.strip() or b"0") + 1
            encoded = f"{sequence}\n".encode("ascii")
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, encoded)
            os.ftruncate(fd, len(encoded))
            os.fsync(fd)
            return sequence
        finally:
            os.close(fd)

    def call(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            socket_info = self.socket_path.lstat()
        except OSError as exc:
            raise BrokerRPCError("dedicated broker socket is unavailable") from exc
        if stat.S_ISLNK(socket_info.st_mode) or not stat.S_ISSOCK(socket_info.st_mode):
            raise BrokerRPCError("dedicated broker endpoint is not a real Unix socket")
        message = signed_request(
            self.client_key,
            sequence=self._next_sequence(),
            nonce=secrets.token_hex(24),
            method=method,
            body=body,
        )
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(self.timeout_seconds)
        try:
            conn.connect(str(self.socket_path))
            if peer_uid(conn) != self.expected_broker_uid:
                raise BrokerRPCError("dedicated broker peer UID mismatch")
            send_frame(conn, message)
            response = receive_frame(conn)
        except (OSError, ValueError, ProtocolError) as exc:
            raise BrokerRPCError("dedicated broker RPC failed closed") from exc
        finally:
            conn.close()
        if response.get("ok") is not True:
            raise BrokerRPCError(str(response.get("error") or "broker rejected RPC"))
        result = response.get("result")
        if not isinstance(result, dict):
            raise BrokerRPCError("dedicated broker returned a malformed result")
        return result


def _read_exact_file(
    path: Path,
    *,
    expected_uid: int,
    expected_mode: int,
    expected_gid: int | None = None,
    max_bytes: int = 1024 * 1024,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(Path(path), flags)
    except OSError as exc:
        raise BrokerRPCError("broker client file is unavailable") from exc
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != int(expected_uid)
            or (expected_gid is not None and before.st_gid != int(expected_gid))
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != int(expected_mode)
        ):
            raise BrokerRPCError("broker client file ownership or mode is unsafe")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise BrokerRPCError("broker client file exceeds size limit")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BrokerRPCError("broker client file changed during read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def load_broker_client(path: Path, *, expected_surface: str) -> BrokerRPCClient:
    """Load one exact surface client using only current-UID owned config."""

    if expected_surface not in {"controller", "publisher", "operator"}:
        raise BrokerRPCError("unsupported broker client surface")
    raw = _read_exact_file(
        Path(path),
        expected_uid=os.geteuid(),  # windows-footgun: ok - Unix socket client only
        expected_mode=0o600,
    )
    try:
        config = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrokerRPCError("broker client config is invalid") from exc
    if (
        not isinstance(config, dict)
        or config.get("contract") != "hermes.kanban_broker_client_config.v1"
        or config.get("surface") != expected_surface
    ):
        raise BrokerRPCError("unsupported broker client config")
    key_path = Path(config["key_path"])
    key = _read_exact_file(
        key_path,
        expected_uid=int(config["expected_broker_uid"]),
        expected_mode=0o640,
        max_bytes=32,
    )
    if len(key) != 32:
        raise BrokerRPCError("broker client key has invalid length")
    return BrokerRPCClient(
        socket_path=Path(config["socket_path"]),
        expected_broker_uid=int(config["expected_broker_uid"]),
        client_key=key,
        sequence_path=Path(config["sequence_path"]),
    )


def _read_operator_client(path: Path) -> BrokerRPCClient:
    return load_broker_client(path, expected_surface="operator")


def quiesce_and_wait(
    client: BrokerRPCClient,
    *,
    wait_seconds: float = 30.0,
    poll_seconds: float = 0.1,
) -> dict[str, Any]:
    """Quiesce and prove all controller/publisher work drained before bootout."""

    if wait_seconds <= 0 or poll_seconds < 0:
        raise ValueError("quiesce wait and poll intervals are invalid")
    deadline = time.monotonic() + float(wait_seconds)
    result = client.call(
        "quiesce",
        {
            "contract": "hermes.kanban_broker_quiesce.v1",
            "reason": "operator rollback",
        },
    )
    while True:
        if result.get("quiescing") is not True:
            raise BrokerRPCError("dedicated broker did not enter quiescing state")
        inflight = result.get("inflight")
        if not isinstance(inflight, int) or isinstance(inflight, bool) or inflight < 0:
            raise BrokerRPCError("dedicated broker returned malformed quiesce status")
        if inflight == 0:
            return result
        if time.monotonic() >= deadline:
            raise BrokerRPCError(
                "dedicated broker still has in-flight work; rollback is stopped"
            )
        time.sleep(float(poll_seconds))
        result = client.call(
            "quiesce_status",
            {"contract": "hermes.kanban_broker_quiesce_status.v1"},
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hermes_cli.kanban_broker_client")
    subparsers = parser.add_subparsers(dest="command", required=True)
    quiesce = subparsers.add_parser("quiesce")
    quiesce.add_argument("--config", type=Path, required=True)
    quiesce.add_argument("--wait-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    client = _read_operator_client(args.config)
    quiesce_and_wait(client, wait_seconds=args.wait_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

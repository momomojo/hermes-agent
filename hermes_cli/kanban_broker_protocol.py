"""Canonical, authenticated Unix-socket framing for the Kanban broker."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import ctypes
import platform
import re
import socket
import struct
from pathlib import Path
from typing import Any

from hermes_cli.kanban_dedicated_broker import BrokerError


MAX_FRAME_BYTES = 1024 * 1024


class ProtocolError(RuntimeError):
    """A broker RPC frame failed authentication, replay, or schema checks."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def send_frame(sock: socket.socket, value: dict[str, Any]) -> None:
    payload = _canonical(value)
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("broker frame exceeds size limit")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ProtocolError("broker frame ended early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def receive_frame(sock: socket.socket) -> dict[str, Any]:
    (size,) = struct.unpack("!I", _read_exact(sock, 4))
    if size <= 0 or size > MAX_FRAME_BYTES:
        raise ProtocolError("broker frame has invalid size")
    try:
        value = json.loads(_read_exact(sock, size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("broker frame is not canonical JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("broker frame must be an object")
    return value


def peer_uid(sock: socket.socket) -> int:
    """Return the kernel-authenticated UID for one connected Unix peer."""
    getpeereid_method = getattr(sock, "getpeereid", None)
    if callable(getpeereid_method):
        uid, _gid = getpeereid_method()
        return int(uid)
    if hasattr(socket, "SO_PEERCRED"):
        raw = sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid)
    if platform.system() == "Darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        uid = ctypes.c_uint()
        gid = ctypes.c_uint()
        getpeereid = libc.getpeereid
        getpeereid.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint),
            ctypes.POINTER(ctypes.c_uint),
        ]
        getpeereid.restype = ctypes.c_int
        if getpeereid(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            errno = ctypes.get_errno()
            raise ProtocolError(f"getpeereid failed with errno {errno}")
        return int(uid.value)
    raise ProtocolError("Unix peer credentials are unavailable on this platform")


def signed_request(
    client_key: bytes,
    *,
    sequence: int,
    nonce: str,
    method: str,
    body: dict[str, Any],
) -> dict[str, Any]:
    unsigned = {
        "protocol": "hermes.kanban_broker_rpc.v1",
        "sequence": int(sequence),
        "nonce": str(nonce),
        "method": str(method),
        "body": body,
    }
    message = dict(unsigned)
    message["mac"] = hmac.new(
        client_key, _canonical(unsigned), hashlib.sha256
    ).hexdigest()
    return message


class BrokerRPCServer:
    """Surface-scoped request verifier and broker method dispatcher.

    Production uses one instance per launchd Unix socket with a distinct peer
    UID and client key.  The authority/receipt key is never reused here.
    """

    def __init__(
        self,
        *,
        broker,
        surface: str,
        allowed_uid: int,
        client_key: bytes,
        worker_socket: Path | None = None,
    ) -> None:
        if surface not in {"controller", "publisher", "operator"}:
            raise ValueError("unknown broker RPC surface")
        if len(client_key) != 32:
            raise ValueError("broker client key must be 32 bytes")
        self.broker = broker
        self.surface = surface
        self.allowed_uid = int(allowed_uid)
        self.client_key = bytes(client_key)
        self.worker_socket = Path(worker_socket) if worker_socket is not None else None
        self.quiesce_callback = None
        self.quiesce_status_callback = None
        self.quiescing_callback = None
        self.mutation_admission_callback = None
        self.mutation_release_callback = None
        self.background_dispatch_callback = None

    def dispatch(self, *, peer_uid: int, message: dict[str, Any]) -> dict[str, Any]:
        if int(peer_uid) != self.allowed_uid:
            raise ProtocolError("broker peer UID is not authorized")
        if message.get("protocol") != "hermes.kanban_broker_rpc.v1":
            raise ProtocolError("unsupported broker RPC protocol")
        try:
            sequence = int(message["sequence"])
            nonce = str(message["nonce"])
            supplied = str(message["mac"])
            method = str(message["method"])
            body = message["body"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("malformed broker RPC request") from exc
        if not nonce or sequence <= 0:
            raise ProtocolError("broker RPC replay fields are invalid")
        unsigned = {key: value for key, value in message.items() if key != "mac"}
        expected = hmac.new(
            self.client_key, _canonical(unsigned), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise ProtocolError("broker RPC authentication failed")
        if not isinstance(body, dict):
            raise ProtocolError("broker RPC body must be an object")
        mutating = (self.surface, method) in {
            ("controller", "trusted_create"),
            ("controller", "request_publish_correction"),
            ("controller", "dispatch_task"),
            ("publisher", "export_bundle"),
            ("publisher", "ack_publish"),
            ("operator", "register_repository"),
            ("operator", "refresh_repository_base"),
        }
        admitted = False
        if mutating and self.mutation_admission_callback is not None:
            admitted = bool(self.mutation_admission_callback())
            if not admitted:
                raise ProtocolError("dedicated broker is quiescing")
        elif (
            mutating
            and self.quiescing_callback is not None
            and self.quiescing_callback()
        ):
            raise ProtocolError("dedicated broker is quiescing")
        try:
            try:
                self.broker.consume_rpc_request(
                    surface=self.surface,
                    sequence=sequence,
                    nonce=nonce,
                    request_sha256=hashlib.sha256(_canonical(unsigned)).hexdigest(),
                )
            except BrokerError as exc:
                raise ProtocolError(str(exc)) from exc
            result = self._invoke(peer_uid=peer_uid, method=method, body=body)
        finally:
            if admitted and self.mutation_release_callback is not None:
                self.mutation_release_callback()
        return {"ok": True, "result": result}

    def _invoke(
        self, *, peer_uid: int, method: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        if self.surface == "controller" and method == "trusted_create":
            result = self.broker.trusted_create(peer_uid=peer_uid, request=body)
        elif self.surface == "controller" and method == "request_publish_correction":
            result = self.broker.request_publish_correction(
                peer_uid=peer_uid, request=body
            )
        elif self.surface == "controller" and method == "dispatch_task":
            if set(body) != {"task_id", "operation_id"}:
                raise ProtocolError("dispatch_task contains unsupported fields")
            if self.worker_socket is None:
                raise ProtocolError("broker worker endpoint is not configured")
            result = self.broker.begin_dispatch(
                task_id=str(body["task_id"]),
                operation_id=str(body["operation_id"]),
            )
            start_required = result.pop("start_required")
            if start_required:
                if self.background_dispatch_callback is None:
                    raise ProtocolError("broker dispatch executor is unavailable")
                self.background_dispatch_callback(
                    operation_id=str(body["operation_id"]),
                    worker_socket=self.worker_socket,
                )
        elif self.surface == "controller" and method == "dispatch_status":
            if set(body) != {"operation_id"}:
                raise ProtocolError("dispatch_status contains unsupported fields")
            result = self.broker.dispatch_operation_status(
                peer_uid=peer_uid,
                operation_id=str(body["operation_id"]),
            )
        elif self.surface == "publisher" and method == "verify_receipt":
            if set(body) != {"receipt_id", "payload_sha256"}:
                raise ProtocolError("verify_receipt contains unsupported fields")
            result = self.broker.verify_publish_receipt(
                peer_uid=peer_uid,
                receipt_id=str(body.get("receipt_id") or ""),
                payload_sha256=str(body.get("payload_sha256") or ""),
            )
        elif self.surface == "publisher" and method == "list_publish_obligations":
            result = self.broker.list_publish_obligations(
                peer_uid=peer_uid,
                query=body,
            )
        elif self.surface == "publisher" and method == "export_bundle":
            if set(body) != {"receipt_id", "payload_sha256"}:
                raise ProtocolError("export_bundle contains unsupported fields")
            result = self.broker.export_publish_bundle(
                peer_uid=peer_uid,
                receipt_id=str(body.get("receipt_id") or ""),
                payload_sha256=str(body.get("payload_sha256") or ""),
            )
        elif self.surface == "publisher" and method == "ack_publish":
            result = self.broker.acknowledge_publish(
                peer_uid=peer_uid,
                acknowledgement=body,
            )
        elif self.surface == "publisher" and method == "verify_completion":
            if set(body) != {"completion_id", "payload_sha256"}:
                raise ProtocolError("verify_completion contains unsupported fields")
            result = self.broker.verify_publish_completion(
                peer_uid=peer_uid,
                completion_id=str(body.get("completion_id") or ""),
                payload_sha256=str(body.get("payload_sha256") or ""),
            )
        elif self.surface == "publisher" and method == "list_completion_obligations":
            result = self.broker.list_publish_completions(
                peer_uid=peer_uid,
                query=body,
            )
        elif self.surface == "operator" and method == "register_repository":
            allowed = {
                "repository_id",
                "source_path",
                "default_branch",
                "project_id",
                "remote_repository",
            }
            # Registration is a source-binding operation.  An operator must
            # carry the reviewed immutable commit through the authenticated
            # wire request; allowing the field to be omitted would make the
            # broker silently trust whatever branch is currently checked out.
            expected_source_sha = body.get("expected_source_sha")
            if (
                not isinstance(expected_source_sha, str)
                or re.fullmatch(r"[0-9a-f]{40}", expected_source_sha) is None
            ):
                raise ProtocolError("register_repository expected_source_sha is required")
            if set(body) != allowed | {"expected_source_sha"}:
                raise ProtocolError("register_repository contains unsupported fields")
            result = self.broker.register_repository(
                peer_uid=peer_uid,
                repository_id=str(body.get("repository_id") or ""),
                source_path=body.get("source_path"),
                default_branch=str(body.get("default_branch") or ""),
                project_id=body.get("project_id"),
                remote_repository=body.get("remote_repository"),
                expected_source_sha=expected_source_sha,
            )
        elif self.surface == "operator" and method == "refresh_repository_base":
            if set(body) != {"repository_id", "expected_old_base_sha"}:
                raise ProtocolError(
                    "refresh_repository_base contains unsupported fields"
                )
            result = self.broker.refresh_repository_base(
                peer_uid=peer_uid,
                repository_id=str(body.get("repository_id") or ""),
                expected_old_base_sha=str(body.get("expected_old_base_sha") or ""),
            )
        elif self.surface == "operator" and method == "quiesce":
            if body.get("contract") != "hermes.kanban_broker_quiesce.v1":
                raise ProtocolError("unsupported broker quiesce contract")
            if self.quiesce_callback is None:
                raise ProtocolError("broker quiesce control is unavailable")
            status = self.quiesce_callback() or {}
            result = {
                "contract": "hermes.kanban_broker_quiesce.v1",
                "quiescing": True,
                **status,
            }
        elif self.surface == "operator" and method == "quiesce_status":
            if body.get("contract") != "hermes.kanban_broker_quiesce_status.v1":
                raise ProtocolError("unsupported broker quiesce status contract")
            if self.quiesce_status_callback is None:
                raise ProtocolError("broker quiesce status is unavailable")
            result = {
                "contract": "hermes.kanban_broker_quiesce_status.v1",
                **self.quiesce_status_callback(),
            }
        else:
            raise ProtocolError("method is unavailable on this broker surface")
        return result

    def handle_connection(self, conn: socket.socket) -> None:
        actual_uid = peer_uid(conn)
        try:
            response = self.dispatch(peer_uid=actual_uid, message=receive_frame(conn))
        except (ProtocolError, BrokerError, OSError, ValueError) as exc:
            response = {"ok": False, "error": str(exc)}
        try:
            send_frame(conn, response)
        except OSError:
            # A peer may disconnect after submitting a complete or malformed
            # request.  That connection is lost, but the serial broker service
            # must remain available for later authenticated clients.
            return

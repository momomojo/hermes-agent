"""Dedicated-identity authority and local-commit broker for Kanban workers.

This module is deliberately not activated by importing it.  A launchd daemon
running under a separate OS identity owns the state directory, receipt key,
authoritative task/run rows, and private Git repositories.  Model workers get
only a source workspace without ``.git`` and return untrusted result data.

The implementation contains no GitHub/publisher credential or network path.
Project-specific publishing is a separate consumer of verified receipts.
"""

from __future__ import annotations

import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import struct
import subprocess
import socket
import threading
import time
import unicodedata
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


KANBAN_BROKER_SECURITY_BOUNDARY = "hermes.dedicated_broker_identity.v1"
KANBAN_TRUSTED_CREATE_REQUEST = "hermes.kanban_trusted_create_request.v1"
KANBAN_DISPATCH_AUTHORITY_CONTRACT = "hermes.kanban_dispatch_authority.v1"
LOCAL_COMMIT_REQUEST_CONTRACT = "hermes.broker_local_commit_request.v1"
PUBLISH_CONTRACT = "hermes.trusted_local_commit.v1"
PUBLISH_MARKER = "AWAITING_TRUSTED_PUBLISHER v1"
PUBLISH_OBLIGATION_QUERY_CONTRACT = "hermes.publisher_obligation_query.v1"
PUBLISH_CORRECTION_REQUEST_CONTRACT = "hermes.publisher_correction_request.v1"
PUBLISH_OBJECT_HANDOFF_CONTRACT = "hermes.publisher_object_handoff.v1"
PUBLISH_ACK_CONTRACT = "hermes.publisher_ack.v1"
PUBLISH_COMPLETION_CONTRACT = "hermes.publisher_completion.v1"
PUBLISH_COMPLETION_QUERY_CONTRACT = "hermes.publisher_completion_query.v1"
BROKER_SCHEMA_VERSION = 1
_BROKER_SCHEMA_COLUMNS = {
    "broker_schema": ("singleton", "schema_version"),
    "repositories": (
        "repository_id", "private_path", "source_path", "default_branch",
        "base_sha", "fingerprint", "project_id", "remote_repository_json",
        "remote_repository_sha256",
    ),
    "tasks": (
        "task_id", "idempotency_key", "request_json", "authority_id",
        "authority_payload_json", "authority_payload_sha256", "authority_hmac",
        "key_id", "repository_id", "workspace_id", "workspace_path", "branch",
        "base_branch", "base_sha", "target_base_sha", "baseline_manifest_json",
        "baseline_manifest_sha256", "project_id", "board", "status",
        "claim_generation", "current_run_id", "workspace_dev", "workspace_ino",
        "created_at",
    ),
    "runs": (
        "run_id", "task_id", "claim_generation", "status", "created_at",
    ),
    "operations": (
        "operation_id", "task_id", "run_id", "request_json", "request_sha256",
        "state", "author_time", "candidate_blob", "candidate_blob_sha256",
        "tree_sha", "head_sha", "event_json",
    ),
    "dispatch_attempts": (
        "operation_id", "task_id", "run_id", "state", "failure_code",
        "timeout_seconds", "result_json", "created_at", "updated_at",
    ),
    "publish_receipts": (
        "receipt_id", "operation_id", "key_id", "payload_json",
        "payload_sha256", "receipt_hmac", "revoked", "created_at",
    ),
    "publish_exports": (
        "receipt_id", "receipt_payload_sha256", "bundle_path", "bundle_sha256",
        "bundle_size", "branch", "base_sha", "head_sha", "handoff_json",
        "created_at",
    ),
    "publish_acks": (
        "receipt_id", "request_json", "request_sha256", "state", "ack_json",
        "created_at", "updated_at",
    ),
    "publish_corrections": (
        "receipt_id", "request_json", "request_sha256", "response_json",
        "created_at",
    ),
    "publisher_completions": (
        "completion_id", "receipt_id", "repository_id", "completion_json",
        "payload_sha256", "completion_hmac", "created_at",
    ),
    "rpc_sequences": ("surface", "last_sequence"),
    "rpc_nonces": (
        "surface", "nonce", "sequence", "request_sha256", "created_at",
    ),
}
GITHUB_REPOSITORY_CONTRACT = "hermes.github_repository.v1"
GITHUB_PUBLISH_READBACK_CONTRACT = "hermes.github_publish_readback.v1"

_KEY_BYTES = 32
_ZERO_SHA = "0" * 40
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PROTECTED_BRANCHES = frozenset({
    "main",
    "master",
    "develop",
    "development",
    "production",
})
_CANDIDATE_MAGIC = b"HKBCAND1"
_RPC_REPLAY_WINDOW = 1024
_FIXED_GIT = Path("/usr/bin/git")
_FIXED_SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


class BrokerError(RuntimeError):
    """Base class for dedicated broker failures."""


class BrokerSecurityError(BrokerError):
    """An ownership, path, workspace, or ref invariant failed."""


class BrokerAuthorizationError(BrokerError):
    """The Unix peer is not authorized for the requested broker surface."""


class BrokerConflict(BrokerError):
    """A durable idempotency or compare-and-swap invariant failed."""


class BrokerInjectedCrash(BrokerError):
    """Test-only crash injection after a durable operation transition."""


class BrokerWorkerFailure(BrokerError):
    """The unprivileged reverse worker reported a failed model turn."""


def _serialized_broker_method(method):
    """Serialize one complete broker authority operation on the shared DB."""

    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._mutation_lock:
            return method(self, *args, **kwargs)

    return wrapped


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_identifier(value: object, *, field: str) -> str:
    value = str(value or "").strip()
    if not _SAFE_ID.fullmatch(value):
        raise BrokerSecurityError(f"unsafe {field}")
    return value


def _safe_object_sha(value: object, *, field: str) -> str:
    value = str(value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise BrokerSecurityError(f"unsafe {field}")
    return value


def _positive_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BrokerConflict(f"{field} must be a positive integer")
    return value


def _github_owner(value: Any) -> str:
    owner = str(value or "")
    if (
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
        or "--" in owner
    ):
        raise BrokerSecurityError("unsafe GitHub repository owner")
    return owner


def _github_name(value: Any) -> str:
    name = str(value or "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name) or name in {".", ".."}:
        raise BrokerSecurityError("unsafe GitHub repository name")
    return name


def _normalize_github_actor(value: Any, *, field: str) -> dict[str, Any]:
    """Normalize an operator-pinned GitHub user or bot identity."""

    if not isinstance(value, dict) or set(value) != {"id", "login", "type"}:
        raise BrokerSecurityError(f"GitHub {field} fields are not exact")
    actor_id = _positive_int(value.get("id"), field=f"{field} id")
    login = str(value.get("login") or "")
    actor_type = str(value.get("type") or "")
    if (
        not 1 <= len(login) <= 100
        or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\[bot\])?", login)
        or "--" in login
        or actor_type not in {"User", "Bot"}
    ):
        raise BrokerSecurityError(f"GitHub {field} is not canonical")
    return {"id": actor_id, "login": login, "type": actor_type}


def _normalize_github_repository(value: Any) -> dict[str, Any]:
    """Validate the operator-pinned GitHub target and release policy exactly."""

    if not isinstance(value, dict):
        raise BrokerSecurityError("GitHub repository binding must be an object")
    required = {
        "contract",
        "host",
        "owner",
        "name",
        "full_name",
        "repository_id",
        "canonical_url",
        "is_fork",
        "publication_policy",
    }
    if set(value) != required or value.get("contract") != GITHUB_REPOSITORY_CONTRACT:
        raise BrokerSecurityError("GitHub repository binding fields are not exact")
    owner = _github_owner(value.get("owner"))
    name = _github_name(value.get("name"))
    full_name = f"{owner}/{name}"
    repository_id = _positive_int(value.get("repository_id"), field="repository_id")
    if (
        value.get("host") != "github.com"
        or value.get("full_name") != full_name
        or value.get("canonical_url") != f"https://github.com/{full_name}"
        or value.get("is_fork") is not False
    ):
        raise BrokerSecurityError("GitHub repository binding is not canonical")
    policy = value.get("publication_policy")
    policy_fields = {
        "pull_request_base",
        "workflow_id",
        "workflow_name",
        "workflow_path",
        "workflow_event",
        "required_job_names",
        "required_app",
        "ready_label_actor",
        "ready_label",
    }
    if not isinstance(policy, dict) or set(policy) != policy_fields:
        raise BrokerSecurityError("GitHub publication policy fields are not exact")
    base = _safe_identifier(policy.get("pull_request_base"), field="PR base")
    workflow_id = _positive_int(policy.get("workflow_id"), field="workflow_id")
    workflow_name = str(policy.get("workflow_name") or "")
    workflow_path = str(policy.get("workflow_path") or "")
    if (
        not workflow_name
        or not re.fullmatch(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml", workflow_path)
        or policy.get("workflow_event") != "pull_request"
    ):
        raise BrokerSecurityError("GitHub workflow policy is not canonical")
    job_names = policy.get("required_job_names")
    if (
        not isinstance(job_names, list)
        or not 1 <= len(job_names) <= 64
        or any(
            not isinstance(item, str) or not item or len(item) > 256
            for item in job_names
        )
        or len(set(job_names)) != len(job_names)
    ):
        raise BrokerSecurityError("GitHub required jobs policy is invalid")
    app = policy.get("required_app")
    if not isinstance(app, dict) or set(app) != {"id", "slug"}:
        raise BrokerSecurityError("GitHub required App policy is invalid")
    app_id = _positive_int(app.get("id"), field="required App id")
    app_slug = _safe_identifier(app.get("slug"), field="required App slug")
    ready_label_actor = _normalize_github_actor(
        policy.get("ready_label_actor"), field="ready label actor"
    )
    ready_label = _safe_identifier(policy.get("ready_label"), field="ready label")
    return {
        "contract": GITHUB_REPOSITORY_CONTRACT,
        "host": "github.com",
        "owner": owner,
        "name": name,
        "full_name": full_name,
        "repository_id": repository_id,
        "canonical_url": f"https://github.com/{full_name}",
        "is_fork": False,
        "publication_policy": {
            "pull_request_base": base,
            "workflow_id": workflow_id,
            "workflow_name": workflow_name,
            "workflow_path": workflow_path,
            "workflow_event": "pull_request",
            "required_job_names": list(job_names),
            "required_app": {"id": app_id, "slug": app_slug},
            "ready_label_actor": ready_label_actor,
            "ready_label": ready_label,
        },
    }


def _validate_github_publish_readback(
    value: Any,
    *,
    event: dict[str, Any],
    registered_repository: dict[str, Any],
) -> dict[str, Any]:
    """Validate publisher-supplied GitHub API readback against pinned policy."""

    if not isinstance(value, dict) or set(value) != {
        "contract",
        "repository",
        "pull_request",
        "workflow",
        "ready_label",
    }:
        raise BrokerConflict("GitHub publish readback fields are not exact")
    if value.get("contract") != GITHUB_PUBLISH_READBACK_CONTRACT:
        raise BrokerConflict("GitHub publish readback contract is unsupported")
    try:
        repository = _normalize_github_repository(value.get("repository"))
    except BrokerSecurityError as exc:
        raise BrokerConflict(str(exc)) from exc
    if repository != registered_repository:
        raise BrokerConflict("GitHub publish readback repository is not registered")
    policy = registered_repository["publication_policy"]

    pull_request = value.get("pull_request")
    pr_fields = {
        "number",
        "url",
        "state",
        "is_draft",
        "head_repository_full_name",
        "head_repository_is_fork",
        "head_ref",
        "head_ref_full",
        "base_ref",
        "base_ref_full",
        "base_sha",
        "head_sha",
    }
    if not isinstance(pull_request, dict) or set(pull_request) != pr_fields:
        raise BrokerConflict("GitHub pull request readback fields are not exact")
    number = _positive_int(pull_request.get("number"), field="pull request number")
    expected_pr_url = f"{repository['canonical_url']}/pull/{number}"
    if (
        pull_request.get("url") != expected_pr_url
        or pull_request.get("state") != "open"
        or pull_request.get("is_draft") is not False
        or pull_request.get("head_repository_full_name") != repository["full_name"]
        or pull_request.get("head_repository_is_fork") is not False
        or pull_request.get("head_ref") != event["branch"]
        or pull_request.get("head_ref_full") != f"refs/heads/{event['branch']}"
        or pull_request.get("base_ref") != event["base_branch"]
        or pull_request.get("base_ref_full") != f"refs/heads/{event['base_branch']}"
        or pull_request.get("base_ref") != policy["pull_request_base"]
        or pull_request.get("base_sha") != event["target_base_sha"]
        or pull_request.get("head_sha") != event["head_sha"]
    ):
        raise BrokerConflict("GitHub pull request does not bind the exact publication")

    workflow = value.get("workflow")
    workflow_fields = {
        "workflow_id",
        "workflow_name",
        "workflow_path",
        "run_id",
        "newest_run_id_for_workflow_and_head",
        "run_attempt",
        "check_suite_id",
        "event",
        "head_sha",
        "status",
        "conclusion",
        "completed_at",
        "required_job_ids",
        "required_jobs",
    }
    if not isinstance(workflow, dict) or set(workflow) != workflow_fields:
        raise BrokerConflict("GitHub workflow readback fields are not exact")
    workflow_id = _positive_int(workflow.get("workflow_id"), field="workflow_id")
    run_id = _positive_int(workflow.get("run_id"), field="workflow run id")
    newest_run_id = _positive_int(
        workflow.get("newest_run_id_for_workflow_and_head"),
        field="newest workflow run id",
    )
    run_attempt = _positive_int(workflow.get("run_attempt"), field="run attempt")
    check_suite_id = _positive_int(
        workflow.get("check_suite_id"), field="check suite id"
    )
    completed_at = _positive_int(
        workflow.get("completed_at"), field="CI completion time"
    )
    if (
        workflow_id != policy["workflow_id"]
        or workflow.get("workflow_name") != policy["workflow_name"]
        or workflow.get("workflow_path") != policy["workflow_path"]
        or workflow.get("event") != policy["workflow_event"]
        or run_id != newest_run_id
        or workflow.get("head_sha") != event["head_sha"]
        or workflow.get("status") != "completed"
        or workflow.get("conclusion") != "success"
    ):
        raise BrokerConflict("GitHub workflow is not the newest exact-head success")
    required_jobs = workflow.get("required_jobs")
    required_job_ids = workflow.get("required_job_ids")
    if (
        not isinstance(required_jobs, list)
        or not isinstance(required_job_ids, list)
        or not 1 <= len(required_jobs) <= 64
        or len(required_jobs) != len(policy["required_job_names"])
    ):
        raise BrokerConflict("GitHub required job readback is incomplete")
    expected_app = policy["required_app"]
    seen_ids: list[int] = []
    seen_names: list[str] = []
    for job in required_jobs:
        job_fields = {
            "job_id",
            "check_run_id",
            "workflow_id",
            "workflow_run_id",
            "run_attempt",
            "check_suite_id",
            "name",
            "status",
            "conclusion",
            "head_sha",
            "app",
        }
        if not isinstance(job, dict) or set(job) != job_fields:
            raise BrokerConflict("GitHub required job fields are not exact")
        job_id = _positive_int(job.get("job_id"), field="job id")
        _positive_int(job.get("check_run_id"), field="check run id")
        job_workflow_id = _positive_int(
            job.get("workflow_id"), field="job workflow id"
        )
        job_run_id = _positive_int(
            job.get("workflow_run_id"), field="job workflow run id"
        )
        job_run_attempt = _positive_int(
            job.get("run_attempt"), field="job run attempt"
        )
        job_check_suite_id = _positive_int(
            job.get("check_suite_id"), field="job check suite id"
        )
        if (
            job_workflow_id != workflow_id
            or job_run_id != run_id
            or job_run_attempt != run_attempt
            or job_check_suite_id != check_suite_id
            or job.get("status") != "completed"
            or job.get("conclusion") != "success"
            or job.get("head_sha") != event["head_sha"]
            or job.get("app") != expected_app
        ):
            raise BrokerConflict("GitHub required job is not an exact-head App success")
        seen_ids.append(job_id)
        seen_names.append(str(job.get("name") or ""))
    if (
        required_job_ids != seen_ids
        or len(set(seen_ids)) != len(seen_ids)
        or seen_names != policy["required_job_names"]
    ):
        raise BrokerConflict("GitHub required job set does not match policy")

    label = value.get("ready_label")
    label_fields = {
        "name",
        "present",
        "label_event_id",
        "actor",
        "pull_request_number",
        "head_sha",
        "workflow_run_id",
        "check_suite_id",
        "event_created_at",
        "readback_at",
    }
    if not isinstance(label, dict) or set(label) != label_fields:
        raise BrokerConflict("GitHub ready-label readback fields are not exact")
    _positive_int(label.get("label_event_id"), field="label event id")
    try:
        label_actor = _normalize_github_actor(
            label.get("actor"), field="ready label actor"
        )
    except BrokerSecurityError as exc:
        raise BrokerConflict(str(exc)) from exc
    label_created_at = _positive_int(
        label.get("event_created_at"), field="label event time"
    )
    label_readback_at = _positive_int(
        label.get("readback_at"), field="label readback time"
    )
    if (
        label.get("name") != policy["ready_label"]
        or label.get("present") is not True
        or label_actor != policy["ready_label_actor"]
        or label.get("pull_request_number") != number
        or label.get("head_sha") != event["head_sha"]
        or label.get("workflow_run_id") != run_id
        or label.get("check_suite_id") != check_suite_id
        or not completed_at <= label_created_at <= label_readback_at
    ):
        raise BrokerConflict("GitHub ready label is not post-CI exact-head evidence")
    # Canonicalization also makes a later signed completion bind byte-for-byte.
    return json.loads(_canonical_json(value))


def _repository_fingerprint(
    *,
    repository_id: str,
    source_path: str,
    default_branch: str,
    base_sha: str,
    remote_repository: dict[str, Any],
) -> str:
    return _sha256_bytes(
        _canonical_json({
            "repository_id": repository_id,
            "source_path": source_path,
            "default_branch": default_branch,
            "base_sha": base_sha,
            "remote_repository": remote_repository,
        })
    )


def _safe_relative_path(value: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise BrokerSecurityError("unsafe workspace path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise BrokerSecurityError("unsafe workspace path")
    if any(_filesystem_component_key(part) == ".git" for part in pure.parts):
        raise BrokerSecurityError("Git metadata is forbidden in worker workspaces")
    return pure.as_posix()


def _filesystem_component_key(value: str) -> str:
    """Return a conservative APFS/HFS-equivalence key for one path component.

    Git treats tree names as opaque bytes while the default macOS filesystem is
    case-insensitive and normalization-insensitive.  HFS-style comparison also
    ignores formatting and variation characters.  Rejecting the conservative
    superset is safer than letting two Git names address one filesystem object.
    """

    normalized = unicodedata.normalize("NFD", str(value).casefold())
    visible: list[str] = []
    for character in normalized:
        codepoint = ord(character)
        if unicodedata.category(character) == "Cf":
            continue
        if character == "\u034f":  # COMBINING GRAPHEME JOINER
            continue
        if 0xFE00 <= codepoint <= 0xFE0F or 0xE0100 <= codepoint <= 0xE01EF:
            continue
        visible.append(character)
    return unicodedata.normalize("NFD", "".join(visible))


def _assert_no_filesystem_path_collisions(paths: Iterable[str]) -> None:
    """Reject distinct Git paths that macOS may resolve to the same object."""

    prefixes: dict[tuple[str, ...], tuple[str, ...]] = {}
    for value in sorted(paths):
        safe = _safe_relative_path(value)
        raw_parts = PurePosixPath(safe).parts
        normalized: list[str] = []
        raw_prefix: list[str] = []
        for part in raw_parts:
            normalized.append(_filesystem_component_key(part))
            raw_prefix.append(part)
            key = tuple(normalized)
            raw = tuple(raw_prefix)
            prior = prefixes.get(key)
            if prior is not None and prior != raw:
                raise BrokerSecurityError(
                    "workspace contains filesystem-equivalent path names"
                )
            prefixes[key] = raw


def _encode_candidate_snapshot(candidate: dict[str, dict[str, Any]]) -> bytes:
    """Serialize broker-read bytes into one immutable private journal blob."""

    _assert_no_filesystem_path_collisions(candidate)
    payload = bytearray(_CANDIDATE_MAGIC)
    payload.extend(struct.pack("!I", len(candidate)))
    total = 0
    for path, entry in sorted(candidate.items()):
        safe = _safe_relative_path(path)
        encoded_path = safe.encode("utf-8")
        content = bytes(entry["content"])
        total += len(content)
        if len(encoded_path) > 65535 or total > 256 * 1024 * 1024:
            raise BrokerSecurityError("candidate snapshot exceeds broker limits")
        mode = entry["mode"]
        if mode not in {"100644", "100755"}:
            raise BrokerSecurityError("candidate snapshot contains an unsafe mode")
        payload.extend(struct.pack("!H", len(encoded_path)))
        payload.extend(encoded_path)
        payload.extend(b"\x01" if mode == "100755" else b"\x00")
        payload.extend(struct.pack("!Q", len(content)))
        payload.extend(content)
    return bytes(payload)


def _decode_candidate_snapshot(payload: bytes) -> dict[str, dict[str, Any]]:
    """Decode and revalidate one private candidate journal blob."""

    view = memoryview(payload)
    cursor = len(_CANDIDATE_MAGIC)
    if len(view) < cursor + 4 or bytes(view[:cursor]) != _CANDIDATE_MAGIC:
        raise BrokerSecurityError("candidate snapshot journal is malformed")
    (count,) = struct.unpack("!I", view[cursor : cursor + 4])
    cursor += 4
    if count > 10000:
        raise BrokerSecurityError("candidate snapshot exceeds broker file limit")
    candidate: dict[str, dict[str, Any]] = {}
    total = 0
    for _index in range(count):
        if len(view) < cursor + 2:
            raise BrokerSecurityError("candidate snapshot journal is truncated")
        (path_size,) = struct.unpack("!H", view[cursor : cursor + 2])
        cursor += 2
        if path_size <= 0 or len(view) < cursor + path_size + 9:
            raise BrokerSecurityError("candidate snapshot journal is truncated")
        try:
            path = _safe_relative_path(
                bytes(view[cursor : cursor + path_size]).decode("utf-8", "strict")
            )
        except UnicodeDecodeError as exc:
            raise BrokerSecurityError(
                "candidate snapshot path is not valid UTF-8"
            ) from exc
        cursor += path_size
        mode_byte = int(view[cursor])
        cursor += 1
        if mode_byte not in {0, 1}:
            raise BrokerSecurityError("candidate snapshot contains an unsafe mode")
        (content_size,) = struct.unpack("!Q", view[cursor : cursor + 8])
        cursor += 8
        total += int(content_size)
        if (
            content_size > 64 * 1024 * 1024
            or total > 256 * 1024 * 1024
            or len(view) < cursor + content_size
        ):
            raise BrokerSecurityError("candidate snapshot exceeds broker limits")
        content = bytes(view[cursor : cursor + content_size])
        cursor += content_size
        if path in candidate:
            raise BrokerSecurityError("candidate snapshot contains a duplicate path")
        candidate[path] = {
            "mode": "100755" if mode_byte else "100644",
            "sha256": _sha256_bytes(content),
            "size": len(content),
            "content": content,
        }
    if cursor != len(view):
        raise BrokerSecurityError("candidate snapshot contains trailing bytes")
    _assert_no_filesystem_path_collisions(candidate)
    return candidate


def _validate_owner_only_dir(path: Path, expected_uid: int) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BrokerSecurityError("broker state directory must be a real directory")
    if info.st_uid != expected_uid:
        raise BrokerSecurityError("broker state directory has wrong owner")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise BrokerSecurityError("broker state directory must have mode 0700")


def _validate_owner_file(path: Path, expected_uid: int, mode: int) -> None:
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise BrokerSecurityError(f"{path.name} must be a real file")
    if info.st_uid != expected_uid:
        raise BrokerSecurityError(f"{path.name} has wrong owner")
    if stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1:
        raise BrokerSecurityError(f"{path.name} must be mode {mode:04o} with one link")


def _validate_immutable_system_executable(path: Path) -> None:
    try:
        info = Path(path).lstat()
    except FileNotFoundError as exc:
        raise BrokerSecurityError(
            f"required system executable is missing: {path}"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o022
        or not stat.S_IMODE(info.st_mode) & 0o111
    ):
        raise BrokerSecurityError(f"system executable is mutable or unsafe: {path}")


class DedicatedKanbanBroker:
    """Stateful core used only by the dedicated launchd broker process."""

    def __init__(
        self,
        *,
        state_dir: Path,
        workspace_root: Path,
        broker_uid: int,
        controller_uid: int,
        publisher_uid: int,
        operator_uid: int = 0,
        worker_uid: int | None = None,
        workspace_gid: int | None = None,
        publisher_handoff_root: Path | None = None,
        publisher_gid: int | None = None,
        trusted_publisher_enabled: bool = False,
    ) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.workspace_root = Path(workspace_root).expanduser()
        if not self.state_dir.is_absolute() or not self.workspace_root.is_absolute():
            raise BrokerSecurityError(
                "broker state and workspace roots must be absolute"
            )
        self.broker_uid = int(broker_uid)
        self.controller_uid = int(controller_uid)
        self.publisher_uid = int(publisher_uid)
        self.operator_uid = int(operator_uid)
        self.worker_uid = int(controller_uid if worker_uid is None else worker_uid)
        if workspace_gid is None:
            workspace_gid = os.getegid()  # windows-footgun: ok - macOS broker only
        if publisher_gid is None:
            publisher_gid = os.getegid()  # windows-footgun: ok - macOS broker only
        self.workspace_gid = int(workspace_gid)
        self.publisher_gid = int(publisher_gid)
        self.publisher_handoff_root = Path(
            publisher_handoff_root
            if publisher_handoff_root is not None
            else self.workspace_root.parent / "publisher-handoffs"
        ).expanduser()
        if not self.publisher_handoff_root.is_absolute():
            raise BrokerSecurityError("publisher handoff root must be absolute")
        roots = (self.state_dir, self.workspace_root, self.publisher_handoff_root)
        for index, left in enumerate(roots):
            for right in roots[index + 1 :]:
                if left == right or left in right.parents or right in left.parents:
                    raise BrokerSecurityError(
                        "private, workspace, and publisher roots must be disjoint"
                    )
        self.trusted_publisher_enabled = trusted_publisher_enabled is True
        self._mutation_lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self._key: bytes | None = None

    @contextmanager
    def serialized_transaction(self):
        """Hold the process-wide authority lock across an explicit transaction."""

        with self._mutation_lock:
            yield

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise BrokerError("broker is not initialized")
        return self._conn

    @property
    def key(self) -> bytes:
        if self._key is None:
            raise BrokerError("broker is not initialized")
        return self._key

    @_serialized_broker_method
    def initialize(self) -> None:
        _validate_immutable_system_executable(_FIXED_GIT)
        if self.state_dir.exists() or self.state_dir.is_symlink():
            _validate_owner_only_dir(self.state_dir, self.broker_uid)
        else:
            self.state_dir.mkdir(parents=True, mode=0o700)
            self.state_dir.chmod(0o700)
            _validate_owner_only_dir(self.state_dir, self.broker_uid)

        repositories = self.state_dir / "repositories"
        operations = self.state_dir / "operations"
        for directory in (repositories, operations):
            if directory.exists() or directory.is_symlink():
                _validate_owner_only_dir(directory, self.broker_uid)
            else:
                directory.mkdir(mode=0o700)
                directory.chmod(0o700)

        key_path = self.state_dir / "authority.key"
        if key_path.exists() or key_path.is_symlink():
            _validate_owner_file(key_path, self.broker_uid, 0o600)
            self._key = key_path.read_bytes()
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(key_path, flags, 0o600)
            try:
                self._key = secrets.token_bytes(_KEY_BYTES)
                os.write(fd, self._key)
                os.fsync(fd)
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            _validate_owner_file(key_path, self.broker_uid, 0o600)
        if len(self.key) != _KEY_BYTES:
            raise BrokerSecurityError("authority key has invalid length")

        db_path = self.state_dir / "broker.sqlite3"
        # The launchd service owns one serial accept loop, but may construct the
        # broker before transferring that loop to its serving thread.
        self._conn = sqlite3.connect(
            db_path,
            isolation_level="IMMEDIATE",
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS broker_schema (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                schema_version INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO broker_schema(singleton, schema_version)
            VALUES (1, 1);
            CREATE TABLE IF NOT EXISTS repositories (
                repository_id TEXT PRIMARY KEY,
                private_path TEXT NOT NULL UNIQUE,
                source_path TEXT NOT NULL UNIQUE,
                default_branch TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                project_id TEXT,
                remote_repository_json TEXT NOT NULL,
                remote_repository_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                request_json TEXT NOT NULL,
                authority_id TEXT NOT NULL UNIQUE,
                authority_payload_json TEXT NOT NULL,
                authority_payload_sha256 TEXT NOT NULL,
                authority_hmac BLOB NOT NULL,
                key_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL UNIQUE,
                workspace_path TEXT NOT NULL UNIQUE,
                branch TEXT NOT NULL UNIQUE,
                base_branch TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                target_base_sha TEXT NOT NULL,
                baseline_manifest_json TEXT NOT NULL,
                baseline_manifest_sha256 TEXT NOT NULL,
                project_id TEXT,
                board TEXT NOT NULL,
                status TEXT NOT NULL,
                claim_generation INTEGER NOT NULL DEFAULT 0,
                current_run_id INTEGER,
                workspace_dev INTEGER,
                workspace_ino INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(repository_id) REFERENCES repositories(repository_id)
            );
            CREATE TABLE IF NOT EXISTS runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                claim_generation INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(task_id),
                UNIQUE(task_id, claim_generation)
            );
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                run_id INTEGER NOT NULL,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                author_time INTEGER NOT NULL,
                candidate_blob BLOB,
                candidate_blob_sha256 TEXT,
                tree_sha TEXT,
                head_sha TEXT,
                event_json TEXT,
                UNIQUE(task_id, run_id)
            );
            CREATE TABLE IF NOT EXISTS dispatch_attempts (
                operation_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                run_id INTEGER NOT NULL UNIQUE,
                state TEXT NOT NULL,
                failure_code TEXT,
                timeout_seconds REAL NOT NULL,
                result_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(task_id) REFERENCES tasks(task_id),
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            );
            CREATE TABLE IF NOT EXISTS publish_receipts (
                receipt_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL UNIQUE,
                key_id TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                receipt_hmac BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS publish_exports (
                receipt_id TEXT PRIMARY KEY,
                receipt_payload_sha256 TEXT NOT NULL,
                bundle_path TEXT NOT NULL UNIQUE,
                bundle_sha256 TEXT NOT NULL,
                bundle_size INTEGER NOT NULL,
                branch TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                handoff_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(receipt_id) REFERENCES publish_receipts(receipt_id)
            );
            CREATE TABLE IF NOT EXISTS publish_acks (
                receipt_id TEXT PRIMARY KEY,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                state TEXT NOT NULL,
                ack_json TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(receipt_id) REFERENCES publish_receipts(receipt_id)
            );
            CREATE TABLE IF NOT EXISTS publish_corrections (
                receipt_id TEXT PRIMARY KEY,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(receipt_id) REFERENCES publish_receipts(receipt_id)
            );
            CREATE TABLE IF NOT EXISTS publisher_completions (
                completion_id TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL UNIQUE,
                repository_id TEXT NOT NULL,
                completion_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL,
                completion_hmac BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(receipt_id) REFERENCES publish_receipts(receipt_id)
            );
            CREATE TABLE IF NOT EXISTS rpc_sequences (
                surface TEXT PRIMARY KEY,
                last_sequence INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rpc_nonces (
                surface TEXT NOT NULL,
                nonce TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                request_sha256 TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(surface, nonce),
                UNIQUE(surface, sequence)
            );
            """
        )
        self._validate_database_schema()
        db_path.chmod(0o600)
        _validate_owner_file(db_path, self.broker_uid, 0o600)

        if self.workspace_root.exists() or self.workspace_root.is_symlink():
            info = self.workspace_root.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise BrokerSecurityError("workspace root must be a real directory")
            if info.st_uid != self.broker_uid:
                raise BrokerSecurityError("workspace root has wrong owner")
        else:
            self.workspace_root.mkdir(parents=True, mode=0o710)
        os.chown(self.workspace_root, -1, self.workspace_gid)
        self.workspace_root.chmod(0o710)

        if (
            self.publisher_handoff_root.exists()
            or self.publisher_handoff_root.is_symlink()
        ):
            handoff_info = self.publisher_handoff_root.lstat()
            if stat.S_ISLNK(handoff_info.st_mode) or not stat.S_ISDIR(
                handoff_info.st_mode
            ):
                raise BrokerSecurityError(
                    "publisher handoff root must be a real directory"
                )
            if handoff_info.st_uid != self.broker_uid:
                raise BrokerSecurityError("publisher handoff root has wrong owner")
        else:
            self.publisher_handoff_root.mkdir(parents=True, mode=0o710)
        os.chown(self.publisher_handoff_root, -1, self.publisher_gid)
        self.publisher_handoff_root.chmod(0o710)
        self.recover_incomplete_dispatches()
        self.recover_publish_acknowledgements()

    def _validate_database_schema(self) -> None:
        """Require an explicit version and exact authority-bearing columns."""

        try:
            row = self.conn.execute(
                "SELECT singleton, schema_version FROM broker_schema"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise BrokerSecurityError("broker database schema version is unavailable") from exc
        if len(row) != 1 or tuple(row[0]) != (1, BROKER_SCHEMA_VERSION):
            raise BrokerSecurityError("broker database schema version is unsupported")
        tables = {
            str(record[0])
            for record in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        if tables != set(_BROKER_SCHEMA_COLUMNS):
            raise BrokerSecurityError("broker database table schema is not exact")
        for table, expected_columns in _BROKER_SCHEMA_COLUMNS.items():
            observed = tuple(
                str(record[1])
                for record in self.conn.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            )
            if observed != expected_columns:
                raise BrokerSecurityError(
                    f"broker database column schema is not exact: {table}"
                )

    @_serialized_broker_method
    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        self._key = None

    def _remove_sealed_workspace(self, task: sqlite3.Row) -> bool:
        """Remove one exact sealed workspace without following worker paths."""

        root = Path(task["workspace_path"])
        if not root.exists() and not root.is_symlink():
            with self.conn:
                self.conn.execute(
                    "UPDATE tasks SET workspace_dev=NULL, workspace_ino=NULL "
                    "WHERE task_id=?",
                    (task["task_id"],),
                )
            return True
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            root_fd = os.open(root, flags)
        except OSError:
            return False
        root_info = os.fstat(root_fd)
        expected = (
            int(task["workspace_dev"] or -1),
            int(task["workspace_ino"] or -1),
        )
        if expected != (int(root_info.st_dev), int(root_info.st_ino)):
            os.close(root_fd)
            return False

        def clear(directory_fd: int, *, root_dev: int) -> None:
            for name in os.listdir(directory_fd):
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                    if int(info.st_dev) != int(root_dev):
                        raise BrokerSecurityError(
                            "worker workspace contains a foreign filesystem"
                        )
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if (opened.st_dev, opened.st_ino) != (
                            info.st_dev,
                            info.st_ino,
                        ):
                            raise BrokerSecurityError(
                                "worker directory changed during cleanup"
                            )
                        clear(child_fd, root_dev=root_dev)
                    finally:
                        os.close(child_fd)
                    os.rmdir(name, dir_fd=directory_fd)
                else:
                    os.unlink(name, dir_fd=directory_fd)

        try:
            clear(root_fd, root_dev=int(root_info.st_dev))
        except (OSError, BrokerSecurityError):
            os.close(root_fd)
            return False
        os.close(root_fd)
        try:
            current = root.lstat()
            if (current.st_dev, current.st_ino) != (
                root_info.st_dev,
                root_info.st_ino,
            ):
                return False
            os.rmdir(root)
        except OSError:
            return False
        with self.conn:
            self.conn.execute(
                "UPDATE tasks SET workspace_dev=NULL, workspace_ino=NULL "
                "WHERE task_id=?",
                (task["task_id"],),
            )
        return True

    @staticmethod
    def _retry_limit(task: sqlite3.Row) -> int:
        try:
            value = json.loads(task["request_json"]).get("max_retries")
            parsed = int(value or 0)
        except (TypeError, ValueError, json.JSONDecodeError):
            return 0
        return max(0, min(parsed, 10))

    def _transition_dispatch_failure(
        self,
        *,
        task_id: str,
        run_id: int,
        operation_id: str | None,
        failure_code: str,
        retryable: bool = True,
        error_type: str | None = None,
    ) -> None:
        """Durably leave no post-claim task or run in an orphan running state."""

        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task is None or int(task["current_run_id"] or 0) != int(run_id):
            raise BrokerConflict("dispatch failure references a stale run")
        cleanup_ok = self._remove_sealed_workspace(task)
        current_status = str(task["status"])
        may_retry = bool(
            retryable
            and cleanup_ok
            and current_status == "running"
            and int(task["claim_generation"]) < self._retry_limit(task)
        )
        task_status = "ready" if may_retry else "blocked"
        code = _safe_identifier(failure_code, field="failure_code")
        now = int(time.time())
        with self.conn:
            task_update = self.conn.execute(
                "UPDATE tasks SET status=? WHERE task_id=? AND current_run_id=? "
                "AND status IN ('running', 'blocked')",
                (task_status, task_id, int(run_id)),
            )
            run_update = self.conn.execute(
                "UPDATE runs SET status='failed' WHERE run_id=? AND task_id=? "
                "AND status IN ('running', 'blocked')",
                (int(run_id), task_id),
            )
            if task_update.rowcount != 1 or run_update.rowcount != 1:
                raise BrokerConflict("dispatch failure compare-and-swap failed")
            if operation_id is not None:
                dispatch_update = self.conn.execute(
                    "UPDATE dispatch_attempts SET state='FAILED', failure_code=?, "
                    "result_json=?, updated_at=? WHERE operation_id=? AND task_id=? AND run_id=? "
                    "AND state NOT IN ('SUCCEEDED', 'FAILED')",
                    (
                        code,
                        _canonical_json({
                            "contract": "hermes.broker_dispatch_operation.v1",
                            "operation_id": operation_id,
                            "task_id": task_id,
                            "run_id": int(run_id),
                            "state": "FAILED",
                            "terminal": True,
                            "failure_code": code,
                            "error_type": error_type,
                        }).decode("utf-8"),
                        now,
                        operation_id,
                        task_id,
                        int(run_id),
                    ),
                )
                if dispatch_update.rowcount != 1:
                    raise BrokerConflict("dispatch journal compare-and-swap failed")

    @_serialized_broker_method
    def recover_incomplete_dispatches(self) -> None:
        """Sweep runs left active by a prior broker process before serving RPC."""

        pending_operations = self.conn.execute(
            "SELECT o.operation_id, o.task_id, o.run_id "
            "FROM operations o JOIN tasks t ON t.task_id=o.task_id "
            "JOIN runs r ON r.run_id=o.run_id "
            "WHERE o.state IN ('SNAPSHOTTED', 'OBJECT_WRITTEN', 'REF_UPDATED') "
            "AND t.status='running' AND r.status='running'"
        ).fetchall()
        for operation in pending_operations:
            self.commit_run(
                task_id=operation["task_id"],
                run_id=int(operation["run_id"]),
                operation_id=operation["operation_id"],
                untrusted_worker_result={},
            )
        recovered_successes = self.conn.execute(
            "SELECT d.*, o.event_json FROM dispatch_attempts d "
            "JOIN operations o ON o.operation_id=d.operation_id "
            "WHERE d.state NOT IN ('SUCCEEDED', 'FAILED') AND o.state='EMITTED'"
        ).fetchall()
        for row in recovered_successes:
            event = json.loads(row["event_json"])
            result = {
                "contract": "hermes.broker_dispatch_operation.v1",
                "operation_id": row["operation_id"],
                "task_id": row["task_id"],
                "run_id": int(row["run_id"]),
                "state": "SUCCEEDED",
                "terminal": True,
                "failure_code": None,
                "event": event,
            }
            with self.conn:
                update = self.conn.execute(
                    "UPDATE dispatch_attempts SET state='SUCCEEDED', "
                    "failure_code=NULL, result_json=?, updated_at=? "
                    "WHERE operation_id=? AND state NOT IN ('SUCCEEDED', 'FAILED')",
                    (
                        _canonical_json(result).decode("utf-8"),
                        int(time.time()),
                        row["operation_id"],
                    ),
                )
                if update.rowcount != 1:
                    raise BrokerConflict("dispatch recovery compare-and-swap failed")
        rows = self.conn.execute(
            "SELECT t.*, r.run_id AS orphan_run_id, d.operation_id AS dispatch_operation "
            "FROM tasks t JOIN runs r ON r.run_id=t.current_run_id "
            "LEFT JOIN dispatch_attempts d ON d.run_id=r.run_id "
            "WHERE t.status='running' AND r.status='running'"
        ).fetchall()
        for row in rows:
            operation_id = row["dispatch_operation"]
            self._transition_dispatch_failure(
                task_id=row["task_id"],
                run_id=int(row["orphan_run_id"]),
                operation_id=operation_id,
                failure_code="broker_restart",
                retryable=True,
            )

    def _authorize(self, actual_uid: int, expected_uid: int, surface: str) -> None:
        if int(actual_uid) != int(expected_uid):
            raise BrokerAuthorizationError(f"peer is not authorized for {surface}")

    @_serialized_broker_method
    def consume_rpc_request(
        self, *, surface: str, sequence: int, nonce: str, request_sha256: str
    ) -> None:
        """Accept bounded out-of-order requests while rejecting durable replay."""
        if surface not in {"controller", "publisher", "operator"}:
            raise BrokerSecurityError("unknown broker RPC surface")
        if sequence <= 0 or not nonce or len(nonce) > 256:
            raise BrokerSecurityError("invalid broker RPC replay fields")
        with self.conn:
            prior = self.conn.execute(
                "SELECT last_sequence FROM rpc_sequences WHERE surface=?", (surface,)
            ).fetchone()
            high_water = int(prior["last_sequence"]) if prior is not None else 0
            if sequence <= max(0, high_water - _RPC_REPLAY_WINDOW):
                raise BrokerConflict("broker RPC replay rejected")
            try:
                self.conn.execute(
                    "INSERT INTO rpc_nonces "
                    "(surface, nonce, sequence, request_sha256, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (surface, nonce, int(sequence), request_sha256, int(time.time())),
                )
            except sqlite3.IntegrityError as exc:
                raise BrokerConflict("broker RPC replay rejected") from exc
            next_high_water = max(high_water, int(sequence))
            self.conn.execute(
                "INSERT INTO rpc_sequences VALUES (?, ?) "
                "ON CONFLICT(surface) DO UPDATE SET last_sequence="
                "MAX(rpc_sequences.last_sequence, excluded.last_sequence)",
                (surface, next_high_water),
            )
            self.conn.execute(
                "DELETE FROM rpc_nonces WHERE surface=? AND sequence<=?",
                (surface, max(0, next_high_water - _RPC_REPLAY_WINDOW)),
            )

    def _git_env(self, **extra: str) -> dict[str, str]:
        env = {
            "PATH": _FIXED_SYSTEM_PATH,
            "TMPDIR": str(self.state_dir / "operations"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": str(self.state_dir),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_AUTHOR_NAME": "Hermes Dedicated Kanban Broker",
            "GIT_AUTHOR_EMAIL": "hermes-kanban@localhost.invalid",
            "GIT_COMMITTER_NAME": "Hermes Dedicated Kanban Broker",
            "GIT_COMMITTER_EMAIL": "hermes-kanban@localhost.invalid",
        }
        env.update(extra)
        return env

    def git_environment_for_test(self) -> dict[str, str]:
        return self._git_env()

    def _git(
        self,
        repository: Path,
        args: Iterable[str],
        *,
        input_bytes: bytes | None = None,
        env_extra: dict[str, str] | None = None,
    ) -> bytes:
        cmd = [
            str(_FIXED_GIT),
            "--no-replace-objects",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "tag.gpgSign=false",
            f"--git-dir={repository}",
            *list(args),
        ]
        result = subprocess.run(
            cmd,
            env=self._git_env(**(env_extra or {})),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=60,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or b"git failed").decode(
                "utf-8", "replace"
            )
            raise BrokerConflict("git operation failed: " + detail.strip()[:500])
        return result.stdout

    def _assert_repository_has_no_rewrites(self, repository: Path) -> None:
        """Reject every Git mechanism that can reinterpret nominal object IDs."""
        repository = Path(repository)
        for relative, label in (
            (Path("info") / "grafts", "graft"),
            (Path("objects") / "info" / "alternates", "object alternate"),
        ):
            control = repository / relative
            if control.exists() or control.is_symlink():
                raise BrokerSecurityError(f"repository contains a forbidden {label}")
        replace_refs = self._git(
            repository,
            ["for-each-ref", "--format=%(refname)", "refs/replace"],
        ).decode("utf-8", "strict")
        if replace_refs.strip():
            raise BrokerSecurityError("repository contains a forbidden replace ref")

    def _assert_trusted_source_checkout(self, source: Path) -> None:
        """Require an operator-selected checkout that the model cannot race.

        The private mirror is authoritative after registration, but its first
        import and any later explicit operator refresh still read this path.
        Every Git control inode and every traversed parent therefore has to be
        owned by root, the operator, or the broker and not writable by an
        untrusted group/world identity.  A root-owned sticky system temporary
        parent is safe because another UID cannot rename the selected child.
        """

        source = Path(source)
        trusted_owners = {0, self.operator_uid, self.broker_uid}
        current = source
        while True:
            info = current.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid not in trusted_owners
                or (mode & 0o022 and not (info.st_uid == 0 and mode & stat.S_ISVTX))
            ):
                raise BrokerSecurityError(
                    "trusted checkout parent is model-mutable or unsafe"
                )
            if current.parent == current:
                break
            current = current.parent

        git_dir = source / ".git"
        pending = [git_dir]
        while pending:
            path = pending.pop()
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if (
                stat.S_ISLNK(info.st_mode)
                or info.st_uid not in trusted_owners
                or mode & 0o022
            ):
                raise BrokerSecurityError(
                    "trusted checkout Git metadata is model-mutable or unsafe"
                )
            if stat.S_ISDIR(info.st_mode):
                pending.extend(path.iterdir())
            elif not stat.S_ISREG(info.st_mode):
                raise BrokerSecurityError(
                    "trusted checkout Git metadata contains a special file"
                )

    @_serialized_broker_method
    def register_repository(
        self,
        *,
        peer_uid: int,
        repository_id: str,
        source_path: Path,
        default_branch: str,
        project_id: str | None,
        remote_repository: dict[str, Any],
    ) -> dict[str, Any]:
        self._authorize(peer_uid, self.operator_uid, "repository registration")
        repository_id = _safe_identifier(repository_id, field="repository_id")
        default_branch = _safe_identifier(default_branch, field="default branch")
        canonical_remote = _normalize_github_repository(remote_repository)
        if (
            canonical_remote["publication_policy"]["pull_request_base"]
            != default_branch
        ):
            raise BrokerSecurityError(
                "GitHub publication policy base must equal the registered default branch"
            )
        remote_json = _canonical_json(canonical_remote).decode("utf-8")
        remote_sha = _sha256_bytes(remote_json.encode("utf-8"))
        source = Path(source_path).expanduser().resolve(strict=True)
        if not (source / ".git").is_dir():
            raise BrokerSecurityError(
                "operator repository is not a normal Git checkout"
            )
        self._assert_trusted_source_checkout(source)
        self._assert_repository_has_no_rewrites(source / ".git")
        private = self.state_dir / "repositories" / f"{repository_id}.git"
        existing = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id=?", (repository_id,)
        ).fetchone()
        if existing is not None:
            expected_fingerprint = _repository_fingerprint(
                repository_id=repository_id,
                source_path=str(source),
                default_branch=default_branch,
                base_sha=existing["base_sha"],
                remote_repository=canonical_remote,
            )
            if (
                existing["private_path"] != str(private.resolve(strict=True))
                or existing["source_path"] != str(source)
                or existing["default_branch"] != default_branch
                or existing["project_id"] != project_id
                or existing["remote_repository_json"] != remote_json
                or existing["remote_repository_sha256"] != remote_sha
                or existing["fingerprint"] != expected_fingerprint
            ):
                raise BrokerConflict("repository registration replay changed")
            self._assert_repository_has_no_rewrites(private)
            actual_base = (
                self
                ._git(private, ["rev-parse", f"refs/heads/{default_branch}"])
                .decode()
                .strip()
            )
            if actual_base != existing["base_sha"]:
                raise BrokerConflict("registered repository base no longer matches")
            return {
                "repository_id": repository_id,
                "source_path": str(source),
                "default_branch": default_branch,
                "base_sha": existing["base_sha"],
                "fingerprint": existing["fingerprint"],
                "project_id": project_id,
                "remote_repository": canonical_remote,
                "remote_repository_sha256": remote_sha,
            }
        if private.exists():
            # A prior process may have crashed after the private clone was
            # renamed but before the authoritative row committed.  Only the
            # exact broker-owned directory below the private repository root
            # is eligible for cleanup and deterministic replay.
            info = private.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != self.broker_uid
                or private.parent != self.state_dir / "repositories"
            ):
                raise BrokerConflict("orphan repository path is unsafe")
            shutil.rmtree(private)
        try:
            result = subprocess.run(
                [
                    str(_FIXED_GIT),
                    "--no-replace-objects",
                    "-c",
                    f"core.hooksPath={os.devnull}",
                    "clone",
                    "--mirror",
                    "--no-local",
                    str(source),
                    str(private),
                ],
                env=self._git_env(),
                capture_output=True,
                check=False,
                timeout=60,
            )
            if result.returncode != 0:
                raise BrokerConflict(
                    "repository registration failed: "
                    + (result.stderr or result.stdout).decode("utf-8", "replace")[:500]
                )
            self._assert_repository_has_no_rewrites(private)
            base_sha = (
                self
                ._git(private, ["rev-parse", f"refs/heads/{default_branch}"])
                .decode()
                .strip()
            )
        except Exception:
            if private.exists() and private.parent == self.state_dir / "repositories":
                shutil.rmtree(private)
            raise
        fingerprint = _repository_fingerprint(
            repository_id=repository_id,
            source_path=str(source),
            default_branch=default_branch,
            base_sha=base_sha,
            remote_repository=canonical_remote,
        )
        with self.conn:
            self.conn.execute(
                "INSERT INTO repositories "
                "(repository_id, private_path, source_path, default_branch, "
                "base_sha, fingerprint, project_id, remote_repository_json, "
                "remote_repository_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    repository_id,
                    str(private.resolve()),
                    str(source),
                    default_branch,
                    base_sha,
                    fingerprint,
                    project_id,
                    remote_json,
                    remote_sha,
                ),
            )
        return {
            "repository_id": repository_id,
            "source_path": str(source),
            "default_branch": default_branch,
            "base_sha": base_sha,
            "fingerprint": fingerprint,
            "project_id": project_id,
            "remote_repository": canonical_remote,
            "remote_repository_sha256": remote_sha,
        }

    @_serialized_broker_method
    def refresh_repository_base(
        self,
        *,
        peer_uid: int,
        repository_id: str,
        expected_old_base_sha: str,
    ) -> dict[str, Any]:
        """Import and CAS one trusted-checkout fast-forward as operator policy."""

        self._authorize(peer_uid, self.operator_uid, "repository refresh")
        repository_id = _safe_identifier(repository_id, field="repository_id")
        expected = _safe_object_sha(
            expected_old_base_sha, field="expected_old_base_sha"
        )
        row = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id=?", (repository_id,)
        ).fetchone()
        if row is None:
            raise BrokerConflict("repository is not registered")
        if row["base_sha"] != expected:
            raise BrokerConflict("repository base compare-and-swap failed")
        source = Path(row["source_path"]).resolve(strict=True)
        if not (source / ".git").is_dir():
            raise BrokerSecurityError("registered repository checkout is unavailable")
        self._assert_trusted_source_checkout(source)
        self._assert_repository_has_no_rewrites(source / ".git")
        new_base = (
            self
            ._git(
                source / ".git",
                ["rev-parse", f"refs/heads/{row['default_branch']}"],
            )
            .decode()
            .strip()
        )
        new_base = _safe_object_sha(new_base, field="new repository base")
        if new_base == expected:
            return {
                "contract": "hermes.repository_base_refresh.v1",
                "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
                "repository_id": repository_id,
                "base_advanced_from": expected,
                "base_advanced_to": new_base,
                "changed": False,
            }
        ancestor = subprocess.run(
            [
                str(_FIXED_GIT),
                "--no-replace-objects",
                "-c",
                f"core.hooksPath={os.devnull}",
                f"--git-dir={source / '.git'}",
                "merge-base",
                "--is-ancestor",
                expected,
                new_base,
            ],
            env=self._git_env(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        if ancestor.returncode != 0:
            raise BrokerConflict("repository refresh is not a fast-forward")
        private = Path(row["private_path"])
        self._assert_repository_has_no_rewrites(private)
        self._git(
            private,
            [
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                str(source),
                new_base,
            ],
        )
        ref = f"refs/heads/{row['default_branch']}"
        current = self._git(private, ["rev-parse", ref]).decode().strip()
        if current == expected:
            self._git(private, ["update-ref", ref, new_base, expected])
        elif current != new_base:
            raise BrokerConflict("repository protected base ref diverged")
        remote_repository = json.loads(row["remote_repository_json"])
        fingerprint = _repository_fingerprint(
            repository_id=repository_id,
            source_path=str(source),
            default_branch=row["default_branch"],
            base_sha=new_base,
            remote_repository=remote_repository,
        )
        with self.conn:
            update = self.conn.execute(
                "UPDATE repositories SET base_sha=?, fingerprint=? "
                "WHERE repository_id=? AND base_sha=?",
                (new_base, fingerprint, repository_id, expected),
            )
            if update.rowcount != 1:
                raise BrokerConflict("repository base compare-and-swap failed")
        return {
            "contract": "hermes.repository_base_refresh.v1",
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "repository_id": repository_id,
            "base_advanced_from": expected,
            "base_advanced_to": new_base,
            "changed": True,
        }

    @_serialized_broker_method
    def private_repository_path(self, repository_id: str) -> Path:
        row = self.conn.execute(
            "SELECT private_path FROM repositories WHERE repository_id = ?",
            (repository_id,),
        ).fetchone()
        if row is None:
            raise BrokerConflict("repository is not registered")
        return Path(row["private_path"])

    def _tree_manifest(
        self, repository: Path, commit: str
    ) -> dict[str, dict[str, Any]]:
        self._assert_repository_has_no_rewrites(repository)
        raw = self._git(repository, ["ls-tree", "-r", "-z", commit])
        manifest: dict[str, dict[str, Any]] = {}
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, separator, path_bytes = record.partition(b"\t")
            if not separator:
                raise BrokerSecurityError("malformed Git tree entry")
            mode, kind, object_sha = metadata.decode("ascii").split(" ", 2)
            path = _safe_relative_path(path_bytes.decode("utf-8", "strict"))
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise BrokerSecurityError(
                    "repository tree contains a symlink or special file"
                )
            content = self._git(repository, ["cat-file", "blob", object_sha])
            manifest[path] = {
                "mode": mode,
                "sha256": _sha256_bytes(content),
                "size": len(content),
            }
        _assert_no_filesystem_path_collisions(manifest)
        return manifest

    def _request_definition(self, request: dict[str, Any]) -> dict[str, Any]:
        if request.get("contract") != KANBAN_TRUSTED_CREATE_REQUEST:
            raise BrokerSecurityError("unsupported trusted-create contract")
        exact_fields = {
            "contract",
            "request_id",
            "board",
            "repository_id",
            "idempotency_key",
            "title",
            "body",
            "assignee",
            "created_by",
            "tenant",
            "priority",
            "requested_initial_status",
            "requested_workspace_kind",
            "requested_workspace_path",
            "requested_branch_name",
            "requested_project_id",
            "requested_triage",
            "parent_ids",
            "max_runtime_seconds",
            "skills",
            "max_retries",
            "model_override",
            "provider_override",
            "reasoning_effort",
            "goal_mode",
            "goal_max_turns",
            "session_id",
            "workflow_template_id",
            "current_step_key",
        }
        if not isinstance(request, dict) or set(request) != exact_fields:
            raise BrokerSecurityError("trusted-create fields are not exact")
        required_text = {
            "request_id",
            "board",
            "repository_id",
            "idempotency_key",
            "title",
            "body",
            "assignee",
            "created_by",
            "requested_initial_status",
            "requested_workspace_kind",
        }
        missing = sorted(
            key
            for key in required_text
            if not isinstance(request.get(key), str) or not request[key].strip()
        )
        if missing:
            raise BrokerSecurityError("trusted-create missing: " + ", ".join(missing))
        for field, maximum in (
            ("request_id", 128),
            ("board", 128),
            ("repository_id", 128),
            ("idempotency_key", 512),
            ("title", 1024),
            ("body", 1_000_000),
            ("assignee", 128),
            ("created_by", 128),
            ("requested_initial_status", 32),
            ("requested_workspace_kind", 32),
        ):
            value = request[field]
            if len(value.encode("utf-8")) > maximum or any(
                ord(character) < 32 and character not in {"\n", "\t"}
                for character in value
            ):
                raise BrokerSecurityError(f"trusted-create {field} is invalid")
        for field, maximum in (
            ("tenant", 128),
            ("requested_project_id", 128),
            ("model_override", 512),
            ("provider_override", 128),
            ("reasoning_effort", 32),
            ("session_id", 256),
            ("workflow_template_id", 256),
            ("current_step_key", 256),
        ):
            value = request[field]
            if value is not None and (
                not isinstance(value, str)
                or not value.strip()
                or len(value.encode("utf-8")) > maximum
                or any(ord(character) < 32 for character in value)
            ):
                raise BrokerSecurityError(f"trusted-create {field} is invalid")
        for field in ("parent_ids", "skills"):
            value = request[field]
            if (
                not isinstance(value, list)
                or len(value) > 128
                or any(
                    not isinstance(item, str)
                    or not item.strip()
                    or len(item.encode("utf-8")) > 256
                    or any(ord(character) < 32 for character in item)
                    for item in value
                )
            ):
                raise BrokerSecurityError("trusted-create list fields are invalid")
        if request.get("requested_branch_name") not in {None, ""}:
            raise BrokerSecurityError(
                "controller may not select an arbitrary task branch"
            )
        if (
            request.get("requested_workspace_kind") != "broker_workspace"
            or request.get("requested_workspace_path") is not None
        ):
            raise BrokerSecurityError(
                "trusted-create workspace authority must be broker-selected"
            )
        normalized = {
            key: request.get(key)
            for key in (
                "request_id",
                "board",
                "repository_id",
                "idempotency_key",
                "title",
                "body",
                "assignee",
                "created_by",
                "tenant",
                "priority",
                "requested_initial_status",
                "requested_branch_name",
                "requested_project_id",
                "requested_triage",
                "max_runtime_seconds",
                "max_retries",
                "model_override",
                "provider_override",
                "reasoning_effort",
                "goal_mode",
                "goal_max_turns",
                "session_id",
                "workflow_template_id",
                "current_step_key",
            )
        }
        normalized["contract"] = KANBAN_TRUSTED_CREATE_REQUEST
        normalized["requested_workspace_kind"] = "broker_workspace"
        normalized["requested_workspace_path"] = None
        normalized["parent_ids"] = sorted(
            set(value.strip() for value in request["parent_ids"])
        )
        normalized["skills"] = sorted(set(value.strip() for value in request["skills"]))
        if request["requested_initial_status"] != "ready":
            raise BrokerSecurityError("trusted-create initial status must be ready")
        if request["requested_triage"] is not False:
            raise BrokerSecurityError("trusted-create triage must be exact false")
        if not isinstance(request["goal_mode"], bool):
            raise BrokerSecurityError("trusted-create goal_mode must be boolean")
        for field, minimum, maximum in (
            ("priority", 0, 100),
            ("max_runtime_seconds", 1, 86400),
            ("max_retries", 0, 10),
        ):
            value = request[field]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise BrokerSecurityError(f"trusted-create {field} is invalid")
        goal_max_turns = request["goal_max_turns"]
        if request["goal_mode"]:
            if (
                isinstance(goal_max_turns, bool)
                or not isinstance(goal_max_turns, int)
                or not 1 <= goal_max_turns <= 1000
            ):
                raise BrokerSecurityError("trusted-create goal_max_turns is invalid")
        elif goal_max_turns is not None:
            raise BrokerSecurityError(
                "trusted-create goal_max_turns must be null when goal mode is false"
            )
        model_override = request["model_override"]
        provider_override = request["provider_override"]
        if provider_override is not None and model_override is None:
            raise BrokerSecurityError(
                "trusted-create provider override requires a model override"
            )
        from hermes_cli.kanban_db import normalize_reasoning_effort

        try:
            normalized["reasoning_effort"] = normalize_reasoning_effort(
                request["reasoning_effort"]
            )
        except ValueError as exc:
            raise BrokerSecurityError(
                "trusted-create reasoning_effort is invalid"
            ) from exc
        for field in (
            "tenant",
            "requested_project_id",
            "model_override",
            "provider_override",
            "session_id",
            "workflow_template_id",
            "current_step_key",
        ):
            value = normalized[field]
            normalized[field] = value.strip() if value is not None else None
        normalized["requested_triage"] = False
        normalized["goal_mode"] = request["goal_mode"]
        normalized["idempotency_key"] = str(normalized["idempotency_key"]).strip()
        normalized["request_id"] = _safe_identifier(
            str(normalized["request_id"] or ""), field="request_id"
        )
        normalized["repository_id"] = _safe_identifier(
            str(normalized["repository_id"] or ""), field="repository_id"
        )
        normalized["board"] = _safe_identifier(
            str(normalized["board"] or ""), field="board"
        )
        return normalized

    @_serialized_broker_method
    def trusted_create(
        self, *, peer_uid: int, request: dict[str, Any]
    ) -> dict[str, Any]:
        self._authorize(peer_uid, self.controller_uid, "trusted-create")
        definition = self._request_definition(request)
        canonical_definition = _canonical_json(definition).decode("utf-8")
        existing = self.conn.execute(
            "SELECT * FROM tasks WHERE idempotency_key = ?",
            (definition["idempotency_key"],),
        ).fetchone()
        if existing is not None:
            if existing["request_json"] != canonical_definition:
                old = json.loads(existing["request_json"])
                mismatches = sorted(
                    key
                    for key in set(old) | set(definition)
                    if old.get(key) != definition.get(key)
                )
                raise BrokerConflict(
                    "sealed idempotency collision differs in: " + ", ".join(mismatches)
                )
            verified = self.verify_dispatch_authority(existing["authority_id"])
            if not verified["verified"]:
                raise BrokerConflict("existing dispatch authority no longer verifies")
            return {
                "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
                "task_id": existing["task_id"],
                "receipt_id": existing["authority_id"],
                "status": existing["status"],
                "reused": True,
            }

        repository = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id = ?",
            (definition["repository_id"],),
        ).fetchone()
        if repository is None:
            raise BrokerConflict("trusted-create repository is not registered")
        if definition["requested_project_id"] != repository["project_id"]:
            raise BrokerConflict(
                "trusted-create project does not match repository registry"
            )
        task_id = "t_" + secrets.token_hex(8)
        authority_id = "ka_" + secrets.token_hex(16)
        workspace_id = "kw_" + secrets.token_hex(12)
        workspace_path = self.workspace_root / task_id
        branch = definition.get("requested_branch_name") or f"wt/{task_id}"
        leaf = branch.rsplit("/", 1)[-1]
        if (
            branch.casefold() in _PROTECTED_BRANCHES
            or leaf.casefold() in _PROTECTED_BRANCHES
        ):
            raise BrokerSecurityError("protected branch is not task-committable")
        base_sha = str(repository["base_sha"])
        target_base_sha = base_sha
        private = Path(repository["private_path"])
        baseline = self._tree_manifest(private, base_sha)
        baseline_bytes = _canonical_json(baseline)
        created_at = int(time.time())
        body = definition.get("body")
        payload = {
            "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "board": definition["board"],
            "request_id": definition["request_id"],
            "task_id": task_id,
            "title": definition["title"],
            "body": body,
            "body_sha256": _sha256_bytes(str(body).encode("utf-8"))
            if body is not None
            else None,
            "assignee": definition.get("assignee"),
            "profile": definition.get("assignee"),
            "created_by": definition["created_by"],
            "creation_origin": "broker_sealed",
            "created_at": created_at,
            "idempotency_key": definition["idempotency_key"],
            "tenant": definition.get("tenant"),
            "priority": definition["priority"],
            "requested_initial_status": definition["requested_initial_status"],
            "requested_workspace_kind": "broker_workspace",
            "requested_workspace_path": None,
            "requested_branch_name": definition.get("requested_branch_name"),
            "requested_project_id": definition.get("requested_project_id"),
            "requested_triage": definition["requested_triage"],
            "pre_dispatch_status": definition["requested_initial_status"],
            "workspace_kind": "broker_workspace",
            "workspace_path": str(workspace_path),
            "workspace_id": workspace_id,
            "workspace_baseline_sha256": _sha256_bytes(baseline_bytes),
            "branch_name": branch,
            "project_id": repository["project_id"],
            "repository_id": repository["repository_id"],
            "repository_fingerprint": repository["fingerprint"],
            "base_sha": base_sha,
            "target_base_sha": target_base_sha,
            "parent_ids": definition["parent_ids"],
            "max_runtime_seconds": definition.get("max_runtime_seconds"),
            "skills": definition["skills"],
            "max_retries": definition.get("max_retries"),
            "model_override": definition.get("model_override"),
            "provider_override": definition.get("provider_override"),
            "reasoning_effort": definition.get("reasoning_effort"),
            "goal_mode": definition["goal_mode"],
            "goal_max_turns": definition.get("goal_max_turns"),
            "session_id": definition.get("session_id"),
            "workflow_template_id": definition.get("workflow_template_id"),
            "current_step_key": definition.get("current_step_key"),
        }
        payload_bytes = _canonical_json(payload)
        payload_sha = _sha256_bytes(payload_bytes)
        receipt_hmac = hmac.new(self.key, payload_bytes, hashlib.sha256).digest()
        key_id = _sha256_bytes(self.key)[:24]
        with self.conn:
            self.conn.execute(
                "INSERT INTO tasks "
                "(task_id, idempotency_key, request_json, authority_id, "
                "authority_payload_json, authority_payload_sha256, authority_hmac, "
                "key_id, repository_id, workspace_id, workspace_path, branch, "
                "base_branch, base_sha, target_base_sha, baseline_manifest_json, "
                "baseline_manifest_sha256, project_id, board, status, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task_id,
                    definition["idempotency_key"],
                    canonical_definition,
                    authority_id,
                    payload_bytes.decode("utf-8"),
                    payload_sha,
                    receipt_hmac,
                    key_id,
                    repository["repository_id"],
                    workspace_id,
                    str(workspace_path),
                    branch,
                    repository["default_branch"],
                    base_sha,
                    target_base_sha,
                    baseline_bytes.decode("utf-8"),
                    _sha256_bytes(baseline_bytes),
                    repository["project_id"],
                    definition["board"],
                    definition["requested_initial_status"],
                    created_at,
                ),
            )
        return {
            "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
            "task_id": task_id,
            "receipt_id": authority_id,
            "status": "ready",
            "reused": False,
        }

    @_serialized_broker_method
    def verify_dispatch_authority(self, receipt_id: str) -> dict[str, Any]:
        row = self.conn.execute(
            "SELECT * FROM tasks WHERE authority_id = ?", (receipt_id,)
        ).fetchone()
        if row is None:
            return {"contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT, "verified": False}
        payload_bytes = row["authority_payload_json"].encode("utf-8")
        payload = json.loads(row["authority_payload_json"])
        field_map = {
            "task_id": row["task_id"],
            "idempotency_key": row["idempotency_key"],
            "repository_id": row["repository_id"],
            "workspace_id": row["workspace_id"],
            "workspace_path": row["workspace_path"],
            "branch_name": row["branch"],
            "base_sha": row["base_sha"],
            "target_base_sha": row["target_base_sha"],
            "project_id": row["project_id"],
            "board": row["board"],
            "workspace_baseline_sha256": row["baseline_manifest_sha256"],
        }
        mismatch_fields = sorted(
            key for key, value in field_map.items() if payload.get(key) != value
        )
        signature_valid = bool(
            _sha256_bytes(payload_bytes) == row["authority_payload_sha256"]
            and hmac.compare_digest(
                bytes(row["authority_hmac"]),
                hmac.new(self.key, payload_bytes, hashlib.sha256).digest(),
            )
        )
        row_matches_payload = not mismatch_fields
        return {
            "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "authority_id": row["authority_id"],
            "receipt_id": row["authority_id"],
            "key_id": row["key_id"],
            "payload": payload,
            "payload_sha256": row["authority_payload_sha256"],
            "signature_valid": signature_valid,
            "row_matches_payload": row_matches_payload,
            "mismatch_fields": mismatch_fields,
            "verified": bool(signature_valid and row_matches_payload),
            "claim_generation": int(row["claim_generation"]),
            "last_claimed_run_id": row["current_run_id"],
            "verification_source": "broker_rpc",
        }

    def _materialize_workspace(self, task: sqlite3.Row) -> None:
        workspace = Path(task["workspace_path"])
        if workspace.exists() or workspace.is_symlink():
            raise BrokerSecurityError("sealed worker workspace already exists")
        repository = self.private_repository_path(task["repository_id"])
        self._assert_repository_has_no_rewrites(repository)
        raw = self._git(repository, ["ls-tree", "-r", "-z", task["base_sha"]])
        entries: list[tuple[str, str, str]] = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, _, path_bytes = record.partition(b"\t")
            mode, kind, object_sha = metadata.decode("ascii").split(" ", 2)
            path = _safe_relative_path(path_bytes.decode("utf-8", "strict"))
            if kind != "blob" or mode not in {"100644", "100755"}:
                raise BrokerSecurityError(
                    "repository tree contains a symlink or special file"
                )
            entries.append((path, mode, object_sha))
        _assert_no_filesystem_path_collisions(path for path, _mode, _sha in entries)

        workspace.mkdir(mode=0o770)
        os.chown(workspace, -1, self.workspace_gid)
        workspace.chmod(0o2770)
        for path, mode, object_sha in entries:
            destination = workspace.joinpath(*PurePosixPath(path).parts)
            current = workspace
            for part in PurePosixPath(path).parts[:-1]:
                current = current / part
                if not current.exists():
                    current.mkdir(mode=0o770)
                info = current.lstat()
                if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                    raise BrokerSecurityError(
                        "workspace parent is not a real directory"
                    )
                os.chown(current, -1, self.workspace_gid)
                current.chmod(0o2770)
            content = self._git(repository, ["cat-file", "blob", object_sha])
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(destination, flags, 0o600)
            try:
                os.write(fd, content)
                os.fchown(fd, -1, self.workspace_gid)
                os.fchmod(fd, 0o770 if mode == "100755" else 0o660)
                os.fsync(fd)
            finally:
                os.close(fd)
        root_info = workspace.lstat()
        with self.conn:
            self.conn.execute(
                "UPDATE tasks SET workspace_dev=?, workspace_ino=? "
                "WHERE task_id=? AND workspace_dev IS NULL AND workspace_ino IS NULL",
                (int(root_info.st_dev), int(root_info.st_ino), task["task_id"]),
            )

    @staticmethod
    def _dispatch_envelope(task: sqlite3.Row) -> dict[str, Any]:
        return {
            "contract": "hermes.broker_reverse_worker_dispatch.v1",
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "task_id": task["task_id"],
            "run_id": int(task["current_run_id"]),
            "claim_generation": int(task["claim_generation"]),
            "workspace_id": task["workspace_id"],
            "workspace_path": task["workspace_path"],
            "repository_id": task["repository_id"],
            "branch": task["branch"],
            "base_branch": task["base_branch"],
            "base_sha": task["base_sha"],
            "target_base_sha": task["target_base_sha"],
            "task": json.loads(task["authority_payload_json"]),
        }

    @_serialized_broker_method
    def claim_for_dispatch(self, task_id: str) -> dict[str, Any]:
        with self.conn:
            task = self.conn.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if task is None or task["status"] != "ready":
                raise BrokerConflict("task is not ready for broker dispatch")
            receipt = self.verify_dispatch_authority(task["authority_id"])
            if not receipt["verified"]:
                raise BrokerConflict("task dispatch authority does not verify")
            generation = int(task["claim_generation"]) + 1
            now = int(time.time())
            cur = self.conn.execute(
                "UPDATE tasks SET status='running', claim_generation=?, current_run_id=NULL "
                "WHERE task_id=? AND status='ready' AND claim_generation=?",
                (generation, task_id, generation - 1),
            )
            if cur.rowcount != 1:
                raise BrokerConflict("task claim compare-and-swap failed")
            run_cur = self.conn.execute(
                "INSERT INTO runs (task_id, claim_generation, status, created_at) VALUES (?, ?, 'running', ?)",
                (task_id, generation, now),
            )
            if run_cur.lastrowid is None:
                raise BrokerConflict("task run insert did not return an identity")
            run_id = int(run_cur.lastrowid)
            self.conn.execute(
                "UPDATE tasks SET current_run_id=? WHERE task_id=? AND claim_generation=?",
                (run_id, task_id, generation),
            )
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()
        try:
            self._materialize_workspace(task)
        except Exception:
            with self.conn:
                self.conn.execute(
                    "UPDATE tasks SET status='blocked' WHERE task_id=?", (task_id,)
                )
                self.conn.execute(
                    "UPDATE runs SET status='blocked' WHERE run_id=?", (run_id,)
                )
            raise
        return self._dispatch_envelope(task)

    def _snapshot_workspace(
        self, task: sqlite3.Row
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        root = Path(task["workspace_path"])
        root_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            root_fd = os.open(root, root_flags)
        except OSError as exc:
            raise BrokerSecurityError(
                "sealed workspace root is not a real directory"
            ) from exc
        root_info = os.fstat(root_fd)
        if (
            int(task["workspace_dev"] or -1),
            int(task["workspace_ino"] or -1),
        ) != (int(root_info.st_dev), int(root_info.st_ino)):
            os.close(root_fd)
            raise BrokerSecurityError("sealed workspace root identity changed")
        candidate: dict[str, dict[str, Any]] = {}
        file_count = 0
        total_bytes = 0

        def visit(directory_fd: int, prefix: tuple[str, ...]) -> None:
            nonlocal file_count, total_bytes
            for name in sorted(os.listdir(directory_fd)):
                if name in {"", ".", ".."} or "/" in name or "\x00" in name:
                    raise BrokerSecurityError(
                        "worker workspace contains an unsafe entry"
                    )
                relative = _safe_relative_path(PurePosixPath(*prefix, name).as_posix())
                info_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info_before.st_mode):
                    raise BrokerSecurityError("worker workspace contains a symlink")
                if stat.S_ISDIR(info_before.st_mode):
                    flags = (
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0)
                    )
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened_dir = os.fstat(child_fd)
                        if (opened_dir.st_dev, opened_dir.st_ino) != (
                            info_before.st_dev,
                            info_before.st_ino,
                        ):
                            raise BrokerSecurityError(
                                "worker directory changed during safe open"
                            )
                        visit(child_fd, (*prefix, name))
                    finally:
                        os.close(child_fd)
                    continue
                if not stat.S_ISREG(info_before.st_mode) or info_before.st_nlink != 1:
                    raise BrokerSecurityError(
                        "worker workspace contains a special or hard-linked file"
                    )
                file_count += 1
                if file_count > 10000:
                    raise BrokerSecurityError(
                        "worker workspace exceeds broker file limit"
                    )
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(fd)
                    if (opened.st_dev, opened.st_ino) != (
                        info_before.st_dev,
                        info_before.st_ino,
                    ):
                        raise BrokerSecurityError(
                            "worker file changed during safe open"
                        )
                    chunks: list[bytes] = []
                    file_bytes = 0
                    while True:
                        chunk = os.read(fd, 1024 * 1024)
                        if not chunk:
                            break
                        file_bytes += len(chunk)
                        total_bytes += len(chunk)
                        if file_bytes > 64 * 1024 * 1024:
                            raise BrokerSecurityError(
                                "worker file exceeds broker size limit"
                            )
                        if total_bytes > 256 * 1024 * 1024:
                            raise BrokerSecurityError(
                                "worker workspace exceeds broker size limit"
                            )
                        chunks.append(chunk)
                    after = os.fstat(fd)
                    if (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                    ) != (
                        opened.st_dev,
                        opened.st_ino,
                        opened.st_size,
                        opened.st_mtime_ns,
                    ):
                        raise BrokerSecurityError("worker file changed during snapshot")
                finally:
                    os.close(fd)
                content = b"".join(chunks)
                candidate[relative] = {
                    "mode": "100755"
                    if info_before.st_mode & stat.S_IXUSR
                    else "100644",
                    "sha256": _sha256_bytes(content),
                    "size": len(content),
                    "content": content,
                }

        try:
            visit(root_fd, ())
        finally:
            os.close(root_fd)
        _assert_no_filesystem_path_collisions(candidate)
        baseline = json.loads(task["baseline_manifest_json"])
        changed: list[dict[str, Any]] = []
        for path in sorted(set(baseline) | set(candidate)):
            old = baseline.get(path)
            new = candidate.get(path)
            comparable = (
                None
                if new is None
                else {key: new[key] for key in ("mode", "sha256", "size")}
            )
            if old == comparable:
                continue
            operation = (
                "delete" if new is None else ("add" if old is None else "modify")
            )
            changed.append({
                "path": path,
                "operation": operation,
                "mode": new["mode"] if new else old["mode"],
                "sha256": new["sha256"] if new else None,
                "size": new["size"] if new else 0,
            })
        return candidate, changed

    def _build_commit(
        self,
        *,
        repository: Path,
        task: sqlite3.Row,
        operation_id: str,
        run_id: int,
        candidate: dict[str, Any],
        changed: list[dict[str, Any]],
        author_time: int,
    ) -> tuple[str, str]:
        self._assert_repository_has_no_rewrites(repository)
        _assert_no_filesystem_path_collisions(candidate)
        _assert_no_filesystem_path_collisions(entry["path"] for entry in changed)
        index = (
            self.state_dir
            / "operations"
            / f"{_safe_identifier(operation_id, field='operation_id')}.index"
        )
        index.unlink(missing_ok=True)
        env = {
            "GIT_INDEX_FILE": str(index),
            "GIT_AUTHOR_DATE": f"@{author_time} +0000",
            "GIT_COMMITTER_DATE": f"@{author_time} +0000",
        }
        self._git(repository, ["read-tree", task["base_sha"]], env_extra=env)
        index_records = bytearray()
        for entry in changed:
            path = entry["path"]
            if entry["operation"] == "delete":
                index_records.extend(f"0 {_ZERO_SHA}\t{path}\0".encode("utf-8"))
                continue
            blob = (
                self
                ._git(
                    repository,
                    ["hash-object", "-w", "--no-filters", "--stdin"],
                    input_bytes=candidate[path]["content"],
                )
                .decode()
                .strip()
            )
            index_records.extend(f"{entry['mode']} {blob}\t{path}\0".encode("utf-8"))
        self._git(
            repository,
            ["update-index", "-z", "--index-info"],
            input_bytes=bytes(index_records),
            env_extra=env,
        )
        tree_sha = self._git(repository, ["write-tree"], env_extra=env).decode().strip()
        message = (
            f"kanban({task['task_id']}): brokered worker change\n\n"
            f"Hermes-Broker-Operation: {operation_id}\n"
            f"Hermes-Kanban-Task: {task['task_id']}\n"
            f"Hermes-Kanban-Run: {run_id}\n"
            f"Hermes-Kanban-Base: {task['base_sha']}\n"
        ).encode("utf-8")
        head_sha = (
            self
            ._git(
                repository,
                ["commit-tree", tree_sha, "-p", task["base_sha"]],
                input_bytes=message,
                env_extra=env,
            )
            .decode()
            .strip()
        )
        index.unlink(missing_ok=True)
        return tree_sha, head_sha

    def _emit_event(self, operation: sqlite3.Row, task: sqlite3.Row) -> dict[str, Any]:
        request = json.loads(operation["request_json"])
        receipt_id = "klc_" + _sha256_bytes(operation["operation_id"].encode())[:32]
        key_id = _sha256_bytes(self.key)[:24]
        event = {
            "contract": PUBLISH_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "receipt_id": receipt_id,
            "key_id": key_id,
            "task_id": task["task_id"],
            "run_id": int(operation["run_id"]),
            "claim_generation": int(task["claim_generation"]),
            "dispatch_authority_receipt_id": task["authority_id"],
            "dispatch_authority_payload_sha256": task["authority_payload_sha256"],
            "project_id": task["project_id"],
            "board": task["board"],
            "repository_id": task["repository_id"],
            "repository_fingerprint": request["repository_fingerprint"],
            "remote_repository": request["remote_repository"],
            "remote_repository_sha256": request["remote_repository_sha256"],
            "workspace": task["workspace_path"],
            "workspace_id": task["workspace_id"],
            "workspace_manifest_sha256": request["candidate_manifest_sha256"],
            "branch": task["branch"],
            "base_branch": task["base_branch"],
            "base_sha": task["base_sha"],
            "target_base_sha": task["target_base_sha"],
            "head_sha": operation["head_sha"],
            "changed_paths": [entry["path"] for entry in request["changed_entries"]],
            "changed_entries": request["changed_entries"],
            "publisher_state": "awaiting"
            if self.trusted_publisher_enabled
            else "disabled",
            "reason": PUBLISH_MARKER if self.trusted_publisher_enabled else None,
        }
        payload_sha = _sha256_bytes(_canonical_json(event))
        event["payload_sha256"] = payload_sha
        event_bytes = _canonical_json(event)
        receipt_hmac = hmac.new(self.key, event_bytes, hashlib.sha256).digest()
        now = int(time.time())
        with self.conn:
            status = "blocked" if self.trusted_publisher_enabled else "done"
            task_update = self.conn.execute(
                "UPDATE tasks SET status=? "
                "WHERE task_id=? AND current_run_id=? AND claim_generation=? "
                "AND status='running'",
                (
                    status,
                    task["task_id"],
                    operation["run_id"],
                    task["claim_generation"],
                ),
            )
            run_update = self.conn.execute(
                "UPDATE runs SET status=? "
                "WHERE run_id=? AND task_id=? AND claim_generation=? AND status='running'",
                (
                    status,
                    operation["run_id"],
                    task["task_id"],
                    task["claim_generation"],
                ),
            )
            operation_update = self.conn.execute(
                "UPDATE operations SET state='EMITTED', event_json=? "
                "WHERE operation_id=? AND task_id=? AND run_id=? AND state='REF_UPDATED'",
                (
                    event_bytes.decode("utf-8"),
                    operation["operation_id"],
                    task["task_id"],
                    operation["run_id"],
                ),
            )
            if (
                task_update.rowcount != 1
                or run_update.rowcount != 1
                or operation_update.rowcount != 1
            ):
                raise BrokerConflict("receipt emission compare-and-swap failed")
            self.conn.execute(
                "INSERT INTO publish_receipts VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    receipt_id,
                    operation["operation_id"],
                    key_id,
                    event_bytes.decode("utf-8"),
                    payload_sha,
                    receipt_hmac,
                    now,
                ),
            )
        return event

    def _validated_operation_journal(
        self,
        *,
        operation: sqlite3.Row,
        task: sqlite3.Row,
        repository: sqlite3.Row,
        require_candidate: bool,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[dict[str, Any]]]:
        """Verify a private operation journal without consulting worker files."""

        if operation["task_id"] != task["task_id"] or int(operation["run_id"]) != int(
            task["current_run_id"] or 0
        ):
            raise BrokerConflict("operation belongs to another run")
        try:
            request = json.loads(operation["request_json"])
        except json.JSONDecodeError as exc:
            raise BrokerSecurityError(
                "operation journal contains invalid JSON"
            ) from exc
        canonical = _canonical_json(request)
        if (
            canonical.decode("utf-8") != operation["request_json"]
            or _sha256_bytes(canonical) != operation["request_sha256"]
        ):
            raise BrokerSecurityError("operation journal request does not verify")
        expected = {
            "contract": LOCAL_COMMIT_REQUEST_CONTRACT,
            "operation_id": operation["operation_id"],
            "board": task["board"],
            "task_id": task["task_id"],
            "run_id": int(operation["run_id"]),
            "claim_generation": int(task["claim_generation"]),
            "dispatch_authority_receipt_id": task["authority_id"],
            "dispatch_authority_payload_sha256": task["authority_payload_sha256"],
            "project_id": task["project_id"],
            "repository_id": task["repository_id"],
            "repository_fingerprint": repository["fingerprint"],
            "remote_repository": json.loads(repository["remote_repository_json"]),
            "remote_repository_sha256": repository["remote_repository_sha256"],
            "workspace_id": task["workspace_id"],
            "baseline_manifest_sha256": task["baseline_manifest_sha256"],
            "branch": task["branch"],
            "base_branch": task["base_branch"],
            "target_base_sha": task["target_base_sha"],
            "expected_base_sha": task["base_sha"],
            "expected_ref_sha": (
                task["base_sha"]
                if task["base_sha"] != task["target_base_sha"]
                else _ZERO_SHA
            ),
        }
        mismatches = sorted(
            key for key, value in expected.items() if request.get(key) != value
        )
        if mismatches:
            raise BrokerSecurityError(
                "operation journal authority mismatch: " + ", ".join(mismatches)
            )
        changed = request.get("changed_entries")
        changed_paths = request.get("changed_paths")
        if (
            not isinstance(changed, list)
            or not isinstance(changed_paths, list)
            or changed_paths != [entry.get("path") for entry in changed]
        ):
            raise BrokerSecurityError("operation journal change list is malformed")
        _assert_no_filesystem_path_collisions(changed_paths)
        if not require_candidate:
            return request, {}, changed
        raw_blob = operation["candidate_blob"]
        if raw_blob is None:
            raise BrokerSecurityError("operation journal candidate is unavailable")
        blob = bytes(raw_blob)
        if _sha256_bytes(blob) != operation["candidate_blob_sha256"]:
            raise BrokerSecurityError("operation journal candidate does not verify")
        candidate = _decode_candidate_snapshot(blob)
        candidate_public = {
            path: {key: value[key] for key in ("mode", "sha256", "size")}
            for path, value in sorted(candidate.items())
        }
        if _sha256_bytes(_canonical_json(candidate_public)) != request.get(
            "candidate_manifest_sha256"
        ):
            raise BrokerSecurityError("operation candidate manifest does not verify")
        if request.get("repository_fingerprint") != repository["fingerprint"]:
            raise BrokerSecurityError("operation repository fingerprint changed")
        return request, candidate, changed

    @_serialized_broker_method
    def commit_run(
        self,
        *,
        task_id: str,
        run_id: int,
        operation_id: str,
        untrusted_worker_result: dict[str, Any],
        inject_crash_after: str | None = None,
    ) -> dict[str, Any]:
        del untrusted_worker_result  # explicitly never an authority source
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        if task is None or int(task["current_run_id"] or 0) != int(run_id):
            raise BrokerConflict("stale or unknown broker run")
        repository = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id=?", (task["repository_id"],)
        ).fetchone()
        if repository is None:
            raise BrokerConflict("task repository is no longer registered")
        private_repository = self.private_repository_path(task["repository_id"])
        self._assert_repository_has_no_rewrites(private_repository)
        existing = self.conn.execute(
            "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if existing is not None:
            if existing["task_id"] != task_id or int(existing["run_id"]) != int(run_id):
                raise BrokerConflict("operation belongs to another run")
            request, candidate, changed = self._validated_operation_journal(
                operation=existing,
                task=task,
                repository=repository,
                require_candidate=existing["state"] != "EMITTED",
            )
            if existing["state"] == "EMITTED":
                return json.loads(existing["event_json"])
            operation = existing
        else:
            if task["status"] != "running":
                raise BrokerConflict("task is not running at commit boundary")
            try:
                candidate, changed = self._snapshot_workspace(task)
            except BrokerSecurityError:
                with self.conn:
                    self.conn.execute(
                        "UPDATE tasks SET status='blocked' "
                        "WHERE task_id=? AND current_run_id=?",
                        (task_id, int(run_id)),
                    )
                    self.conn.execute(
                        "UPDATE runs SET status='blocked' WHERE task_id=? AND run_id=?",
                        (task_id, int(run_id)),
                    )
                raise
            if not changed:
                raise BrokerConflict("worker produced no file changes")
            candidate_public = {
                path: {key: value[key] for key in ("mode", "sha256", "size")}
                for path, value in sorted(candidate.items())
            }
            request = {
                "contract": LOCAL_COMMIT_REQUEST_CONTRACT,
                "operation_id": operation_id,
                "board": task["board"],
                "task_id": task_id,
                "run_id": int(run_id),
                "claim_generation": int(task["claim_generation"]),
                "dispatch_authority_receipt_id": task["authority_id"],
                "dispatch_authority_payload_sha256": task["authority_payload_sha256"],
                "project_id": task["project_id"],
                "repository_id": task["repository_id"],
                "repository_fingerprint": repository["fingerprint"],
                "remote_repository": json.loads(repository["remote_repository_json"]),
                "remote_repository_sha256": repository["remote_repository_sha256"],
                "workspace_id": task["workspace_id"],
                "baseline_manifest_sha256": task["baseline_manifest_sha256"],
                "candidate_manifest_sha256": _sha256_bytes(
                    _canonical_json(candidate_public)
                ),
                "branch": task["branch"],
                "base_branch": task["base_branch"],
                "target_base_sha": task["target_base_sha"],
                "expected_base_sha": task["base_sha"],
                "expected_ref_sha": (
                    task["base_sha"]
                    if task["base_sha"] != task["target_base_sha"]
                    else _ZERO_SHA
                ),
                "changed_entries": changed,
                "changed_paths": [entry["path"] for entry in changed],
            }
            request_bytes = _canonical_json(request)
            request_sha = _sha256_bytes(request_bytes)
            candidate_blob = _encode_candidate_snapshot(candidate)
            candidate_blob_sha = _sha256_bytes(candidate_blob)
            author_time = int(time.time())
            with self.conn:
                self.conn.execute(
                    "INSERT INTO operations "
                    "(operation_id, task_id, run_id, request_json, request_sha256, "
                    "state, author_time, candidate_blob, candidate_blob_sha256, "
                    "tree_sha, head_sha, event_json) "
                    "VALUES (?, ?, ?, ?, ?, 'SNAPSHOTTED', ?, ?, ?, NULL, NULL, NULL)",
                    (
                        operation_id,
                        task_id,
                        int(run_id),
                        request_bytes.decode("utf-8"),
                        request_sha,
                        author_time,
                        candidate_blob,
                        candidate_blob_sha,
                    ),
                )
            operation = self.conn.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()

        private = Path(repository["private_path"])
        if operation["state"] == "SNAPSHOTTED":
            tree_sha, head_sha = self._build_commit(
                repository=private,
                task=task,
                operation_id=operation_id,
                run_id=run_id,
                candidate=candidate,
                changed=changed,
                author_time=int(operation["author_time"]),
            )
            with self.conn:
                self.conn.execute(
                    "UPDATE operations SET state='OBJECT_WRITTEN', tree_sha=?, head_sha=? WHERE operation_id=? AND state='SNAPSHOTTED'",
                    (tree_sha, head_sha, operation_id),
                )
            operation = self.conn.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
        if operation["state"] == "OBJECT_WRITTEN":
            ref = f"refs/heads/{task['branch']}"
            head_sha = _safe_object_sha(
                operation["head_sha"], field="operation head_sha"
            )
            expected_ref_sha = _safe_object_sha(
                request.get("expected_ref_sha"), field="expected_ref_sha"
            )
            readback = subprocess.run(
                [
                    str(_FIXED_GIT),
                    "--no-replace-objects",
                    f"--git-dir={private}",
                    "rev-parse",
                    "--verify",
                    ref,
                ],
                env=self._git_env(),
                capture_output=True,
                check=False,
                timeout=60,
            )
            if readback.returncode == 0:
                current_ref = readback.stdout.decode().strip()
                if current_ref == expected_ref_sha:
                    self._git(
                        private,
                        [
                            "update-ref",
                            ref,
                            head_sha,
                            expected_ref_sha,
                        ],
                    )
                    if inject_crash_after == "REF_BEFORE_JOURNAL":
                        raise BrokerInjectedCrash(
                            "injected crash after REF_BEFORE_JOURNAL"
                        )
                elif current_ref != head_sha:
                    raise BrokerConflict("task branch compare-and-swap failed")
            else:
                if expected_ref_sha != _ZERO_SHA:
                    raise BrokerConflict("task correction branch disappeared")
                result = subprocess.run(
                    [
                        str(_FIXED_GIT),
                        "--no-replace-objects",
                        "-c",
                        f"core.hooksPath={os.devnull}",
                        f"--git-dir={private}",
                        "update-ref",
                        ref,
                        head_sha,
                        _ZERO_SHA,
                    ],
                    env=self._git_env(),
                    capture_output=True,
                    check=False,
                    timeout=60,
                )
                if result.returncode != 0:
                    raise BrokerConflict("task branch compare-and-swap failed")
                if inject_crash_after == "REF_BEFORE_JOURNAL":
                    raise BrokerInjectedCrash("injected crash after REF_BEFORE_JOURNAL")
            with self.conn:
                self.conn.execute(
                    "UPDATE operations SET state='REF_UPDATED' WHERE operation_id=? AND state='OBJECT_WRITTEN'",
                    (operation_id,),
                )
            operation = self.conn.execute(
                "SELECT * FROM operations WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if inject_crash_after == "REF_UPDATED":
                raise BrokerInjectedCrash("injected crash after REF_UPDATED")
        if operation["state"] == "REF_UPDATED":
            ref_head = (
                self
                ._git(private, ["rev-parse", f"refs/heads/{task['branch']}"])
                .decode()
                .strip()
            )
            if ref_head != operation["head_sha"]:
                raise BrokerConflict("task ref diverged during recovery")
            return self._emit_event(operation, task)
        raise BrokerConflict("operation journal is in an unknown state")

    def _dispatch_operation_result(self, row: sqlite3.Row) -> dict[str, Any]:
        if row["result_json"]:
            return json.loads(row["result_json"])
        return {
            "contract": "hermes.broker_dispatch_operation.v1",
            "operation_id": row["operation_id"],
            "task_id": row["task_id"],
            "run_id": int(row["run_id"]),
            "state": row["state"],
            "terminal": row["state"] in {"SUCCEEDED", "FAILED"},
            "failure_code": row["failure_code"],
        }

    @_serialized_broker_method
    def begin_dispatch(
        self,
        *,
        task_id: str,
        operation_id: str,
    ) -> dict[str, Any]:
        """Claim and journal one operation, returning immediately and replayably."""

        task_id = _safe_identifier(task_id, field="task_id")
        operation_id = _safe_identifier(operation_id, field="operation_id")
        prior = self.conn.execute(
            "SELECT * FROM dispatch_attempts WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if prior is not None:
            if prior["task_id"] != task_id:
                raise BrokerConflict("dispatch operation belongs to another task")
            result = self._dispatch_operation_result(prior)
            result["start_required"] = False
            return result
        envelope = self.claim_for_dispatch(task_id)
        run_id = int(envelope["run_id"])
        runtime = envelope["task"].get("max_runtime_seconds")
        if isinstance(runtime, bool) or not isinstance(runtime, int):
            raise BrokerSecurityError("sealed task runtime is invalid")
        timeout_seconds = max(1, min(runtime, 86400))
        now = int(time.time())
        with self.conn:
            self.conn.execute(
                "INSERT INTO dispatch_attempts "
                "(operation_id, task_id, run_id, state, failure_code, "
                "timeout_seconds, result_json, created_at, updated_at) "
                "VALUES (?, ?, ?, 'CLAIMED', NULL, ?, NULL, ?, ?)",
                (operation_id, task_id, run_id, timeout_seconds, now, now),
            )
        return {
            "contract": "hermes.broker_dispatch_operation.v1",
            "operation_id": operation_id,
            "task_id": task_id,
            "run_id": run_id,
            "state": "CLAIMED",
            "terminal": False,
            "failure_code": None,
            "timeout_seconds": timeout_seconds,
            "start_required": True,
        }

    @_serialized_broker_method
    def dispatch_operation_status(
        self, *, peer_uid: int, operation_id: str
    ) -> dict[str, Any]:
        self._authorize(peer_uid, self.controller_uid, "dispatch status")
        operation_id = _safe_identifier(operation_id, field="operation_id")
        row = self.conn.execute(
            "SELECT * FROM dispatch_attempts WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            return {
                "contract": "hermes.broker_dispatch_operation.v1",
                "operation_id": operation_id,
                "state": "UNKNOWN",
                "terminal": True,
                "verified": False,
            }
        result = self._dispatch_operation_result(row)
        result["verified"] = True
        return result

    @_serialized_broker_method
    def fail_dispatch_submission(self, *, operation_id: str) -> None:
        operation_id = _safe_identifier(operation_id, field="operation_id")
        row = self.conn.execute(
            "SELECT * FROM dispatch_attempts WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None or row["state"] != "CLAIMED":
            raise BrokerConflict("dispatch submission failure is stale")
        self._transition_dispatch_failure(
            task_id=row["task_id"],
            run_id=int(row["run_id"]),
            operation_id=operation_id,
            failure_code="executor_unavailable",
            retryable=True,
            error_type="ExecutorUnavailable",
        )

    def perform_dispatch(
        self,
        *,
        operation_id: str,
        worker_socket: Path,
    ) -> dict[str, Any]:
        """Perform network wait outside the authority lock, journaling every edge.

        The worker socket is an untrusted execution surface.  It receives no
        authority key, database row, Git metadata, claim token, or credential;
        its response is never used as repository/workspace/ref authority.
        """
        from hermes_cli.kanban_broker_protocol import peer_uid
        from hermes_cli.kanban_broker_protocol import receive_frame
        from hermes_cli.kanban_broker_protocol import send_frame

        operation_id = _safe_identifier(operation_id, field="operation_id")
        with self._mutation_lock:
            row = self.conn.execute(
                "SELECT * FROM dispatch_attempts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise BrokerConflict("dispatch operation is not journaled")
            if row["state"] in {"SUCCEEDED", "FAILED"}:
                return self._dispatch_operation_result(row)
            if row["state"] != "CLAIMED":
                raise BrokerConflict("dispatch operation is already in progress")
            task_id = row["task_id"]
            run_id = int(row["run_id"])
            timeout_seconds = float(row["timeout_seconds"])
            task = self.conn.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if (
                task is None
                or task["status"] != "running"
                or int(task["current_run_id"] or 0) != run_id
            ):
                raise BrokerConflict("dispatch operation references a stale claim")
            envelope = self._dispatch_envelope(task)
        stage = "endpoint"
        try:
            endpoint = Path(worker_socket)
            info = endpoint.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISSOCK(info.st_mode):
                raise BrokerSecurityError("worker endpoint is not a real Unix socket")
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.settimeout(float(timeout_seconds))
            try:
                stage = "connect"
                conn.connect(str(endpoint))
                actual_uid = peer_uid(conn)
                if actual_uid != self.worker_uid:
                    raise BrokerAuthorizationError("worker socket peer UID mismatch")
                with self._mutation_lock, self.conn:
                    update = self.conn.execute(
                        "UPDATE dispatch_attempts SET state='CONNECTED', updated_at=? "
                        "WHERE operation_id=? AND state='CLAIMED'",
                        (int(time.time()), operation_id),
                    )
                    if update.rowcount != 1:
                        raise BrokerConflict(
                            "dispatch connect journal compare-and-swap failed"
                        )
                stage = "worker_result"
                send_frame(conn, envelope)
                result = receive_frame(conn)
            finally:
                conn.close()
            if result.get("contract") == "hermes.worker_turn_failed.v1":
                if set(result) != {"contract", "outcome", "error_class"} or (
                    result.get("outcome") != "failed"
                    or not isinstance(result.get("error_class"), str)
                    or not result["error_class"]
                ):
                    raise BrokerSecurityError(
                        "worker returned a malformed failed-turn contract"
                    )
                raise BrokerWorkerFailure("worker turn failed")
            if result.get("contract") != "hermes.worker_turn_complete.v1":
                raise BrokerSecurityError(
                    "worker returned an unsupported turn contract"
                )
            with self._mutation_lock, self.conn:
                update = self.conn.execute(
                    "UPDATE dispatch_attempts SET state='COMMITTING', updated_at=? "
                    "WHERE operation_id=? AND state='CONNECTED'",
                    (int(time.time()), operation_id),
                )
                if update.rowcount != 1:
                    raise BrokerConflict(
                        "dispatch commit journal compare-and-swap failed"
                    )
            stage = "commit"
            event = self.commit_run(
                task_id=task_id,
                run_id=run_id,
                operation_id=operation_id,
                untrusted_worker_result=result,
            )
            success = {
                "contract": "hermes.broker_dispatch_operation.v1",
                "operation_id": operation_id,
                "task_id": task_id,
                "run_id": run_id,
                "state": "SUCCEEDED",
                "terminal": True,
                "failure_code": None,
                "event": event,
            }
            with self._mutation_lock, self.conn:
                update = self.conn.execute(
                    "UPDATE dispatch_attempts SET state='SUCCEEDED', failure_code=NULL, result_json=?, "
                    "updated_at=? WHERE operation_id=? AND state='COMMITTING'",
                    (
                        _canonical_json(success).decode("utf-8"),
                        int(time.time()),
                        operation_id,
                    ),
                )
                if update.rowcount != 1:
                    raise BrokerConflict(
                        "dispatch success journal compare-and-swap failed"
                    )
            return success
        except Exception as exc:
            if isinstance(exc, FileNotFoundError) and stage == "endpoint":
                failure_code = "endpoint_missing"
            elif isinstance(exc, (socket.timeout, TimeoutError)):
                failure_code = "timeout"
            elif isinstance(exc, ConnectionRefusedError):
                failure_code = "refused"
            elif isinstance(exc, BrokerAuthorizationError):
                failure_code = "peer_mismatch"
            elif isinstance(exc, BrokerWorkerFailure):
                failure_code = "worker_failed"
            elif stage == "worker_result":
                failure_code = "malformed"
            elif isinstance(exc, BrokerConflict) and "no file changes" in str(exc):
                failure_code = "no_change"
            elif stage == "endpoint":
                failure_code = "endpoint_unsafe"
            else:
                failure_code = "dispatch_failed"
            with self._mutation_lock:
                self._transition_dispatch_failure(
                    task_id=task_id,
                    run_id=run_id,
                    operation_id=operation_id,
                    failure_code=failure_code,
                    retryable=failure_code
                    not in {"endpoint_unsafe", "peer_mismatch", "malformed"},
                    error_type=type(exc).__name__,
                )
            raise

    def dispatch_to_worker(
        self,
        *,
        task_id: str,
        worker_socket: Path,
        operation_id: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Synchronous compatibility wrapper over the replayable operation API."""

        accepted = self.begin_dispatch(task_id=task_id, operation_id=operation_id)
        if not accepted.pop("start_required"):
            if accepted.get("state") == "SUCCEEDED":
                return accepted["event"]
            if accepted.get("state") == "FAILED":
                raise BrokerConflict("dispatch operation previously failed")
            raise BrokerConflict("dispatch operation is already in progress")
        if timeout_seconds is not None:
            bounded = max(0.01, min(float(timeout_seconds), 86400.0))
            with self._mutation_lock, self.conn:
                self.conn.execute(
                    "UPDATE dispatch_attempts SET timeout_seconds=? "
                    "WHERE operation_id=? AND state='CLAIMED'",
                    (bounded, operation_id),
                )
        result = self.perform_dispatch(
            operation_id=operation_id,
            worker_socket=worker_socket,
        )
        return result["event"]

    @_serialized_broker_method
    def verify_publish_receipt(
        self, *, peer_uid: int, receipt_id: str, payload_sha256: str
    ) -> dict[str, Any]:
        self._authorize(peer_uid, self.publisher_uid, "receipt verification")
        row = self.conn.execute(
            "SELECT * FROM publish_receipts WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if row is None:
            return {
                "contract": PUBLISH_CONTRACT,
                "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
                "receipt_id": receipt_id,
                "verified": False,
            }
        payload_bytes = row["payload_json"].encode("utf-8")
        payload = json.loads(row["payload_json"])
        actual_payload_sha = _sha256_bytes(
            _canonical_json({
                key: value for key, value in payload.items() if key != "payload_sha256"
            })
        )
        valid = bool(
            not row["revoked"]
            and payload_sha256 == row["payload_sha256"] == actual_payload_sha
            and hmac.compare_digest(
                bytes(row["receipt_hmac"]),
                hmac.new(self.key, payload_bytes, hashlib.sha256).digest(),
            )
        )
        operation = self.conn.execute(
            "SELECT state FROM operations WHERE operation_id=?", (row["operation_id"],)
        ).fetchone()
        operation_state = operation["state"] if operation else None
        valid = bool(valid and operation_state in {"EMITTED", "PUBLISHED"})
        return {
            "contract": PUBLISH_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "receipt_id": receipt_id,
            "key_id": row["key_id"],
            "payload_sha256": row["payload_sha256"],
            "verified": valid,
            "revoked": bool(row["revoked"]),
            "operation_state": operation_state,
            "canonical_payload": payload,
        }

    @_serialized_broker_method
    def list_publish_obligations(
        self,
        *,
        peer_uid: int,
        query: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a bounded stable page of unpublished verified receipts."""

        self._authorize(peer_uid, self.publisher_uid, "publish obligation query")
        required = {
            "contract",
            "repository_id",
            "after_created_at",
            "after_receipt_id",
            "limit",
        }
        if (
            set(query) != required
            or query.get("contract") != PUBLISH_OBLIGATION_QUERY_CONTRACT
        ):
            raise BrokerConflict("publisher obligation query fields are not exact")
        limit = query.get("limit")
        after_created_at = query.get("after_created_at")
        after_receipt_id = query.get("after_receipt_id")
        repository_id = query.get("repository_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise BrokerConflict("publisher obligation query limit is out of bounds")
        if (
            not isinstance(after_created_at, int)
            or isinstance(after_created_at, bool)
            or after_created_at < 0
            or not isinstance(after_receipt_id, str)
        ):
            raise BrokerConflict("publisher obligation query cursor is invalid")
        if after_receipt_id:
            _safe_identifier(after_receipt_id, field="after_receipt_id")
        if repository_id is not None:
            repository_id = _safe_identifier(repository_id, field="repository_id")
        rows = self.conn.execute(
            "SELECT receipt.receipt_id, receipt.payload_sha256, receipt.created_at "
            "FROM publish_receipts AS receipt "
            "JOIN operations AS operation "
            "ON operation.operation_id = receipt.operation_id "
            "JOIN tasks AS task ON task.task_id = operation.task_id "
            "WHERE receipt.revoked = 0 AND operation.state = 'EMITTED' "
            "AND task.status = 'blocked' "
            "AND (receipt.created_at > ? OR "
            "(receipt.created_at = ? AND receipt.receipt_id > ?)) "
            "AND (? IS NULL OR task.repository_id = ?) "
            "ORDER BY receipt.created_at ASC, receipt.receipt_id ASC LIMIT ?",
            (
                int(after_created_at),
                int(after_created_at),
                after_receipt_id,
                repository_id,
                repository_id,
                int(limit) + 1,
            ),
        ).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        items: list[dict[str, Any]] = []
        for row in page:
            verified = self.verify_publish_receipt(
                peer_uid=peer_uid,
                receipt_id=row["receipt_id"],
                payload_sha256=row["payload_sha256"],
            )
            if verified.get("verified") is not True:
                raise BrokerSecurityError(
                    "publisher obligation durable state does not verify"
                )
            items.append({**verified, "created_at": int(row["created_at"])})
        next_cursor = (
            {
                "created_at": items[-1]["created_at"],
                "receipt_id": items[-1]["receipt_id"],
            }
            if items
            else None
        )
        return {
            "contract": PUBLISH_OBLIGATION_QUERY_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "items": items,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }

    def _cleanup_superseded_export(self, receipt_id: str) -> None:
        export = self.conn.execute(
            "SELECT * FROM publish_exports WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if export is None:
            return
        bundle = Path(export["bundle_path"])
        if bundle.exists() or bundle.is_symlink():
            content, info = self._read_verified_export(bundle)
            if (
                _sha256_bytes(content) != export["bundle_sha256"]
                or int(info.st_size) != int(export["bundle_size"])
            ):
                raise BrokerSecurityError(
                    "superseded publisher bundle no longer verifies"
                )
            current = bundle.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise BrokerSecurityError(
                    "superseded publisher bundle changed during cleanup"
                )
            bundle.unlink()
            directory_fd = os.open(
                self.publisher_handoff_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        with self.conn:
            self.conn.execute(
                "DELETE FROM publish_exports WHERE receipt_id=?", (receipt_id,)
            )

    @_serialized_broker_method
    def request_publish_correction(
        self,
        *,
        peer_uid: int,
        request: dict[str, Any],
    ) -> dict[str, Any]:
        """Supersede one failed-CI receipt and reseal its task at that head."""

        self._authorize(peer_uid, self.controller_uid, "publish correction")
        required = {
            "contract",
            "receipt_id",
            "receipt_payload_sha256",
            "reason_code",
        }
        if (
            not isinstance(request, dict)
            or set(request) != required
            or request.get("contract") != PUBLISH_CORRECTION_REQUEST_CONTRACT
            or request.get("reason_code")
            not in {"ci_failed", "ci_cancelled", "ci_timed_out", "publication_stale"}
        ):
            raise BrokerConflict("publish correction request fields are not exact")
        receipt_id = _safe_identifier(request.get("receipt_id"), field="receipt_id")
        payload_sha256 = _safe_object_sha(
            request.get("receipt_payload_sha256"),
            field="receipt_payload_sha256",
        )
        request_bytes = _canonical_json(request)
        request_sha = _sha256_bytes(request_bytes)
        existing = self.conn.execute(
            "SELECT * FROM publish_corrections WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if existing is not None:
            if (
                existing["request_json"] != request_bytes.decode("utf-8")
                or existing["request_sha256"] != request_sha
            ):
                raise BrokerConflict("publish correction replay changed")
            self._cleanup_superseded_export(receipt_id)
            return json.loads(existing["response_json"])
        if self.conn.execute(
            "SELECT 1 FROM publish_acks WHERE receipt_id=?", (receipt_id,)
        ).fetchone() is not None:
            raise BrokerConflict("published acknowledgement cannot be corrected")
        verified = self.verify_publish_receipt(
            peer_uid=self.publisher_uid,
            receipt_id=receipt_id,
            payload_sha256=payload_sha256,
        )
        if not verified.get("verified") or verified.get("operation_state") != "EMITTED":
            raise BrokerConflict("publish correction receipt is not pending")
        event = verified["canonical_payload"]
        receipt = self.conn.execute(
            "SELECT * FROM publish_receipts WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        operation = self.conn.execute(
            "SELECT * FROM operations WHERE operation_id=?",
            (receipt["operation_id"],),
        ).fetchone()
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (event["task_id"],)
        ).fetchone()
        run = self.conn.execute(
            "SELECT * FROM runs WHERE run_id=?", (event["run_id"],)
        ).fetchone()
        if (
            receipt is None
            or operation is None
            or task is None
            or run is None
            or operation["state"] != "EMITTED"
            or task["status"] != "blocked"
            or run["status"] != "blocked"
            or int(task["current_run_id"] or 0) != int(event["run_id"])
            or task["base_sha"] != event["base_sha"]
            or task["target_base_sha"] != event["target_base_sha"]
        ):
            raise BrokerConflict("publish correction lifecycle is stale")
        if not self._remove_sealed_workspace(task):
            raise BrokerSecurityError(
                "publish correction workspace cleanup failed"
            )
        private = self.private_repository_path(event["repository_id"])
        self._assert_repository_has_no_rewrites(private)
        ref_head = (
            self
            ._git(private, ["rev-parse", f"refs/heads/{event['branch']}"])
            .decode()
            .strip()
        )
        if ref_head != event["head_sha"]:
            raise BrokerConflict("publish correction branch head diverged")
        baseline = self._tree_manifest(private, event["head_sha"])
        baseline_bytes = _canonical_json(baseline)
        new_workspace_id = "kw_" + secrets.token_hex(12)
        new_authority_id = "ka_" + secrets.token_hex(16)
        authority = json.loads(task["authority_payload_json"])
        authority.update({
            "workspace_id": new_workspace_id,
            "workspace_baseline_sha256": _sha256_bytes(baseline_bytes),
            "base_sha": event["head_sha"],
            "target_base_sha": event["target_base_sha"],
        })
        authority_bytes = _canonical_json(authority)
        authority_sha = _sha256_bytes(authority_bytes)
        authority_hmac = hmac.new(
            self.key, authority_bytes, hashlib.sha256
        ).digest()
        response = {
            "contract": PUBLISH_CORRECTION_REQUEST_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "receipt_id": receipt_id,
            "task_id": event["task_id"],
            "status": "ready",
            "reason_code": request["reason_code"],
            "superseded_head_sha": event["head_sha"],
            "target_base_sha": event["target_base_sha"],
            "branch": event["branch"],
            "new_dispatch_authority_receipt_id": new_authority_id,
        }
        response_json = _canonical_json(response).decode("utf-8")
        now = int(time.time())
        with self.conn:
            receipt_update = self.conn.execute(
                "UPDATE publish_receipts SET revoked=1 WHERE receipt_id=? AND revoked=0",
                (receipt_id,),
            )
            operation_update = self.conn.execute(
                "UPDATE operations SET state='SUPERSEDED', candidate_blob=NULL, "
                "candidate_blob_sha256=NULL WHERE operation_id=? AND state='EMITTED'",
                (operation["operation_id"],),
            )
            run_update = self.conn.execute(
                "UPDATE runs SET status='superseded' WHERE run_id=? AND status='blocked'",
                (event["run_id"],),
            )
            task_update = self.conn.execute(
                "UPDATE tasks SET status='ready', current_run_id=NULL, base_sha=?, "
                "baseline_manifest_json=?, baseline_manifest_sha256=?, workspace_id=?, "
                "authority_id=?, authority_payload_json=?, authority_payload_sha256=?, "
                "authority_hmac=?, workspace_dev=NULL, workspace_ino=NULL "
                "WHERE task_id=? AND current_run_id=? AND status='blocked'",
                (
                    event["head_sha"],
                    baseline_bytes.decode("utf-8"),
                    _sha256_bytes(baseline_bytes),
                    new_workspace_id,
                    new_authority_id,
                    authority_bytes.decode("utf-8"),
                    authority_sha,
                    authority_hmac,
                    event["task_id"],
                    event["run_id"],
                ),
            )
            correction_insert = self.conn.execute(
                "INSERT INTO publish_corrections VALUES (?, ?, ?, ?, ?)",
                (
                    receipt_id,
                    request_bytes.decode("utf-8"),
                    request_sha,
                    response_json,
                    now,
                ),
            )
            if any(
                update.rowcount != 1
                for update in (
                    receipt_update,
                    operation_update,
                    run_update,
                    task_update,
                    correction_insert,
                )
            ):
                raise BrokerConflict("publish correction compare-and-swap failed")
        self._cleanup_superseded_export(receipt_id)
        return response

    def _read_verified_export(self, path: Path) -> tuple[bytes, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise BrokerSecurityError(
                "publisher bundle is not safely readable"
            ) from exc
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.broker_uid
                or info.st_gid != self.publisher_gid
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o640
            ):
                raise BrokerSecurityError("publisher bundle ownership or mode changed")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
            ):
                raise BrokerSecurityError(
                    "publisher bundle changed during verification"
                )
            return b"".join(chunks), info
        finally:
            os.close(fd)

    def _verify_bundle_head(
        self, *, repository: Path, bundle: Path, branch: str, head_sha: str
    ) -> None:
        output = self._git(repository, ["bundle", "list-heads", str(bundle)]).decode(
            "utf-8", "strict"
        )
        advertised = [line.split(" ", 1) for line in output.splitlines() if line]
        if advertised != [[head_sha, f"refs/heads/{branch}"]]:
            raise BrokerSecurityError(
                "publisher bundle does not advertise the receipt head"
            )

    @_serialized_broker_method
    def export_publish_bundle(
        self,
        *,
        peer_uid: int,
        receipt_id: str,
        payload_sha256: str,
        inject_crash_after: str | None = None,
    ) -> dict[str, Any]:
        """Materialize one broker-owned, publisher-readable exact-object bundle."""
        self._authorize(peer_uid, self.publisher_uid, "publisher object export")
        if not self.trusted_publisher_enabled:
            raise BrokerConflict("trusted publisher handoff is disabled")
        receipt_id = _safe_identifier(receipt_id, field="receipt_id")
        verified = self.verify_publish_receipt(
            peer_uid=peer_uid,
            receipt_id=receipt_id,
            payload_sha256=payload_sha256,
        )
        if not verified.get("verified"):
            raise BrokerConflict("publish receipt does not verify at emitted state")
        event = verified["canonical_payload"]
        existing = self.conn.execute(
            "SELECT * FROM publish_exports WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if existing is not None:
            if existing["receipt_payload_sha256"] != payload_sha256:
                raise BrokerConflict("publisher export receipt payload changed")
            handoff = json.loads(existing["handoff_json"])
            bundle = Path(existing["bundle_path"])
            content, info = self._read_verified_export(bundle)
            if _sha256_bytes(content) != existing["bundle_sha256"] or int(
                info.st_size
            ) != int(existing["bundle_size"]):
                raise BrokerSecurityError("publisher bundle no longer matches journal")
            repository = self.private_repository_path(event["repository_id"])
            self._assert_repository_has_no_rewrites(repository)
            self._verify_bundle_head(
                repository=repository,
                bundle=bundle,
                branch=event["branch"],
                head_sha=event["head_sha"],
            )
            return handoff

        repository = self.private_repository_path(event["repository_id"])
        self._assert_repository_has_no_rewrites(repository)
        bundle = self.publisher_handoff_root / f"{receipt_id}.bundle"
        if not bundle.exists() and not bundle.is_symlink():
            temporary = (
                self.state_dir
                / "operations"
                / (f"{receipt_id}.{secrets.token_hex(8)}.bundle.tmp")
            )
            try:
                self._git(
                    repository,
                    [
                        "bundle",
                        "create",
                        str(temporary),
                        f"refs/heads/{event['branch']}",
                    ],
                )
                temp_info = temporary.lstat()
                if stat.S_ISLNK(temp_info.st_mode) or not stat.S_ISREG(
                    temp_info.st_mode
                ):
                    raise BrokerSecurityError("Git did not create a regular bundle")
                os.chown(temporary, -1, self.publisher_gid)
                temporary.chmod(0o640)
                with temporary.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(temporary, bundle)
                directory_fd = os.open(
                    self.publisher_handoff_root,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
                )
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
                if inject_crash_after == "BUNDLE_RENAMED":
                    raise BrokerInjectedCrash("injected crash after BUNDLE_RENAMED")
            finally:
                temporary.unlink(missing_ok=True)
        content, info = self._read_verified_export(bundle)
        self._verify_bundle_head(
            repository=repository,
            bundle=bundle,
            branch=event["branch"],
            head_sha=event["head_sha"],
        )
        handoff = {
            "contract": PUBLISH_OBJECT_HANDOFF_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "receipt_id": receipt_id,
            "receipt_payload_sha256": payload_sha256,
            "bundle_path": str(bundle),
            "bundle_sha256": _sha256_bytes(content),
            "bundle_size": int(info.st_size),
            "repository_id": event["repository_id"],
            "branch": event["branch"],
            "base_branch": event["base_branch"],
            "base_sha": event["base_sha"],
            "target_base_sha": event["target_base_sha"],
            "head_sha": event["head_sha"],
        }
        handoff_json = _canonical_json(handoff).decode("utf-8")
        with self.conn:
            self.conn.execute(
                "INSERT INTO publish_exports VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    receipt_id,
                    payload_sha256,
                    str(bundle),
                    handoff["bundle_sha256"],
                    handoff["bundle_size"],
                    event["branch"],
                    event["base_sha"],
                    event["head_sha"],
                    handoff_json,
                    int(time.time()),
                ),
            )
        return handoff

    def _finish_publish_cleanup(self, receipt_id: str) -> dict[str, Any]:
        ack = self.conn.execute(
            "SELECT * FROM publish_acks WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if ack is None or ack["state"] not in {"PUBLISHED", "CLEANED"}:
            raise BrokerConflict("publisher acknowledgement is not finalizable")
        result = json.loads(ack["ack_json"])
        if ack["state"] == "CLEANED":
            return result
        receipt = self.conn.execute(
            "SELECT * FROM publish_receipts WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        export = self.conn.execute(
            "SELECT * FROM publish_exports WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if receipt is None or export is None:
            raise BrokerSecurityError("published artifact journal is incomplete")
        event = json.loads(receipt["payload_json"])
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (event["task_id"],)
        ).fetchone()
        if task is None:
            raise BrokerSecurityError("published task journal is unavailable")
        if not self._remove_sealed_workspace(task):
            raise BrokerSecurityError("published workspace could not be safely cleaned")

        repository = self.private_repository_path(event["repository_id"])
        task_ref = f"refs/heads/{event['branch']}"
        readback = subprocess.run(
            [
                str(_FIXED_GIT),
                "--no-replace-objects",
                f"--git-dir={repository}",
                "rev-parse",
                "--verify",
                task_ref,
            ],
            env=self._git_env(),
            capture_output=True,
            check=False,
            timeout=60,
        )
        if readback.returncode == 0:
            if readback.stdout.decode().strip() != event["head_sha"]:
                raise BrokerSecurityError("published task ref diverged before cleanup")
            self._git(
                repository,
                ["update-ref", "-d", task_ref, event["head_sha"]],
            )

        bundle = Path(export["bundle_path"])
        if bundle.exists() or bundle.is_symlink():
            content, info = self._read_verified_export(bundle)
            if _sha256_bytes(content) != export["bundle_sha256"] or len(content) != int(
                export["bundle_size"]
            ):
                raise BrokerSecurityError("published bundle changed before cleanup")
            current = bundle.lstat()
            if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                raise BrokerSecurityError("published bundle changed during cleanup")
            bundle.unlink()
            directory_fd = os.open(
                self.publisher_handoff_root,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

        result["cleanup_state"] = "cleaned"
        encoded = _canonical_json(result).decode("utf-8")
        with self.conn:
            operation_update = self.conn.execute(
                "UPDATE operations SET candidate_blob=NULL, "
                "candidate_blob_sha256=NULL WHERE operation_id=? AND state='PUBLISHED'",
                (receipt["operation_id"],),
            )
            ack_update = self.conn.execute(
                "UPDATE publish_acks SET state='CLEANED', ack_json=?, updated_at=? "
                "WHERE receipt_id=? AND state='PUBLISHED'",
                (encoded, int(time.time()), receipt_id),
            )
            if operation_update.rowcount != 1 or ack_update.rowcount != 1:
                raise BrokerConflict("publisher cleanup compare-and-swap failed")
        return result

    @_serialized_broker_method
    def acknowledge_publish(
        self,
        *,
        peer_uid: int,
        acknowledgement: dict[str, Any],
        inject_crash_after: str | None = None,
    ) -> dict[str, Any]:
        """Finalize one exact branch publication without moving protected base."""

        self._authorize(peer_uid, self.publisher_uid, "publisher acknowledgement")
        required = {
            "contract",
            "receipt_id",
            "receipt_payload_sha256",
            "bundle_sha256",
            "repository_id",
            "task_id",
            "run_id",
            "branch",
            "base_branch",
            "base_sha",
            "target_base_sha",
            "head_sha",
            "published_head_sha",
            "publish_outcome",
            "readback_complete",
            "remote_readback",
        }
        if set(acknowledgement) != required:
            raise BrokerConflict("publisher acknowledgement fields are not exact")
        if (
            acknowledgement.get("contract") != PUBLISH_ACK_CONTRACT
            or acknowledgement.get("publish_outcome") != "fast_forwarded"
            or acknowledgement.get("readback_complete") is not True
            or acknowledgement.get("published_head_sha")
            != acknowledgement.get("head_sha")
        ):
            raise BrokerConflict(
                "publisher acknowledgement is not an exact fast-forward"
            )
        receipt_id = _safe_identifier(acknowledgement["receipt_id"], field="receipt_id")
        request_bytes = _canonical_json(acknowledgement)
        request_sha = _sha256_bytes(request_bytes)
        existing_ack = self.conn.execute(
            "SELECT * FROM publish_acks WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if existing_ack is not None:
            if existing_ack["request_sha256"] != request_sha or existing_ack[
                "request_json"
            ] != request_bytes.decode("utf-8"):
                raise BrokerConflict("publisher acknowledgement idempotency changed")
            if existing_ack["state"] in {"PUBLISHED", "CLEANED"}:
                return self._finish_publish_cleanup(receipt_id)

        verified = self.verify_publish_receipt(
            peer_uid=peer_uid,
            receipt_id=receipt_id,
            payload_sha256=str(acknowledgement["receipt_payload_sha256"]),
        )
        if not verified.get("verified") or verified.get("operation_state") != "EMITTED":
            raise BrokerConflict("publisher acknowledgement receipt is not awaiting")
        event = verified["canonical_payload"]
        bound = {
            "receipt_id": event["receipt_id"],
            "receipt_payload_sha256": event["payload_sha256"],
            "repository_id": event["repository_id"],
            "task_id": event["task_id"],
            "run_id": event["run_id"],
            "branch": event["branch"],
            "base_branch": event["base_branch"],
            "base_sha": event["base_sha"],
            "target_base_sha": event["target_base_sha"],
            "head_sha": event["head_sha"],
        }
        if any(acknowledgement.get(key) != value for key, value in bound.items()):
            raise BrokerConflict("publisher acknowledgement does not bind the receipt")
        export = self.conn.execute(
            "SELECT * FROM publish_exports WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        if (
            export is None
            or acknowledgement["bundle_sha256"] != export["bundle_sha256"]
            or export["receipt_payload_sha256"] != event["payload_sha256"]
            or export["head_sha"] != event["head_sha"]
        ):
            raise BrokerConflict("publisher acknowledgement does not bind the export")
        bundle_content, bundle_info = self._read_verified_export(
            Path(export["bundle_path"])
        )
        if _sha256_bytes(bundle_content) != export["bundle_sha256"] or len(
            bundle_content
        ) != int(bundle_info.st_size):
            raise BrokerSecurityError("publisher export no longer verifies")
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (event["task_id"],)
        ).fetchone()
        receipt_row = self.conn.execute(
            "SELECT * FROM publish_receipts WHERE receipt_id=?", (receipt_id,)
        ).fetchone()
        operation = self.conn.execute(
            "SELECT * FROM operations WHERE operation_id=?",
            (receipt_row["operation_id"],),
        ).fetchone()
        run = self.conn.execute(
            "SELECT * FROM runs WHERE run_id=?", (event["run_id"],)
        ).fetchone()
        repository = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id=?",
            (event["repository_id"],),
        ).fetchone()
        if (
            task is None
            or run is None
            or operation is None
            or repository is None
            or task["status"] != "blocked"
            or run["status"] != "blocked"
            or operation["state"] != "EMITTED"
        ):
            raise BrokerConflict("publisher acknowledgement lifecycle is stale")
        try:
            registered_remote = json.loads(repository["remote_repository_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise BrokerSecurityError(
                "registered GitHub repository binding is malformed"
            ) from exc
        if (
            _canonical_json(registered_remote).decode("utf-8")
            != repository["remote_repository_json"]
            or _sha256_bytes(_canonical_json(registered_remote))
            != repository["remote_repository_sha256"]
            or event.get("remote_repository") != registered_remote
            or event.get("remote_repository_sha256")
            != repository["remote_repository_sha256"]
        ):
            raise BrokerSecurityError(
                "publisher acknowledgement repository authority does not verify"
            )
        remote_readback = _validate_github_publish_readback(
            acknowledgement["remote_readback"],
            event=event,
            registered_repository=registered_remote,
        )
        if repository["base_sha"] != event["target_base_sha"]:
            raise BrokerConflict("publisher acknowledgement target base is stale")
        private = Path(repository["private_path"])
        self._assert_repository_has_no_rewrites(private)
        parent = (
            self._git(private, ["rev-parse", f"{event['head_sha']}^"]).decode().strip()
        )
        if parent != event["base_sha"]:
            raise BrokerConflict("publisher acknowledgement head is not a fast-forward")
        if existing_ack is None:
            now = int(time.time())
            with self.conn:
                self.conn.execute(
                    "INSERT INTO publish_acks "
                    "(receipt_id, request_json, request_sha256, state, ack_json, "
                    "created_at, updated_at) VALUES (?, ?, ?, 'PREPARED', NULL, ?, ?)",
                    (
                        receipt_id,
                        request_bytes.decode("utf-8"),
                        request_sha,
                        now,
                        now,
                    ),
                )
        if not self._remove_sealed_workspace(task):
            raise BrokerSecurityError(
                "publisher acknowledgement workspace cleanup failed"
            )
        base_ref = f"refs/heads/{event['base_branch']}"
        ref_head = self._git(private, ["rev-parse", base_ref]).decode().strip()
        if ref_head != event["target_base_sha"]:
            raise BrokerConflict("publisher acknowledgement protected base diverged")
        if inject_crash_after == "BASE_REF_UPDATED":
            raise BrokerInjectedCrash("injected crash after BASE_REF_UPDATED")
        completion_id = (
            "kpc_" + _sha256_bytes(f"{receipt_id}:{request_sha}".encode("utf-8"))[:32]
        )
        completion_created_at = int(time.time())
        completion = {
            "contract": PUBLISH_COMPLETION_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "completion_id": completion_id,
            "key_id": receipt_row["key_id"],
            "receipt_id": receipt_id,
            "receipt_payload_sha256": event["payload_sha256"],
            "acknowledgement_sha256": request_sha,
            "bundle_sha256": acknowledgement["bundle_sha256"],
            "dispatch_authority_receipt_id": event["dispatch_authority_receipt_id"],
            "dispatch_authority_payload_sha256": event[
                "dispatch_authority_payload_sha256"
            ],
            "board": event["board"],
            "project_id": event["project_id"],
            "task_id": event["task_id"],
            "run_id": event["run_id"],
            "claim_generation": event["claim_generation"],
            "repository_id": event["repository_id"],
            "repository_fingerprint": event["repository_fingerprint"],
            "remote_repository": registered_remote,
            "remote_repository_sha256": repository["remote_repository_sha256"],
            "remote_readback": remote_readback,
            "remote_readback_sha256": _sha256_bytes(_canonical_json(remote_readback)),
            "workspace_id": event["workspace_id"],
            "branch": event["branch"],
            "base_branch": event["base_branch"],
            "base_sha": event["base_sha"],
            "target_base_sha": event["target_base_sha"],
            "head_sha": event["head_sha"],
            "publish_outcome": "fast_forwarded",
            "task_status": "done",
            "run_status": "done",
            "operation_state": "PUBLISHED",
            "repository_base_sha": event["target_base_sha"],
            "created_at": completion_created_at,
        }
        completion_payload_sha = _sha256_bytes(_canonical_json(completion))
        completion["completion_payload_sha256"] = completion_payload_sha
        completion_bytes = _canonical_json(completion)
        completion_hmac = hmac.new(self.key, completion_bytes, hashlib.sha256).digest()
        result = {
            "contract": PUBLISH_ACK_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "receipt_id": receipt_id,
            "task_id": event["task_id"],
            "run_id": event["run_id"],
            "repository_id": event["repository_id"],
            "branch": event["branch"],
            "base_branch": event["base_branch"],
            "head_sha": event["head_sha"],
            "branch_published_from": event["base_sha"],
            "branch_published_to": event["head_sha"],
            "repository_base_sha": event["target_base_sha"],
            "publish_outcome": "fast_forwarded",
            "cleanup_state": "pending",
            "completion_id": completion_id,
            "completion_payload_sha256": completion_payload_sha,
            "remote_readback_sha256": completion["remote_readback_sha256"],
        }
        result_json = _canonical_json(result).decode("utf-8")
        with self.conn:
            repository_guard = self.conn.execute(
                "UPDATE repositories SET base_sha=base_sha "
                "WHERE repository_id=? AND base_sha=?",
                (event["repository_id"], event["target_base_sha"]),
            )
            task_update = self.conn.execute(
                "UPDATE tasks SET status='done' WHERE task_id=? "
                "AND current_run_id=? AND status='blocked'",
                (event["task_id"], int(event["run_id"])),
            )
            run_update = self.conn.execute(
                "UPDATE runs SET status='done' WHERE run_id=? AND task_id=? "
                "AND status='blocked'",
                (int(event["run_id"]), event["task_id"]),
            )
            operation_update = self.conn.execute(
                "UPDATE operations SET state='PUBLISHED' WHERE operation_id=? "
                "AND state='EMITTED'",
                (receipt_row["operation_id"],),
            )
            ack_update = self.conn.execute(
                "UPDATE publish_acks SET state='PUBLISHED', ack_json=?, updated_at=? "
                "WHERE receipt_id=? AND state='PREPARED'",
                (result_json, int(time.time()), receipt_id),
            )
            completion_insert = self.conn.execute(
                "INSERT INTO publisher_completions "
                "(completion_id, receipt_id, repository_id, completion_json, "
                "payload_sha256, completion_hmac, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    completion_id,
                    receipt_id,
                    event["repository_id"],
                    completion_bytes.decode("utf-8"),
                    completion_payload_sha,
                    completion_hmac,
                    completion_created_at,
                ),
            )
            if any(
                update.rowcount != 1
                for update in (
                    repository_guard,
                    task_update,
                    run_update,
                    operation_update,
                    ack_update,
                    completion_insert,
                )
            ):
                raise BrokerConflict(
                    "publisher acknowledgement compare-and-swap failed"
                )
        if inject_crash_after == "COMPLETION_CAS":
            raise BrokerInjectedCrash("injected crash after COMPLETION_CAS")
        return self._finish_publish_cleanup(receipt_id)

    @_serialized_broker_method
    def verify_publish_completion(
        self,
        *,
        peer_uid: int,
        completion_id: str,
        payload_sha256: str,
    ) -> dict[str, Any]:
        """Verify one immutable completion CAS receipt from private broker state."""

        self._authorize(peer_uid, self.publisher_uid, "completion verification")
        completion_id = _safe_identifier(completion_id, field="completion_id")
        row = self.conn.execute(
            "SELECT * FROM publisher_completions WHERE completion_id=?",
            (completion_id,),
        ).fetchone()
        if row is None:
            return {
                "contract": PUBLISH_COMPLETION_CONTRACT,
                "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
                "completion_id": completion_id,
                "verified": False,
            }
        try:
            payload = json.loads(row["completion_json"])
        except (TypeError, json.JSONDecodeError):
            payload = {}
        canonical_stored = _canonical_json(payload)
        unsigned = (
            {
                key: value
                for key, value in payload.items()
                if key != "completion_payload_sha256"
            }
            if isinstance(payload, dict)
            else {}
        )
        actual_payload_sha = _sha256_bytes(_canonical_json(unsigned))
        ack = self.conn.execute(
            "SELECT * FROM publish_acks WHERE receipt_id=?", (row["receipt_id"],)
        ).fetchone()
        receipt = self.conn.execute(
            "SELECT * FROM publish_receipts WHERE receipt_id=?", (row["receipt_id"],)
        ).fetchone()
        task = self.conn.execute(
            "SELECT * FROM tasks WHERE task_id=?", (payload.get("task_id"),)
        ).fetchone()
        run = self.conn.execute(
            "SELECT * FROM runs WHERE run_id=?", (payload.get("run_id"),)
        ).fetchone()
        operation = (
            self.conn.execute(
                "SELECT * FROM operations WHERE operation_id=?",
                (receipt["operation_id"],),
            ).fetchone()
            if receipt is not None
            else None
        )
        repository = self.conn.execute(
            "SELECT * FROM repositories WHERE repository_id=?",
            (payload.get("repository_id"),),
        ).fetchone()
        try:
            ack_request = json.loads(ack["request_json"]) if ack is not None else {}
            registered_remote = (
                json.loads(repository["remote_repository_json"])
                if repository is not None
                else {}
            )
            completion_remote = payload.get("remote_readback")
            validated_remote = (
                _validate_github_publish_readback(
                    completion_remote,
                    event=json.loads(receipt["payload_json"]),
                    registered_repository=registered_remote,
                )
                if receipt is not None and repository is not None
                else None
            )
            remote_bindings = bool(
                validated_remote == completion_remote
                and ack_request.get("remote_readback") == completion_remote
                and payload.get("remote_repository") == registered_remote
                and payload.get("remote_repository_sha256")
                == repository["remote_repository_sha256"]
                and _sha256_bytes(_canonical_json(registered_remote))
                == repository["remote_repository_sha256"]
                and payload.get("remote_readback_sha256")
                == _sha256_bytes(_canonical_json(completion_remote))
            )
        except (
            TypeError,
            json.JSONDecodeError,
            BrokerConflict,
            BrokerSecurityError,
        ):
            remote_bindings = False
        repository_contains_completion = False
        if repository is not None and payload.get("head_sha"):
            private = Path(repository["private_path"])
            self._assert_repository_has_no_rewrites(private)
            object_readback = subprocess.run(
                [
                    str(_FIXED_GIT),
                    "--no-replace-objects",
                    f"--git-dir={private}",
                    "cat-file",
                    "-e",
                    f"{payload.get('head_sha')}^{{commit}}",
                ],
                env=self._git_env(),
                capture_output=True,
                check=False,
                timeout=60,
            )
            repository_contains_completion = object_readback.returncode == 0
        bindings = bool(
            ack is not None
            and ack["state"] in {"PUBLISHED", "CLEANED"}
            and ack["request_sha256"] == payload.get("acknowledgement_sha256")
            and receipt is not None
            and receipt["payload_sha256"] == payload.get("receipt_payload_sha256")
            and task is not None
            and task["task_id"] == payload.get("task_id")
            and int(task["current_run_id"] or 0) == payload.get("run_id")
            and int(task["claim_generation"]) == payload.get("claim_generation")
            and task["status"] == "done"
            and task["repository_id"] == payload.get("repository_id")
            and task["branch"] == payload.get("branch")
            and task["base_branch"] == payload.get("base_branch")
            and task["base_sha"] == payload.get("base_sha")
            and task["target_base_sha"] == payload.get("target_base_sha")
            and run is not None
            and run["task_id"] == payload.get("task_id")
            and int(run["claim_generation"]) == payload.get("claim_generation")
            and run["status"] == "done"
            and operation is not None
            and operation["state"] == "PUBLISHED"
            and operation["head_sha"] == payload.get("head_sha")
            and repository is not None
            and payload.get("repository_base_sha") == payload.get("target_base_sha")
            and repository["base_sha"] == payload.get("target_base_sha")
            and repository_contains_completion
            and remote_bindings
        )
        valid = bool(
            isinstance(payload, dict)
            and canonical_stored.decode("utf-8") == row["completion_json"]
            and payload.get("contract") == PUBLISH_COMPLETION_CONTRACT
            and payload.get("broker_boundary") == KANBAN_BROKER_SECURITY_BOUNDARY
            and payload.get("completion_id") == completion_id
            and payload.get("receipt_id") == row["receipt_id"]
            and payload.get("repository_id") == row["repository_id"]
            and payload_sha256 == row["payload_sha256"] == actual_payload_sha
            and payload.get("completion_payload_sha256") == actual_payload_sha
            and hmac.compare_digest(
                bytes(row["completion_hmac"]),
                hmac.new(self.key, canonical_stored, hashlib.sha256).digest(),
            )
            and bindings
        )
        return {
            "contract": PUBLISH_COMPLETION_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "completion_id": completion_id,
            "payload_sha256": row["payload_sha256"],
            "verified": valid,
            "cleanup_state": (
                "cleaned"
                if ack is not None and ack["state"] == "CLEANED"
                else "pending"
            ),
            "canonical_payload": payload,
            "created_at": int(row["created_at"]),
        }

    @_serialized_broker_method
    def list_publish_completions(
        self,
        *,
        peer_uid: int,
        query: dict[str, Any],
    ) -> dict[str, Any]:
        """Return a bounded, stable cursor page of verified completion receipts."""

        self._authorize(peer_uid, self.publisher_uid, "completion query")
        required = {
            "contract",
            "repository_id",
            "after_created_at",
            "after_completion_id",
            "limit",
        }
        if (
            set(query) != required
            or query.get("contract") != PUBLISH_COMPLETION_QUERY_CONTRACT
        ):
            raise BrokerConflict("publisher completion query fields are not exact")
        limit = query.get("limit")
        after_created_at = query.get("after_created_at")
        after_completion_id = query.get("after_completion_id")
        repository_id = query.get("repository_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 100
        ):
            raise BrokerConflict("publisher completion query limit is out of bounds")
        if (
            not isinstance(after_created_at, int)
            or isinstance(after_created_at, bool)
            or after_created_at < 0
            or not isinstance(after_completion_id, str)
        ):
            raise BrokerConflict("publisher completion query cursor is invalid")
        if after_completion_id:
            _safe_identifier(after_completion_id, field="after_completion_id")
        if repository_id is not None:
            repository_id = _safe_identifier(repository_id, field="repository_id")
        rows = self.conn.execute(
            "SELECT completion_id, payload_sha256, created_at "
            "FROM publisher_completions "
            "WHERE (created_at > ? OR (created_at = ? AND completion_id > ?)) "
            "AND (? IS NULL OR repository_id = ?) "
            "ORDER BY created_at ASC, completion_id ASC LIMIT ?",
            (
                int(after_created_at),
                int(after_created_at),
                after_completion_id,
                repository_id,
                repository_id,
                int(limit) + 1,
            ),
        ).fetchall()
        has_more = len(rows) > limit
        page = rows[:limit]
        items: list[dict[str, Any]] = []
        for row in page:
            verified = self.verify_publish_completion(
                peer_uid=peer_uid,
                completion_id=row["completion_id"],
                payload_sha256=row["payload_sha256"],
            )
            if verified.get("verified") is not True:
                raise BrokerSecurityError(
                    "publisher completion durable state does not verify"
                )
            items.append(verified)
        next_cursor = (
            {
                "created_at": items[-1]["created_at"],
                "completion_id": items[-1]["completion_id"],
            }
            if items
            else None
        )
        return {
            "contract": PUBLISH_COMPLETION_QUERY_CONTRACT,
            "broker_boundary": KANBAN_BROKER_SECURITY_BOUNDARY,
            "items": items,
            "has_more": has_more,
            "next_cursor": next_cursor,
        }

    @_serialized_broker_method
    def recover_publish_acknowledgements(self) -> None:
        """Resume authenticated acknowledgements left prepared or cleaning."""

        rows = self.conn.execute(
            "SELECT request_json FROM publish_acks WHERE state IN ('PREPARED', 'PUBLISHED')"
        ).fetchall()
        for row in rows:
            self.acknowledge_publish(
                peer_uid=self.publisher_uid,
                acknowledgement=json.loads(row["request_json"]),
            )

    @_serialized_broker_method
    def task_status(self, task_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT status FROM tasks WHERE task_id=?", (task_id,)
        ).fetchone()
        return row["status"] if row else None

    @_serialized_broker_method
    def operation_state(self, operation_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT state FROM operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        return row["state"] if row else None

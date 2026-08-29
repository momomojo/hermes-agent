"""Host-only, board-local authority for trusted Kanban task dispatch.

The model never receives the board HMAC key or raw receipt MAC.  A normal CLI
or model-tool task is intentionally unsealed.  The no-agent host controller
initializes the board key once, then uses :func:`trusted_create_task` to create
an exact task definition and its receipt in one SQLite write transaction.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Any, Iterable

from hermes_cli import kanban_db as kb


KANBAN_DISPATCH_AUTHORITY_CONTRACT = "hermes.kanban_dispatch_authority.v1"
_AUTHORITY_KEY_NAME = ".trusted-dispatch-authority.key"
_AUTHORITY_KEY_BYTES = 32


class DispatchAuthorityError(RuntimeError):
    """Trusted dispatch authority could not be established or verified."""


def _worker_model_context() -> bool:
    try:
        from agent.delegation_context import is_dispatcher_owned_worker_context

        owns_dispatch = is_dispatcher_owned_worker_context()
    except Exception:
        owns_dispatch = True
    return bool(
        owns_dispatch
        and os.environ.get("HERMES_SESSION_SOURCE") == "kanban"
        and str(os.environ.get("HERMES_KANBAN_TASK") or "").strip()
    )


def _database_path(conn) -> Path:
    row = conn.execute("PRAGMA database_list").fetchone()
    raw = row["file"] if hasattr(row, "keys") else row[2]
    path = Path(str(raw)).expanduser()
    if not path.is_absolute():
        raise DispatchAuthorityError("Kanban authority requires an absolute board DB")
    return path.resolve(strict=True)


def authority_key_path_for_db(db_path: Path) -> Path:
    """Return the fixed board-local key path without resolving a symlink leaf."""
    return db_path.expanduser().resolve(strict=True).parent / _AUTHORITY_KEY_NAME


def authority_key_path(conn) -> Path:
    db_path = _database_path(conn)
    board = kb.get_current_board()
    try:
        configured_db = kb.kanban_db_path(board=board).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        configured_db = None
    if configured_db == db_path:
        return kb.board_dir(board) / _AUTHORITY_KEY_NAME
    return authority_key_path_for_db(db_path)


def _validate_board_dir(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise DispatchAuthorityError("dispatch authority board directory is missing") from exc
    if stat.S_ISLNK(info.st_mode):
        raise DispatchAuthorityError("dispatch authority board directory is a symlink")
    if not stat.S_ISDIR(info.st_mode):
        raise DispatchAuthorityError("dispatch authority board path is not a directory")
    if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
        raise DispatchAuthorityError("dispatch authority board directory has wrong owner")
    try:
        path.chmod(0o700)
    except OSError as exc:
        raise DispatchAuthorityError("dispatch authority board directory must be 0700") from exc


def _open_validated_key(path: Path) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as exc:
        raise DispatchAuthorityError(
            "dispatch authority key is not initialized"
        ) from exc
    if stat.S_ISLNK(before.st_mode):
        raise DispatchAuthorityError("dispatch authority key is a symlink")
    if not stat.S_ISREG(before.st_mode):
        raise DispatchAuthorityError("dispatch authority key is not a regular file")
    if stat.S_IMODE(before.st_mode) != 0o600:
        raise DispatchAuthorityError("dispatch authority key must have mode 0600")
    if hasattr(os, "geteuid") and before.st_uid != os.geteuid():
        raise DispatchAuthorityError("dispatch authority key has wrong owner")
    if before.st_nlink != 1:
        raise DispatchAuthorityError("dispatch authority key must have one link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise DispatchAuthorityError("dispatch authority key could not be opened safely") from exc
    after = os.fstat(fd)
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(fd)
        raise DispatchAuthorityError("dispatch authority key changed during open")
    return fd, after


def _load_key(conn) -> bytes:
    path = authority_key_path(conn)
    fd, _info = _open_validated_key(path)
    try:
        key = os.read(fd, _AUTHORITY_KEY_BYTES + 1)
    finally:
        os.close(fd)
    if len(key) != _AUTHORITY_KEY_BYTES:
        raise DispatchAuthorityError("dispatch authority key has invalid length")
    return key


def initialize_authority(conn) -> dict[str, Any]:
    """Initialize the board key from a no-agent host controller only."""
    if _worker_model_context():
        raise DispatchAuthorityError(
            "trusted dispatch authority is unavailable to Kanban model workers"
        )
    key_path = authority_key_path(conn)
    if not key_path.parent.exists():
        key_path.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    _validate_board_dir(key_path.parent)
    if key_path.exists() or key_path.is_symlink():
        key = _load_key(conn)
        initialized = False
    else:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(key_path, flags, 0o600)
        except OSError as exc:
            raise DispatchAuthorityError(
                "dispatch authority key could not be created safely"
            ) from exc
        key = secrets.token_bytes(_AUTHORITY_KEY_BYTES)
        try:
            os.write(fd, key)
            os.fsync(fd)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        # Re-open with the same strict checks before reporting success.
        key = _load_key(conn)
        initialized = True
    return {
        "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
        "initialized": initialized,
        "key_id": hashlib.sha256(key).hexdigest()[:24],
    }


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _normalized_skills(task: kb.Task) -> list[str]:
    return [str(skill) for skill in (task.skills or [])]


def task_payload(
    conn,
    task: kb.Task,
    *,
    board: str,
    requested_initial_status: str,
    requested_workspace_kind: str | None = None,
    requested_workspace_path: str | None = None,
    requested_branch_name: str | None = None,
    requested_project_id: str | None = None,
    requested_triage: bool = False,
) -> dict[str, Any]:
    body = task.body
    return {
        "contract": KANBAN_DISPATCH_AUTHORITY_CONTRACT,
        "board": board,
        "task_id": task.id,
        "title": task.title,
        "body": body,
        "body_sha256": (
            hashlib.sha256(body.encode("utf-8")).hexdigest()
            if body is not None
            else None
        ),
        "assignee": task.assignee,
        "profile": task.assignee,
        "created_by": task.created_by,
        "creation_origin": task.creation_origin,
        "created_at": task.created_at,
        "idempotency_key": task.idempotency_key,
        "tenant": task.tenant,
        "priority": task.priority,
        "requested_initial_status": requested_initial_status,
        "requested_workspace_kind": requested_workspace_kind,
        "requested_workspace_path": requested_workspace_path,
        "requested_branch_name": requested_branch_name,
        "requested_project_id": requested_project_id,
        "requested_triage": bool(requested_triage),
        "pre_dispatch_status": task.status,
        "workspace_kind": task.workspace_kind,
        "workspace_path": task.workspace_path,
        "branch_name": task.branch_name,
        "project_id": task.project_id,
        "parent_ids": sorted(kb.parent_ids(conn, task.id)),
        "max_runtime_seconds": task.max_runtime_seconds,
        "skills": _normalized_skills(task),
        "max_retries": task.max_retries,
        "model_override": task.model_override,
        "provider_override": task.provider_override,
        "reasoning_effort": task.reasoning_effort,
        "goal_mode": bool(task.goal_mode),
        "goal_max_turns": task.goal_max_turns,
        "session_id": task.session_id,
        "workflow_template_id": task.workflow_template_id,
        "current_step_key": task.current_step_key,
    }


def _receipt_hmac(key: bytes, payload_bytes: bytes) -> bytes:
    return hmac.new(key, payload_bytes, hashlib.sha256).digest()


def _mismatch_fields(expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    return sorted(
        key
        for key in set(expected) | set(actual)
        if expected.get(key) != actual.get(key)
    )


def verify_task_authority(conn, task_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM task_dispatch_authorities WHERE task_id = ?",
        (task_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["payload_json"])
    except (TypeError, ValueError):
        payload = {}
    signature_valid = False
    try:
        key = _load_key(conn)
        canonical = _canonical_json(payload)
        signature_valid = bool(
            row["contract"] == KANBAN_DISPATCH_AUTHORITY_CONTRACT
            and payload.get("contract") == KANBAN_DISPATCH_AUTHORITY_CONTRACT
            and hashlib.sha256(canonical).hexdigest() == row["payload_sha256"]
            and hmac.compare_digest(
                bytes(row["receipt_hmac"]),
                _receipt_hmac(key, canonical),
            )
        )
    except (DispatchAuthorityError, TypeError, ValueError):
        signature_valid = False

    task = kb.get_task(conn, task_id)
    mismatch_fields: list[str] = []
    if task is None or not isinstance(payload, dict):
        row_matches = False
        mismatch_fields = ["task_id"]
    else:
        requested_initial = str(payload.get("requested_initial_status") or "")
        actual = task_payload(
            conn,
            task,
            board=str(payload.get("board") or ""),
            requested_initial_status=requested_initial,
            requested_workspace_kind=payload.get("requested_workspace_kind"),
            requested_workspace_path=payload.get("requested_workspace_path"),
            requested_branch_name=payload.get("requested_branch_name"),
            requested_project_id=payload.get("requested_project_id"),
            requested_triage=bool(payload.get("requested_triage")),
        )
        # Status is signed as the exact initial/pre-dispatch state. Once the
        # host has CAS-consumed the receipt for a run, normal lifecycle state
        # changes do not mutate or silently refresh the signed definition.
        if int(row["claim_generation"] or 0) > 0:
            actual["pre_dispatch_status"] = payload.get("pre_dispatch_status")
        mismatch_fields = _mismatch_fields(payload, actual)
        active_matches = []
        if task.idempotency_key:
            active_matches = conn.execute(
                "SELECT id FROM tasks WHERE idempotency_key = ? "
                "AND status != 'archived' ORDER BY id",
                (task.idempotency_key,),
            ).fetchall()
        if len(active_matches) != 1 or str(active_matches[0]["id"]) != task_id:
            mismatch_fields.append("idempotency_key")
        mismatch_fields = sorted(set(mismatch_fields))
        row_matches = not mismatch_fields
    verified = bool(signature_valid and row_matches)
    return {
        "contract": str(row["contract"]),
        "authority_id": str(row["authority_id"]),
        "key_id": str(row["key_id"]),
        "sealed_at": int(row["sealed_at"]),
        "payload": payload,
        "payload_sha256": str(row["payload_sha256"]),
        "receipt_id": str(row["authority_id"]),
        "signature_valid": signature_valid,
        "row_matches_payload": row_matches,
        "verified": verified,
        "mismatch_fields": mismatch_fields,
        "claim_generation": int(row["claim_generation"] or 0),
        "last_claimed_run_id": row["last_claimed_run_id"],
    }


def _reuse_request_mismatches(
    task: kb.Task,
    payload: dict[str, Any],
    *,
    title: str,
    body: str | None,
    assignee: str | None,
    created_by: str | None,
    tenant: str | None,
    priority: int,
    idempotency_key: str,
    max_runtime_seconds: int | None,
    skills: Iterable[str] | None,
    max_retries: int | None,
    model_override: str | None,
    provider_override: str | None,
    reasoning_effort: str | None,
    goal_mode: bool,
    goal_max_turns: int | None,
    initial_status: str,
    session_id: str | None,
    workflow_template_id: str | None,
    current_step_key: str | None,
    parents: Iterable[str],
    workspace_kind: str,
    workspace_path: str | None,
    branch_name: str | None,
    project_id: str | None,
    triage: bool,
) -> list[str]:
    normalized_assignee = kb._canonical_assignee(assignee)
    requested = {
        "title": title.strip(),
        "body": body,
        "assignee": normalized_assignee,
        "created_by": created_by,
        "idempotency_key": idempotency_key,
        "tenant": tenant,
        "priority": int(priority),
        "requested_initial_status": initial_status,
        "requested_workspace_kind": workspace_kind,
        "requested_workspace_path": workspace_path,
        "requested_branch_name": branch_name,
        "requested_project_id": project_id,
        "requested_triage": bool(triage),
        "parent_ids": sorted(str(parent) for parent in parents),
        "max_runtime_seconds": max_runtime_seconds,
        "skills": list(dict.fromkeys(str(skill).strip() for skill in (skills or []) if str(skill).strip())),
        "max_retries": max_retries,
        "model_override": (model_override or "").strip() or None,
        "provider_override": (provider_override or "").strip() or None,
        "reasoning_effort": kb.normalize_reasoning_effort(reasoning_effort),
        "goal_mode": bool(goal_mode),
        "goal_max_turns": goal_max_turns,
        "session_id": session_id,
        "workflow_template_id": workflow_template_id,
        "current_step_key": current_step_key,
    }
    return sorted(key for key, value in requested.items() if payload.get(key) != value)


def trusted_create_task(
    conn,
    *,
    board: str,
    title: str,
    body: str | None = None,
    assignee: str | None = None,
    created_by: str | None = None,
    workspace_kind: str = "scratch",
    workspace_path: str | None = None,
    branch_name: str | None = None,
    project_id: str | None = None,
    tenant: str | None = None,
    priority: int = 0,
    parents: Iterable[str] = (),
    triage: bool = False,
    idempotency_key: str,
    max_runtime_seconds: int | None = None,
    skills: Iterable[str] | None = None,
    max_retries: int | None = None,
    model_override: str | None = None,
    provider_override: str | None = None,
    reasoning_effort: str | None = None,
    goal_mode: bool = False,
    goal_max_turns: int | None = None,
    initial_status: str = "running",
    session_id: str | None = None,
    workflow_template_id: str | None = None,
    current_step_key: str | None = None,
) -> tuple[str, bool]:
    """Atomically create/reuse one exact host-sealed task definition."""
    if _worker_model_context():
        raise DispatchAuthorityError(
            "trusted-create is unavailable to Kanban model workers"
        )
    if not str(idempotency_key or "").strip():
        raise DispatchAuthorityError("trusted-create requires --idempotency-key")
    idempotency_key = str(idempotency_key).strip()
    key = _load_key(conn)
    parent_ids = tuple(str(parent) for parent in parents)

    with kb.write_txn(conn):
        matches = conn.execute(
            "SELECT id FROM tasks WHERE idempotency_key = ? "
            "AND status != 'archived' ORDER BY id",
            (idempotency_key,),
        ).fetchall()
        if len(matches) > 1:
            raise DispatchAuthorityError(
                "trusted-create found multiple active idempotency collisions"
            )
        if matches:
            task_id = str(matches[0]["id"])
            receipt = verify_task_authority(conn, task_id)
            if receipt is None:
                raise DispatchAuthorityError(
                    "trusted-create refused an unsealed idempotency collision"
                )
            if not receipt["verified"]:
                raise DispatchAuthorityError(
                    "trusted-create refused an invalid sealed idempotency collision"
                )
            task = kb.get_task(conn, task_id)
            mismatches = _reuse_request_mismatches(
                task,
                receipt["payload"],
                title=title,
                body=body,
                assignee=assignee,
                created_by=created_by,
                tenant=tenant,
                priority=priority,
                idempotency_key=idempotency_key,
                max_runtime_seconds=max_runtime_seconds,
                skills=skills,
                max_retries=max_retries,
                model_override=model_override,
                provider_override=provider_override,
                reasoning_effort=reasoning_effort,
                goal_mode=goal_mode,
                goal_max_turns=goal_max_turns,
                initial_status=initial_status,
                session_id=session_id,
                workflow_template_id=workflow_template_id,
                current_step_key=current_step_key,
                parents=parent_ids,
                workspace_kind=workspace_kind,
                workspace_path=workspace_path,
                branch_name=branch_name,
                project_id=project_id,
                triage=triage,
            )
            if mismatches:
                raise DispatchAuthorityError(
                    "trusted-create sealed collision differs in: "
                    + ", ".join(mismatches)
                )
            return task_id, True

        task_id = kb.create_task(
            conn,
            title=title,
            body=body,
            assignee=assignee,
            created_by=created_by,
            creation_origin="host_sealed",
            workspace_kind=workspace_kind,
            workspace_path=workspace_path,
            branch_name=branch_name,
            project_id=project_id,
            tenant=tenant,
            priority=priority,
            parents=parent_ids,
            triage=triage,
            idempotency_key=idempotency_key,
            max_runtime_seconds=max_runtime_seconds,
            skills=skills,
            max_retries=max_retries,
            model_override=model_override,
            provider_override=provider_override,
            reasoning_effort=reasoning_effort,
            goal_mode=goal_mode,
            goal_max_turns=goal_max_turns,
            workflow_template_id=workflow_template_id,
            current_step_key=current_step_key,
            initial_status=initial_status,
            session_id=session_id,
            board=board,
        )
        task = kb.get_task(conn, task_id)
        if task is None:
            raise DispatchAuthorityError("trusted-create task disappeared before seal")
        payload = task_payload(
            conn,
            task,
            board=board,
            requested_initial_status=initial_status,
            requested_workspace_kind=workspace_kind,
            requested_workspace_path=workspace_path,
            requested_branch_name=branch_name,
            requested_project_id=project_id,
            requested_triage=triage,
        )
        canonical = _canonical_json(payload)
        authority_id = "ka_" + secrets.token_hex(16)
        now = int(time.time())
        conn.execute(
            "INSERT INTO task_dispatch_authorities "
            "(task_id, contract, authority_id, key_id, payload_json, "
            "payload_sha256, receipt_hmac, sealed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                task_id,
                KANBAN_DISPATCH_AUTHORITY_CONTRACT,
                authority_id,
                hashlib.sha256(key).hexdigest()[:24],
                canonical.decode("utf-8"),
                hashlib.sha256(canonical).hexdigest(),
                _receipt_hmac(key, canonical),
                now,
            ),
        )
        receipt = verify_task_authority(conn, task_id)
        if receipt is None or not receipt["verified"]:
            raise DispatchAuthorityError("trusted-create receipt verification failed")
        return task_id, False


def consume_claim_authority(
    conn,
    task_id: str,
    run_id: int,
    *,
    expected_generation: int,
) -> bool:
    """CAS-consume a verified sealed definition for one dispatcher claim."""
    cur = conn.execute(
        "UPDATE task_dispatch_authorities "
        "SET claim_generation = claim_generation + 1, last_claimed_run_id = ? "
        "WHERE task_id = ? AND claim_generation = ?",
        (run_id, task_id, expected_generation),
    )
    return cur.rowcount == 1

"""Secret-safe credential intake token scaffolding.

This module intentionally does not write submitted secrets anywhere. It creates
short-lived bearer tokens, stores only token hashes plus destination metadata,
and consumes a token exactly once through placeholder adapters that future
storage integrations can implement behind explicit user action.
"""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import logging
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs, quote, unquote, urlparse

from hermes_constants import get_hermes_home
from utils import atomic_json_write, config_file_lock

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "hci_"
REQUEST_PREFIX = "ci_"
DEFAULT_TTL_SECONDS = 15 * 60
DEFAULT_LOCAL_BASE_URL = "http://127.0.0.1:8765"
STORE_VERSION = 1

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TTL_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$", re.IGNORECASE)
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


class CredentialIntakeError(RuntimeError):
    """Base class for credential-intake failures."""


class CredentialIntakeExpired(CredentialIntakeError):
    """Raised when a token is expired."""


class CredentialIntakeUsed(CredentialIntakeError):
    """Raised when a token was already used or revoked."""


class CredentialIntakeNotFound(CredentialIntakeError):
    """Raised when no stored token hash matches."""


@dataclass(frozen=True)
class CreatedIntakeToken:
    """Token returned once at creation time."""

    request_id: str
    token: str
    expires_at: str
    local_url: str


@dataclass(frozen=True)
class IntakeReceipt:
    """Sanitized result of consuming a token."""

    request_id: str
    adapter: str
    target: str
    stored: bool
    used_at: str


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _format_dt(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_ttl(value: str | int | None) -> int:
    """Parse TTL values like ``900``, ``15m``, ``2h``, or ``1d``."""

    if value is None:
        return DEFAULT_TTL_SECONDS
    if isinstance(value, int):
        seconds = value
    else:
        match = _TTL_RE.match(value)
        if not match:
            raise ValueError("TTL must be an integer seconds value or use s/m/h/d suffix")
        amount = int(match.group(1))
        unit = match.group(2).lower() or "s"
        multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
        seconds = amount * multiplier
    if seconds <= 0:
        raise ValueError("TTL must be positive")
    return seconds


def _hash_token(token: str) -> str:
    digest = hashlib.sha256(f"hermes-credential-intake-v1:{token}".encode()).hexdigest()
    return f"sha256:{digest}"


def _new_token() -> str:
    return f"{TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def _new_request_id() -> str:
    return f"{REQUEST_PREFIX}{secrets.token_hex(4)}"


def _target_label(destination: Mapping[str, Any]) -> str:
    adapter = str(destination.get("adapter") or "")
    if adapter == "profile-env":
        return str(destination.get("key") or "")
    if adapter == "onepassword":
        item = str(destination.get("item") or "")
        field = str(destination.get("field") or "")
        return f"{item}:{field}" if field else item
    return str(destination.get("target") or "")


def validate_destination(destination: Mapping[str, Any]) -> dict[str, Any]:
    """Return a sanitized destination descriptor for supported scaffold adapters."""

    adapter = str(destination.get("adapter") or "").strip()
    if adapter == "profile-env":
        key = str(destination.get("key") or destination.get("target") or "").strip()
        if not _ENV_NAME_RE.match(key):
            raise ValueError("profile-env destinations require a valid env var key")
        return {"adapter": "profile-env", "key": key}
    if adapter == "onepassword":
        vault = str(destination.get("vault") or "").strip()
        item = str(destination.get("item") or "").strip()
        field = str(destination.get("field") or "").strip()
        if not item or not field:
            raise ValueError("onepassword destinations require item and field")
        sanitized: dict[str, Any] = {"adapter": "onepassword", "item": item, "field": field}
        if vault:
            sanitized["vault"] = vault
        return sanitized
    raise ValueError("adapter must be one of: profile-env, onepassword")


def ensure_local_base_url(base_url: str) -> str:
    """Validate that generated intake links target localhost only."""

    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("base URL must be an http(s) localhost URL")
    if parsed.hostname not in _LOCAL_HOSTS:
        raise ValueError("credential intake links must use localhost, 127.0.0.1, or ::1")
    return base_url.rstrip("/")


def build_local_intake_url(base_url: str, request_id: str, token: str) -> str:
    """Build a localhost intake URL with the bearer token in the URL fragment."""

    base = ensure_local_base_url(base_url)
    return f"{base}/credential-intake/{quote(request_id)}#token={quote(token)}"


def parse_token_reference(value: str) -> str:
    """Accept a raw token or a generated local intake URL."""

    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("credential-intake URLs must use http(s)")
        if parsed.hostname not in _LOCAL_HOSTS:
            raise ValueError("only localhost credential-intake URLs are accepted")
        query_token = parse_qs(parsed.query).get("token")
        if query_token:
            raise ValueError("token must be in the URL fragment, not the query string")
        fragment = parse_qs(parsed.fragment).get("token")
        if not fragment:
            raise ValueError("credential-intake URL is missing #token=...")
        return unquote(fragment[0])
    return raw


def default_store_path() -> Path:
    return get_hermes_home() / "credential-intake" / "tokens.json"


class ScaffoldCredentialAdapter:
    """Placeholder adapter that acknowledges intake without persisting secrets."""

    def store_secret(
        self,
        *,
        request: Mapping[str, Any],
        secret: str,
    ) -> Mapping[str, Any]:
        destination = request.get("destination") or {}
        if not isinstance(destination, Mapping):
            destination = {}
        adapter = str(destination.get("adapter") or "")
        target = _target_label(destination)
        if not secret:
            raise ValueError("submitted secret cannot be empty")
        return {
            "adapter": adapter,
            "target": target,
            "stored": False,
            "storage": "scaffold",
            "note": "secret received and intentionally not persisted",
        }


class CredentialIntakeStore:
    """JSON-backed store for credential intake token metadata."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = Path(path) if path is not None else default_store_path()
        self._now = now or _now_utc

    def create(
        self,
        *,
        label: str,
        destination: Mapping[str, Any],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        base_url: str = DEFAULT_LOCAL_BASE_URL,
    ) -> CreatedIntakeToken:
        destination = validate_destination(destination)
        now = self._now()
        expires_at = now + timedelta(seconds=ttl_seconds)
        with config_file_lock(self.path):
            data = self._read()
            request_id = _new_request_id()
            known_ids = {item.get("id") for item in data["requests"]}
            while request_id in known_ids:
                request_id = _new_request_id()
            token = _new_token()
            data["requests"].append(
                {
                    "id": request_id,
                    "label": label.strip() or _target_label(destination) or "credential",
                    "destination": destination,
                    "token_hash": _hash_token(token),
                    "created_at": _format_dt(now),
                    "expires_at": _format_dt(expires_at),
                    "used_at": None,
                    "revoked_at": None,
                    "status": "pending",
                    "receipt": None,
                }
            )
            self._write(data)
        logger.info(
            "credential intake token created request_id=%s adapter=%s target=%s ttl_seconds=%s",
            request_id,
            destination.get("adapter"),
            _target_label(destination),
            ttl_seconds,
        )
        return CreatedIntakeToken(
            request_id=request_id,
            token=token,
            expires_at=_format_dt(expires_at),
            local_url=build_local_intake_url(base_url, request_id, token),
        )

    def list_requests(self) -> list[dict[str, Any]]:
        with config_file_lock(self.path):
            data = self._read()
            changed = self._refresh_expired(data)
            if changed:
                self._write(data)
            return [self._public_record(item) for item in data["requests"]]

    def get_request(self, request_id: str) -> dict[str, Any]:
        with config_file_lock(self.path):
            data = self._read()
            changed = self._refresh_expired(data)
            for item in data["requests"]:
                if item.get("id") == request_id:
                    if changed:
                        self._write(data)
                    return self._public_record(item)
            if changed:
                self._write(data)
        raise CredentialIntakeNotFound(f"credential intake request not found: {request_id}")

    def revoke(self, request_id: str) -> dict[str, Any]:
        with config_file_lock(self.path):
            data = self._read()
            now_text = _format_dt(self._now())
            for item in data["requests"]:
                if item.get("id") == request_id:
                    if item.get("used_at"):
                        raise CredentialIntakeUsed(f"credential intake request already used: {request_id}")
                    item["revoked_at"] = now_text
                    item["status"] = "revoked"
                    self._write(data)
                    logger.info("credential intake token revoked request_id=%s", request_id)
                    return self._public_record(item)
        raise CredentialIntakeNotFound(f"credential intake request not found: {request_id}")

    def consume(
        self,
        token_or_url: str,
        secret: str,
        *,
        adapter: ScaffoldCredentialAdapter | None = None,
    ) -> IntakeReceipt:
        if not secret:
            raise ValueError("submitted secret cannot be empty")
        token = parse_token_reference(token_or_url)
        token_hash = _hash_token(token)
        with config_file_lock(self.path):
            data = self._read()
            now = self._now()
            now_text = _format_dt(now)
            item = self._find_by_hash(data, token_hash)
            if item is None:
                raise CredentialIntakeNotFound("credential intake token not found")
            request_id = str(item.get("id") or "")
            if item.get("used_at") or item.get("status") == "used":
                raise CredentialIntakeUsed(f"credential intake request already used: {request_id}")
            if item.get("revoked_at") or item.get("status") == "revoked":
                raise CredentialIntakeUsed(f"credential intake request revoked: {request_id}")
            if now >= _parse_dt(str(item.get("expires_at"))):
                item["status"] = "expired"
                self._write(data)
                raise CredentialIntakeExpired(f"credential intake request expired: {request_id}")

            public_request = self._public_record(item)
            destination = item.get("destination") if isinstance(item.get("destination"), Mapping) else {}
            item["used_at"] = now_text
            item["status"] = "used"
            item["receipt"] = {
                "adapter": str(destination.get("adapter") or ""),
                "target": _target_label(destination),
                "stored": False,
                "storage": "scaffold",
                "note": "adapter did not return a safe receipt",
            }
            try:
                raw_receipt = (adapter or ScaffoldCredentialAdapter()).store_secret(
                    request=public_request,
                    secret=secret,
                )
                receipt = dict(raw_receipt)
                self._ensure_receipt_safe(receipt, secret)
                item["receipt"] = {
                    "adapter": str(receipt.get("adapter") or destination.get("adapter") or ""),
                    "target": str(receipt.get("target") or _target_label(destination)),
                    "stored": bool(receipt.get("stored")),
                    "storage": str(receipt.get("storage") or "scaffold"),
                    "note": str(receipt.get("note") or ""),
                }
            except Exception as exc:
                self._write(data)
                raise CredentialIntakeError("credential adapter failed to return a safe receipt") from exc
            self._write(data)
            sanitized_receipt = item["receipt"]
        logger.info(
            "credential intake token consumed request_id=%s adapter=%s target=%s stored=%s",
            request_id,
            sanitized_receipt["adapter"],
            sanitized_receipt["target"],
            sanitized_receipt["stored"],
        )
        return IntakeReceipt(
            request_id=request_id,
            adapter=sanitized_receipt["adapter"],
            target=sanitized_receipt["target"],
            stored=sanitized_receipt["stored"],
            used_at=now_text,
        )

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": STORE_VERSION, "requests": []}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise CredentialIntakeError(f"invalid credential intake store: {self.path}") from exc
        if not isinstance(data, dict):
            raise CredentialIntakeError(f"invalid credential intake store: {self.path}")
        requests = data.get("requests")
        if not isinstance(requests, list):
            requests = []
        return {"version": STORE_VERSION, "requests": requests}

    def _write(self, data: Mapping[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_json_write(self.path, data, indent=2, mode=0o600)

    def _refresh_expired(self, data: dict[str, Any]) -> bool:
        now = self._now()
        changed = False
        for item in data["requests"]:
            if item.get("status") != "pending":
                continue
            try:
                expires_at = _parse_dt(str(item.get("expires_at")))
            except (TypeError, ValueError):
                continue
            if now >= expires_at:
                item["status"] = "expired"
                changed = True
        return changed

    def _find_by_hash(self, data: Mapping[str, Any], token_hash: str) -> dict[str, Any] | None:
        for item in data.get("requests", []):
            stored_hash = str(item.get("token_hash") or "")
            if hmac.compare_digest(stored_hash, token_hash):
                return item
        return None

    def _public_record(self, item: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": item.get("id"),
            "label": item.get("label"),
            "destination": item.get("destination"),
            "created_at": item.get("created_at"),
            "expires_at": item.get("expires_at"),
            "used_at": item.get("used_at"),
            "revoked_at": item.get("revoked_at"),
            "status": item.get("status"),
            "receipt": item.get("receipt"),
        }

    def _ensure_receipt_safe(self, receipt: Mapping[str, Any], secret: str) -> None:
        rendered = json.dumps(receipt, sort_keys=True, default=str)
        if secret and secret in rendered:
            raise CredentialIntakeError("credential adapter receipt included submitted secret")


def _print_json(payload: Mapping[str, Any] | list[Mapping[str, Any]]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _destination_from_args(args: Any) -> dict[str, Any]:
    if args.adapter == "profile-env":
        return {"adapter": "profile-env", "key": args.key}
    return {
        "adapter": "onepassword",
        "vault": args.vault,
        "item": args.item,
        "field": args.field,
    }


def _read_secret_from_stdin_or_prompt(args: Any) -> str:
    if getattr(args, "value_stdin", False):
        return sys.stdin.read().rstrip("\r\n")
    if not sys.stdin.isatty():
        raise ValueError("use --value-stdin when submitting non-interactively")
    return getpass.getpass("Credential value: ")


def credential_intake_command(args: Any) -> None:
    """CLI entrypoint for ``hermes credential-intake``."""

    try:
        _credential_intake_command(args)
    except (CredentialIntakeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)


def _credential_intake_command(args: Any) -> None:
    action = getattr(args, "credential_intake_action", None)
    if not action:
        print("usage: hermes credential-intake <create|list|show|submit|revoke>", file=sys.stderr)
        return
    store = CredentialIntakeStore()

    if action == "create":
        ttl_seconds = parse_ttl(args.ttl)
        created = store.create(
            label=args.label or "",
            destination=_destination_from_args(args),
            ttl_seconds=ttl_seconds,
            base_url=args.base_url,
        )
        payload = {
            "id": created.request_id,
            "expires_at": created.expires_at,
            "local_url": created.local_url,
            "submit_command": "hermes credential-intake submit '<local_url>'",
            "warning": "token is shown once; submitted secrets are not persisted by scaffold adapters",
        }
        if args.json:
            _print_json(payload)
        else:
            print(f"Created credential intake request: {created.request_id}")
            print(f"Expires: {created.expires_at}")
            print(f"Local URL: {created.local_url}")
            print("Submit locally with: hermes credential-intake submit '<local_url>'")
        return

    if action == "list":
        records = store.list_requests()
        if args.json:
            _print_json(records)
            return
        if not records:
            print("No credential intake requests.")
            return
        for record in records:
            destination = record.get("destination") or {}
            print(
                f"{record.get('id')}  {record.get('status')}  "
                f"{destination.get('adapter')}:{_target_label(destination)}  "
                f"expires {record.get('expires_at')}"
            )
        return

    if action == "show":
        record = store.get_request(args.request_id)
        if args.json:
            _print_json(record)
        else:
            destination = record.get("destination") or {}
            print(f"ID: {record.get('id')}")
            print(f"Status: {record.get('status')}")
            print(f"Label: {record.get('label')}")
            print(f"Destination: {destination.get('adapter')}:{_target_label(destination)}")
            print(f"Expires: {record.get('expires_at')}")
            print(f"Used: {record.get('used_at') or '-'}")
        return

    if action == "submit":
        secret = _read_secret_from_stdin_or_prompt(args)
        receipt = store.consume(args.token_or_url, secret)
        payload = {
            "id": receipt.request_id,
            "adapter": receipt.adapter,
            "target": receipt.target,
            "stored": receipt.stored,
            "used_at": receipt.used_at,
        }
        if args.json:
            _print_json(payload)
        else:
            print(f"Accepted credential intake request: {receipt.request_id}")
            print("Secret was not persisted by the scaffold adapter.")
        return

    if action == "revoke":
        record = store.revoke(args.request_id)
        if args.json:
            _print_json(record)
        else:
            print(f"Revoked credential intake request: {record.get('id')}")
        return

    print(f"Unknown credential-intake action: {action}", file=sys.stderr)

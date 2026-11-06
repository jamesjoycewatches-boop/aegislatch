"""One-time, action-bound approval tokens backed by transactional SQLite.

The issuer MUST only live in a separate trusted, human-operated component.
Never expose issue() or its signing key as an LLM tool.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from .core import Decision, ToolCall, canonical_json, load_json_strict


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class ApprovalAuthority:
    """Host-only: issue after independent human verification; consume at execution."""
    def __init__(self, database: str | Path, signing_key: bytes) -> None:
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("A dedicated secret signing key of at least 32 bytes is required")
        self._key = signing_key
        self._db = Path(database)
        self._db.parent.mkdir(parents=True, exist_ok=True)
        if not self._db.exists():
            fd = os.open(str(self._db), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        with sqlite3.connect(self._db) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS tickets (nonce_hash TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, rule_id TEXT NOT NULL, expires INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0)")

    def issue_after_human_review(self, call: ToolCall, decision: Decision, *, approver: str,
                                 ttl_seconds: int = 120) -> str:
        if decision.status != "review" or not decision.rule_id:
            raise ValueError("Only review-required decisions can receive approval tickets")
        if not isinstance(approver, str) or not approver.strip() or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 300:
            raise ValueError("A verified human approver and short expiry are required")
        nonce = secrets.token_hex(32)
        expiry = int(time.time()) + ttl_seconds
        body = {"v": 1, "nonce": nonce, "expires": expiry, "fingerprint": call.fingerprint(),
                "rule_id": decision.rule_id}
        payload = _b64(canonical_json(body))
        mac = _b64(hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest())
        with sqlite3.connect(self._db, timeout=5) as conn:
            conn.execute("INSERT INTO tickets (nonce_hash, fingerprint, rule_id, expires) VALUES (?,?,?,?)",
                         (hashlib.sha256(nonce.encode()).hexdigest(), body["fingerprint"], decision.rule_id, expiry))
        # Approver identity intentionally not written to the ticket or DB in this MVP.
        return payload + "." + mac

    def consume(self, ticket: str, call: ToolCall, decision: Decision) -> bool:
        if decision.status != "review" or not decision.rule_id or not isinstance(ticket, str) or len(ticket) > 4096:
            return False
        try:
            payload, mac = ticket.split(".")
            expected = hmac.new(self._key, payload.encode("ascii"), hashlib.sha256).digest()
            if not hmac.compare_digest(expected, _unb64(mac)):
                return False
            body = load_json_strict(_unb64(payload).decode("utf-8"))
            if (set(body) != {"v", "nonce", "expires", "fingerprint", "rule_id"}
                or body["v"] != 1 or not isinstance(body["nonce"], str)
                or not isinstance(body["expires"], int)
                or body["expires"] < int(time.time())
                or not hmac.compare_digest(body["fingerprint"], call.fingerprint())
                or not hmac.compare_digest(body["rule_id"], decision.rule_id)):
                return False
            nonce_hash = hashlib.sha256(body["nonce"].encode()).hexdigest()
            with sqlite3.connect(self._db, timeout=5) as conn:
                cursor = conn.execute("UPDATE tickets SET used=1 WHERE nonce_hash=? AND fingerprint=? AND rule_id=? AND expires>=? AND used=0",
                                      (nonce_hash, body["fingerprint"], decision.rule_id, int(time.time())))
                return cursor.rowcount == 1
        except (ValueError, TypeError, UnicodeError, KeyError, json.JSONDecodeError, OverflowError):
            return False

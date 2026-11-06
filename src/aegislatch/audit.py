"""HMAC-chained append-only intent logs; stores no raw tool arguments.

Local integrity evidence only, not tamper-proof against key compromise or deletion.
Single-writer within a process; external locking required for multi-process writes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
import os
import threading
import time

from .core import Decision, ToolCall, canonical_json, load_json_strict


class AuditLedger:
    def __init__(self, path: str | Path, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("Audit key requires at least 32 secret bytes")
        self._path = Path(path)
        self._key = key
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if not self._path.exists():
            try:
                fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        if self._path.exists() and not self.verify():
            raise ValueError("Audit chain verification failed: refusing to append")

    def verify(self) -> bool:
        previous = "0" * 64
        try:
            if not self._path.exists():
                return True
            with self._path.open("r", encoding="utf-8") as file:
                for line in file:
                    record = load_json_strict(line)
                    if set(record) != {"event", "previous", "mac"} or record["previous"] != previous:
                        return False
                    calculated = hmac.new(self._key, canonical_json({"event": record["event"],
                                                                     "previous": previous}), hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(calculated, record["mac"]):
                        return False
                    previous = record["mac"]
            return True
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            return False

    def append(self, call: ToolCall, decision: Decision) -> None:
        with self._lock:
            if not self.verify():
                raise ValueError("Refusing to append to modified audit chain")
            previous = "0" * 64
            if self._path.exists():
                with self._path.open("rb") as file:
                    for line in file:
                        if line.strip():
                            previous = json.loads(line)["mac"]
            event = {"utc_unix": int(time.time()), "call_hash": call.fingerprint(),
                     "status": decision.status, "rule_id": decision.rule_id,
                     "reason": decision.reason}
            mac = hmac.new(self._key, canonical_json({"event": event, "previous": previous}),
                           hashlib.sha256).hexdigest()
            record = {"event": event, "previous": previous, "mac": mac}
            with self._path.open("a", encoding="utf-8") as file:
                file.write(canonical_json(record).decode("ascii") + "\n")
                file.flush()

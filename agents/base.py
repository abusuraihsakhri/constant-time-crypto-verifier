"""Input guards and an in-memory HMAC-SHA256 audit chain."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

PHI_PATTERNS = [
    re.compile(r"\b(?:MRN|mrn)[:#\s-]*\d{4,10}\b", re.IGNORECASE),
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    re.compile(r"\b(?:DOB|Date of Birth)[:\s]*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.IGNORECASE),
    re.compile(r"\b(?:Patient\s+Name|Patient)[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b", re.IGNORECASE),
]


class SecurityException(Exception):
    """Raised when an outbound text guard detects a configured sensitive identifier."""


class ResourceLimitExceededException(Exception):
    """Raised when computational parameters exceed configured safety bounds."""


def assert_no_phi(text: str) -> None:
    """Reject text matching the small built-in sensitive-identifier pattern set.

    This is a narrow heuristic guard, not a complete HIPAA de-identification mechanism.
    """

    if not text:
        return
    value = str(text)
    for pattern in PHI_PATTERNS:
        if pattern.search(value):
            raise SecurityException("Sensitive identifier detected by outbound text guard")


class PHIGuard:
    @staticmethod
    def assert_no_phi(text: str) -> None:
        assert_no_phi(text)

    @staticmethod
    def redact_phi(text: str) -> str:
        result = str(text)
        for pattern in PHI_PATTERNS:
            result = pattern.sub("[REDACTED_IDENTIFIER]", result)
        return result


class AuditTrail:
    """Process-local HMAC chain for detecting mutation of recorded entries.

    When ``AUDIT_SECRET_KEY`` is absent, a random process-local key is generated. That keeps
    the example safe from a repository-wide default key, but it also means verification does
    not persist across process restarts unless the caller explicitly supplies a stable key.
    """

    GENESIS = "GENESIS_BLOCK_0000000000000000"

    def __init__(self, secret_key: Optional[str | bytes] = None):
        configured = secret_key if secret_key is not None else os.getenv("AUDIT_SECRET_KEY")
        if configured is None:
            self.secret_key = secrets.token_bytes(32)
        elif isinstance(configured, bytes):
            self.secret_key = configured
        else:
            self.secret_key = configured.encode("utf-8")
        if len(self.secret_key) < 16:
            raise ValueError("audit secret key must be at least 16 bytes")
        self.logs: List[Dict[str, Any]] = []

    def _signature_for(self, entry: Dict[str, Any]) -> str:
        sign_string = "|".join(
            [
                str(entry["audit_id"]),
                str(entry["timestamp"]),
                str(entry["actor"]),
                str(entry["actor_tier"]),
                str(entry["event_type"]),
                str(entry["payload_hash"]),
                str(entry["prev_hash"]),
            ]
        )
        return hmac.new(self.secret_key, sign_string.encode("utf-8"), hashlib.sha256).hexdigest()

    def log(self, actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        payload_str = json.dumps(details, sort_keys=True, separators=(",", ":"), default=str)
        assert_no_phi(payload_str)
        entry: Dict[str, Any] = {
            "audit_id": f"AUDIT-{time.time_ns()}-{len(self.logs) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "actor_tier": actor_tier,
            "event_type": event_type,
            "payload_hash": hashlib.sha256(payload_str.encode("utf-8")).hexdigest(),
            "prev_hash": self.logs[-1]["current_hash"] if self.logs else self.GENESIS,
        }
        entry["current_hash"] = self._signature_for(entry)
        self.logs.append(entry)
        return dict(entry)

    def verify_integrity(self) -> bool:
        previous = self.GENESIS
        for entry in self.logs:
            required = {
                "audit_id",
                "timestamp",
                "actor",
                "actor_tier",
                "event_type",
                "payload_hash",
                "prev_hash",
                "current_hash",
            }
            if not required.issubset(entry):
                return False
            if entry["prev_hash"] != previous:
                return False
            expected = self._signature_for(entry)
            if not hmac.compare_digest(str(entry["current_hash"]), expected):
                return False
            previous = str(entry["current_hash"])
        return True

    def get_trail(self) -> List[Dict[str, Any]]:
        return [dict(entry) for entry in self.logs]


GLOBAL_AUDIT = AuditTrail()


class AuditLogger:
    @staticmethod
    def log(actor: str, actor_tier: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        return GLOBAL_AUDIT.log(actor, actor_tier, event_type, details)

    @staticmethod
    def get_trail() -> List[Dict[str, Any]]:
        return GLOBAL_AUDIT.get_trail()

    @staticmethod
    def verify_integrity() -> bool:
        return GLOBAL_AUDIT.verify_integrity()


class ActionExecutor:
    @staticmethod
    def execute_with_audit(actor: str, actor_tier: str, action_type: str, fn, *args, **kwargs):
        result = fn(*args, **kwargs)
        AuditLogger.log(actor, actor_tier, action_type, {"status": "SUCCESS"})
        return result

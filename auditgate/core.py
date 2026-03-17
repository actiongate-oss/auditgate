# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Core types for AuditGate."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any


class Mode(Enum):
    """Enforcement mode for audit failures."""
    HARD = auto()
    SOFT = auto()


class StoreErrorMode(Enum):
    """Behavior when audit store backend fails."""
    FAIL_CLOSED = auto()
    FAIL_OPEN = auto()


class Status(Enum):
    """Audit recording outcome."""
    RECORDED = auto()
    DROPPED = auto()


class Severity(Enum):
    """Audit entry severity level."""
    DEBUG = auto()
    INFO = auto()
    WARN = auto()
    ERROR = auto()
    CRITICAL = auto()


class Verdict(Enum):
    """Outcome of the gate decision being audited."""
    ALLOW = auto()
    BLOCK = auto()
    ERROR = auto()
    OVERRIDE = auto()


class IntegrityMode(Enum):
    """Tamper-evidence mode for audit entries."""
    NONE = auto()
    HASH = auto()
    CHAIN = auto()


@dataclass(frozen=True, slots=True)
class Trail:
    """Identifies an audit trail (log stream)."""
    namespace: str
    source: str
    principal: str = "global"

    def __str__(self) -> str:
        return f"{self.namespace}:{self.source}@{self.principal}"

    @property
    def key(self) -> str:
        return f"aud:{self.namespace}:{self.source}:{self.principal}"


@dataclass(frozen=True, slots=True)
class AuditPolicy:
    """Configuration for an audit trail."""
    mode: Mode = Mode.HARD
    on_store_error: StoreErrorMode = StoreErrorMode.FAIL_CLOSED
    min_severity: Severity = Severity.DEBUG
    retention_seconds: float | None = None
    integrity: IntegrityMode = IntegrityMode.HASH

    def __post_init__(self) -> None:
        if self.retention_seconds is not None and self.retention_seconds <= 0:
            raise ValueError("retention_seconds must be positive or None")


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """A single audit log entry."""
    trail: Trail
    ts: float
    wall_ts: str
    verdict: Verdict
    severity: Severity
    gate_type: str
    gate_identity: str
    recorded_by: str = ""
    reason: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    entry_hash: str | None = None
    prev_hash: str | None = None
    sequence: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Canonical JSON-portable format for cross-language compatibility."""
        return {
            "schema_version": "0.1.1",
            "trail": str(self.trail),
            "ts": self.ts,
            "wall_ts": self.wall_ts,
            "verdict": self.verdict.name,
            "severity": self.severity.name,
            "gate_type": self.gate_type,
            "gate_identity": self.gate_identity,
            "recorded_by": self.recorded_by,
            "reason": self.reason,
            "detail": self.detail,
            "entry_hash": self.entry_hash,
            "prev_hash": self.prev_hash,
            "sequence": self.sequence,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of attempting to record an audit entry."""
    status: Status
    trail: Trail
    policy: AuditPolicy
    entry: AuditEntry | None = None
    reason: str | None = None

    @property
    def recorded(self) -> bool:
        return self.status == Status.RECORDED

    @property
    def dropped(self) -> bool:
        return self.status == Status.DROPPED

    def __bool__(self) -> bool:
        return self.recorded


class _Missing:
    """Sentinel for distinguishing None from missing value."""
    __slots__ = ()
    def __repr__(self) -> str:
        return "<MISSING>"


MISSING = _Missing()


@dataclass(frozen=True, slots=True)
class Result[T]:
    """Wrapper for guarded function results."""
    decision: Decision
    _value: T | _Missing = field(default=MISSING)

    @property
    def ok(self) -> bool:
        return self.decision.recorded

    def unwrap(self) -> T:
        if isinstance(self._value, _Missing):
            raise RuntimeError(
                f"unwrap() called on dropped audit: {self.decision.reason}"
            )
        return self._value

    def unwrap_or(self, default: T) -> T:
        if isinstance(self._value, _Missing):
            return default
        return self._value


# ── Integrity ──

def compute_hash(
    entry_data: dict[str, Any],
    prev_hash: str | None = None,
) -> str:
    """Deterministic SHA-256 content hash over canonical JSON."""
    hashable = {
        "trail": entry_data.get("trail", ""),
        "ts": entry_data.get("ts", 0),
        "verdict": entry_data.get("verdict", ""),
        "severity": entry_data.get("severity", ""),
        "gate_type": entry_data.get("gate_type", ""),
        "gate_identity": entry_data.get("gate_identity", ""),
        "reason": entry_data.get("reason"),
        "detail": entry_data.get("detail", {}),
        "sequence": entry_data.get("sequence", 0),
    }
    if prev_hash is not None:
        hashable["prev_hash"] = prev_hash
    canonical = json.dumps(hashable, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(entries: list[AuditEntry]) -> tuple[bool, int | None]:
    """Verify hash chain integrity. Returns (valid, broken_at)."""
    for i, entry in enumerate(entries):
        if entry.entry_hash is None:
            continue

        base_data = {
            "trail": str(entry.trail),
            "ts": entry.ts,
            "verdict": entry.verdict.name,
            "severity": entry.severity.name,
            "gate_type": entry.gate_type,
            "gate_identity": entry.gate_identity,
            "reason": entry.reason,
            "detail": entry.detail,
            "sequence": entry.sequence,
        }

        expected = compute_hash(base_data, prev_hash=entry.prev_hash)
        if entry.entry_hash != expected:
            return False, entry.sequence

        if entry.prev_hash is not None and i > 0 and entries[i - 1].entry_hash != entry.prev_hash:
                return False, entry.sequence

    return True, None


def wall_clock() -> str:
    """Current wall-clock time as ISO 8601 UTC."""
    return datetime.now(UTC).isoformat()

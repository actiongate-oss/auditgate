# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""AuditGate engine for compliance-grade audit logging."""

from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, ParamSpec, TypeVar

from .core import (
    MISSING, AuditEntry, AuditPolicy, Decision, IntegrityMode,
    Mode, Result, Severity, Status, StoreErrorMode, Trail,
    Verdict, compute_hash, wall_clock,
)
from .emitter import Emitter
from .store import MemoryStore, Store

P = ParamSpec("P")
T = TypeVar("T")


class AuditError(RuntimeError):
    """Raised when audit logging fails in HARD mode."""
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.reason or f"Audit failure: {decision.status}")
        self.decision = decision


class Engine:
    """AuditGate engine for compliance-grade audit logging."""

    __slots__ = (
        "_store", "_clock", "_wall_clock", "_recorded_by",
        "_policies", "_sequences", "_emitter",
    )

    def __init__(
        self,
        store: Store | None = None,
        clock: Callable[[], float] | None = None,
        wall_clock_fn: Callable[[], str] | None = None,
        recorded_by: str = "",
        emitter: Emitter | None = None,
    ) -> None:
        self._store: Store = store or MemoryStore()
        self._clock = clock or time.monotonic
        self._wall_clock = wall_clock_fn or wall_clock
        self._recorded_by = recorded_by
        self._policies: dict[Trail, AuditPolicy] = {}
        self._sequences: dict[Trail, int] = {}
        self._emitter = emitter or Emitter()

    def register(self, trail: Trail, policy: AuditPolicy) -> None:
        self._policies[trail] = policy

    def policy_for(self, trail: Trail) -> AuditPolicy | None:
        return self._policies.get(trail)

    def on_decision(self, listener: Callable[[Decision], None]) -> None:
        self._emitter.add(listener)

    @property
    def listener_errors(self) -> int:
        return self._emitter.error_count

    def record(
        self,
        trail: Trail,
        *,
        verdict: Verdict,
        severity: Severity,
        gate_type: str,
        gate_identity: str,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
        policy: AuditPolicy | None = None,
    ) -> Decision:
        """Record an audit entry for a gate decision."""
        if policy is not None:
            self._policies[trail] = policy
        p = self._policies.get(trail)
        if p is None:
            p = AuditPolicy()
            self._policies[trail] = p
        if _sev_rank(severity) < _sev_rank(p.min_severity):
            return self._decide(trail, p, Status.DROPPED,
                                reason=f"Below min_severity ({p.min_severity.name})")
        now = self._clock()
        try:
            entry = self._build_entry(trail, p, now, verdict, severity,
                                      gate_type, gate_identity, reason, detail or {})
        except Exception as exc:
            return self._on_store_error(trail, p, f"Entry build failed: {exc}")
        try:
            self._store.append(entry)
        except Exception as exc:
            return self._on_store_error(trail, p, f"Store append failed: {exc}")
        if p.retention_seconds is not None:
            try:
                self._store.prune(trail, now - p.retention_seconds)
            except Exception:
                pass
        return self._decide(trail, p, Status.RECORDED, entry=entry)

    def enforce(self, decision: Decision) -> None:
        if decision.dropped and decision.policy.mode == Mode.HARD:
            raise AuditError(decision)

    def clear(self, trail: Trail) -> None:
        self._store.clear(trail)
        self._sequences.pop(trail, None)

    def clear_all(self) -> None:
        self._store.clear_all()
        self._sequences.clear()

    def guard(
        self, trail: Trail, *, policy: AuditPolicy | None = None,
        verdict: Verdict = Verdict.ALLOW, severity: Severity = Severity.INFO,
        gate_type: str = "auditgate", meta: dict[str, Any] | None = None,
    ) -> Callable[[Callable[P, T]], Callable[P, T]]:
        if policy is not None:
            self.register(trail, policy)
        def decorator(fn: Callable[P, T]) -> Callable[P, T]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                d = self._guard_record(trail, verdict, severity, gate_type, fn, meta)
                if d.dropped:
                    self.enforce(d)
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    def guard_result(
        self, trail: Trail, *, policy: AuditPolicy | None = None,
        verdict: Verdict = Verdict.ALLOW, severity: Severity = Severity.INFO,
        gate_type: str = "auditgate", meta: dict[str, Any] | None = None,
    ) -> Callable[[Callable[P, T]], Callable[P, Result[T]]]:
        if policy is not None:
            self.register(trail, policy)
        def decorator(fn: Callable[P, T]) -> Callable[P, Result[T]]:
            @wraps(fn)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
                d = self._guard_record(trail, verdict, severity, gate_type, fn, meta,
                                       prefix="guard_result")
                if d.dropped:
                    return Result(decision=d)
                return Result(decision=d, _value=fn(*args, **kwargs))
            return wrapper
        return decorator

    def _guard_record(self, trail, verdict, severity, gate_type, fn, meta, prefix="guard"):
        return self.record(trail=trail, verdict=verdict, severity=severity,
                           gate_type=gate_type, gate_identity=str(trail),
                           reason=f"{prefix}:{fn.__qualname__}", detail=meta or {})

    def _build_entry(self, trail, policy, now, verdict, severity, gate_type,
                     gate_identity, reason, detail):
        seq = self._next_seq(trail)
        base = {
            "trail": str(trail), "ts": now, "verdict": verdict.name,
            "severity": severity.name, "gate_type": gate_type,
            "gate_identity": gate_identity, "reason": reason,
            "detail": detail, "sequence": seq,
        }
        entry_hash = None
        prev_hash = None
        if policy.integrity == IntegrityMode.HASH:
            entry_hash = compute_hash(base)
        elif policy.integrity == IntegrityMode.CHAIN:
            prev = self._store.last_entry(trail)
            prev_hash = prev.entry_hash if prev is not None else None
            entry_hash = compute_hash(base, prev_hash=prev_hash)
        return AuditEntry(
            trail=trail, ts=now, wall_ts=self._wall_clock(),
            verdict=verdict, severity=severity, gate_type=gate_type,
            gate_identity=gate_identity, recorded_by=self._recorded_by,
            reason=reason, detail=detail, entry_hash=entry_hash,
            prev_hash=prev_hash, sequence=seq,
        )

    def _next_seq(self, trail):
        if trail not in self._sequences:
            last = self._store.last_entry(trail)
            self._sequences[trail] = (last.sequence + 1) if last is not None else 0
        seq = self._sequences[trail]
        self._sequences[trail] = seq + 1
        return seq

    def _on_store_error(self, trail, policy, msg):
        decision = self._decide(trail, policy, Status.DROPPED, reason=msg)
        if policy.on_store_error == StoreErrorMode.FAIL_CLOSED and policy.mode == Mode.HARD:
            raise AuditError(decision)
        return decision

    def _decide(self, trail, policy, status, entry=None, reason=None):
        d = Decision(status=status, trail=trail, policy=policy, entry=entry, reason=reason)
        self._emitter.emit(d)
        return d


def _sev_rank(severity: Severity) -> int:
    return {Severity.DEBUG: 0, Severity.INFO: 1, Severity.WARN: 2,
            Severity.ERROR: 3, Severity.CRITICAL: 4}[severity]

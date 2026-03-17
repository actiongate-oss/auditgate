# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""AuditGate engine for compliance-grade audit logging."""

from __future__ import annotations

import contextlib
import time
from collections.abc import Callable, Coroutine
from functools import wraps
from typing import Any, ParamSpec, TypeVar

from .core import (
    AuditEntry,
    AuditPolicy,
    Decision,
    IntegrityMode,
    Mode,
    Result,
    Severity,
    Status,
    StoreErrorMode,
    Trail,
    Verdict,
    compute_hash,
    wall_clock,
)
from .emitter import Emitter
from .store import AsyncMemoryStore, AsyncStore, MemoryStore, Store

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
        "_store", "_async_store", "_clock", "_wall_clock", "_recorded_by",
        "_policies", "_sequences", "_emitter",
    )

    def __init__(
        self,
        store: Store | None = None,
        clock: Callable[[], float] | None = None,
        wall_clock_fn: Callable[[], str] | None = None,
        recorded_by: str = "",
        emitter: Emitter | None = None,
        async_store: AsyncStore | None = None,
    ) -> None:
        self._store: Store = store or MemoryStore()
        self._async_store: AsyncStore = async_store or AsyncMemoryStore()
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
            with contextlib.suppress(Exception):
                self._store.prune(trail, now - p.retention_seconds)
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

    # ─────────────────────────────────────────────────────────────
    # Async API
    # ─────────────────────────────────────────────────────────────

    async def async_record(
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
        """Async version of record(). Uses async_store."""
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
            entry = await self._async_build_entry(
                trail, p, now, verdict, severity,
                gate_type, gate_identity, reason, detail or {},
            )
        except Exception as exc:
            return self._on_store_error(trail, p, f"Entry build failed: {exc}")
        try:
            await self._async_store.append(entry)
        except Exception as exc:
            return self._on_store_error(trail, p, f"Store append failed: {exc}")
        if p.retention_seconds is not None:
            with contextlib.suppress(Exception):
                await self._async_store.prune(trail, now - p.retention_seconds)
        return self._decide(trail, p, Status.RECORDED, entry=entry)

    async def async_enforce(self, decision: Decision) -> None:
        """Async version of enforce(). Raises AuditError in HARD mode."""
        if decision.dropped and decision.policy.mode == Mode.HARD:
            raise AuditError(decision)

    def async_guard(
        self, trail: Trail, *, policy: AuditPolicy | None = None,
        verdict: Verdict = Verdict.ALLOW, severity: Severity = Severity.INFO,
        gate_type: str = "auditgate", meta: dict[str, Any] | None = None,
    ) -> Callable[
        [Callable[P, Coroutine[object, object, T]]],
        Callable[P, Coroutine[object, object, T]],
    ]:
        """Async decorator that raises AuditError on dropped + HARD."""
        if policy is not None:
            self.register(trail, policy)

        def decorator(
            fn: Callable[P, Coroutine[object, object, T]],
        ) -> Callable[P, Coroutine[object, object, T]]:
            @wraps(fn)
            async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                d = await self._async_guard_record(
                    trail, verdict, severity, gate_type, fn, meta,
                )
                if d.dropped:
                    await self.async_enforce(d)
                return await fn(*args, **kwargs)
            return wrapper
        return decorator

    def async_guard_result(
        self, trail: Trail, *, policy: AuditPolicy | None = None,
        verdict: Verdict = Verdict.ALLOW, severity: Severity = Severity.INFO,
        gate_type: str = "auditgate", meta: dict[str, Any] | None = None,
    ) -> Callable[
        [Callable[P, Coroutine[object, object, T]]],
        Callable[P, Coroutine[object, object, Result[T]]],
    ]:
        """Async decorator that returns Result[T] (never raises)."""
        if policy is not None:
            self.register(trail, policy)

        def decorator(
            fn: Callable[P, Coroutine[object, object, T]],
        ) -> Callable[P, Coroutine[object, object, Result[T]]]:
            @wraps(fn)
            async def wrapper(*args: P.args, **kwargs: P.kwargs) -> Result[T]:
                d = await self._async_guard_record(
                    trail, verdict, severity, gate_type, fn, meta,
                    prefix="async_guard_result",
                )
                if d.dropped:
                    return Result(decision=d)
                return Result(decision=d, _value=await fn(*args, **kwargs))
            return wrapper
        return decorator

    async def _async_guard_record(
        self, trail: Trail, verdict: Verdict, severity: Severity,
        gate_type: str, fn: Any, meta: dict[str, Any] | None,
        prefix: str = "async_guard",
    ) -> Decision:
        return await self.async_record(
            trail=trail, verdict=verdict, severity=severity,
            gate_type=gate_type, gate_identity=str(trail),
            reason=f"{prefix}:{fn.__qualname__}", detail=meta or {},
        )

    async def _async_build_entry(
        self, trail: Trail, policy: AuditPolicy, now: float,
        verdict: Verdict, severity: Severity, gate_type: str,
        gate_identity: str, reason: str | None, detail: dict[str, Any],
    ) -> AuditEntry:
        seq = await self._async_next_seq(trail)
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
            prev = await self._async_store.last_entry(trail)
            prev_hash = prev.entry_hash if prev is not None else None
            entry_hash = compute_hash(base, prev_hash=prev_hash)
        return AuditEntry(
            trail=trail, ts=now, wall_ts=self._wall_clock(),
            verdict=verdict, severity=severity, gate_type=gate_type,
            gate_identity=gate_identity, recorded_by=self._recorded_by,
            reason=reason, detail=detail, entry_hash=entry_hash,
            prev_hash=prev_hash, sequence=seq,
        )

    async def _async_next_seq(self, trail: Trail) -> int:
        if trail not in self._sequences:
            last = await self._async_store.last_entry(trail)
            self._sequences[trail] = (last.sequence + 1) if last is not None else 0
        seq = self._sequences[trail]
        self._sequences[trail] = seq + 1
        return seq

    # ─────────────────────────────────────────────────────────────
    # Internal (sync)
    # ─────────────────────────────────────────────────────────────

    def _guard_record(
        self, trail: Trail, verdict: Verdict, severity: Severity,
        gate_type: str, fn: Any, meta: dict[str, Any] | None,
        prefix: str = "guard",
    ) -> Decision:
        return self.record(trail=trail, verdict=verdict, severity=severity,
                           gate_type=gate_type, gate_identity=str(trail),
                           reason=f"{prefix}:{fn.__qualname__}", detail=meta or {})

    def _build_entry(
        self, trail: Trail, policy: AuditPolicy, now: float,
        verdict: Verdict, severity: Severity, gate_type: str,
        gate_identity: str, reason: str | None, detail: dict[str, Any],
    ) -> AuditEntry:
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

    def _next_seq(self, trail: Trail) -> int:
        if trail not in self._sequences:
            last = self._store.last_entry(trail)
            self._sequences[trail] = (last.sequence + 1) if last is not None else 0
        seq = self._sequences[trail]
        self._sequences[trail] = seq + 1
        return seq

    def _on_store_error(
        self, trail: Trail, policy: AuditPolicy, msg: str,
    ) -> Decision:
        decision = self._decide(trail, policy, Status.DROPPED, reason=msg)
        if policy.on_store_error == StoreErrorMode.FAIL_CLOSED and policy.mode == Mode.HARD:
            raise AuditError(decision)
        return decision

    def _decide(
        self, trail: Trail, policy: AuditPolicy, status: Status,
        entry: AuditEntry | None = None, reason: str | None = None,
    ) -> Decision:
        d = Decision(status=status, trail=trail, policy=policy, entry=entry, reason=reason)
        self._emitter.emit(d)
        return d


def _sev_rank(severity: Severity) -> int:
    return {Severity.DEBUG: 0, Severity.INFO: 1, Severity.WARN: 2,
            Severity.ERROR: 3, Severity.CRITICAL: 4}[severity]

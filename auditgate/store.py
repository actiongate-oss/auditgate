"""Storage backends for AuditGate."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol, Sequence

from .core import AuditEntry, Severity, Trail, Verdict


@dataclass(frozen=True, slots=True)
class QueryFilter:
    """Filter criteria for querying audit entries."""
    trail: Trail | None = None
    verdict: Verdict | None = None
    min_severity: Severity | None = None
    after_ts: float | None = None
    before_ts: float | None = None
    gate_type: str | None = None
    offset: int = 0
    limit: int | None = None


class Store(Protocol):
    """Protocol for audit storage backends. Must be thread-safe."""

    def append(self, entry: AuditEntry) -> None: ...
    def query(self, filter: QueryFilter) -> Sequence[AuditEntry]: ...
    def last_entry(self, trail: Trail) -> AuditEntry | None: ...
    def count(self, trail: Trail) -> int: ...
    def prune(self, trail: Trail, before_ts: float) -> int: ...
    def clear(self, trail: Trail) -> None: ...
    def clear_all(self) -> None: ...


_SEV_ORDER: dict[Severity, int] = {
    Severity.DEBUG: 0, Severity.INFO: 1, Severity.WARN: 2,
    Severity.ERROR: 3, Severity.CRITICAL: 4,
}


class MemoryStore:
    """Thread-safe in-memory audit store."""

    __slots__ = ("_trails", "_locks", "_global_lock")

    def __init__(self) -> None:
        self._trails: dict[Trail, list[AuditEntry]] = {}
        self._locks: dict[Trail, threading.Lock] = {}
        self._global_lock = threading.Lock()

    def _get_lock(self, trail: Trail) -> threading.Lock:
        with self._global_lock:
            if trail not in self._locks:
                self._locks[trail] = threading.Lock()
            return self._locks[trail]

    def append(self, entry: AuditEntry) -> None:
        lock = self._get_lock(entry.trail)
        with lock:
            if entry.trail not in self._trails:
                self._trails[entry.trail] = []
            self._trails[entry.trail].append(entry)

    def query(self, filter: QueryFilter) -> Sequence[AuditEntry]:
        with self._global_lock:
            if filter.trail is not None:
                keys = [filter.trail] if filter.trail in self._trails else []
            else:
                keys = list(self._trails.keys())

        results: list[AuditEntry] = []
        for k in keys:
            lock = self._get_lock(k)
            with lock:
                for entry in self._trails.get(k, []):
                    if self._matches(entry, filter):
                        results.append(entry)

        results.sort(key=lambda e: (e.ts, e.sequence))
        if filter.offset > 0:
            results = results[filter.offset:]
        if filter.limit is not None:
            results = results[:filter.limit]
        return results

    def last_entry(self, trail: Trail) -> AuditEntry | None:
        lock = self._get_lock(trail)
        with lock:
            entries = self._trails.get(trail)
            return entries[-1] if entries else None

    def count(self, trail: Trail) -> int:
        lock = self._get_lock(trail)
        with lock:
            return len(self._trails.get(trail, []))

    def prune(self, trail: Trail, before_ts: float) -> int:
        lock = self._get_lock(trail)
        with lock:
            entries = self._trails.get(trail, [])
            original = len(entries)
            self._trails[trail] = [e for e in entries if e.ts >= before_ts]
            return original - len(self._trails[trail])

    def clear(self, trail: Trail) -> None:
        lock = self._get_lock(trail)
        with lock:
            self._trails.pop(trail, None)

    def clear_all(self) -> None:
        with self._global_lock:
            self._trails.clear()
            self._locks.clear()

    @staticmethod
    def _matches(entry: AuditEntry, filter: QueryFilter) -> bool:
        if filter.verdict is not None and entry.verdict != filter.verdict:
            return False
        if filter.min_severity is not None:
            if _SEV_ORDER[entry.severity] < _SEV_ORDER[filter.min_severity]:
                return False
        if filter.after_ts is not None and entry.ts < filter.after_ts:
            return False
        if filter.before_ts is not None and entry.ts > filter.before_ts:
            return False
        if filter.gate_type is not None and entry.gate_type != filter.gate_type:
            return False
        return True

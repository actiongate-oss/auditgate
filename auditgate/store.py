"""Storage backends for AuditGate."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

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


class AsyncStore(Protocol):
    """Async protocol for audit storage backends."""

    async def append(self, entry: AuditEntry) -> None: ...
    async def query(self, filter: QueryFilter) -> Sequence[AuditEntry]: ...
    async def last_entry(self, trail: Trail) -> AuditEntry | None: ...
    async def count(self, trail: Trail) -> int: ...
    async def prune(self, trail: Trail, before_ts: float) -> int: ...
    async def clear(self, trail: Trail) -> None: ...
    async def clear_all(self) -> None: ...


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
        if (filter.min_severity is not None
                and _SEV_ORDER[entry.severity] < _SEV_ORDER[filter.min_severity]):
            return False
        if filter.after_ts is not None and entry.ts < filter.after_ts:
            return False
        if filter.before_ts is not None and entry.ts > filter.before_ts:
            return False
        return not (filter.gate_type is not None and entry.gate_type != filter.gate_type)


class AsyncMemoryStore:
    """Async in-memory audit store using asyncio.Lock."""

    __slots__ = ("_trails", "_locks", "_global_lock")

    def __init__(self) -> None:
        self._trails: dict[Trail, list[AuditEntry]] = {}
        self._locks: dict[Trail, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _get_lock(self, trail: Trail) -> asyncio.Lock:
        async with self._global_lock:
            if trail not in self._locks:
                self._locks[trail] = asyncio.Lock()
            return self._locks[trail]

    async def append(self, entry: AuditEntry) -> None:
        lock = await self._get_lock(entry.trail)
        async with lock:
            if entry.trail not in self._trails:
                self._trails[entry.trail] = []
            self._trails[entry.trail].append(entry)

    async def query(self, filter: QueryFilter) -> Sequence[AuditEntry]:
        async with self._global_lock:
            if filter.trail is not None:
                keys = [filter.trail] if filter.trail in self._trails else []
            else:
                keys = list(self._trails.keys())

        results: list[AuditEntry] = []
        for k in keys:
            lock = await self._get_lock(k)
            async with lock:
                for entry in self._trails.get(k, []):
                    if MemoryStore._matches(entry, filter):
                        results.append(entry)

        results.sort(key=lambda e: (e.ts, e.sequence))
        if filter.offset > 0:
            results = results[filter.offset:]
        if filter.limit is not None:
            results = results[:filter.limit]
        return results

    async def last_entry(self, trail: Trail) -> AuditEntry | None:
        lock = await self._get_lock(trail)
        async with lock:
            entries = self._trails.get(trail)
            return entries[-1] if entries else None

    async def count(self, trail: Trail) -> int:
        lock = await self._get_lock(trail)
        async with lock:
            return len(self._trails.get(trail, []))

    async def prune(self, trail: Trail, before_ts: float) -> int:
        lock = await self._get_lock(trail)
        async with lock:
            entries = self._trails.get(trail, [])
            original = len(entries)
            self._trails[trail] = [e for e in entries if e.ts >= before_ts]
            return original - len(self._trails[trail])

    async def clear(self, trail: Trail) -> None:
        lock = await self._get_lock(trail)
        async with lock:
            self._trails.pop(trail, None)

    async def clear_all(self) -> None:
        async with self._global_lock:
            self._trails.clear()
            self._locks.clear()

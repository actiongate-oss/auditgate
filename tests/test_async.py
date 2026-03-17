# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0

"""Async tests for AuditGate."""

from __future__ import annotations

from typing import Any

import pytest

from auditgate import (
    AsyncMemoryStore,
    AuditError,
    AuditPolicy,
    Decision,
    Engine,
    IntegrityMode,
    Mode,
    Severity,
    StoreErrorMode,
    Trail,
    Verdict,
    verify_chain,
)
from auditgate.store import QueryFilter

# ═══════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════


class MockClock:
    """Controllable clock for testing."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class AsyncBrokenStore:
    """Async store that always raises."""

    async def append(self, entry: Any) -> None:
        raise RuntimeError("store is down")

    async def query(self, filter: Any) -> list:
        return []

    async def last_entry(self, trail: Any) -> None:
        return None

    async def count(self, trail: Any) -> int:
        return 0

    async def prune(self, trail: Any, before_ts: float) -> int:
        raise RuntimeError("store is down")

    async def clear(self, trail: Any) -> None:
        pass

    async def clear_all(self) -> None:
        pass


def _trail() -> Trail:
    return Trail("test", "action")


def _engine(**kwargs: Any) -> Engine:
    return Engine(async_store=AsyncMemoryStore(), **kwargs)


# ═══════════════════════════════════════════════════════════════
# async_record
# ═══════════════════════════════════════════════════════════════


class TestAsyncRecord:
    """async_record mirrors sync record behavior."""

    async def test_record_allow(self) -> None:
        engine = _engine()
        trail = _trail()
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="actiongate", gate_identity="test:action",
        )
        assert d.recorded
        assert d.entry is not None
        assert d.entry.verdict == Verdict.ALLOW

    async def test_record_block(self) -> None:
        engine = _engine()
        trail = _trail()
        d = await engine.async_record(
            trail, verdict=Verdict.BLOCK, severity=Severity.WARN,
            gate_type="actiongate", gate_identity="test:action",
            reason="rate limit exceeded",
        )
        assert d.recorded
        assert d.entry is not None
        assert d.entry.verdict == Verdict.BLOCK
        assert d.entry.reason == "rate limit exceeded"

    async def test_below_min_severity_drops(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(min_severity=Severity.WARN)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.DEBUG,
            gate_type="actiongate", gate_identity="test:action",
            policy=policy,
        )
        assert d.dropped
        assert "min_severity" in (d.reason or "")

    async def test_hash_integrity(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(integrity=IntegrityMode.HASH)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="actiongate", gate_identity="test:action",
            policy=policy,
        )
        assert d.entry is not None
        assert d.entry.entry_hash is not None
        assert d.entry.prev_hash is None

    async def test_chain_integrity(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(integrity=IntegrityMode.CHAIN)
        d1 = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="actiongate", gate_identity="test:action",
            policy=policy,
        )
        d2 = await engine.async_record(
            trail, verdict=Verdict.BLOCK, severity=Severity.WARN,
            gate_type="actiongate", gate_identity="test:action",
        )
        assert d1.entry is not None and d2.entry is not None
        assert d2.entry.prev_hash == d1.entry.entry_hash
        valid, broken_at = verify_chain([d1.entry, d2.entry])
        assert valid
        assert broken_at is None

    async def test_no_integrity(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(integrity=IntegrityMode.NONE)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="actiongate", gate_identity="test:action",
            policy=policy,
        )
        assert d.entry is not None
        assert d.entry.entry_hash is None

    async def test_sequence_increments(self) -> None:
        engine = _engine()
        trail = _trail()
        d1 = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        d2 = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        assert d1.entry is not None and d2.entry is not None
        assert d2.entry.sequence == d1.entry.sequence + 1

    async def test_detail_passed_through(self) -> None:
        engine = _engine()
        trail = _trail()
        detail = {"user": "alice", "action": "search"}
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t", detail=detail,
        )
        assert d.entry is not None
        assert d.entry.detail == detail

    async def test_retention_pruning(self) -> None:
        clock = MockClock()
        store = AsyncMemoryStore()
        engine = Engine(async_store=store, clock=clock)
        trail = _trail()
        policy = AuditPolicy(retention_seconds=10.0)

        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t", policy=policy,
        )
        clock.advance(15.0)
        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        count = await store.count(trail)
        assert count == 1

    async def test_default_policy_created(self) -> None:
        engine = _engine()
        trail = _trail()
        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        assert engine.policy_for(trail) is not None


# ═══════════════════════════════════════════════════════════════
# async_enforce
# ═══════════════════════════════════════════════════════════════


class TestAsyncEnforce:
    """async_enforce mirrors sync enforce."""

    async def test_hard_mode_dropped_raises(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(mode=Mode.HARD, min_severity=Severity.WARN)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.DEBUG,
            gate_type="ag", gate_identity="t", policy=policy,
        )
        assert d.dropped
        with pytest.raises(AuditError) as exc_info:
            await engine.async_enforce(d)
        assert exc_info.value.decision is d

    async def test_soft_mode_no_raise(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(mode=Mode.SOFT, min_severity=Severity.WARN)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.DEBUG,
            gate_type="ag", gate_identity="t", policy=policy,
        )
        assert d.dropped
        await engine.async_enforce(d)  # Should not raise

    async def test_recorded_no_raise(self) -> None:
        engine = _engine()
        trail = _trail()
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        assert d.recorded
        await engine.async_enforce(d)


# ═══════════════════════════════════════════════════════════════
# async_guard
# ═══════════════════════════════════════════════════════════════


class TestAsyncGuard:
    """@engine.async_guard decorator."""

    async def test_allow(self) -> None:
        engine = _engine()
        trail = _trail()

        @engine.async_guard(trail)
        async def action() -> str:
            return "ok"

        assert await action() == "ok"

    async def test_dropped_hard_raises(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(mode=Mode.HARD, min_severity=Severity.ERROR)

        @engine.async_guard(trail, policy=policy)
        async def action() -> str:
            return "ok"

        with pytest.raises(AuditError):
            await action()

    async def test_preserves_function_metadata(self) -> None:
        engine = _engine()
        trail = _trail()

        @engine.async_guard(trail)
        async def my_action() -> str:
            """My docstring."""
            return "ok"

        assert my_action.__name__ == "my_action"
        assert my_action.__doc__ == "My docstring."

    async def test_meta_passed_as_detail(self) -> None:
        decisions: list[Decision] = []
        engine = _engine()
        engine.on_decision(decisions.append)
        trail = _trail()

        @engine.async_guard(trail, meta={"env": "test"})
        async def action() -> str:
            return "ok"

        await action()
        assert decisions[0].entry is not None
        assert decisions[0].entry.detail == {"env": "test"}


# ═══════════════════════════════════════════════════════════════
# async_guard_result
# ═══════════════════════════════════════════════════════════════


class TestAsyncGuardResult:
    """@engine.async_guard_result decorator."""

    async def test_recorded_ok(self) -> None:
        engine = _engine()
        trail = _trail()

        @engine.async_guard_result(trail)
        async def action() -> str:
            return "ok"

        result = await action()
        assert result.ok
        assert result.unwrap() == "ok"

    async def test_dropped_returns_result(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(mode=Mode.SOFT, min_severity=Severity.ERROR)

        @engine.async_guard_result(trail, policy=policy)
        async def action() -> str:
            return "ok"

        result = await action()
        assert not result.ok
        assert result.unwrap_or("fallback") == "fallback"

    async def test_none_return_not_confused_with_dropped(self) -> None:
        engine = _engine()
        trail = _trail()

        @engine.async_guard_result(trail)
        async def void_op() -> None:
            return None

        result = await void_op()
        assert result.ok is True
        assert result.unwrap() is None

    async def test_unwrap_or_default(self) -> None:
        engine = _engine()
        trail = _trail()
        policy = AuditPolicy(mode=Mode.SOFT, min_severity=Severity.ERROR)

        @engine.async_guard_result(trail, policy=policy)
        async def action() -> int:
            return 42

        assert (await action()).unwrap_or(0) == 0


# ═══════════════════════════════════════════════════════════════
# Async store error handling
# ═══════════════════════════════════════════════════════════════


class TestAsyncStoreErrors:
    """Async store failures handled correctly."""

    async def test_store_failure_drops_fail_open(self) -> None:
        engine = Engine(async_store=AsyncBrokenStore())  # type: ignore[arg-type]
        trail = _trail()
        policy = AuditPolicy(on_store_error=StoreErrorMode.FAIL_OPEN, mode=Mode.SOFT)
        d = await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t", policy=policy,
        )
        assert d.dropped
        assert "Store append failed" in (d.reason or "")

    async def test_store_failure_fail_closed_hard_raises(self) -> None:
        engine = Engine(async_store=AsyncBrokenStore())  # type: ignore[arg-type]
        trail = _trail()
        policy = AuditPolicy(
            on_store_error=StoreErrorMode.FAIL_CLOSED, mode=Mode.HARD,
        )
        with pytest.raises(AuditError):
            await engine.async_record(
                trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
                gate_type="ag", gate_identity="t", policy=policy,
            )


# ═══════════════════════════════════════════════════════════════
# Async listeners
# ═══════════════════════════════════════════════════════════════


class TestAsyncListeners:
    """Async decisions still emit to listeners."""

    async def test_listener_receives_async_decisions(self) -> None:
        decisions: list[Decision] = []
        engine = _engine()
        engine.on_decision(decisions.append)
        trail = _trail()

        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        await engine.async_record(
            trail, verdict=Verdict.BLOCK, severity=Severity.WARN,
            gate_type="ag", gate_identity="t",
        )
        assert len(decisions) == 2
        assert decisions[0].recorded
        assert decisions[1].recorded


# ═══════════════════════════════════════════════════════════════
# AsyncMemoryStore
# ═══════════════════════════════════════════════════════════════


class TestAsyncMemoryStore:
    """AsyncMemoryStore mirrors MemoryStore behavior."""

    async def test_query_filter(self) -> None:
        store = AsyncMemoryStore()
        engine = Engine(async_store=store)
        trail = _trail()

        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        await engine.async_record(
            trail, verdict=Verdict.BLOCK, severity=Severity.WARN,
            gate_type="ag", gate_identity="t",
        )

        results = await store.query(QueryFilter(trail=trail, verdict=Verdict.BLOCK))
        assert len(results) == 1
        assert results[0].verdict == Verdict.BLOCK

    async def test_clear(self) -> None:
        store = AsyncMemoryStore()
        engine = Engine(async_store=store)
        trail = _trail()

        await engine.async_record(
            trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        assert await store.count(trail) == 1
        await store.clear(trail)
        assert await store.count(trail) == 0

    async def test_clear_all(self) -> None:
        store = AsyncMemoryStore()
        engine = Engine(async_store=store)
        trail1 = Trail("ns1", "a")
        trail2 = Trail("ns2", "b")

        await engine.async_record(
            trail1, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        await engine.async_record(
            trail2, verdict=Verdict.ALLOW, severity=Severity.INFO,
            gate_type="ag", gate_identity="t",
        )
        await store.clear_all()
        assert await store.count(trail1) == 0
        assert await store.count(trail2) == 0

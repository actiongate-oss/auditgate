"""AuditGate benchmark suite.

Measures latency for all critical paths:
  - Engine.record() across integrity modes (NONE, HASH, CHAIN)
  - MemoryStore.append() raw throughput
  - MemoryStore.query() at scale
  - verify_chain() at scale
  - guard/guard_result decorator overhead

Run:
    python3 bench_auditgate.py
"""

from __future__ import annotations

import statistics
import sys
import time

sys.path.insert(0, ".")

from auditgate import (
    AuditPolicy,
    Engine,
    IntegrityMode,
    MemoryStore,
    QueryFilter,
    Severity,
    Trail,
    Verdict,
    verify_chain,
)

WARMUP = 200
ITERATIONS = 5000


def bench(name: str, fn, iterations: int = ITERATIONS, warmup: int = WARMUP):
    """Run a benchmark and print results."""
    for _ in range(warmup):
        fn()

    times = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        times.append(time.perf_counter_ns() - start)

    times.sort()
    p50 = times[len(times) // 2] / 1000
    p99 = times[int(len(times) * 0.99)] / 1000
    mean = statistics.mean(times) / 1000
    print(f"  {name:45s}  p50={p50:7.1f}µs  p99={p99:8.1f}µs  mean={mean:7.1f}µs")


def main():
    print("AuditGate Benchmark")
    print("=" * 80)

    trail = Trail("bench", "actiongate", "global")

    # ── Engine.record() across integrity modes ──
    print("\n── Engine.record() latency ──")

    for mode_name, mode in [("NONE", IntegrityMode.NONE),
                            ("HASH", IntegrityMode.HASH),
                            ("CHAIN", IntegrityMode.CHAIN)]:
        engine = Engine()
        engine.register(trail, AuditPolicy(integrity=mode))

        def record_fn(e=engine, t=trail):
            e.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                     gate_type="actiongate", gate_identity="bench:test@global")

        bench(f"record (integrity={mode_name})", record_fn)
        engine.clear(trail)

    # ── Engine.record() with detail payload ──
    print("\n── Engine.record() with payload ──")

    engine = Engine()
    engine.register(trail, AuditPolicy(integrity=IntegrityMode.HASH))
    detail = {"calls_in_window": 3, "max_calls": 10, "cooldown": 0.0,
              "user_id": "u:12345", "session": "sess:abc", "model": "gpt-4"}

    def record_with_detail():
        engine.record(trail=trail, verdict=Verdict.ALLOW, severity=Severity.INFO,
                      gate_type="actiongate", gate_identity="bench:test@global",
                      reason="Rate limit passed", detail=detail)

    bench("record (HASH + 6-field detail)", record_with_detail)
    engine.clear(trail)

    # ── Raw MemoryStore.append() ──
    print("\n── MemoryStore raw operations ──")

    from auditgate.core import AuditEntry

    store = MemoryStore()
    entry = AuditEntry(
        trail=trail, ts=1.0, wall_ts="2026-02-27T12:00:00+00:00",
        verdict=Verdict.ALLOW, severity=Severity.INFO,
        gate_type="x", gate_identity="x", sequence=0,
    )

    def append_fn():
        store.append(entry)

    bench("MemoryStore.append()", append_fn)

    # ── Query at scale ──
    print("\n── MemoryStore.query() at scale ──")

    store2 = MemoryStore()
    for i in range(10_000):
        store2.append(AuditEntry(
            trail=trail, ts=float(i), wall_ts="2026-02-27T00:00:00+00:00",
            verdict=Verdict.ALLOW if i % 3 else Verdict.BLOCK,
            severity=Severity.INFO, gate_type="actiongate",
            gate_identity="x", sequence=i,
        ))

    def query_all():
        store2.query(QueryFilter(trail=trail, limit=100))

    def query_filtered():
        store2.query(QueryFilter(trail=trail, verdict=Verdict.BLOCK, limit=50))

    def query_paginated():
        store2.query(QueryFilter(trail=trail, offset=5000, limit=100))

    bench("query (10K entries, limit=100)", query_all, iterations=500)
    bench("query (10K entries, filtered, limit=50)", query_filtered, iterations=500)
    bench("query (10K entries, offset=5000, limit=100)", query_paginated, iterations=500)

    # ── verify_chain ──
    print("\n── verify_chain() ──")

    engine3 = Engine()
    chain_trail = Trail("bench", "chain", "global")
    engine3.register(chain_trail, AuditPolicy(integrity=IntegrityMode.CHAIN))
    chain_entries = []
    for i in range(1000):
        d = engine3.record(trail=chain_trail, verdict=Verdict.ALLOW,
                           severity=Severity.INFO, gate_type="x", gate_identity="x")
        chain_entries.append(d.entry)

    def verify_1000():
        verify_chain(chain_entries)

    bench("verify_chain (1000 entries)", verify_1000, iterations=100)

    # ── Decorator overhead ──
    print("\n── Decorator overhead ──")

    engine4 = Engine()

    @engine4.guard(Trail("bench", "dec", "global"),
                   policy=AuditPolicy(integrity=IntegrityMode.HASH),
                   severity=Severity.INFO, gate_type="auditgate")
    def guarded_add(a: int, b: int) -> int:
        return a + b

    def guard_fn():
        guarded_add(2, 3)

    bench("guard decorator (HASH)", guard_fn)
    engine4.clear(Trail("bench", "dec", "global"))

    @engine4.guard_result(Trail("bench", "dec2", "global"),
                          policy=AuditPolicy(integrity=IntegrityMode.HASH),
                          severity=Severity.INFO, gate_type="auditgate")
    def guarded_result_add(a: int, b: int) -> int:
        return a + b

    def guard_result_fn():
        guarded_result_add(2, 3)

    bench("guard_result decorator (HASH)", guard_result_fn)

    print(f"\n{'=' * 80}")
    print("Done.")


if __name__ == "__main__":
    main()

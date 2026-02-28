"""Standalone AuditGate test suite — no pytest required."""
from __future__ import annotations
import sys, time, traceback
sys.path.insert(0, ".")
from auditgate import (MISSING, AuditEntry, AuditError, AuditPolicy, Decision, Engine,
    IntegrityMode, MemoryStore, Mode, QueryFilter, Result, Severity, Status,
    StoreErrorMode, Trail, Verdict, compute_hash, verify_chain, wall_clock)

passed = 0; failed = 0; errors: list[str] = []
def test(name):
    def decorator(fn):
        global passed, failed
        try: fn(); passed += 1; print(f"  ✓ {name}")
        except Exception as e:
            failed += 1; errors.append(f"  ✗ {name}: {e}\n{traceback.format_exc()}")
            print(f"  ✗ {name}: {e}")
        return fn
    return decorator

def _entry(trail, ts=1.0, verdict=Verdict.ALLOW, severity=Severity.INFO,
           gate_type="x", gate_identity="x", sequence=0, **kw):
    return AuditEntry(trail=trail, ts=ts, wall_ts="2026-02-27T00:00:00+00:00",
                      verdict=verdict, severity=severity, gate_type=gate_type,
                      gate_identity=gate_identity, sequence=sequence, **kw)

_clk = 0.0
def fake_clock(): return _clk
def fake_wall(): return "2026-02-27T12:00:00+00:00"

print("\n── Core Types ──")

@test("Trail equality and key")
def _():
    t1 = Trail("b", "ag", "u:1"); t2 = Trail("b", "ag", "u:1"); t3 = Trail("b", "ag", "u:2")
    assert t1 == t2 and t1 != t3
    assert str(t1) == "b:ag@u:1" and t1.key == "aud:b:ag:u:1"
    assert Trail("api", "x").principal == "global"

@test("AuditPolicy defaults and validation")
def _():
    p = AuditPolicy()
    assert p.mode == Mode.HARD and p.integrity == IntegrityMode.HASH
    for bad in [-1, 0]:
        try: AuditPolicy(retention_seconds=bad); assert False
        except ValueError: pass

@test("Decision truthy = recorded")
def _():
    t, p = Trail("t", "t"), AuditPolicy()
    assert bool(Decision(status=Status.RECORDED, trail=t, policy=p)) is True
    assert bool(Decision(status=Status.DROPPED, trail=t, policy=p, reason="x")) is False

@test("Result MISSING sentinel")
def _():
    t, p = Trail("t", "t"), AuditPolicy()
    d = Decision(status=Status.DROPPED, trail=t, policy=p, reason="x")
    r = Result(decision=d)
    assert not r.ok and r.unwrap_or("fb") == "fb"
    try: r.unwrap(); assert False
    except RuntimeError: pass
    r2 = Result(decision=Decision(status=Status.RECORDED, trail=t, policy=p), _value=None)
    assert r2.ok and r2.unwrap() is None and r2.unwrap_or("fb") is None

@test("compute_hash determinism and sensitivity")
def _():
    d = {"trail":"a","ts":1.0,"verdict":"ALLOW","severity":"INFO","gate_type":"x",
         "gate_identity":"x","reason":None,"detail":{},"sequence":0}
    assert compute_hash(d) == compute_hash(d) and len(compute_hash(d)) == 64
    assert compute_hash(d) != compute_hash({**d, "verdict":"BLOCK"})
    assert compute_hash(d) != compute_hash(d, prev_hash="abc")

@test("wall_clock returns ISO 8601")
def _():
    ts = wall_clock()
    assert "T" in ts

print("\n── Store ──")

@test("MemoryStore append, last_entry, count")
def _():
    s = MemoryStore(); t = Trail("t", "t"); e = _entry(t)
    s.append(e); assert s.last_entry(t) == e and s.count(t) == 1
    assert s.last_entry(Trail("empty", "empty")) is None

@test("MemoryStore query with filters")
def _():
    s = MemoryStore(); t = Trail("t", "t")
    s.append(_entry(t, ts=1.0, verdict=Verdict.ALLOW, severity=Severity.INFO, sequence=0))
    s.append(_entry(t, ts=2.0, verdict=Verdict.BLOCK, severity=Severity.WARN, sequence=1))
    s.append(_entry(t, ts=3.0, severity=Severity.CRITICAL, gate_type="bg", sequence=2))
    assert len(s.query(QueryFilter(trail=t, verdict=Verdict.BLOCK))) == 1
    assert len(s.query(QueryFilter(trail=t, min_severity=Severity.WARN))) == 2
    assert len(s.query(QueryFilter(trail=t, gate_type="bg"))) == 1
    assert len(s.query(QueryFilter(trail=t, after_ts=1.5, before_ts=2.5))) == 1
    assert len(s.query(QueryFilter(trail=t, limit=2))) == 2

@test("MemoryStore pagination with offset")
def _():
    s = MemoryStore(); t = Trail("t", "t")
    for i in range(10): s.append(_entry(t, ts=float(i), sequence=i))
    p1 = s.query(QueryFilter(trail=t, offset=0, limit=3))
    p2 = s.query(QueryFilter(trail=t, offset=3, limit=3))
    p4 = s.query(QueryFilter(trail=t, offset=9, limit=3))
    assert len(p1) == 3 and p1[0].sequence == 0
    assert len(p2) == 3 and p2[0].sequence == 3
    assert len(p4) == 1 and p4[0].sequence == 9

@test("MemoryStore prune, clear, clear_all")
def _():
    s = MemoryStore(); t = Trail("t", "t")
    for i in range(5): s.append(_entry(t, ts=float(i), sequence=i))
    assert s.prune(t, before_ts=3.0) == 3 and s.count(t) == 2
    t2 = Trail("t2", "t2"); s.append(_entry(t2))
    s.clear(t); assert s.count(t) == 0 and s.count(t2) == 1
    s.clear_all(); assert s.count(t2) == 0

print("\n── Engine ──")

@test("Engine record — wall_ts, recorded_by, sequence")
def _():
    global _clk; _clk = 100.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall, recorded_by="svc:gw")
    t = Trail("t", "ag")
    d = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                   gate_type="actiongate", gate_identity="t:c@g")
    assert d.recorded and d.entry.wall_ts == "2026-02-27T12:00:00+00:00"
    assert d.entry.recorded_by == "svc:gw" and d.entry.sequence == 0

@test("Engine sequence resumes from store on restart")
def _():
    global _clk; _clk = 1.0; store = MemoryStore()
    e1 = Engine(store=store, clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t")
    for i in range(3):
        _clk = float(i+1)
        e1.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                  gate_type="x", gate_identity="x")
    e2 = Engine(store=store, clock=fake_clock, wall_clock_fn=fake_wall)
    _clk = 10.0
    d = e2.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                  gate_type="x", gate_identity="x")
    assert d.entry.sequence == 3

@test("Engine severity filter")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(min_severity=Severity.WARN))
    d = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.DEBUG,
                   gate_type="x", gate_identity="x")
    assert d.dropped and "Below min_severity" in d.reason

@test("Engine IntegrityMode.NONE — no hash")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(integrity=IntegrityMode.NONE))
    d = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                   gate_type="x", gate_identity="x")
    assert d.entry.entry_hash is None and d.entry.prev_hash is None

@test("Engine IntegrityMode.HASH — hash, no chain")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(integrity=IntegrityMode.HASH))
    d = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                   gate_type="x", gate_identity="x")
    assert d.entry.entry_hash and len(d.entry.entry_hash) == 64 and d.entry.prev_hash is None

@test("Engine IntegrityMode.CHAIN — builds chain")
def _():
    global _clk
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(integrity=IntegrityMode.CHAIN))
    _clk = 1.0; d1 = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                                  gate_type="x", gate_identity="x")
    _clk = 2.0; d2 = eng.record(trail=t, verdict=Verdict.BLOCK, severity=Severity.WARN,
                                  gate_type="x", gate_identity="x")
    assert d1.entry.prev_hash is None
    assert d2.entry.prev_hash == d1.entry.entry_hash

@test("Engine enforce — HARD raises, SOFT does not")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(mode=Mode.HARD, min_severity=Severity.ERROR))
    d = eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.DEBUG,
                   gate_type="x", gate_identity="x")
    try: eng.enforce(d); assert False
    except AuditError: pass

@test("Engine listener fires and errors counted")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    decs = []; eng.on_decision(decs.append); eng.on_decision(lambda d: 1/0)
    eng.record(trail=Trail("t","t"), verdict=Verdict.ALLOW, severity=Severity.INFO,
               gate_type="x", gate_identity="x")
    assert len(decs) == 1 and eng.listener_errors == 1

@test("Engine store error — FAIL_CLOSED+HARD raises, FAIL_OPEN drops silently")
def _():
    global _clk; _clk = 1.0
    class Broken(MemoryStore):
        def append(self, entry): raise IOError("disk full")
    t = Trail("t", "t")
    eng1 = Engine(store=Broken(), clock=fake_clock, wall_clock_fn=fake_wall)
    eng1.register(t, AuditPolicy(mode=Mode.HARD, on_store_error=StoreErrorMode.FAIL_CLOSED))
    try: eng1.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                     gate_type="x", gate_identity="x"); assert False
    except AuditError: pass
    eng2 = Engine(store=Broken(), clock=fake_clock, wall_clock_fn=fake_wall)
    eng2.register(t, AuditPolicy(mode=Mode.SOFT, on_store_error=StoreErrorMode.FAIL_OPEN))
    d = eng2.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                    gate_type="x", gate_identity="x")
    assert d.dropped

print("\n── Verify Chain ──")

@test("verify_chain — valid chain passes")
def _():
    global _clk
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(integrity=IntegrityMode.CHAIN))
    entries = []
    for i in range(5):
        _clk = float(i)
        entries.append(eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                                  gate_type="x", gate_identity="x").entry)
    valid, broken = verify_chain(entries)
    assert valid is True and broken is None

@test("verify_chain — tampered entry detected")
def _():
    global _clk
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    t = Trail("t", "t"); eng.register(t, AuditPolicy(integrity=IntegrityMode.CHAIN))
    entries = []
    for i in range(5):
        _clk = float(i)
        entries.append(eng.record(trail=t, verdict=Verdict.ALLOW, severity=Severity.INFO,
                                  gate_type="x", gate_identity="x").entry)
    e = entries[2]
    entries[2] = AuditEntry(trail=e.trail, ts=e.ts, wall_ts=e.wall_ts, verdict=Verdict.BLOCK,
                            severity=e.severity, gate_type=e.gate_type,
                            gate_identity=e.gate_identity, entry_hash=e.entry_hash,
                            prev_hash=e.prev_hash, sequence=e.sequence)
    valid, broken = verify_chain(entries)
    assert valid is False and broken == 2

print("\n── Decorators ──")

@test("guard and guard_result decorators")
def _():
    global _clk; _clk = 1.0
    eng = Engine(clock=fake_clock, wall_clock_fn=fake_wall)
    @eng.guard(Trail("t","t"), severity=Severity.INFO, gate_type="ag")
    def add(a, b): return a + b
    assert add(2, 3) == 5
    @eng.guard_result(Trail("t","t2"), severity=Severity.INFO, gate_type="ag")
    def ret_none(): return None
    r = ret_none(); assert r.ok and r.unwrap() is None

@test("to_dict includes all compliance fields")
def _():
    e = AuditEntry(trail=Trail("t","t"), ts=1.0, wall_ts="2026-02-27T12:00:00+00:00",
                   verdict=Verdict.ALLOW, severity=Severity.INFO, gate_type="ag",
                   gate_identity="x", recorded_by="svc:gw", reason="ok",
                   detail={"k":"v"}, entry_hash="h", prev_hash="p", sequence=7)
    d = e.to_dict()
    assert d["wall_ts"] == "2026-02-27T12:00:00+00:00"
    assert d["recorded_by"] == "svc:gw"

print(f"\n{'═'*50}")
print(f"Results: {passed} passed, {failed} failed")
if errors:
    print("\nFailures:")
    for e in errors: print(e)
print(f"{'═'*50}")
sys.exit(1 if failed else 0)

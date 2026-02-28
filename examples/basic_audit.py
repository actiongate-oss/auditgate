"""Example: Basic audit recording and chain verification.

Demonstrates the core AuditGate workflow:
  1. Create an engine with chain integrity
  2. Record decisions from different gates
  3. Query the audit trail
  4. Verify the hash chain is intact
"""

from auditgate import (
    AuditPolicy,
    Engine,
    IntegrityMode,
    Mode,
    QueryFilter,
    Severity,
    StoreErrorMode,
    Trail,
    Verdict,
    verify_chain,
)


def main():
    # Create engine with a service identity
    engine = Engine(recorded_by="svc:example-agent")

    # Define a trail with chain integrity (tamper-evident)
    trail = Trail("billing", "actiongate", "user:123")
    policy = AuditPolicy(
        mode=Mode.HARD,
        on_store_error=StoreErrorMode.FAIL_CLOSED,
        integrity=IntegrityMode.CHAIN,
        min_severity=Severity.INFO,
    )
    engine.register(trail, policy)

    # ── Record some gate decisions ──

    # ActionGate allowed a refund
    d1 = engine.record(
        trail=trail,
        verdict=Verdict.ALLOW,
        severity=Severity.INFO,
        gate_type="actiongate",
        gate_identity="billing:refund@user:123",
        reason="Rate limit check passed (3/10 in window)",
        detail={"calls_in_window": 3, "max_calls": 10},
    )
    print(f"Entry 0: {d1.entry.verdict.name}, hash={d1.entry.entry_hash[:12]}...")

    # BudgetGate blocked a large spend
    d2 = engine.record(
        trail=trail,
        verdict=Verdict.BLOCK,
        severity=Severity.WARN,
        gate_type="budgetgate",
        gate_identity="billing:refund@user:123",
        reason="Budget exceeded ($95.00 / $100.00 limit)",
        detail={"current_spend": "95.00", "max_spend": "100.00", "requested": "20.00"},
    )
    print(f"Entry 1: {d2.entry.verdict.name}, hash={d2.entry.entry_hash[:12]}..., "
          f"prev={d2.entry.prev_hash[:12]}...")

    # Human override of the budget block
    d3 = engine.record(
        trail=trail,
        verdict=Verdict.OVERRIDE,
        severity=Severity.WARN,
        gate_type="manual",
        gate_identity="billing:refund@user:123",
        reason="Manager override: approved by ops@company.com",
        detail={"approver": "ops@company.com", "ticket": "OPS-1234"},
    )
    print(f"Entry 2: {d3.entry.verdict.name}, hash={d3.entry.entry_hash[:12]}..., "
          f"prev={d3.entry.prev_hash[:12]}...")

    # ── Query the trail ──

    print("\n── All blocked decisions ──")
    blocked = engine._store.query(QueryFilter(trail=trail, verdict=Verdict.BLOCK))
    for entry in blocked:
        print(f"  [{entry.severity.name}] {entry.gate_type}: {entry.reason}")

    print("\n── All overrides ──")
    overrides = engine._store.query(QueryFilter(trail=trail, verdict=Verdict.OVERRIDE))
    for entry in overrides:
        print(f"  [{entry.severity.name}] {entry.reason}")
        print(f"    Approver: {entry.detail.get('approver')}")
        print(f"    Ticket:   {entry.detail.get('ticket')}")

    # ── Verify chain integrity ──

    all_entries = list(engine._store.query(QueryFilter(trail=trail)))
    valid, broken_at = verify_chain(all_entries)
    print(f"\n── Chain verification: {'VALID' if valid else f'BROKEN at seq {broken_at}'} ──")
    print(f"   Entries in trail: {len(all_entries)}")
    print(f"   First hash: {all_entries[0].entry_hash[:16]}...")
    print(f"   Last hash:  {all_entries[-1].entry_hash[:16]}...")

    # ── Serialization ──

    print("\n── Serialized entry (JSON-portable format) ──")
    import json
    print(json.dumps(d3.entry.to_dict(), indent=2))


if __name__ == "__main__":
    main()

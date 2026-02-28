"""Example: Guaranteeing no unaudited actions.

Demonstrates the FAIL_CLOSED + HARD configuration where
an action physically cannot proceed if the audit entry
cannot be recorded. This is the compliance-grade mode.
"""

from auditgate import (
    AuditError,
    AuditPolicy,
    Engine,
    IntegrityMode,
    MemoryStore,
    Mode,
    Severity,
    StoreErrorMode,
    Trail,
    Verdict,
)


class UnreliableStore(MemoryStore):
    """A store that fails intermittently (simulates disk/network errors)."""

    def __init__(self, fail_after: int = 3):
        super().__init__()
        self._call_count = 0
        self._fail_after = fail_after

    def append(self, entry):
        self._call_count += 1
        if self._call_count > self._fail_after:
            raise IOError(f"Simulated disk failure (call #{self._call_count})")
        return super().append(entry)


def main():
    print("── FAIL_CLOSED + HARD: No unaudited actions ──\n")

    store = UnreliableStore(fail_after=3)
    engine = Engine(store=store, recorded_by="svc:compliance-demo")

    trail = Trail("billing", "actiongate", "global")
    policy = AuditPolicy(
        mode=Mode.HARD,
        on_store_error=StoreErrorMode.FAIL_CLOSED,
        integrity=IntegrityMode.HASH,
    )
    engine.register(trail, policy)

    # Process actions — each one MUST be audited
    for i in range(6):
        try:
            decision = engine.record(
                trail=trail,
                verdict=Verdict.ALLOW,
                severity=Severity.INFO,
                gate_type="actiongate",
                gate_identity=f"billing:refund@user:{i}",
                reason=f"Action {i} allowed",
            )
            print(f"  Action {i}: RECORDED (hash={decision.entry.entry_hash[:12]}...)")

            # Proceed with the action — we KNOW it's audited
            print(f"           → Executing action {i}")

        except AuditError as e:
            print(f"  Action {i}: BLOCKED — audit failed!")
            print(f"           → Action {i} NOT executed (no unaudited actions)")
            print(f"           → Reason: {e.decision.reason}")

    print(f"\nTotal recorded: {store.count(trail)}")
    print(f"Total blocked:  {6 - store.count(trail)}")
    print("\nThe guarantee: every executed action has an audit record.")

    # ── Compare with FAIL_OPEN + SOFT (fire-and-forget) ──

    print("\n\n── FAIL_OPEN + SOFT: Best-effort audit ──\n")

    store2 = UnreliableStore(fail_after=3)
    engine2 = Engine(store=store2, recorded_by="svc:soft-demo")

    trail2 = Trail("api", "combined", "global")
    policy2 = AuditPolicy(
        mode=Mode.SOFT,
        on_store_error=StoreErrorMode.FAIL_OPEN,
        integrity=IntegrityMode.HASH,
    )
    engine2.register(trail2, policy2)

    for i in range(6):
        decision = engine2.record(
            trail=trail2,
            verdict=Verdict.ALLOW,
            severity=Severity.INFO,
            gate_type="actiongate",
            gate_identity=f"api:search@user:{i}",
            reason=f"Action {i} allowed",
        )

        if decision.recorded:
            print(f"  Action {i}: RECORDED")
        else:
            print(f"  Action {i}: DROPPED (audit lost, action proceeds anyway)")

        # Action always proceeds regardless of audit status
        print(f"           → Executing action {i}")

    print(f"\nTotal recorded: {store2.count(trail2)}")
    print(f"Total lost:     {6 - store2.count(trail2)}")
    print("\nNo guarantee: some actions may not have audit records.")


if __name__ == "__main__":
    main()

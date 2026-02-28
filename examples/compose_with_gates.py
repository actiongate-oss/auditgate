"""Example: Composing AuditGate with other gates.

Shows how to wire AuditGate as a listener on ActionGate, BudgetGate,
or RuleGate so every decision is automatically audit-logged.

This example uses mock gate decisions since the other gates may not
be installed. The pattern is identical with the real gates.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from auditgate import (
    AuditPolicy,
    Engine,
    IntegrityMode,
    QueryFilter,
    Severity,
    Trail,
    Verdict,
    verify_chain,
)


# ── Mock ActionGate decision (matches real ActionGate's Decision shape) ──

class GateStatus(Enum):
    ALLOW = auto()
    BLOCK = auto()

class BlockReason(Enum):
    RATE_LIMIT = auto()
    COOLDOWN = auto()

@dataclass(frozen=True)
class MockGateDecision:
    status: GateStatus
    gate_str: str
    reason: BlockReason | None = None
    calls_in_window: int = 0
    max_calls: int = 10

    @property
    def allowed(self) -> bool:
        return self.status == GateStatus.ALLOW

    @property
    def blocked(self) -> bool:
        return self.status == GateStatus.BLOCK


def main():
    # ── Set up AuditGate engine ──
    audit = Engine(recorded_by="svc:agent-orchestrator")

    trail = Trail("api", "actiongate", "global")
    audit.register(trail, AuditPolicy(integrity=IntegrityMode.CHAIN))

    # ── Create the listener function ──
    # This is what you'd pass to action_engine.on_decision()

    def audit_listener(gate_decision: MockGateDecision):
        """Bridge between ActionGate decisions and AuditGate recording."""
        audit.record(
            trail=trail,
            verdict=Verdict.ALLOW if gate_decision.allowed else Verdict.BLOCK,
            severity=Severity.INFO if gate_decision.allowed else Severity.WARN,
            gate_type="actiongate",
            gate_identity=gate_decision.gate_str,
            reason=gate_decision.reason.name if gate_decision.reason else "Passed",
            detail={
                "calls_in_window": gate_decision.calls_in_window,
                "max_calls": gate_decision.max_calls,
            },
        )

    # ── Simulate ActionGate decisions ──

    simulated_decisions = [
        MockGateDecision(GateStatus.ALLOW, "api:search@user:1", calls_in_window=1),
        MockGateDecision(GateStatus.ALLOW, "api:search@user:1", calls_in_window=2),
        MockGateDecision(GateStatus.ALLOW, "api:search@user:1", calls_in_window=3),
        MockGateDecision(GateStatus.BLOCK, "api:search@user:1",
                         reason=BlockReason.RATE_LIMIT, calls_in_window=10, max_calls=10),
        MockGateDecision(GateStatus.BLOCK, "api:search@user:1",
                         reason=BlockReason.COOLDOWN, calls_in_window=10, max_calls=10),
        MockGateDecision(GateStatus.ALLOW, "api:search@user:1", calls_in_window=1),
    ]

    print("── Simulating ActionGate decisions ──")
    for decision in simulated_decisions:
        audit_listener(decision)
        print(f"  {decision.status.name:5s}  {decision.gate_str}  "
              f"calls={decision.calls_in_window}/{decision.max_calls}")

    # ── Query results ──

    print(f"\n── Audit trail: {audit._store.count(trail)} entries ──")

    blocked = audit._store.query(QueryFilter(trail=trail, verdict=Verdict.BLOCK))
    print(f"\nBlocked decisions: {len(blocked)}")
    for entry in blocked:
        print(f"  seq={entry.sequence}  {entry.gate_identity}  reason={entry.reason}")

    # ── Verify integrity ──

    all_entries = list(audit._store.query(QueryFilter(trail=trail)))
    valid, _ = verify_chain(all_entries)
    print(f"\nChain integrity: {'VALID' if valid else 'BROKEN'}")

    # ── Pagination example ──

    print("\n── Paginated query (page size=2) ──")
    page = 0
    while True:
        results = audit._store.query(QueryFilter(trail=trail, offset=page * 2, limit=2))
        if not results:
            break
        print(f"  Page {page}: {[f'seq={e.sequence} {e.verdict.name}' for e in results]}")
        page += 1

    # ── With real ActionGate, the wiring is just: ──
    # action_engine.on_decision(audit_listener)
    # That's it. Every ActionGate decision is now audit-logged.

    print("\n── Integration code (real ActionGate) ──")
    print("  action_engine.on_decision(audit_listener)")
    print("  # Every decision is now audit-logged with chain integrity.")


if __name__ == "__main__":
    main()

# AuditGate

**Compliance-grade audit logging for agent systems.**

Every decision, every verdict, every override — structured, queryable, and tamper-evident.

```bash
pip install auditgate
```

---

## What It Does

AuditGate records every gate decision as a structured audit entry with optional tamper-evidence via content hashing or hash chaining. It pairs with [ActionGate](https://github.com/actiongate-oss/actiongate), [BudgetGate](https://github.com/actiongate-oss/budgetgate), and [RuleGate](https://github.com/actiongate-oss/rulegate) as the fourth composable primitive in the agent execution layer.

AuditGate does **not** make allow/block decisions. It records what other gates decided and guarantees the record exists.

**Vendoring encouraged.** This is a small, stable primitive. Copy it, fork it, reimplement it. If you vendor AuditGate, you must preserve the LICENSE file, preserve copyright headers in source files, and not remove or modify the BSL terms. The production use restriction applies to vendored copies. See [SEMANTICS.md](SEMANTICS.md) for the behavioral contract if you reimplement.

## Quick Start

```python
from auditgate import (
    Engine, Trail, AuditPolicy, Verdict, Severity, IntegrityMode
)

engine = Engine()

# Define an audit trail with hash chain integrity
trail = Trail("billing", "actiongate", "user:123")
policy = AuditPolicy(integrity=IntegrityMode.CHAIN)
engine.register(trail, policy)

# Record a decision from ActionGate
decision = engine.record(
    trail=trail,
    verdict=Verdict.ALLOW,
    severity=Severity.INFO,
    gate_type="actiongate",
    gate_identity="billing:refund@user:123",
    reason="Rate limit check passed",
    detail={"calls_in_window": 3, "max_calls": 10},
)

assert decision.recorded
assert decision.entry.entry_hash is not None
```

## Integrity Modes

| Mode    | Behavior | Use Case |
|---------|----------|----------|
| `NONE`  | No hashing | Maximum throughput, trust the store |
| `HASH`  | SHA-256 per entry | Detect tampering of individual entries |
| `CHAIN` | Hash includes previous entry's hash | Detect tampering or deletion of any entry |

## Failure Modes

| Policy | Behavior |
|--------|----------|
| `HARD` + `FAIL_CLOSED` | No action can proceed without a recorded audit entry |
| `HARD` + `FAIL_OPEN` | Raises on failure but allows unaudited actions |
| `SOFT` + `FAIL_CLOSED` | Returns DROPPED decision, caller decides |
| `SOFT` + `FAIL_OPEN` | Fire-and-forget audit (best-effort) |

## Decorator API

```python
# Raises AuditError if audit recording fails (HARD mode default)
@engine.guard(
    Trail("api", "combined", "global"),
    policy=AuditPolicy(integrity=IntegrityMode.HASH),
    severity=Severity.INFO,
    gate_type="auditgate",
)
def process_order(order_id: str) -> dict:
    return {"status": "processed", "id": order_id}

# Or use guard_result for no-exception handling
@engine.guard_result(
    Trail("api", "combined", "global"),
    policy=AuditPolicy(mode=Mode.SOFT),
    severity=Severity.INFO,
    gate_type="auditgate",
)
def fetch_data(query: str) -> list:
    return db.search(query)

result = fetch_data(query="recent orders")
data = result.unwrap_or([])
```

## Querying the Audit Trail

```python
from auditgate import QueryFilter, Verdict, Severity

# All blocked decisions in the last hour
entries = engine._store.query(QueryFilter(
    trail=trail,
    verdict=Verdict.BLOCK,
    after_ts=time.monotonic() - 3600,
))

# All critical events across all trails
critical = engine._store.query(QueryFilter(
    min_severity=Severity.CRITICAL,
))
```

## Composing with Other Gates

```python
from actiongate import Engine as ActionEngine, Gate, Policy
from auditgate import Engine as AuditEngine, Trail, AuditPolicy, Verdict, Severity

action_engine = ActionEngine()
audit_engine = AuditEngine()

trail = Trail("api", "actiongate", "global")
audit_engine.register(trail, AuditPolicy())

# Listen to ActionGate decisions and auto-audit them
def audit_listener(action_decision):
    audit_engine.record(
        trail=trail,
        verdict=Verdict.ALLOW if action_decision.allowed else Verdict.BLOCK,
        severity=Severity.INFO if action_decision.allowed else Severity.WARN,
        gate_type="actiongate",
        gate_identity=str(action_decision.gate),
        reason=str(action_decision.reason) if action_decision.reason else None,
    )

action_engine.on_decision(audit_listener)
```

## Performance

Sub-20µs per audit entry with MemoryStore and SHA-256 hashing (benchmarked). Hash chain mode adds negligible overhead. For context, a single LLM API call is 200ms–2s.

## File Structure

```
auditgate/
├── __init__.py   # Public API, exports, version
├── core.py       # All value types (Trail, AuditPolicy, AuditEntry, Decision, Result)
├── engine.py     # Engine class (record, guard, guard_result)
└── store.py      # Store protocol + MemoryStore
```

## Specification

See [SEMANTICS.md](SEMANTICS.md) for the normative behavior specification. When this document and the code conflict, the specification governs.

## License

AuditGate is licensed under the [Business Source License 1.1](LICENSE).

```
Licensor:             actiongate-oss
Licensed Work:        AuditGate
Additional Use Grant: None
Change Date:          2030-02-28 (four years from initial publication)
Change License:       Mozilla Public License 2.0
```

**What this means:** You may copy, modify, create derivative works, redistribute, and make non-production use of AuditGate. The Additional Use Grant is "None", which means any use in a live environment that provides value to end users or internal business operations — including SaaS, internal enterprise deployment, and paid betas — requires a commercial license from the licensor. On the Change Date, AuditGate becomes available under [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/) and the production restriction terminates. Each version has its own Change Date calculated from its publication.

**If you vendor AuditGate:** Preserve the LICENSE file and copyright headers. Do not remove or modify the BSL terms. The production restriction applies to all copies, vendored or otherwise.

**Licensing difference from siblings:** [ActionGate](https://github.com/actiongate-oss/actiongate) and [BudgetGate](https://github.com/actiongate-oss/budgetgate) are Apache 2.0. AuditGate is BSL 1.1. If composing all three, ensure your use complies with both license terms.

See [LICENSE](LICENSE) for the legally binding text.

# AuditGate Semantics

This document defines the normative behavior of AuditGate. Any implementation claiming compatibility must conform to these semantics.

Version: 0.1

---

## 1. Purpose

AuditGate is a **compliance-grade audit logging primitive** for AI agent systems. It records every gate decision as a structured, queryable, and optionally tamper-evident audit entry.

AuditGate does not make allow/block decisions. It records the decisions made by ActionGate, BudgetGate, RuleGate, and any other gate in the execution layer.

It is not a general-purpose logger, metrics system, or observability platform.

---

## 2. Trail Identity

An audit trail is identified by a **Trail**, a 3-tuple:

```
Trail = (namespace: string, source: string, principal: string)
```

| Field       | Purpose                | Examples                                   |
|-------------|------------------------|--------------------------------------------|
| `namespace` | Domain or subsystem    | `"billing"`, `"support"`, `"api"`          |
| `source`    | Originating gate       | `"actiongate"`, `"budgetgate"`, `"combined"` |
| `principal` | Scope of the trail     | `"user:123"`, `"agent:42"`, `"global"`     |

Two trails are equal if and only if all three fields are equal. Audit entries are **not shared** across distinct trails.

---

## 3. Audit Policy

Each trail is governed by an **AuditPolicy**:

| Field               | Type           | Default      | Meaning                                         |
|---------------------|----------------|--------------|--------------------------------------------------|
| `mode`              | HARD \| SOFT   | HARD         | HARD raises on audit failure; SOFT degrades      |
| `on_store_error`    | FAIL_CLOSED \| FAIL_OPEN | FAIL_CLOSED | FAIL_CLOSED blocks unaudited actions |
| `min_severity`      | Severity       | DEBUG        | Drop entries below this severity                 |
| `retention_seconds` | float \| null  | null         | Auto-prune entries older than this (null = keep forever) |
| `integrity`         | IntegrityMode  | HASH         | Tamper-evidence mode                             |

---

## 4. Audit Entry Structure

Every recorded event produces an **AuditEntry** containing at minimum:

| Field          | Type           | Meaning                                          |
|----------------|----------------|--------------------------------------------------|
| `trail`        | Trail          | Which audit trail this belongs to                |
| `ts`           | float          | Monotonic timestamp for ordering guarantees      |
| `wall_ts`      | string         | Wall-clock ISO 8601 timestamp for human/legal consumption |
| `verdict`      | Verdict        | What the originating gate decided                |
| `severity`     | Severity       | Operational importance (DEBUG/INFO/WARN/ERROR/CRITICAL) |
| `gate_type`    | string         | Which gate produced this decision ("actiongate", "budgetgate", etc.) |
| `gate_identity`| string         | String form of the gate's identity tuple         |
| `recorded_by`  | string         | Identity of the service/agent that wrote this entry |
| `reason`       | string \| null | Why the verdict was reached (gate-specific reason string) |
| `detail`       | dict           | Arbitrary structured metadata from the gate decision |
| `entry_hash`   | string \| null | Content hash for tamper detection (null if integrity=NONE) |
| `prev_hash`    | string \| null | Previous entry's hash for chain integrity (null if integrity!=CHAIN) |
| `sequence`     | int            | Monotonic sequence number within the trail       |

Clock trustworthiness is the caller's responsibility. AuditGate records whatever timestamps it receives. If wall-clock accuracy matters for compliance, use NTP-synced clocks and document the sync policy in your audit procedures.

### 4.1 Verdict Values

| Verdict    | Meaning                                    |
|------------|--------------------------------------------|
| `ALLOW`    | The originating gate allowed the action    |
| `BLOCK`    | The originating gate blocked the action    |
| `ERROR`    | The originating gate itself errored        |
| `OVERRIDE` | A human override of a gate decision        |

### 4.2 Severity Values

Severity levels, in ascending order: DEBUG, INFO, WARN, ERROR, CRITICAL.

Entries below the trail's `min_severity` are dropped before recording.

---

## 5. Integrity Semantics

AuditGate supports three integrity modes for tamper-evidence:

### 5.1 NONE

No integrity checks. Entries have no `entry_hash` or `prev_hash`. Fastest mode.

### 5.2 HASH

Each entry receives a SHA-256 content hash computed over its semantic fields (trail, ts, verdict, severity, gate_type, gate_identity, reason, detail, sequence). The hash is deterministic: same inputs always produce the same hash.

Modification of any field invalidates the hash.

### 5.3 CHAIN

Each entry's hash includes the previous entry's `entry_hash`. This creates a hash chain where modification of any entry invalidates all subsequent entries.

The first entry in a chain has `prev_hash = null`.

### 5.4 Hash Computation

The hash function **must** use SHA-256 over a canonical JSON representation of the entry's semantic fields, sorted by key, with compact separators (`(",", ":")`). For CHAIN mode, the `prev_hash` value is included in the hash input.

The canonical field set for hash computation is:

```
trail, ts, verdict, severity, gate_type, gate_identity, reason, detail, sequence
```

Fields excluded from hashing: `wall_ts`, `recorded_by`, `entry_hash`, `prev_hash` (except as a chaining input in CHAIN mode).

This function is deterministic: same inputs always produce the same hash. Implementations in other languages **must** produce identical hashes for the same input by following this exact serialization.

### 5.5 Serialization Contract

The `to_dict()` method produces the canonical JSON-portable format. Field names, types, and enum string representations defined here constitute the AuditGate serialization contract:

| Field          | JSON type | Format                                |
|----------------|-----------|---------------------------------------|
| `trail`        | string    | `"namespace:source@principal"`        |
| `ts`           | number    | Monotonic float                       |
| `wall_ts`      | string    | ISO 8601 UTC                          |
| `verdict`      | string    | Enum name: `"ALLOW"`, `"BLOCK"`, `"ERROR"`, `"OVERRIDE"` |
| `severity`     | string    | Enum name: `"DEBUG"`, `"INFO"`, `"WARN"`, `"ERROR"`, `"CRITICAL"` |
| `gate_type`    | string    | Free-form                             |
| `gate_identity`| string    | Free-form                             |
| `recorded_by`  | string    | Free-form                             |
| `reason`       | string \| null | Free-form                        |
| `detail`       | object    | Arbitrary JSON-serializable dict      |
| `entry_hash`   | string \| null | 64-char lowercase hex SHA-256    |
| `prev_hash`    | string \| null | 64-char lowercase hex SHA-256    |
| `sequence`     | integer   | Zero-based monotonic                  |

Implementations in other languages must produce identical output for the same input.

---

## 6. Recording Semantics

When `record()` is called:

1. Resolve the AuditPolicy for the trail (registered or default).
2. Check severity: if the entry's severity is below `min_severity`, return DROPPED.
3. Assign the next monotonic sequence number for the trail.
4. If integrity is HASH or CHAIN, compute the content hash.
5. Append the entry to the store.
6. If `retention_seconds` is set, prune entries older than `now - retention_seconds` (best-effort).
7. Return a Decision with status RECORDED.

Step 5 (append) **must** be atomic per-trail. A failed append **must not** leave partial state.

---

## 7. Failure Semantics

When the storage backend is unavailable or errors:

| `on_store_error` | Behavior                                             |
|-------------------|------------------------------------------------------|
| `FAIL_CLOSED`     | Return DROPPED; in HARD mode, raise AuditError       |
| `FAIL_OPEN`       | Return DROPPED silently (action proceeds unaudited)  |

The FAIL_CLOSED + HARD combination guarantees: **if the audit entry cannot be recorded, the engine raises `AuditError` and the caller's code does not continue past the `record()` call**. This is not an allow/block decision about the action itself (§9) — it is a guarantee that no action proceeds without a corresponding audit record.

---

## 8. Decision Structure

Every `record()` call returns a Decision containing:

| Field    | Type           | Meaning                           |
|----------|----------------|-----------------------------------|
| `status` | RECORDED \| DROPPED | Whether the entry was persisted |
| `trail`  | Trail          | The target trail                  |
| `policy` | AuditPolicy    | The policy used                   |
| `entry`  | AuditEntry \| null | The recorded entry (null if dropped) |
| `reason` | string \| null | Why dropped (null if recorded)    |

---

## 9. Out of Scope

AuditGate **does not** and **must not**:

- Make allow/block decisions on actions
- Perform rate limiting or cost management
- Evaluate policy rules or predicates
- Provide authentication or authorization
- Implement log shipping, aggregation, or forwarding
- Replace structured logging frameworks (e.g., structlog)
- Provide real-time alerting or monitoring

AuditGate is a **write-ahead audit log primitive**. It records what happened and guarantees the record exists. Downstream systems consume the audit trail for analytics, compliance reporting, and forensics.

---

## 10. Compatibility

An implementation is **AuditGate-compatible** if and only if:

1. It implements the Trail identity model (§2)
2. It implements the AuditPolicy parameters (§3)
3. AuditEntry contains all required fields (§4)
4. Integrity modes produce correct hashes (§5)
5. Recording follows the specified sequence (§6)
6. Failure modes match the specification (§7)
7. Decisions include all required fields (§8)
8. It does not extend scope beyond §9

Compatible implementations may:

- Use any storage backend for audit persistence
- Be written in any language
- Add non-normative fields to AuditEntry
- Provide additional query capabilities beyond the minimum
- Implement both synchronous and asynchronous recording

Compatible implementations must not:

- Change the hash computation algorithm or field ordering
- Make allow/block decisions based on audit content
- Skip hash computation when integrity mode requires it
- Allow entries with out-of-order sequence numbers within a trail

---

## 11. Reference Implementation

The canonical reference implementation is at:

```
https://github.com/actiongate-oss/auditgate
```

When this specification and the reference implementation conflict, **this specification governs**.

---

## Changelog

- **0.1** (2026-02): Initial specification

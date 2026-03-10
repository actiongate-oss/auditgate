
## Trust boundary

This section defines what AuditGate's integrity mechanisms protect against
and what they do not. Honest documentation of limitations is intentional.

### What hash chains protect against

**Accidental corruption.** If any field in any entry is accidentally modified
(storage error, encoding issue, truncation), `auditgate verify` detects it
immediately because the recomputed hash will not match.

**Naive tampering.** An attacker who modifies a single entry without
recomputing the chain will be detected. The chain linkage means changing
entry N invalidates entries N+1 through the end of the trail.

**Insertion and deletion.** Inserting a forged entry breaks the chain
because prev_hash won't match the preceding entry. Deleting an entry
creates a sequence gap and a chain break.

**Reordering.** Entries carry monotonic sequence numbers and chain hashes.
Reordering entries breaks both.

### What hash chains do NOT protect against

**Full chain recomputation.** An attacker with write access to the entire
log file can modify entries and recompute all hashes from the beginning,
producing an internally consistent forged chain. Hash chains prove
*internal consistency*, not *provenance*.

**Replay.** Valid entries from one trail could theoretically be replayed
into another context. The trail identity is included in the hash, which
prevents cross-trail replay, but same-trail replay of old entries is not
detected by hash verification alone (sequence numbers help but are not
cryptographically bound).

**Provenance.** Hash chains do not prove which engine produced an entry.
There is no signature scheme in v0.1.x. Any process that knows the
canonical JSON format can produce valid hashes.

### Planned mitigations (future versions)

**v0.4: Entry signing.** Ed25519 signatures on each entry hash, binding
entries to a specific engine identity. This upgrades from tamper-evident
to tamper-proof within a single trust boundary.

**v0.5: External anchoring.** Periodic Merkle root publication to an
append-only external store (e.g., transparency log, blockchain, or
signed timestamp service). This extends the trust boundary beyond the
system that produced the log.

### Current recommendation

For v0.1.x deployments:
- Store audit logs in an append-only backend (S3 with object lock, 
  write-once database, or immutable filesystem)
- Use `auditgate verify` as part of your audit review process
- Treat hash chain verification as a corruption and naive-tampering
  detector, not as a cryptographic proof of authenticity

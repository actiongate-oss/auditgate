# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Golden vector tests for AuditGate canonical JSON hashing.

These vectors are normative. Any implementation of compute_hash()
that produces these hashes from these inputs is conformant.
See CANONICAL_JSON.md for the full specification.
"""

from auditgate import compute_hash

def test_vector_1_minimal():
    """Minimal entry, no chaining."""
    v = {
        "trail": "test:action@global", "ts": 1000.0,
        "verdict": "ALLOW", "severity": "INFO",
        "gate_type": "actiongate", "gate_identity": "test:action@global",
        "reason": None, "detail": {}, "sequence": 0,
    }
    assert compute_hash(v) == "6e2239ee3b234854d729bbad0ec9fa58458bd3b1db5bc81bf4292d4799e90723"

def test_vector_2_chained():
    """Same entry as vector 1, chained off a zero hash."""
    v = {
        "trail": "test:action@global", "ts": 1000.0,
        "verdict": "ALLOW", "severity": "INFO",
        "gate_type": "actiongate", "gate_identity": "test:action@global",
        "reason": None, "detail": {}, "sequence": 0,
    }
    assert compute_hash(v, prev_hash="0" * 64) == "0f510008d027b9f0bc8df59fda55265368c8b298694540f7e7de36039df13e4b"

def test_vector_3_with_detail():
    """Entry with nested detail object."""
    v = {
        "trail": "billing:refund@user:42", "ts": 2000.5,
        "verdict": "BLOCK", "severity": "WARN",
        "gate_type": "rulegate", "gate_identity": "billing:refund@user:42",
        "reason": "Policy violation: no_pii",
        "detail": {"violated": ["no_pii"], "context": "ssn detected"},
        "sequence": 7,
    }
    assert compute_hash(v) == "1e38877f639d96dc0fabf7d1ab82397507a3017bd16e9aaec2f5964f1d73e679"

def test_vector_4_two_entry_chain():
    """Vector 3 chained off vector 1."""
    v1_hash = "6e2239ee3b234854d729bbad0ec9fa58458bd3b1db5bc81bf4292d4799e90723"
    v = {
        "trail": "billing:refund@user:42", "ts": 2000.5,
        "verdict": "BLOCK", "severity": "WARN",
        "gate_type": "rulegate", "gate_identity": "billing:refund@user:42",
        "reason": "Policy violation: no_pii",
        "detail": {"violated": ["no_pii"], "context": "ssn detected"},
        "sequence": 7,
    }
    assert compute_hash(v, prev_hash=v1_hash) == "76303466bec8897f90745033ed8aefa8135468169db0d7b9f3c036e6b76a4d8a"

if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"  PASS  {name}")
    print("\nAll golden vectors verified.")

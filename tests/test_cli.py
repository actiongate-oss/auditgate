# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""Tests for auditgate CLI verify command."""

from __future__ import annotations

import json
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, ".")
from auditgate import compute_hash
from auditgate.cli import _verify_log, main

passed = 0
failed = 0
errors: list[str] = []


def test(name):
    def decorator(fn):
        global passed, failed
        try:
            fn()
            passed += 1
            print(f"  PASS  {name}")
        except Exception as e:
            failed += 1
            errors.append(f"  FAIL  {name}: {e}\n{traceback.format_exc()}")
            print(f"  FAIL  {name}: {e}")
        return fn
    return decorator


def _make_entry(trail, ts, verdict, severity, gate_type, gate_identity,
                reason, detail, sequence, prev_hash=None):
    """Build a valid entry dict with computed hash."""
    data = {
        "schema_version": "0.1.1",
        "trail": trail, "ts": ts, "wall_ts": "2026-01-01T00:00:00+00:00",
        "verdict": verdict, "severity": severity,
        "gate_type": gate_type, "gate_identity": gate_identity,
        "recorded_by": "test", "reason": reason,
        "detail": detail, "sequence": sequence,
    }
    entry_hash = compute_hash(data, prev_hash=prev_hash)
    data["entry_hash"] = entry_hash
    data["prev_hash"] = prev_hash
    return data


def _make_chain(n=3):
    """Build a valid chain of n entries."""
    entries = []
    prev = None
    for i in range(n):
        entry = _make_entry(
            trail="test:action@global", ts=1000.0 + i,
            verdict="ALLOW", severity="INFO",
            gate_type="actiongate", gate_identity="test:action@global",
            reason=None, detail={}, sequence=i, prev_hash=prev,
        )
        prev = entry["entry_hash"]
        entries.append(entry)
    return entries


print("── CLI verify_log ──")


@test("valid chain passes")
def _():
    entries = _make_chain(5)
    valid, msgs = _verify_log(entries)
    assert valid, f"expected valid: {msgs}"


@test("empty log passes")
def _():
    valid, msgs = _verify_log([])
    assert valid


@test("single entry passes")
def _():
    entries = _make_chain(1)
    valid, msgs = _verify_log(entries)
    assert valid


@test("tampered entry detected")
def _():
    entries = _make_chain(3)
    entries[1]["verdict"] = "BLOCK"  # tamper without recomputing hash
    valid, msgs = _verify_log(entries)
    assert not valid, "should detect tampered entry"


@test("broken chain linkage detected")
def _():
    entries = _make_chain(3)
    # Replace entry[2]'s prev_hash with garbage
    entries[2]["prev_hash"] = "0" * 64
    # Recompute entry[2]'s hash with the wrong prev_hash
    entries[2]["entry_hash"] = compute_hash(entries[2], prev_hash="0" * 64)
    valid, msgs = _verify_log(entries)
    assert not valid, "should detect chain break"


@test("sequence gap produces warning")
def _():
    entries = _make_chain(3)
    entries[2]["sequence"] = 5  # gap: 0, 1, 5
    # Recompute hash with new sequence
    entries[2]["entry_hash"] = compute_hash(entries[2], prev_hash=entries[1]["entry_hash"])
    valid, msgs = _verify_log(entries, verbose=True)
    # Valid chain (hashes ok) but should warn about gap
    has_warn = any("WARN" in m and "gap" in m for m in msgs)
    assert has_warn, f"expected sequence gap warning: {msgs}"


@test("entries without hashes are skipped")
def _():
    entry = {
        "schema_version": "0.1.1", "trail": "test:x@global",
        "ts": 1.0, "wall_ts": "2026-01-01T00:00:00+00:00",
        "verdict": "ALLOW", "severity": "INFO",
        "gate_type": "actiongate", "gate_identity": "test:x@global",
        "recorded_by": "", "reason": None, "detail": {},
        "entry_hash": None, "prev_hash": None, "sequence": 0,
    }
    valid, msgs = _verify_log([entry])
    assert valid


@test("multiple trails verified independently")
def _():
    chain_a = _make_chain(2)
    chain_b = []
    prev = None
    for i in range(2):
        entry = _make_entry(
            trail="other:trail@global", ts=2000.0 + i,
            verdict="BLOCK", severity="WARN",
            gate_type="rulegate", gate_identity="other:trail@global",
            reason="violation", detail={}, sequence=i, prev_hash=prev,
        )
        prev = entry["entry_hash"]
        chain_b.append(entry)
    # Mix them together
    mixed = chain_a + chain_b
    valid, msgs = _verify_log(mixed)
    assert valid


@test("full chain recomputation attack produces valid result (documented limitation)")
def _():
    """An attacker who recomputes all hashes produces a valid-looking chain.
    This is the documented trust boundary limitation."""
    entries = _make_chain(3)
    # Tamper with entry 0 and recompute entire chain
    entries[0]["verdict"] = "BLOCK"
    entries[0]["entry_hash"] = compute_hash(entries[0], prev_hash=None)
    for i in range(1, len(entries)):
        entries[i]["prev_hash"] = entries[i - 1]["entry_hash"]
        entries[i]["entry_hash"] = compute_hash(entries[i], prev_hash=entries[i]["prev_hash"])
    valid, msgs = _verify_log(entries)
    # This SHOULD pass — it's a known limitation documented in trust_boundary
    assert valid, "full recomputation attack should produce valid chain (known limitation)"


print("\n── CLI main() ──")


@test("main verify with valid file returns 0")
def _():
    entries = _make_chain(3)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(entries, f)
        f.flush()
        ret = main(["verify", f.name])
    assert ret == 0


@test("main verify with tampered file returns 1")
def _():
    entries = _make_chain(3)
    entries[1]["verdict"] = "BLOCK"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(entries, f)
        f.flush()
        ret = main(["verify", f.name])
    assert ret == 1


@test("main verify --json outputs valid JSON")
def _():
    entries = _make_chain(2)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(entries, f)
        f.flush()
        # Capture stdout
        import io
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        ret = main(["verify", f.name, "--json"])
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
    assert ret == 0
    result = json.loads(output)
    assert result["valid"] is True
    assert result["entries"] == 2


@test("main verify missing file returns 1")
def _():
    ret = main(["verify", "/nonexistent/file.json"])
    assert ret == 1


@test("main verify invalid JSON returns 1")
def _():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not json{{{")
        f.flush()
        ret = main(["verify", f.name])
    assert ret == 1


print(f"\n{'═' * 50}")
print(f"Results: {passed} passed, {failed} failed")
if errors:
    print("\nFailures:")
    for e in errors:
        print(e)
print(f"{'═' * 50}")
sys.exit(1 if failed else 0)

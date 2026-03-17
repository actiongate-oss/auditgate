# Copyright 2026 actiongate-oss
# Licensed under the Apache License, Version 2.0;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""AuditGate CLI — verify hash chain integrity of audit logs.

Usage:
    auditgate verify log.json
    auditgate verify log.json --verbose
    auditgate verify log.json --json
    python -m auditgate verify log.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core import compute_hash


def _verify_log(entries: list[dict[str, Any]], verbose: bool = False) -> tuple[bool, list[str]]:
    """Verify a list of serialized audit entries.

    Works with raw dicts from JSON (no AuditEntry objects needed).
    Returns (valid, messages).
    """
    messages: list[str] = []

    if not entries:
        return True, ["Empty log — nothing to verify."]

    # Group by trail
    trails: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        trail = entry.get("trail", "<unknown>")
        trails.setdefault(trail, []).append(entry)

    all_valid = True

    for trail_name, trail_entries in trails.items():
        # Sort by sequence within each trail
        trail_entries.sort(key=lambda e: e.get("sequence", 0))

        messages.append(f"Trail: {trail_name} ({len(trail_entries)} entries)")

        for i, entry in enumerate(trail_entries):
            seq = entry.get("sequence", "?")
            entry_hash = entry.get("entry_hash")
            prev_hash = entry.get("prev_hash")

            # Skip entries without hashes (IntegrityMode.NONE)
            if entry_hash is None:
                if verbose:
                    messages.append(f"  [{seq}] SKIP — no hash (integrity=NONE)")
                continue

            # Recompute hash from entry data
            expected = compute_hash(entry, prev_hash=prev_hash)

            if entry_hash != expected:
                all_valid = False
                messages.append(
                    f"  [{seq}] FAIL — hash mismatch"
                )
                if verbose:
                    messages.append(f"         expected: {expected}")
                    messages.append(f"         got:      {entry_hash}")
                continue

            # Check chain linkage
            if prev_hash is not None and i > 0:
                prev_entry = trail_entries[i - 1]
                prev_entry_hash = prev_entry.get("entry_hash")
                if prev_entry_hash != prev_hash:
                    all_valid = False
                    prev_seq = prev_entry.get('sequence', '?')
                    messages.append(
                        f"  [{seq}] FAIL — chain break"
                        f" (prev_hash does not match entry [{prev_seq}])"
                    )
                    if verbose:
                        messages.append(f"         expected prev: {prev_entry_hash}")
                        messages.append(f"         got prev:      {prev_hash}")
                    continue

            # Check sequence continuity
            if i > 0:
                prev_seq = trail_entries[i - 1].get("sequence", -1)
                if seq != prev_seq + 1:
                    messages.append(
                        f"  [{seq}] WARN — sequence gap (expected {prev_seq + 1})"
                    )

            if verbose:
                verdict = entry.get("verdict", "?")
                messages.append(f"  [{seq}] OK — {verdict} hash:{entry_hash[:12]}...")

        if all_valid:
            messages.append("  VALID — all hashes verified")

    return all_valid, messages


def _cmd_verify(args: argparse.Namespace) -> int:
    """Handle the 'verify' subcommand."""
    path = Path(args.file)

    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON: {e}", file=sys.stderr)
        return 1

    # Accept both a list of entries and a single entry
    if isinstance(data, dict):
        entries = [data]
    elif isinstance(data, list):
        entries = data
    else:
        print("Error: expected a JSON array of entries or a single entry object", file=sys.stderr)
        return 1

    valid, messages = _verify_log(entries, verbose=args.verbose)

    if args.json:
        result = {
            "valid": valid,
            "entries": len(entries),
            "trails": len({e.get("trail", "") for e in entries}),
            "messages": messages,
        }
        print(json.dumps(result, indent=2))
    else:
        for msg in messages:
            print(msg)
        print()
        if valid:
            print(f"RESULT: VALID ({len(entries)} entries verified)")
        else:
            print("RESULT: INVALID (chain integrity broken)")

    return 0 if valid else 1


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="auditgate",
        description="AuditGate — compliance-grade audit log verification",
    )
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Verify hash chain integrity of an audit log",
    )
    verify_parser.add_argument("file", help="Path to JSON audit log file")
    verify_parser.add_argument("--verbose", "-v", action="store_true",
                               help="Show per-entry verification details")
    verify_parser.add_argument("--json", action="store_true",
                               help="Output results as JSON")

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "verify":
        return _cmd_verify(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())

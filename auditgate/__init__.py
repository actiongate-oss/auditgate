# Copyright 2026 actiongate-oss
# Licensed under the Business Source License 1.1 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License in the LICENSE file at the
# root of this repository.

"""AuditGate: Compliance-grade audit logging for agent systems."""

from .core import (
    MISSING,
    AuditEntry,
    AuditPolicy,
    Decision,
    IntegrityMode,
    Mode,
    Result,
    Severity,
    Status,
    StoreErrorMode,
    Trail,
    Verdict,
    compute_hash,
    verify_chain,
    wall_clock,
)
from .emitter import Emitter
from .engine import AuditError, Engine
from .store import MemoryStore, QueryFilter, Store

__all__ = [
    "Trail",
    "AuditPolicy",
    "AuditEntry",
    "Decision",
    "Result",
    "MISSING",
    "compute_hash",
    "verify_chain",
    "wall_clock",
    "Mode",
    "Status",
    "Severity",
    "Verdict",
    "IntegrityMode",
    "StoreErrorMode",
    "Engine",
    "AuditError",
    "Emitter",
    "Store",
    "MemoryStore",
    "QueryFilter",
]

__version__ = "0.1.1"

"""
ai-audit — Tamper-evident AI pipeline audit trail for EU AI Act compliance.

Provides cryptographically signed, hash-chained Decision Receipts for every
AI pipeline decision. Drop-in for any Python AI application.

Quick start::

    from ai_audit import AuditConfig, init_audit_config, ReceiptCollector, ReceiptStore

    # 1. Configure once at startup
    init_audit_config(AuditConfig.from_env())

    # 2. Wrap each request
    store = ReceiptStore()
    collector = ReceiptCollector(trace_id="req-1", tenant_id="acme")
    collector.set_input("User question here")
    collector.add_check("safety", score=0.05, threshold=0.8)
    collector.set_output("Answer here")
    collector.set_action("allow")
    receipt_id = collector.emit(store)
    collector.cleanup()

    # 3. Verify the chain (e.g. for a compliance audit)
    from ai_audit import verify_chain, get_verify_key_hex
    result = verify_chain(store.get_by_tenant("acme"), get_verify_key_hex())
    assert result.valid
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from ai_audit.batch import BatchSeal, MerkleBatcher, merkle_root, verify_inclusion
from ai_audit.buffer import AuditBuffer, AuditBufferFullError
from ai_audit.collector import ReceiptCollector, get_current_collector
from ai_audit.config import AuditConfig
from ai_audit.contracts import BehavioralContract, Constraint, ContractMonitor, SatisfactionState
from ai_audit.crosswalk import ComplianceCrosswalk, ControlStatus, build_crosswalk, nist_function_map
from ai_audit.dashboard import ComplianceSummary, build_compliance_summary
from ai_audit.drift import DriftMonitor, DriftState
from ai_audit.epochs import EpochManager, EpochSeal
from ai_audit.export import export_evidence_package, verify_evidence_package
from ai_audit.hashing import (
    acanonicalize_input,
    ahash_output,
    ahash_state,
    canonicalize_input,
    hash_json,
    hash_output,
    hash_state,
)
from ai_audit.keys import (
    DefaultKeyProvider,
    KeyProvider,
    get_verify_key_hex,
    init_audit_config,
    init_key_provider,
    reset_signing_key,
)
from ai_audit.models import CheckRecord, DecisionReceipt, ReceiptAction
from ai_audit.pii import PiiConfig, PiiMode, PiiType, aobfuscate_text, obfuscate_text
from ai_audit.provenance import ProvenanceChain, ProvenanceRecord, SourceType, TrustSummary
from ai_audit.receipt_store import ReceiptStore
from ai_audit.report import ArticleScore, AuditReport, ComplianceReportGenerator
from ai_audit.sprt import SPRTMonitor, SPRTState
from ai_audit.storage import InMemoryBackend, StorageBackend
from ai_audit.toolcall import ToolCallReceipt, seal_tool_call, verify_tool_call_chain
from ai_audit.tracegraph import TraceGraph, TraceNode
from ai_audit.verifier import VerificationResult, verify_chain

try:
    __version__ = _pkg_version("ai-audit-trail")
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    # Config
    "AuditConfig",
    "init_audit_config",
    # Core models
    "DecisionReceipt",
    "CheckRecord",
    "ReceiptAction",
    # Collection
    "ReceiptCollector",
    "get_current_collector",
    # Storage
    "ReceiptStore",
    # Verification
    "verify_chain",
    "VerificationResult",
    "get_verify_key_hex",
    "reset_signing_key",
    # Dashboard
    "build_compliance_summary",
    "ComplianceSummary",
    # Key management
    "KeyProvider",
    "DefaultKeyProvider",
    "init_key_provider",
    # Hashing utilities (sync)
    "canonicalize_input",
    "hash_output",
    "hash_state",
    "hash_json",
    # Hashing utilities (async)
    "acanonicalize_input",
    "ahash_output",
    "ahash_state",
    # PII-Redaction
    "PiiType",
    "PiiMode",
    "PiiConfig",
    "obfuscate_text",
    "aobfuscate_text",
    # EU AI Act Report Generator
    "ArticleScore",
    "AuditReport",
    "ComplianceReportGenerator",
    # Merkle-Tree Batch Sealing
    "BatchSeal",
    "MerkleBatcher",
    "merkle_root",
    "verify_inclusion",
    # Online SPRT
    "SPRTMonitor",
    "SPRTState",
    # Evidence Package Export
    "export_evidence_package",
    "verify_evidence_package",
    # Compliance Crosswalk
    "ComplianceCrosswalk",
    "ControlStatus",
    "build_crosswalk",
    "nist_function_map",
    # Epochs
    "EpochManager",
    "EpochSeal",
    # Drift Detection
    "DriftMonitor",
    "DriftState",
    # Storage ABCs
    "StorageBackend",
    "InMemoryBackend",
    # Ring-Buffer
    "AuditBuffer",
    "AuditBufferFullError",
    # Agent Behavioral Contracts
    "BehavioralContract",
    "Constraint",
    "ContractMonitor",
    "SatisfactionState",
    # Tool-Call Receipts
    "ToolCallReceipt",
    "seal_tool_call",
    "verify_tool_call_chain",
    # Multi-Agent Trace-Graphs
    "TraceGraph",
    "TraceNode",
    # Epistemische Integrität / Provenance
    "ProvenanceChain",
    "ProvenanceRecord",
    "SourceType",
    "TrustSummary",
]

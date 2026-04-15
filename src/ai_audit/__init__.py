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

from ai_audit.collector import ReceiptCollector, get_current_collector
from ai_audit.config import AuditConfig
from ai_audit.dashboard import ComplianceSummary, build_compliance_summary
from ai_audit.hashing import canonicalize_input, hash_output, hash_state
from ai_audit.keys import get_verify_key_hex, init_audit_config, reset_signing_key
from ai_audit.models import CheckRecord, DecisionReceipt, ReceiptAction
from ai_audit.receipt_store import ReceiptStore
from ai_audit.verifier import VerificationResult, verify_chain

__version__ = "0.1.0"

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
    # Hashing utilities
    "canonicalize_input",
    "hash_output",
    "hash_state",
]

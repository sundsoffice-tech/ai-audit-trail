"""Integration tests — cross-module compatibility and edge cases.

Tests that the full stack works end-to-end and catches regressions
at module boundaries.
"""

import threading
from datetime import UTC, datetime, timedelta

from ai_audit import (
    AuditConfig,
    BehavioralContract,
    Constraint,
    ContractMonitor,
    DriftMonitor,
    EpochManager,
    MerkleBatcher,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    SPRTMonitor,
    build_crosswalk,
    get_verify_key_hex,
    init_audit_config,
    reset_signing_key,
    verify_chain,
)
from ai_audit.keys import get_signing_key
from ai_audit.provenance import ProvenanceChain, ProvenanceRecord, SourceType
from ai_audit.toolcall import seal_tool_call, verify_tool_call_chain


def setup_function() -> None:
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


def test_full_lifecycle_receipt_to_crosswalk() -> None:
    """Full lifecycle: create receipts → verify chain → build crosswalk."""
    store = ReceiptStore()
    for i in range(10):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"query {i}")
        c.add_check("safety", score=0.05, threshold=0.8)
        c.set_output(f"answer {i}")
        c.set_action(ReceiptAction.ALLOW)
        c._receipt.model_id = "claude-3"
        c._receipt.nist_tags = ["GOVERN-1.1"]
        c._receipt.timestamp = datetime.now(UTC) + timedelta(microseconds=i)
        c.emit(store)
        c.cleanup()

    receipts = store.get_by_tenant("acme", limit=20)
    result = verify_chain(receipts, get_verify_key_hex())
    assert result.valid, f"Chain broken: {result.error}"

    crosswalk = build_crosswalk(receipts, chain_intact=True)
    assert len(crosswalk) == 9


def test_concurrent_emit_chain_integrity() -> None:
    """Concurrent emitters must NOT fork the hash-chain (TOCTOU fix test)."""
    store = ReceiptStore()
    errors: list[Exception] = []

    def worker(thread_id: int) -> None:
        try:
            for i in range(20):
                c = ReceiptCollector(trace_id=f"w{thread_id}-{i}", tenant_id="acme")
                c.set_input(f"q{i}")
                c.set_output(f"a{i}")
                c.set_action(ReceiptAction.ALLOW)
                c._receipt.timestamp = datetime.now(UTC) + timedelta(microseconds=thread_id * 1000 + i)
                c.emit(store)
                c.cleanup()
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Errors: {errors}"
    assert store.count == 80

    # Verify the chain is NOT forked — use insertion order (not timestamp order)
    # because concurrent threads have interleaved timestamps
    receipts_insertion_order = list(store._receipts.values())
    prev_hash = ""
    for i, r in enumerate(receipts_insertion_order):
        assert r.prev_receipt_hash == prev_hash, (
            f"Chain forked at receipt {i}: expected prev={prev_hash[:16]}, "
            f"got={r.prev_receipt_hash[:16]} (TOCTOU bug)"
        )
        prev_hash = r.receipt_hash


def test_receipt_sprt_drift_contract_pipeline() -> None:
    """Receipt → SPRT + Drift + Contract should all consume the same data."""
    store = ReceiptStore()
    sprt = SPRTMonitor(tenant_id="acme")
    drift = DriftMonitor(window_size=10)
    contract = BehavioralContract(
        contract_id="test",
        constraints=[Constraint(name="allow_only", kind="hard", field="action", operator="==", value="allow")],
    )
    monitor = ContractMonitor(contract)

    for i in range(30):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"q{i}")
        c.set_output(f"a{i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()

        r = store.get(c._receipt.receipt_id)
        assert r is not None
        sprt.update(is_reject=False)
        drift.update("allow")
        monitor.evaluate(r)

    assert sprt.state.status == "CERTIFIED"
    assert drift.state.status == "STABLE"
    assert monitor.state.status == "COMPLIANT"
    assert monitor.state.reliability_index == 1.0


def test_merkle_batch_with_real_receipts() -> None:
    """MerkleBatcher should work with real receipt payloads."""
    store = ReceiptStore()
    key = get_signing_key()
    batcher = MerkleBatcher(tenant_id="acme", private_key=key, max_batch_size=5)

    for i in range(12):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"q{i}")
        c.set_output(f"a{i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
        r = store.get(c._receipt.receipt_id)
        assert r is not None
        batcher.add(r.receipt_id, r.seal_payload())

    # Should have auto-flushed twice (5+5), with 2 remaining
    assert len(batcher.seals) == 2
    assert batcher.pending_count == 2

    # Manual flush for remaining
    batcher.flush()
    assert len(batcher.seals) == 3
    assert batcher.verify_chain_of_roots(key.verify_key)


def test_epoch_with_real_receipts() -> None:
    """EpochManager should work with real sealed receipts."""
    store = ReceiptStore()
    key = get_signing_key()
    mgr = EpochManager(tenant_id="acme", private_key=key, max_epoch_size=5)

    for i in range(12):
        c = ReceiptCollector(trace_id=f"t{i}", tenant_id="acme")
        c.set_input(f"q{i}")
        c.set_output(f"a{i}")
        c.set_action(ReceiptAction.ALLOW)
        c.emit(store)
        c.cleanup()
        r = store.get(c._receipt.receipt_id)
        assert r is not None
        mgr.add_receipt(r)

    assert len(mgr.seals) == 2  # auto-sealed at 5+5
    mgr.seal_epoch()  # remaining 2
    assert len(mgr.seals) == 3
    assert mgr.verify_epoch_chain(key.verify_key)


def test_toolcall_chain_with_provenance() -> None:
    """Tool-call receipts + provenance should work together."""
    key = get_signing_key()
    chain: list = []
    prev = ""

    for i in range(3):
        receipt = seal_tool_call(
            agent_id="researcher",
            tool_name=f"search_{i}",
            tool_args={"query": f"topic {i}"},
            tool_result=f"results for topic {i}",
            private_key=key,
            tenant_id="acme",
            prev_receipt_hash=prev,
        )
        chain.append(receipt)
        prev = receipt.receipt_hash

        # Add provenance for each tool call
        prov = ProvenanceChain(receipt_id=receipt.receipt_id, tenant_id="acme")
        prov.add(ProvenanceRecord(
            source_type=SourceType.TOOL,
            source_id=f"search_{i}",
            content_hash=receipt.tool_result_hash,
            trust_level=0.7,
        ))
        assert prov.verify_integrity()

    assert verify_tool_call_chain(chain, key.verify_key)


def test_empty_store_operations() -> None:
    """All store operations should handle empty state gracefully."""
    store = ReceiptStore()
    assert store.count == 0
    assert store.get_chain_tip("nonexistent") == ""
    assert store.get("nonexistent") is None
    assert store.get_by_tenant("nonexistent") == []
    assert store.get_by_session("nonexistent") == []
    assert store.get_by_trace("nonexistent") == []

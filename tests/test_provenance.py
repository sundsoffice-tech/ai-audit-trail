"""Tests for Epistemische Integrität & Unforgeable Provenance."""

from ai_audit.provenance import ProvenanceChain, ProvenanceRecord, SourceType


def test_provenance_record_seal() -> None:
    """Record should compute a deterministic hash."""
    record = ProvenanceRecord(
        source_type=SourceType.DOCUMENT,
        source_id="doc-123",
        content_hash="abc123",
        trust_level=0.9,
    )
    record.seal()
    assert record.record_hash != ""
    assert record.timestamp != ""

    # Deterministic — same data = same hash
    record2 = ProvenanceRecord(
        source_type=SourceType.DOCUMENT,
        source_id="doc-123",
        content_hash="abc123",
        trust_level=0.9,
        timestamp=record.timestamp,
    )
    record2.seal()
    assert record.record_hash == record2.record_hash


def test_provenance_chain_integrity() -> None:
    """Chain with untampered records should pass integrity check."""
    chain = ProvenanceChain(receipt_id="r1", tenant_id="acme")
    chain.add(ProvenanceRecord(source_type=SourceType.SYSTEM, source_id="prompt", content_hash="a1"))
    chain.add(ProvenanceRecord(source_type=SourceType.USER, source_id="input", content_hash="b2"))
    chain.add(ProvenanceRecord(source_type=SourceType.DOCUMENT, source_id="doc-1", content_hash="c3"))

    assert chain.verify_integrity()
    assert len(chain.records) == 3


def test_provenance_chain_tamper_detected() -> None:
    """Modifying a record after sealing should fail integrity check."""
    chain = ProvenanceChain(receipt_id="r1")
    record = ProvenanceRecord(source_type=SourceType.TOOL, source_id="api", content_hash="x")
    chain.add(record)

    record.source_id = "TAMPERED"
    assert not chain.verify_integrity()


def test_trust_summary() -> None:
    """Trust summary should aggregate correctly."""
    chain = ProvenanceChain(receipt_id="r1")
    chain.add(ProvenanceRecord(source_type=SourceType.SYSTEM, trust_level=1.0, content_hash="a"))
    chain.add(ProvenanceRecord(source_type=SourceType.USER, trust_level=0.5, content_hash="b"))
    chain.add(ProvenanceRecord(source_type=SourceType.DOCUMENT, trust_level=0.8, content_hash="c"))

    summary = chain.trust_summary()
    assert summary.total_sources == 3
    assert summary.system_grounded
    assert not summary.potentially_injected
    assert summary.min_trust == 0.5
    assert 0.7 < summary.avg_trust < 0.8


def test_trust_summary_detects_injection_risk() -> None:
    """UNKNOWN source type should flag potential injection."""
    chain = ProvenanceChain(receipt_id="r1")
    chain.add(ProvenanceRecord(source_type=SourceType.SYSTEM, trust_level=1.0, content_hash="a"))
    chain.add(ProvenanceRecord(source_type=SourceType.UNKNOWN, trust_level=0.0, content_hash="suspicious"))

    summary = chain.trust_summary()
    assert summary.potentially_injected
    assert summary.untrusted_sources == 1


def test_trust_summary_not_grounded() -> None:
    """Missing SYSTEM source should flag as not grounded."""
    chain = ProvenanceChain(receipt_id="r1")
    chain.add(ProvenanceRecord(source_type=SourceType.USER, trust_level=0.5, content_hash="a"))

    summary = chain.trust_summary()
    assert not summary.system_grounded


def test_get_by_type() -> None:
    """Filter by source type should work."""
    chain = ProvenanceChain(receipt_id="r1")
    chain.add(ProvenanceRecord(source_type=SourceType.DOCUMENT, source_id="d1", content_hash="a"))
    chain.add(ProvenanceRecord(source_type=SourceType.TOOL, source_id="t1", content_hash="b"))
    chain.add(ProvenanceRecord(source_type=SourceType.DOCUMENT, source_id="d2", content_hash="c"))

    docs = chain.get_by_type(SourceType.DOCUMENT)
    assert len(docs) == 2
    tools = chain.get_by_type(SourceType.TOOL)
    assert len(tools) == 1


def test_chain_hash() -> None:
    """Chain hash should be deterministic."""
    chain = ProvenanceChain(receipt_id="r1")
    r1 = ProvenanceRecord(source_type=SourceType.SYSTEM, content_hash="a", timestamp="2026-01-01T00:00:00Z")
    r1.seal()
    chain.add(r1)

    hash1 = chain.chain_hash
    assert hash1 != ""

    # Same records = same chain hash
    chain2 = ProvenanceChain(receipt_id="r1")
    r2 = ProvenanceRecord(source_type=SourceType.SYSTEM, content_hash="a", timestamp="2026-01-01T00:00:00Z")
    r2.seal()
    chain2.add(r2)
    assert chain2.chain_hash == hash1


def test_empty_chain() -> None:
    """Empty chain should have empty hash and pass integrity."""
    chain = ProvenanceChain(receipt_id="r1")
    assert chain.chain_hash == ""
    assert chain.verify_integrity()
    summary = chain.trust_summary()
    assert summary.total_sources == 0


def test_to_dict_serialization() -> None:
    """Chain should serialize to dict."""
    chain = ProvenanceChain(receipt_id="r1", tenant_id="acme")
    chain.add(ProvenanceRecord(source_type=SourceType.USER, source_id="u1", content_hash="x"))

    d = chain.to_dict()
    assert d["receipt_id"] == "r1"
    assert d["tenant_id"] == "acme"
    assert d["record_count"] == 1
    assert len(d["records"]) == 1  # type: ignore[arg-type]

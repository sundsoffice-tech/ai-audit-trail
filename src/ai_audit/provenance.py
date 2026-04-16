"""
ai_audit.provenance — Epistemische Integrität & Unforgeable Provenance.

World-first: Tracks the *origin* of every piece of information that
influenced an AI agent's decision, creating cryptographic proof of
WHERE information came from (system prompt vs. retrieved document vs.
tool result vs. user input).

This solves the "Lethal Trifecta" problem: untrusted inputs + privileged
access + external actions. By binding provenance to the audit trail,
auditors can prove a decision was NOT influenced by prompt injection.

**Key concepts:**
- **ProvenanceRecord:** Captures a single information source with its origin type
- **ProvenanceChain:** Links provenance records to a decision receipt
- **Source types:** SYSTEM, USER, DOCUMENT, TOOL, AGENT, MEMORY, UNKNOWN

Usage::

    from ai_audit.provenance import ProvenanceChain, ProvenanceRecord, SourceType

    chain = ProvenanceChain(receipt_id="r1", tenant_id="acme")
    chain.add(ProvenanceRecord(
        source_type=SourceType.DOCUMENT,
        source_id="doc-123",
        content_hash="abc...",
        trust_level=0.9,
    ))
    chain.add(ProvenanceRecord(
        source_type=SourceType.USER,
        source_id="user-input",
        content_hash="def...",
    ))
    assert chain.verify_integrity()
    print(chain.trust_summary())

NB ee9616a5 (CHEF) + NB a861f2b3 (Agentic) validated — 2026-04-16.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

import orjson


class SourceType(StrEnum):
    """Origin type for a piece of information."""

    SYSTEM = "system"         # System prompt, configuration
    USER = "user"             # Direct user input
    DOCUMENT = "document"     # Retrieved document (RAG)
    TOOL = "tool"             # Tool/API result
    AGENT = "agent"           # Output from another agent
    MEMORY = "memory"         # From conversation memory / context
    UNKNOWN = "unknown"       # Origin cannot be determined


@dataclass
class ProvenanceRecord:
    """A single provenance attestation — where a piece of information came from.

    Attributes:
        source_type:    Origin category (system, user, document, tool, agent, memory).
        source_id:      Identifier of the source (document ID, tool name, agent ID).
        content_hash:   SHA-256 of the source content (proves what was seen).
        trust_level:    Trust score 0.0–1.0 (system=1.0, user=0.5, unknown=0.0).
        timestamp:      When the source was accessed.
        metadata:       Additional context (URL, chunk index, etc.).
        record_hash:    SHA-256 of the canonical record (for chain integrity).
    """

    source_type: SourceType = SourceType.UNKNOWN
    source_id: str = ""
    content_hash: str = ""
    trust_level: float = 0.5
    timestamp: str = ""
    metadata: dict[str, str] = field(default_factory=dict)
    record_hash: str = ""

    def compute_hash(self) -> str:
        """SHA-256 of the canonical record (excludes record_hash)."""
        data = {
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "content_hash": self.content_hash,
            "trust_level": self.trust_level,
            "timestamp": self.timestamp,
        }
        return hashlib.sha256(
            orjson.dumps(data, option=orjson.OPT_SORT_KEYS)
        ).hexdigest()

    def seal(self) -> None:
        """Compute and store the record hash."""
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()
        self.record_hash = self.compute_hash()


@dataclass
class TrustSummary:
    """Aggregated trust analysis for a decision's provenance.

    Attributes:
        total_sources:       Number of provenance records.
        avg_trust:           Average trust level across all sources.
        min_trust:           Lowest trust level (weakest link).
        source_types:        Count of each source type.
        untrusted_sources:   Sources with trust_level < 0.3.
        system_grounded:     Whether at least one SYSTEM source exists.
        potentially_injected: Whether UNKNOWN sources are present (prompt injection risk).
    """

    total_sources: int = 0
    avg_trust: float = 0.0
    min_trust: float = 1.0
    source_types: dict[str, int] = field(default_factory=dict)
    untrusted_sources: int = 0
    system_grounded: bool = False
    potentially_injected: bool = False


class ProvenanceChain:
    """Ordered chain of provenance records for a single decision.

    Tracks all information sources that contributed to a decision,
    with cryptographic integrity verification.

    Parameters:
        receipt_id:  The decision receipt this provenance belongs to.
        tenant_id:   Tenant context.
    """

    def __init__(self, receipt_id: str = "", tenant_id: str = "") -> None:
        self.receipt_id = receipt_id
        self.tenant_id = tenant_id
        self._records: list[ProvenanceRecord] = []

    def add(self, record: ProvenanceRecord) -> None:
        """Add a provenance record to the chain.

        Automatically seals the record if not already sealed.
        """
        if not record.record_hash:
            record.seal()
        self._records.append(record)

    @property
    def records(self) -> list[ProvenanceRecord]:
        return list(self._records)

    @property
    def chain_hash(self) -> str:
        """SHA-256 of all record hashes concatenated (chain fingerprint)."""
        if not self._records:
            return ""
        combined = "".join(r.record_hash for r in self._records)
        return hashlib.sha256(combined.encode()).hexdigest()

    def verify_integrity(self) -> bool:
        """Verify that all record hashes are correct (no tampering)."""
        for record in self._records:
            if record.record_hash != record.compute_hash():
                return False
        return True

    def trust_summary(self) -> TrustSummary:
        """Compute an aggregated trust analysis."""
        if not self._records:
            return TrustSummary()

        trusts = [r.trust_level for r in self._records]
        type_counts: dict[str, int] = {}
        for r in self._records:
            type_counts[r.source_type.value] = type_counts.get(r.source_type.value, 0) + 1

        return TrustSummary(
            total_sources=len(self._records),
            avg_trust=sum(trusts) / len(trusts),
            min_trust=min(trusts),
            source_types=type_counts,
            untrusted_sources=sum(1 for t in trusts if t < 0.3),
            system_grounded=SourceType.SYSTEM.value in type_counts,
            potentially_injected=SourceType.UNKNOWN.value in type_counts,
        )

    def get_by_type(self, source_type: SourceType) -> list[ProvenanceRecord]:
        """Filter records by source type."""
        return [r for r in self._records if r.source_type == source_type]

    def to_dict(self) -> dict[str, object]:
        """Serialize for storage or export."""
        return {
            "receipt_id": self.receipt_id,
            "tenant_id": self.tenant_id,
            "chain_hash": self.chain_hash,
            "record_count": len(self._records),
            "records": [
                {
                    "source_type": r.source_type.value,
                    "source_id": r.source_id,
                    "content_hash": r.content_hash,
                    "trust_level": r.trust_level,
                    "timestamp": r.timestamp,
                    "record_hash": r.record_hash,
                }
                for r in self._records
            ],
        }

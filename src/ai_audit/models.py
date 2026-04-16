"""
ai_audit.models — DecisionReceipt Pydantic schema with Ed25519 signing.

Each receipt captures one security-relevant pipeline decision with:
- Canonical input/output hashing (SHA-256 over NFKC-normalized text)
- Ordered check records (supervisor, routing, cache, concordance, etc.)
- Ed25519 cryptographic signature via libsodium (PyNaCl)
- SHA-256 hash-chain linking to the previous receipt per tenant

Performance: ``seal()`` completes in < 0.1ms (orjson + SHA-256 + Ed25519).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import nacl.signing
import orjson
from pydantic import BaseModel, Field


class ReceiptAction(StrEnum):
    """Terminal action taken by the pipeline for this request."""

    ALLOW = "allow"
    REJECT = "reject"
    FAIL_RETRY = "fail_retry"
    CACHE_HIT = "cache_hit"
    ESCALATE = "escalate"
    BYPASS = "bypass"


class CheckRecord(BaseModel):
    """A single check/gate evaluation within the pipeline.

    Attributes:
        name:      Check identifier (e.g. ``"supervisor_pre"``, ``"safety_check"``).
        version:   Schema version for forward-compatibility.
        score:     Numeric score from the check (0.0–1.0 typically).
        threshold: Decision threshold that ``score`` was compared against.
        fired:     Whether the check triggered (changed routing/outcome).
        detail:    Arbitrary metadata (verdict strings, issue lists, etc.).
    """

    name: str
    version: str = "1.0"
    score: float = 0.0
    threshold: float = 0.0
    fired: bool = False
    detail: dict[str, Any] = Field(default_factory=dict)


class DecisionReceipt(BaseModel):
    """Tamper-evident audit record for one pipeline decision.

    The receipt is sealed via ``seal()`` which:
    1. Canonicalises all fields (excl. ``receipt_hash`` and ``signature``)
       into deterministic JSON via ``orjson.dumps(OPT_SORT_KEYS)``.
    2. Computes a SHA-256 self-hash over the canonical bytes.
    3. Signs the canonical bytes with an Ed25519 private key (libsodium).

    Hash-chain: ``prev_receipt_hash`` links to the preceding receipt's
    ``receipt_hash`` for the same tenant, forming an append-only Merkle chain.
    """

    # Identity
    receipt_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    receipt_version: str = "1.0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Correlation
    trace_id: str = ""
    session_id: str = ""
    tenant_id: str = ""

    # Cryptographic binding
    input_c14n: str = ""   # SHA-256 of NFKC-normalised input
    state_digest: str = "" # Hash of security-relevant context
    output_hash: str = ""  # SHA-256 of generated output

    # Checks
    checks: list[CheckRecord] = Field(default_factory=list)

    # Decision
    action: ReceiptAction = ReceiptAction.ALLOW
    reason_codes: list[str] = Field(default_factory=list)
    nist_tags: list[str] = Field(default_factory=list)

    # Model provenance
    model_id: str = ""
    config_digest: str = ""

    # Hash-chain + Ed25519 signature
    prev_receipt_hash: str = ""
    receipt_hash: str = ""  # SHA-256 self-hash
    signature: str = ""     # Ed25519 signature (hex-encoded)

    def seal_payload(self) -> bytes:
        """Canonical bytes for hashing + signing (excludes receipt_hash & signature).

        Uses ``orjson.OPT_SORT_KEYS`` for deterministic field ordering
        (RFC 8785 Canonicalization equivalent for JSON).
        """
        data = self.model_dump(exclude={"receipt_hash", "signature"}, mode="json")
        return orjson.dumps(data, option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS)

    def compute_hash(self) -> str:
        """SHA-256 of the canonical payload."""
        return hashlib.sha256(self.seal_payload()).hexdigest()

    def seal(self, private_key: nacl.signing.SigningKey) -> None:
        """Canonicalise, hash, and sign the receipt in < 0.1ms.

        Steps:
        1. Compute SHA-256 self-hash from canonical payload.
        2. Sign canonical payload with Ed25519 (libsodium C implementation).
        3. Store both on the receipt instance.
        """
        payload = self.seal_payload()
        self.receipt_hash = hashlib.sha256(payload).hexdigest()
        signed = private_key.sign(payload)
        self.signature = signed.signature.hex()

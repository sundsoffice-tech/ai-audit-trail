"""
ai_audit.hashing — SHA-256 canonicalization utilities for Decision Receipts.

All hashing functions produce deterministic hex-encoded SHA-256 digests
suitable for cryptographic binding in audit records.

Canonicalization:
- Input text: NFKC normalisation → whitespace collapse → lowercase → SHA-256
- Output text: Raw SHA-256 (no normalisation — output must be bit-exact)
- State digest: Pipe-delimited parts → SHA-256
"""

from __future__ import annotations

import hashlib
import re
import unicodedata


def canonicalize_input(text: str) -> str:
    """SHA-256 of NFKC-normalized, whitespace-collapsed, lowercased input.

    This ensures that semantically identical inputs (differing only in
    whitespace, unicode representation, or casing) produce the same digest.

    Parameters:
        text: Raw user input text.

    Returns:
        Hex-encoded SHA-256 digest (64 chars).
    """
    normalised = unicodedata.normalize("NFKC", text)
    collapsed = re.sub(r"\s+", " ", normalised).strip()
    lowered = collapsed.lower()
    return hashlib.sha256(lowered.encode("utf-8")).hexdigest()


def hash_output(output: str) -> str:
    """SHA-256 of the generated output (no normalisation — bit-exact).

    Parameters:
        output: Generated response text.

    Returns:
        Hex-encoded SHA-256 digest (64 chars).
    """
    return hashlib.sha256(output.encode("utf-8")).hexdigest()


def hash_state(parts: list[str]) -> str:
    """SHA-256 of pipe-delimited state components.

    Combines security-relevant context (session_id, tenant_id, model_id, etc.)
    into a single digest for the ``state_digest`` field.

    Parameters:
        parts: Ordered list of state components.

    Returns:
        Hex-encoded SHA-256 digest (64 chars).
    """
    combined = "|".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

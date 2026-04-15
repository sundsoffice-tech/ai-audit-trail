"""
ai_audit.hashing — SHA-256 canonicalization utilities for Decision Receipts.

Sync functions for direct/test use. Async wrappers (a*) offload
CPU-intensive work via asyncio.to_thread() to keep the event loop free.

Written by NB 005c5140 (Performance), semantic alignment by HACCA.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import unicodedata
from typing import Any

import orjson

# ---------------------------------------------------------------------------
# Sync (used in tests + fallback)
# ---------------------------------------------------------------------------

def canonicalize_input(text: str) -> str:
    """SHA-256 of NFKC-normalised, whitespace-collapsed, lowercased input.

    WARNING: CPU-bound. Use ``acanonicalize_input`` in async pipelines.
    """
    normalised = unicodedata.normalize("NFKC", str(text))
    collapsed = re.sub(r"\s+", " ", normalised).strip()
    lowered = collapsed.lower()
    return hashlib.sha256(lowered.encode("utf-8")).hexdigest()


def hash_output(output: str) -> str:
    """SHA-256 of the generated output (bit-exact, no normalisation).

    WARNING: CPU-bound. Use ``ahash_output`` in async pipelines.
    """
    return hashlib.sha256(output.encode("utf-8")).hexdigest()


def hash_state(parts: list[str]) -> str:
    """SHA-256 of pipe-delimited state components.

    Combines security-relevant context (session_id, tenant_id, model_id)
    into a single digest for the ``state_digest`` field.
    """
    combined = "|".join(parts)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def hash_json(data: Any) -> str:
    """SHA-256 of deterministically serialised JSON (orjson OPT_SORT_KEYS).

    Use for hashing arbitrary dicts/objects (e.g. config digests).
    orjson releases the GIL internally — safe under concurrent load.
    """
    try:
        serialised = orjson.dumps(data, option=orjson.OPT_SORT_KEYS | orjson.OPT_NON_STR_KEYS)
    except orjson.JSONEncodeError as exc:
        raise ValueError(f"Data could not be serialised for hashing: {exc}") from exc
    return hashlib.sha256(serialised).hexdigest()


# ---------------------------------------------------------------------------
# Async wrappers — offload to thread pool, keep event loop free
# ---------------------------------------------------------------------------

async def acanonicalize_input(text: str) -> str:
    """Async wrapper for canonicalize_input.

    Short-circuits for strings under 500 chars to avoid thread-spawn overhead.
    """
    if len(text) < 500:
        return canonicalize_input(text)
    return await asyncio.to_thread(canonicalize_input, text)


async def ahash_output(output: str) -> str:
    """Async wrapper for hash_output."""
    if len(output) < 500:
        return hash_output(output)
    return await asyncio.to_thread(hash_output, output)


async def ahash_state(parts: list[str]) -> str:
    """Async wrapper for hash_state."""
    return await asyncio.to_thread(hash_state, parts)

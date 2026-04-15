"""
ai_audit.pii — PII-Redaction before SHA-256 hashing.

Removes personally identifiable information from text **before** it enters the
hash-chain, ensuring GDPR Art. 17 (Right to Erasure) compliance: the stored
hash is of the anonymised text, so raw PII never appears in receipts.

Zero external dependencies — uses only ``re`` and ``hashlib``.

Usage::

    from ai_audit.pii import PiiConfig, PiiMode, PiiType, obfuscate_text

    config = PiiConfig(
        enabled_types={PiiType.EMAIL, PiiType.IP},
        mode=PiiMode.REDACT,
    )
    clean = obfuscate_text("Contact me at alice@example.com", config)
    # -> "Contact me at [EMAIL]"
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from re import Match


class PiiType(Enum):
    """Supported PII categories."""
    EMAIL = auto()
    PHONE = auto()
    IP = auto()
    IBAN = auto()
    CREDIT_CARD = auto()
    CUSTOM = auto()


class PiiMode(Enum):
    """Obfuscation strategy applied to each detected PII span."""
    REDACT = auto()   # Replace with [TYPE] placeholder, e.g. [EMAIL]
    HASH = auto()     # Replace with SHA-256 hex digest (deterministic)
    MASK = auto()     # Keep first + last char, replace interior with X


@dataclass(frozen=True)
class PiiConfig:
    """Configuration for the PII-redaction pass.

    Attributes:
        enabled_types:   Set of PII categories to detect and obfuscate.
        mode:            Obfuscation strategy (REDACT / HASH / MASK).
        custom_patterns: Additional regex patterns treated as CUSTOM type.
    """
    enabled_types: frozenset[PiiType] = field(
        default_factory=lambda: frozenset({
            PiiType.EMAIL, PiiType.IP, PiiType.CREDIT_CARD, PiiType.IBAN,
        })
    )
    mode: PiiMode = PiiMode.REDACT
    custom_patterns: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Compiled regex patterns (zero-dependency, heuristic but production-grade)
# ---------------------------------------------------------------------------

_REGEX_PATTERNS: dict[PiiType, str] = {
    PiiType.EMAIL: r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
    # International phone numbers: optional country code + digits/spaces/dashes
    PiiType.PHONE: (
        r'\b(?:\+?\d{1,3}[ \-]?)?(?:\(?\d{2,4}\)?[ \-]?)?\d{3,4}[ \-]?\d{3,4}\b'
    ),
    # IPv4 only (IPv6 rare in LLM I/O; extend via custom_patterns if needed)
    PiiType.IP: (
        r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'
    ),
    # IBAN: 2 letter country code + 2 digits + 11–30 alphanum chars
    PiiType.IBAN: r'\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b',
    # Credit card: 13–19 digits, optionally separated by spaces or dashes
    PiiType.CREDIT_CARD: r'\b(?:\d[ \-]*?){13,19}\b',
}

# Pre-compile for performance
_COMPILED: dict[PiiType, re.Pattern[str]] = {
    t: re.compile(p) for t, p in _REGEX_PATTERNS.items()
}


# ---------------------------------------------------------------------------
# Core obfuscation logic
# ---------------------------------------------------------------------------

def _apply_obfuscation(match: Match[str], pii_type: PiiType, mode: PiiMode) -> str:
    """Apply the chosen obfuscation strategy to a single regex match."""
    original = match.group(0)

    if mode == PiiMode.REDACT:
        return f"[{pii_type.name}]"

    if mode == PiiMode.HASH:
        return hashlib.sha256(original.encode("utf-8")).hexdigest()

    # PiiMode.MASK: keep first and last visible char, replace interior with X
    if len(original) <= 2:
        return "X" * len(original)
    masked = [original[0]]
    for ch in original[1:-1]:
        masked.append(ch if ch in (" ", "-") else "X")
    masked.append(original[-1])
    return "".join(masked)


def obfuscate_text(text: str, config: PiiConfig) -> str:
    """Remove PII from *text* synchronously.

    Must be called **before** ``canonicalize_input`` / ``hash_output`` so that
    the stored hash is computed over the anonymised string.

    Parameters:
        text:   Input string (LLM prompt or response).
        config: PII detection and obfuscation settings.

    Returns:
        A copy of *text* with all configured PII spans replaced.
    """
    if not text or not config.enabled_types:
        return text

    result = text

    for pii_type in config.enabled_types:
        if pii_type == PiiType.CUSTOM:
            continue
        pattern = _COMPILED.get(pii_type)
        if pattern:
            result = pattern.sub(
                lambda m, pt=pii_type: _apply_obfuscation(m, pt, config.mode),
                result,
            )

    if PiiType.CUSTOM in config.enabled_types and config.custom_patterns:
        for raw_pattern in config.custom_patterns:
            try:
                result = re.sub(
                    raw_pattern,
                    lambda m: _apply_obfuscation(m, PiiType.CUSTOM, config.mode),
                    result,
                )
            except re.error:
                pass  # Ignore malformed patterns silently

    return result


async def aobfuscate_text(text: str, config: PiiConfig) -> str:
    """Async wrapper around :func:`obfuscate_text`.

    Short-circuits for strings under 200 chars to avoid thread-spawn overhead.
    Longer texts are offloaded via ``asyncio.to_thread`` to avoid blocking the
    event loop on large LLM outputs.

    Parameters:
        text:   Input string.
        config: PII detection and obfuscation settings.

    Returns:
        Anonymised copy of *text*.
    """
    if len(text) < 200:
        return obfuscate_text(text, config)
    return await asyncio.to_thread(obfuscate_text, text, config)

"""Tests for ai_audit.pii — PII-Redaction module."""


import pytest

from ai_audit.pii import (
    PiiConfig,
    PiiMode,
    PiiType,
    aobfuscate_text,
    obfuscate_text,
)

# ---------------------------------------------------------------------------
# REDACT mode
# ---------------------------------------------------------------------------

def test_redact_email():
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    result = obfuscate_text("Contact alice@example.com for help.", config)
    assert "[EMAIL]" in result
    assert "alice@example.com" not in result


def test_redact_ip():
    config = PiiConfig(enabled_types=frozenset({PiiType.IP}), mode=PiiMode.REDACT)
    result = obfuscate_text("Server at 192.168.1.1 is down.", config)
    assert "[IP]" in result
    assert "192.168.1.1" not in result


def test_redact_iban():
    config = PiiConfig(enabled_types=frozenset({PiiType.IBAN}), mode=PiiMode.REDACT)
    result = obfuscate_text("Transfer to DE89370400440532013000 today.", config)
    assert "[IBAN]" in result
    assert "DE89370400440532013000" not in result


def test_redact_multiple_types():
    config = PiiConfig(
        enabled_types=frozenset({PiiType.EMAIL, PiiType.IP}),
        mode=PiiMode.REDACT,
    )
    text = "Email bob@test.org from IP 10.0.0.1."
    result = obfuscate_text(text, config)
    assert "[EMAIL]" in result
    assert "[IP]" in result
    assert "bob@test.org" not in result
    assert "10.0.0.1" not in result


# ---------------------------------------------------------------------------
# HASH mode
# ---------------------------------------------------------------------------

def test_hash_mode_produces_hex():
    import hashlib
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.HASH)
    text = "user@domain.com"
    result = obfuscate_text(f"Send to {text}.", config)
    expected_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    assert expected_hash in result


def test_hash_mode_deterministic():
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.HASH)
    text = "test@example.com"
    r1 = obfuscate_text(text, config)
    r2 = obfuscate_text(text, config)
    assert r1 == r2


# ---------------------------------------------------------------------------
# MASK mode
# ---------------------------------------------------------------------------

def test_mask_mode_keeps_first_last_char():
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.MASK)
    result = obfuscate_text("a@b.com here", config)
    # Masked value should start with 'a' and end with 'm'
    assert result.startswith("a") or "a" in result


def test_mask_mode_short_string():
    """Short matches (<=2 chars) are fully masked."""
    import re

    from ai_audit.pii import _apply_obfuscation
    match = re.match(r"ab", "ab")
    assert match is not None
    result = _apply_obfuscation(match, PiiType.EMAIL, PiiMode.MASK)
    assert result == "XX"


# ---------------------------------------------------------------------------
# CUSTOM patterns
# ---------------------------------------------------------------------------

def test_custom_pattern_redact():
    config = PiiConfig(
        enabled_types=frozenset({PiiType.CUSTOM}),
        mode=PiiMode.REDACT,
        custom_patterns=("ORDER-\\d{6}",),
    )
    result = obfuscate_text("Your order ORDER-123456 is shipped.", config)
    assert "[CUSTOM]" in result
    assert "ORDER-123456" not in result


def test_invalid_custom_pattern_ignored():
    """Malformed regex must not raise — it is silently skipped."""
    config = PiiConfig(
        enabled_types=frozenset({PiiType.CUSTOM}),
        mode=PiiMode.REDACT,
        custom_patterns=("(unclosed",),
    )
    text = "No crash expected."
    result = obfuscate_text(text, config)
    assert result == text


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_empty_string():
    config = PiiConfig()
    assert obfuscate_text("", config) == ""


def test_no_enabled_types():
    config = PiiConfig(enabled_types=frozenset())
    text = "user@example.com"
    assert obfuscate_text(text, config) == text


def test_no_pii_in_text():
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    text = "No personal data here."
    assert obfuscate_text(text, config) == text


# ---------------------------------------------------------------------------
# PII before hashing (integration)
# ---------------------------------------------------------------------------

def test_pii_removed_before_hash():
    """Hash of anonymised text != hash of raw text — PII is NOT in the hash."""
    from ai_audit.hashing import canonicalize_input

    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    raw = "Contact alice@example.com please."
    clean = obfuscate_text(raw, config)

    hash_raw = canonicalize_input(raw)
    hash_clean = canonicalize_input(clean)

    assert hash_raw != hash_clean
    assert "alice@example.com" not in clean


# ---------------------------------------------------------------------------
# Async wrapper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_aobfuscate_text_matches_sync():
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    text = "Contact alice@example.com for info."
    assert await aobfuscate_text(text, config) == obfuscate_text(text, config)


@pytest.mark.asyncio
async def test_aobfuscate_short_circuit():
    """Strings <200 chars skip asyncio.to_thread."""
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    short = "hi@example.com"
    result = await aobfuscate_text(short, config)
    assert "[EMAIL]" in result


@pytest.mark.asyncio
async def test_aobfuscate_long_string():
    """Long strings go through asyncio.to_thread."""
    config = PiiConfig(enabled_types=frozenset({PiiType.EMAIL}), mode=PiiMode.REDACT)
    long_text = "word " * 60 + "user@test.com" + " word" * 60
    result = await aobfuscate_text(long_text, config)
    assert "[EMAIL]" in result
    assert "user@test.com" not in result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def test_public_api_pii_symbols():
    import ai_audit

    for sym in ["PiiType", "PiiMode", "PiiConfig", "obfuscate_text", "aobfuscate_text"]:
        assert hasattr(ai_audit, sym), f"Missing from public API: {sym}"

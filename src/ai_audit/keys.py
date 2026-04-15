"""
ai_audit.keys — Ed25519 key management for Decision Receipt signing.

Key sourcing (in priority order):
1. Injected via ``init_audit_config(AuditConfig(signing_key_hex="..."))``
2. Ephemeral key generated at startup (development/CI only — logs a warning)

Thread-safety: Module-level lazy init with GIL protection.

Generate a persistent key::

    python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
"""

from __future__ import annotations

import logging

import nacl.signing

from ai_audit.config import AuditConfig

logger = logging.getLogger(__name__)

_SIGNING_KEY: nacl.signing.SigningKey | None = None
_config: AuditConfig = AuditConfig()


def init_audit_config(config: AuditConfig) -> None:
    """Inject audit configuration (call once at application startup).

    Parameters:
        config: Immutable :class:`AuditConfig` instance.
    """
    global _config, _SIGNING_KEY  # noqa: PLW0603
    _config = config
    _SIGNING_KEY = None  # Reset to force re-init with new key


def get_signing_key() -> nacl.signing.SigningKey:
    """Return the Ed25519 signing key (lazy-initialised singleton).

    Sources:
        1. ``config.signing_key_hex`` (injected via ``init_audit_config``).
        2. Auto-generated ephemeral key (logs a warning in non-production).

    Returns:
        Ed25519 ``SigningKey`` instance backed by libsodium.

    Raises:
        RuntimeError: If ``config.is_production=True`` and no key is set.
    """
    global _SIGNING_KEY  # noqa: PLW0603
    if _SIGNING_KEY is None:
        key_hex = _config.signing_key_hex
        if key_hex:
            _SIGNING_KEY = nacl.signing.SigningKey(bytes.fromhex(key_hex))
            logger.info("Ed25519 signing key loaded from AuditConfig")
        else:
            if _config.is_production:
                raise RuntimeError(
                    "No signing key set in production mode. "
                    "Provide a persistent Ed25519 key via AuditConfig(signing_key_hex=...). "
                    'Generate with: python -c "import nacl.signing; '
                    'print(nacl.signing.SigningKey.generate().encode().hex())"'
                )
            _SIGNING_KEY = nacl.signing.SigningKey.generate()
            logger.warning(
                "No signing key configured — using ephemeral Ed25519 key. "
                "Set AuditConfig(signing_key_hex=...) for production use."
            )
    return _SIGNING_KEY


def get_verify_key_hex() -> str:
    """Return the Ed25519 public verification key as a hex string.

    This key is safe to share — it can verify signatures but not create them.
    """
    return get_signing_key().verify_key.encode().hex()


def reset_signing_key() -> None:
    """Reset the cached signing key (for testing only)."""
    global _SIGNING_KEY  # noqa: PLW0603
    _SIGNING_KEY = None

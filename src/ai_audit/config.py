"""
ai_audit.config — AuditConfig: Dependency-injected configuration.

Instead of reading environment variables directly (which would violate
Inversion-of-Control), callers construct an AuditConfig and inject it
via init_audit_config(). This keeps the library framework-agnostic.

Usage::

    from ai_audit import init_audit_config, AuditConfig

    init_audit_config(AuditConfig(is_production=True))
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditConfig:
    """Immutable audit configuration.

    Attributes:
        is_production:      Enforce persistent signing key (raises RuntimeError
                            if no key is provided and this is True).
        signing_key_hex:    Hex-encoded 32-byte Ed25519 seed. If empty, an
                            ephemeral key is generated (development only).
        receipt_ttl:        Redis TTL for stored receipts in seconds (default: 30 days).
        receipt_max_size:   Max in-memory receipts before LRU eviction.
    """

    is_production: bool = False
    signing_key_hex: str = ""
    receipt_ttl: int = 2_592_000  # 30 days
    receipt_max_size: int = 50_000

    @classmethod
    def from_env(cls) -> "AuditConfig":
        """Convenience factory: read common config from environment variables.

        Variables:
            AI_AUDIT_ENV           = "production" → is_production=True
            AI_AUDIT_SIGNING_KEY   = "<hex-encoded 32-byte seed>"
            AI_AUDIT_RECEIPT_TTL   = "<seconds>"

        This helper lives here (not in the core modules) so the library
        stays testable without any environment setup.
        """
        import os

        return cls(
            is_production=os.getenv("AI_AUDIT_ENV", "").lower() == "production",
            signing_key_hex=os.getenv("AI_AUDIT_SIGNING_KEY", ""),
            receipt_ttl=int(os.getenv("AI_AUDIT_RECEIPT_TTL", "2592000")),
        )

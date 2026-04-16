"""
ai_audit.keys — Ed25519 key management for Decision Receipt signing.

Two usage modes:

1. Simple (default): inject via AuditConfig::

    init_audit_config(AuditConfig(signing_key_hex="..."))

2. Enterprise KMS: inject a custom KeyProvider::

    class VaultKeyProvider(KeyProvider):
        def get_signing_key(self): ...
        def get_verify_key_hex(self): ...

    init_key_provider(VaultKeyProvider())

KeyProvider ABC written by NB 409cad95 (Enterprise AI 2026).

Generate a persistent key::

    python -c "import nacl.signing; print(nacl.signing.SigningKey.generate().encode().hex())"
"""

from __future__ import annotations

import abc
import logging
import threading

import nacl.signing

from ai_audit.config import AuditConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# KeyProvider ABC — NB 409cad95
# ---------------------------------------------------------------------------

class KeyProvider(abc.ABC):
    """Abstract base class for cryptographic key providers.

    Implement this to integrate external KMS solutions (HashiCorp Vault,
    AWS KMS, GCP KMS, Azure Key Vault, etc.) without modifying ai-audit.

    Example::

        class VaultKeyProvider(KeyProvider):
            def __init__(self, vault_client, key_path):
                self._client = vault_client
                self._path = key_path

            def get_signing_key(self) -> nacl.signing.SigningKey:
                secret = self._client.secrets.kv.read_secret(self._path)
                return nacl.signing.SigningKey(bytes.fromhex(secret["data"]["key"]))

            def get_verify_key_hex(self) -> str:
                return self.get_signing_key().verify_key.encode().hex()

        init_key_provider(VaultKeyProvider(vault, "secret/ai-audit/signing-key"))
    """

    @abc.abstractmethod
    def get_signing_key(self) -> nacl.signing.SigningKey:
        """Return the Ed25519 signing key."""

    @abc.abstractmethod
    def get_verify_key_hex(self) -> str:
        """Return the public verification key as a hex string."""


class DefaultKeyProvider(KeyProvider):
    """Default KeyProvider backed by AuditConfig.signing_key_hex.

    Suitable for development and small deployments. For production,
    use a KMS-backed provider.
    """

    def __init__(self, config: AuditConfig) -> None:
        self._config = config
        self._key: nacl.signing.SigningKey | None = None
        self._lock = threading.Lock()

    def _load(self) -> nacl.signing.SigningKey:
        with self._lock:
            if self._key is None:
                if self._config.signing_key_hex:
                    self._key = nacl.signing.SigningKey(bytes.fromhex(self._config.signing_key_hex))
                    logger.info("Ed25519 signing key loaded from AuditConfig")
                else:
                    if self._config.is_production:
                        raise RuntimeError(
                            "No signing key set in production mode. "
                            "Provide AuditConfig(signing_key_hex=...) or a custom KeyProvider. "
                            'Generate: python -c "import nacl.signing; '
                            'print(nacl.signing.SigningKey.generate().encode().hex())"'
                        )
                    self._key = nacl.signing.SigningKey.generate()
                    logger.warning(
                        "No signing key configured — using ephemeral Ed25519 key. "
                        "Set AuditConfig(signing_key_hex=...) for production use."
                    )
            return self._key

    def get_signing_key(self) -> nacl.signing.SigningKey:
        return self._load()

    def get_verify_key_hex(self) -> str:
        return self._load().verify_key.encode().hex()


# ---------------------------------------------------------------------------
# Module-level singleton — backward-compatible API
# ---------------------------------------------------------------------------

_provider: KeyProvider | None = None
_config: AuditConfig = AuditConfig()


def init_audit_config(config: AuditConfig) -> None:
    """Inject audit configuration (call once at startup).

    Resets any previously injected KeyProvider.
    """
    global _config, _provider  # noqa: PLW0603
    _config = config
    _provider = DefaultKeyProvider(config)


def init_key_provider(provider: KeyProvider) -> None:
    """Inject a custom KeyProvider (e.g. Vault, AWS KMS).

    Takes precedence over ``init_audit_config``.
    """
    global _provider  # noqa: PLW0603
    _provider = provider
    logger.info("Custom KeyProvider registered: %s", type(provider).__name__)


def _get_provider() -> KeyProvider:
    global _provider  # noqa: PLW0603
    if _provider is None:
        _provider = DefaultKeyProvider(_config)
    return _provider


def get_signing_key() -> nacl.signing.SigningKey:
    """Return the active Ed25519 signing key."""
    return _get_provider().get_signing_key()


def get_verify_key_hex() -> str:
    """Return the Ed25519 public verification key as a hex string."""
    return _get_provider().get_verify_key_hex()


def reset_signing_key() -> None:
    """Reset all key state (for testing only)."""
    global _provider, _config  # noqa: PLW0603
    _provider = None
    _config = AuditConfig()

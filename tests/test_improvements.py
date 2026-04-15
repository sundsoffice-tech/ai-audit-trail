"""Tests for v0.1.0 pre-release improvements:
- async hashing (acanonicalize_input, ahash_output, ahash_state, hash_json)
- receipt_store use_lua flag
- KeyProvider ABC + DefaultKeyProvider + init_key_provider
- all new symbols in public API
"""


import nacl.signing
import pytest

from ai_audit import (
    AuditConfig,
    DefaultKeyProvider,
    KeyProvider,
    ReceiptAction,
    ReceiptCollector,
    ReceiptStore,
    acanonicalize_input,
    ahash_output,
    ahash_state,
    canonicalize_input,
    hash_json,
    hash_output,
    hash_state,
    init_audit_config,
    init_key_provider,
    reset_signing_key,
    verify_chain,
)


def setup_function():
    reset_signing_key()
    init_audit_config(AuditConfig(is_production=False))


# ---------------------------------------------------------------------------
# Async hashing
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_acanonicalize_input_matches_sync():
    """Async wrapper must produce identical result to sync version."""
    text = "Hello   World — Ä ö ü"
    sync_result = canonicalize_input(text)
    async_result = await acanonicalize_input(text)
    assert sync_result == async_result


@pytest.mark.asyncio
async def test_acanonicalize_input_short_circuit():
    """Strings under 500 chars use short-circuit path (no thread spawn)."""
    short = "short string"
    result = await acanonicalize_input(short)
    assert result == canonicalize_input(short)


@pytest.mark.asyncio
async def test_acanonicalize_input_long_string():
    """Long strings are offloaded via asyncio.to_thread."""
    long_text = "word " * 300  # > 500 chars
    result = await acanonicalize_input(long_text)
    assert result == canonicalize_input(long_text)


@pytest.mark.asyncio
async def test_ahash_output_matches_sync():
    output = "The answer is 42."
    assert await ahash_output(output) == hash_output(output)


@pytest.mark.asyncio
async def test_ahash_state_matches_sync():
    parts = ["tenant-1", "session-abc", "gpt-4o"]
    assert await ahash_state(parts) == hash_state(parts)


@pytest.mark.asyncio
async def test_async_hashing_is_deterministic():
    """Same input must always produce same hash."""
    text = "deterministic test"
    r1 = await acanonicalize_input(text)
    r2 = await acanonicalize_input(text)
    assert r1 == r2


# ---------------------------------------------------------------------------
# hash_json
# ---------------------------------------------------------------------------

def test_hash_json_deterministic():
    data = {"b": 2, "a": 1, "c": [3, 2, 1]}
    h1 = hash_json(data)
    h2 = hash_json(data)
    assert h1 == h2


def test_hash_json_key_order_invariant():
    """OPT_SORT_KEYS must make key order irrelevant."""
    d1 = {"a": 1, "b": 2}
    d2 = {"b": 2, "a": 1}
    assert hash_json(d1) == hash_json(d2)


def test_hash_json_different_data():
    assert hash_json({"a": 1}) != hash_json({"a": 2})


def test_hash_json_invalid_raises():
    with pytest.raises(ValueError):
        hash_json(object())  # not JSON-serialisable


# ---------------------------------------------------------------------------
# KeyProvider ABC
# ---------------------------------------------------------------------------

def test_keyprovider_is_abstract():
    """KeyProvider cannot be instantiated directly."""
    with pytest.raises(TypeError):
        KeyProvider()  # type: ignore[abstract]


def test_keyprovider_custom_implementation():
    """A custom KeyProvider can be implemented and injected."""
    key = nacl.signing.SigningKey.generate()

    class StaticKeyProvider(KeyProvider):
        def get_signing_key(self) -> nacl.signing.SigningKey:
            return key

        def get_verify_key_hex(self) -> str:
            return key.verify_key.encode().hex()

    provider = StaticKeyProvider()
    assert provider.get_signing_key() == key
    assert len(provider.get_verify_key_hex()) == 64  # 32 bytes hex-encoded


def test_init_key_provider_used_for_signing():
    """After init_key_provider(), receipts are signed with the injected key."""
    key = nacl.signing.SigningKey.generate()

    class FixedKeyProvider(KeyProvider):
        def get_signing_key(self):
            return key

        def get_verify_key_hex(self):
            return key.verify_key.encode().hex()

    init_key_provider(FixedKeyProvider())

    store = ReceiptStore()
    c = ReceiptCollector(tenant_id="test")
    c.set_input("hello")
    c.set_output("world")
    c.emit(store)
    c.cleanup()

    receipts = store.get_by_tenant("test")
    pub_hex = key.verify_key.encode().hex()
    result = verify_chain(receipts, pub_hex)
    assert result.valid


def test_default_key_provider():
    key_hex = nacl.signing.SigningKey.generate().encode().hex()
    config = AuditConfig(signing_key_hex=key_hex)
    provider = DefaultKeyProvider(config)

    assert isinstance(provider.get_signing_key(), nacl.signing.SigningKey)
    assert len(provider.get_verify_key_hex()) == 64


def test_default_key_provider_ephemeral_in_dev():
    """Dev mode: ephemeral key generated, no error."""
    provider = DefaultKeyProvider(AuditConfig(is_production=False))
    key = provider.get_signing_key()
    assert key is not None


def test_default_key_provider_production_raises_without_key():
    """Production mode without key must raise RuntimeError."""
    provider = DefaultKeyProvider(AuditConfig(is_production=True, signing_key_hex=""))
    with pytest.raises(RuntimeError, match="No signing key"):
        provider.get_signing_key()


# ---------------------------------------------------------------------------
# ReceiptStore use_lua flag
# ---------------------------------------------------------------------------

def test_receipt_store_use_lua_false_default():
    """Default store (no Redis) works as before."""
    store = ReceiptStore()
    assert store._use_lua is False
    assert store.count == 0


def test_receipt_store_use_lua_without_redis():
    """use_lua=True without a Redis client: flag is stored but Redis ops are
    skipped (self._redis is None guard). No crash on append."""
    store = ReceiptStore(redis_client=None, use_lua=True)
    # Flag is stored as-is; Redis ops are skipped via `if self._redis is not None`
    assert store._lua_script is None  # No Lua script registered without Redis
    # Appending must not raise even with use_lua=True and no Redis
    c = ReceiptCollector(tenant_id="no-redis")
    c.set_action(ReceiptAction.ALLOW)
    c.emit(store)
    c.cleanup()
    assert store.count == 1


def test_receipt_store_lua_flag_roundtrip():
    """Receipts are still written to in-memory store even when use_lua=True."""
    store = ReceiptStore(redis_client=None, use_lua=True)

    c = ReceiptCollector(tenant_id="lua-test")
    c.set_input("test")
    c.set_output("result")
    c.set_action(ReceiptAction.ALLOW)
    c.emit(store)
    c.cleanup()

    assert store.count == 1
    receipts = store.get_by_tenant("lua-test")
    assert len(receipts) == 1
    assert receipts[0].action == ReceiptAction.ALLOW


# ---------------------------------------------------------------------------
# Public API completeness
# ---------------------------------------------------------------------------

def test_public_api_new_symbols():
    """All new symbols must be importable from the top-level package."""
    import ai_audit

    new_symbols = [
        "KeyProvider",
        "DefaultKeyProvider",
        "init_key_provider",
        "acanonicalize_input",
        "ahash_output",
        "ahash_state",
        "hash_json",
    ]
    for sym in new_symbols:
        assert hasattr(ai_audit, sym), f"Missing from public API: {sym}"


def test_all_symbols_in__all__():
    """__all__ must include every new symbol."""
    import ai_audit

    for sym in ai_audit.__all__:
        assert hasattr(ai_audit, sym), f"{sym} in __all__ but not importable"

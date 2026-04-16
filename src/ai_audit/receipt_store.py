"""
ai_audit.receipt_store — Atomic Redis Store for Decision Receipts.

In-memory primary store with optional Redis persistence.

Two Redis write modes (NB 005c5140):
- ``use_lua=False`` (default): atomic MULTI/EXEC pipeline
- ``use_lua=True``:  server-side Lua script — one network roundtrip,
  no connection-pool exhaustion under high load (10k+ req/s)

Lua script written by NB 005c5140 (2028 Frontiers: Stigmergic Systems
and Performance Design).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import OrderedDict
from typing import Any

import orjson

from ai_audit.models import DecisionReceipt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Redis exception handling — safe when redis is not installed.
# ---------------------------------------------------------------------------
try:
    import redis as _redis_mod

    REDIS_CONNECTION_ERRORS: tuple[type[BaseException], ...] = (
        _redis_mod.exceptions.ConnectionError,
        _redis_mod.exceptions.ResponseError,
        AttributeError,
    )
    REDIS_RUNTIME_ERRORS: tuple[type[BaseException], ...] = (
        _redis_mod.exceptions.RedisError,
        OSError,
    )
except ImportError:
    REDIS_CONNECTION_ERRORS = (AttributeError,)
    REDIS_RUNTIME_ERRORS = (OSError,)

# ---------------------------------------------------------------------------
# Lua script — NB 005c5140
# Atomically appends a receipt: updates chain tip + indices in one roundtrip.
# ---------------------------------------------------------------------------
_LUA_APPEND_SCRIPT = """
local tip_key    = KEYS[1]
local receipt_key = KEYS[2]
local tenant_idx = KEYS[3]
local session_idx = KEYS[4]
local trace_idx  = KEYS[5]

local new_hash    = ARGV[1]
local receipt_json = ARGV[2]
local receipt_id  = ARGV[3]
local timestamp   = ARGV[4]

redis.call('SET', tip_key, new_hash)
redis.call('SET', receipt_key, receipt_json)
redis.call('ZADD', tenant_idx, timestamp, receipt_id)

if session_idx ~= 'NONE' then
    redis.call('ZADD', session_idx, timestamp, receipt_id)
end
if trace_idx ~= 'NONE' then
    redis.call('ZADD', trace_idx, timestamp, receipt_id)
end

return "OK"
"""


class ReceiptStore:
    """Append-only store for Decision Receipts with optional Redis persistence.

    Parameters:
        redis_client:       Optional sync Redis client (``redis.Redis``).
        ttl:                Redis key TTL in seconds (default: 30 days).
        max_size:           Max in-memory receipts before LRU eviction.
        use_lua:            Use server-side Lua script instead of MULTI/EXEC.
                            Recommended for high-throughput deployments (>1k req/s).
        fail_on_redis_error: If ``True`` (default), Redis write failures propagate
                            as exceptions — the audited operation must abort.
                            If ``False``, failures are logged but swallowed (best-effort).
    """

    def __init__(
        self,
        redis_client: Any | None = None,
        ttl: int = 2_592_000,
        max_size: int = 50_000,
        use_lua: bool = False,
        fail_on_redis_error: bool = True,
    ) -> None:
        self._redis = redis_client
        self._ttl = ttl
        self._max_size = max_size
        self._use_lua = use_lua
        self._fail_on_redis_error = fail_on_redis_error
        self._lua_script: Any | None = None

        if redis_client is not None and use_lua:
            try:
                self._lua_script = redis_client.register_script(_LUA_APPEND_SCRIPT)
                logger.info("Redis Lua script registered (use_lua=True)")
            except REDIS_CONNECTION_ERRORS as e:
                logger.warning("Could not register Lua script, falling back to MULTI/EXEC: %s", e)
                self._use_lua = False

        self._receipts: OrderedDict[str, DecisionReceipt] = OrderedDict()
        self._chain_tips: dict[str, str] = {}
        self._session_index: dict[str, set[str]] = {}
        self._trace_index: dict[str, set[str]] = {}
        self._tenant_locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()  # Protects _tenant_locks dict itself

    def _get_tenant_lock(self, tenant_id: str) -> threading.Lock:
        """Get or create a per-tenant lock (thread-safe)."""
        with self._locks_lock:
            if tenant_id not in self._tenant_locks:
                self._tenant_locks[tenant_id] = threading.Lock()
            return self._tenant_locks[tenant_id]

    def get_chain_tip(self, tenant_id: str) -> str:
        """Return the receipt_hash of the latest receipt for this tenant (memory-only)."""
        tip_id = self._chain_tips.get(tenant_id)
        if tip_id and tip_id in self._receipts:
            return self._receipts[tip_id].receipt_hash
        return ""

    def atomic_seal_and_append(
        self,
        receipt: DecisionReceipt,
        signing_key: Any,
    ) -> None:
        """Atomically read chain tip, seal receipt, and append — no TOCTOU race.

        This method holds a per-tenant lock across the entire sequence,
        preventing concurrent emitters from forking the hash-chain.

        Parameters:
            receipt:     The receipt to seal and store.
            signing_key: Ed25519 ``nacl.signing.SigningKey``.
        """
        lock = self._get_tenant_lock(receipt.tenant_id)
        with lock:
            receipt.prev_receipt_hash = self.get_chain_tip(receipt.tenant_id)
            receipt.seal(signing_key)
            self._store_in_memory(receipt)

    async def aget_chain_tip(self, tenant_id: str) -> str:
        """Return the receipt_hash of the latest receipt, with Redis fallback.

        After LRU eviction or process restart the in-memory tip is gone.
        This method falls back to ``GET receipt_chain:{tenant_id}`` in Redis
        so the hash-chain remains unbroken.
        """
        tip_id = self._chain_tips.get(tenant_id)
        if tip_id and tip_id in self._receipts:
            return self._receipts[tip_id].receipt_hash
        if self._redis is not None:
            try:
                tip_hash = await asyncio.to_thread(
                    self._redis.get, f"receipt_chain:{tenant_id}"
                )
                if tip_hash:
                    return tip_hash.decode() if isinstance(tip_hash, bytes) else tip_hash
            except REDIS_RUNTIME_ERRORS:
                pass
        return ""

    def _store_in_memory(self, receipt: DecisionReceipt) -> None:
        """In-memory storage + index updates (shared by append/aappend)."""
        while len(self._receipts) >= self._max_size:
            evicted_id, _ = self._receipts.popitem(last=False)
            logger.debug("Receipt LRU eviction: %s", evicted_id)

        self._receipts[receipt.receipt_id] = receipt
        self._chain_tips[receipt.tenant_id] = receipt.receipt_id

        if receipt.session_id:
            self._session_index.setdefault(receipt.session_id, set()).add(receipt.receipt_id)
        if receipt.trace_id:
            self._trace_index.setdefault(receipt.trace_id, set()).add(receipt.receipt_id)

    def append(self, receipt: DecisionReceipt) -> None:
        """Store a sealed receipt (in-memory + fire-and-forget Redis).

        For guaranteed Redis persistence, use :meth:`aappend` instead.
        """
        self._store_in_memory(receipt)

        if self._redis is not None:
            try:
                asyncio.get_running_loop()
                if self._use_lua and self._lua_script is not None:
                    asyncio.create_task(self._lua_redis_commit(receipt))
                else:
                    asyncio.create_task(self._atomic_redis_commit(receipt))
            except RuntimeError:
                pass  # No event-loop (sync tests / CLI) — skip Redis

    async def aappend(self, receipt: DecisionReceipt) -> None:
        """Store a sealed receipt with awaited Redis persistence.

        Unlike :meth:`append`, this method ``await``\\s the Redis write so
        that ``fail_on_redis_error=True`` actually propagates exceptions
        to the caller.
        """
        self._store_in_memory(receipt)

        if self._redis is not None:
            if self._use_lua and self._lua_script is not None:
                await self._lua_redis_commit(receipt)
            else:
                await self._atomic_redis_commit(receipt)

    async def _lua_redis_commit(self, receipt: DecisionReceipt) -> None:
        """Single-roundtrip Lua commit — no connection-pool exhaustion."""
        if self._redis is None or self._lua_script is None:
            return
        try:
            payload = orjson.dumps(receipt.model_dump(mode="json"))
            timestamp = receipt.timestamp.timestamp()

            keys = [
                f"receipt_chain:{receipt.tenant_id}",
                f"receipt:{receipt.tenant_id}:{receipt.receipt_id}",
                f"receipt_tenant:{receipt.tenant_id}",
                receipt.session_id or "NONE",
                receipt.trace_id or "NONE",
            ]
            args = [
                receipt.receipt_hash,
                payload,
                receipt.receipt_id,
                str(timestamp),
            ]
            await asyncio.to_thread(self._lua_script, keys=keys, args=args)

            # TTL for receipt data key
            await asyncio.to_thread(
                self._redis.expire,
                f"receipt:{receipt.tenant_id}:{receipt.receipt_id}",
                self._ttl,
            )
        except REDIS_RUNTIME_ERRORS as e:
            if self._fail_on_redis_error:
                raise
            logger.warning("Receipt Lua commit failed (best-effort): %s", e)

    async def _atomic_redis_commit(self, receipt: DecisionReceipt) -> None:
        """MULTI/EXEC pipeline — crash-consistent, one network roundtrip."""
        if self._redis is None:
            return
        try:
            payload = orjson.dumps(receipt.model_dump(mode="json"))
            pipe = self._redis.pipeline(transaction=True)

            pipe.setex(f"receipt:{receipt.tenant_id}:{receipt.receipt_id}", self._ttl, payload)
            pipe.set(f"receipt_chain:{receipt.tenant_id}", receipt.receipt_hash)
            if receipt.session_id:
                pipe.sadd(f"receipt_session:{receipt.session_id}", receipt.receipt_id)
            if receipt.trace_id:
                pipe.sadd(f"receipt_trace:{receipt.trace_id}", receipt.receipt_id)

            await asyncio.to_thread(pipe.execute)
        except REDIS_RUNTIME_ERRORS as e:
            if self._fail_on_redis_error:
                raise
            logger.warning("Receipt Redis commit failed (best-effort): %s", e)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get(self, receipt_id: str) -> DecisionReceipt | None:
        return self._receipts.get(receipt_id)

    def get_by_session(self, session_id: str) -> list[DecisionReceipt]:
        ids = self._session_index.get(session_id, set())
        receipts = [self._receipts[rid] for rid in ids if rid in self._receipts]
        return sorted(receipts, key=lambda r: r.timestamp)

    def get_by_trace(self, trace_id: str) -> list[DecisionReceipt]:
        ids = self._trace_index.get(trace_id, set())
        receipts = [self._receipts[rid] for rid in ids if rid in self._receipts]
        return sorted(receipts, key=lambda r: r.timestamp)

    def get_by_tenant(self, tenant_id: str, limit: int = 100) -> list[DecisionReceipt]:
        matching = [r for r in self._receipts.values() if r.tenant_id == tenant_id]
        matching.sort(key=lambda r: r.timestamp, reverse=True)
        return matching[:limit]

    @property
    def count(self) -> int:
        return len(self._receipts)

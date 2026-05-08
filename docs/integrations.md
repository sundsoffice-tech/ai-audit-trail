# Integrations

Each integration lives in its own optional submodule and pulls in its own
optional dependencies. Importing `ai_audit.integrations` itself does **not**
load any optional package.

## FastAPI / Starlette

```python
from fastapi import FastAPI
from ai_audit import AuditConfig, init_audit_config, ReceiptStore
from ai_audit.integrations.fastapi import AuditMiddleware

init_audit_config(AuditConfig.from_env())
store = ReceiptStore()

app = FastAPI()
app.add_middleware(
    AuditMiddleware,
    store=store,
    tenant_id="acme",
    path_prefix="/v1/ai/",        # only audit AI endpoints
    capture_body=True,            # include request body in input hash
    max_body_bytes=64 * 1024,
    trace_header="x-trace-id",    # propagate from upstream
    session_header="x-session-id",
)
```

The middleware emits one `DecisionReceipt` per matched request, mapping HTTP
status codes to actions:

- `2xx` / `3xx` → `ALLOW`
- `4xx` / `5xx` → `REJECT`
- exception during `call_next` → `FAIL_RETRY`

Install: `pip install "ai-audit-trail[fastapi]"`

## LangChain

```python
from langchain_openai import ChatOpenAI
from ai_audit import AuditConfig, init_audit_config, ReceiptStore
from ai_audit.integrations.langchain import AuditCallbackHandler

init_audit_config(AuditConfig.from_env())
store = ReceiptStore()

handler = AuditCallbackHandler(store=store, tenant_id="acme")
llm = ChatOpenAI(callbacks=[handler])
```

One receipt per LLM call (`on_llm_start` / `on_llm_end` / `on_llm_error`).
Errors map to `FAIL_RETRY`.

Install: `pip install "ai-audit-trail[langchain]"`

## OpenAI SDK

```python
from ai_audit.integrations.openai import AuditedOpenAI

client = AuditedOpenAI(store=store, tenant_id="acme")
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

`finish_reason` maps to actions:

- `content_filter` → `REJECT`
- `length` → `ALLOW` + `truncated_by_length` reason code
- `stop` (and others) → `ALLOW`

For manual control over the receipt:

```python
from ai_audit.integrations.openai import emit_chat_completion_receipt

response = openai_client.chat.completions.create(...)
emit_chat_completion_receipt(
    store, tenant_id="acme", model="gpt-4o-mini",
    messages=messages, response=response,
)
```

Install: `pip install "ai-audit-trail[openai]"`

## Anthropic SDK

```python
from ai_audit.integrations.anthropic import AuditedAnthropic

client = AuditedAnthropic(store=store, tenant_id="acme")
response = client.messages.create(
    model="claude-opus-4-7",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

`stop_reason` maps to actions:

- `refusal` → `REJECT`
- `max_tokens` → `ALLOW` + `truncated_by_length` reason code
- `end_turn` (and others) → `ALLOW`

Install: `pip install "ai-audit-trail[anthropic]"`

## Build your own

Every integration is ~100 lines of glue using the same three primitives:

```python
from ai_audit import ReceiptCollector, ReceiptStore

collector = ReceiptCollector(trace_id=..., tenant_id=...)
collector.set_input(prompt_text)
collector.set_output(response_text)
collector.set_action("allow")
collector.emit(store)
collector.cleanup()
```

There is no framework coupling — `tenant_id`, `trace_id`, and `session_id`
are opaque strings to the protocol.

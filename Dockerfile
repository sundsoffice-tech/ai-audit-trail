FROM python:3.11-slim

LABEL org.opencontainers.image.source="https://github.com/sundsoffice-tech/ai-audit-trail"
LABEL org.opencontainers.image.description="ai-audit-trail MCP server — read-only verification tools for AI Decision Receipts"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir ".[mcp]"

ENTRYPOINT ["ai-audit-mcp"]

"""
Anthropic LLM adapter — two auth modes, one interface, chosen by whatever is set (OAuth
takes priority):

1) Claude subscription: `CLAUDE_CODE_OAUTH_TOKEN` -> `Authorization: Bearer` +
   `anthropic-beta` header (the same mechanism Claude Code itself uses). No
   `x-api-key` is sent in this mode.
2) API key: `ANTHROPIC_API_KEY` -> `x-api-key`.

Ported from dandelion's real, already-field-tested adapter — same two-mode logic, kept as
its own copy rather than a cross-import, synchronous instead of
async (matches `services/breadth_pass.py`'s sequential orchestration).

For most users the simpler path is `claude_cli_adapter.py` (shells out to the already
logged-in `claude` CLI — no token to obtain or configure at all). This adapter exists for
contexts where a raw `CLAUDE_CODE_OAUTH_TOKEN` is already provisioned some other way (e.g.
a server/fleet context with its own token-provisioning setup) and shelling out to
a CLI isn't the right shape.
"""
from __future__ import annotations

import os

import httpx

# in oauth mode Anthropic requires the Claude Code system prompt as the first block
_CLAUDE_CODE_SYSTEM = "You are Claude Code, Anthropic's official CLI for Claude."


class AnthropicLLM:
    def __init__(
        self,
        api_key: str | None = None,
        oauth_token: str | None = None,
        base_url: str = "https://api.anthropic.com/v1",
        version: str = "2023-06-01",
        timeout: float = 300.0,
    ) -> None:
        self.oauth_token = oauth_token or os.getenv("CLAUDE_CODE_OAUTH_TOKEN")
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not (self.oauth_token or self.api_key):
            raise ValueError("anthropic: set CLAUDE_CODE_OAUTH_TOKEN (subscription) or ANTHROPIC_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.version = version
        self.timeout = timeout
        self.last_usage: dict | None = None  # raw `usage` block from the last response

    @property
    def auth_mode(self) -> str:
        return "oauth" if self.oauth_token else "api_key"

    def _headers(self) -> dict[str, str]:
        h = {"anthropic-version": self.version, "content-type": "application/json"}
        if self.oauth_token:
            h["authorization"] = f"Bearer {self.oauth_token}"
            h["anthropic-beta"] = "oauth-2025-04-20"
        else:
            h["x-api-key"] = self.api_key or ""
        return h

    def complete(self, prompt: str, *, model: str) -> str:
        payload: dict = {
            "model": model,
            "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.auth_mode == "oauth":
            payload["system"] = _CLAUDE_CODE_SYSTEM  # required first block in this mode

        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.base_url}/messages", json=payload, headers=self._headers())
            r.raise_for_status()
            body = r.json()
        self.last_usage = body.get("usage")
        blocks = body.get("content", [])
        return "".join(b.get("text", "") for b in blocks if b.get("type") == "text")

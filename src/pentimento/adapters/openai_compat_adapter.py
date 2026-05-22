"""
OpenAI-compatible LLM adapter — one line to add a provider: DeepSeek, OpenAI, OpenRouter,
Groq, Together, xAI, Moonshot, a self-hosted vLLM server, or any other OpenAI-compatible
endpoint. Anthropic has its own adapter (a different protocol) — see `anthropic_adapter.py`.

Same `KNOWN_BASES` table as dandelion's sibling adapter — kept as its own copy, not
a cross-import, per this repo's own rule (integration with dandelion happens only through
the CDV contract, never a cross-import). Synchronous here (dandelion's is async) — matches
`services/breadth_pass.py`'s own sequential, synchronous orchestration; nothing in this
repo needs concurrent LLM calls yet.

The "vllm" entry exists for a planned self-hosted inference experiment
(head-to-head against the API backends above on recall/latency/$) — deliberately
just the LOGIC, not the infrastructure: standing up a real GPU (Modal/Together/Fireworks-
class serverless, or a rented box) is real external spend, a decision for a human to make
explicitly, not something this repo's own code should do or assume. Once that box exists,
`--llm vllm:<served-model-name> --base-url http://<host>:8000/v1` (vLLM's own default
OpenAI-compatible port/path) works with zero code changes — the whole point of building
this now rather than when the GPU is actually up.
"""
from __future__ import annotations

import os

import httpx

# provider name -> (base_url, key env variable — "" means no key required)
KNOWN_BASES: dict[str, tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "together": ("https://api.together.xyz/v1", "TOGETHER_API_KEY"),
    "xai": ("https://api.x.ai/v1", "XAI_API_KEY"),
    "moonshot": ("https://api.moonshot.ai/v1", "MOONSHOT_API_KEY"),
    # self-hosted vLLM's own OpenAI-compatible server default — see module docstring.
    # No API key required by default (vLLM only checks one if served with --api-key);
    # override with --base-url once the real host is known.
    "vllm": ("http://localhost:8000/v1", ""),
}

# providers where a missing API key means "not configured, use the server's default"
# (self-hosted, no billing/auth infrastructure by default) rather than a real error.
_NO_KEY_REQUIRED = {"vllm"}


class OpenAICompatLLM:
    """`provider` — a key from `KNOWN_BASES` (e.g. "deepseek", "vllm"), or arbitrary if
    `base_url` is given directly (any other local/self-hosted OpenAI-compatible server)."""

    def __init__(
        self,
        provider: str = "deepseek",
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 300.0,
    ) -> None:
        base, env = KNOWN_BASES.get(provider, (base_url, ""))
        resolved_base = base_url or base
        if not resolved_base:
            raise ValueError(f"unknown provider '{provider}' and no base_url given")
        self.base_url = resolved_base.rstrip("/")
        self.api_key = api_key or (os.getenv(env) if env else None)
        if not self.api_key:
            if provider in _NO_KEY_REQUIRED:
                self.api_key = "not-required"
            else:
                raise ValueError(f"no API key for provider '{provider}' — set {env or 'the right env var'}")
        self.timeout = timeout
        self.last_usage: dict | None = None  # raw `usage` block from the last response, if any

    def complete(self, prompt: str, *, model: str) -> str:
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.0}
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
            r.raise_for_status()
            body = r.json()
        self.last_usage = body.get("usage")
        return str(body["choices"][0]["message"]["content"])

"""
Port for the LLM call used by Phase 4's breadth-pass — kept to the smallest possible
contract (one text in, one text out) so `services/breadth_pass.py`'s orchestration logic
can be fully tested against a fake, without a real network call or API key.

The real adapter (calling a model gateway — `litellm_config.yaml`'s `pentimento-breadth`/
`pentimento-verdict` roles) is deliberately NOT built
yet. This repo's own standing rule — no stage is considered done on a feeling that "it
seems to work", only on a measurable criterion over a fixed set of cases — means
an adapter nobody has actually run against a real model can't honestly be called done —
shipping one now would be unverified code dressed up as verified. Wiring it is the next
step after this, gated on an explicit decision to spend real API budget.
"""
from __future__ import annotations

from typing import Protocol


class LLMPort(Protocol):
    def complete(self, prompt: str, *, model: str) -> str:
        """Send `prompt` to `model`, return its raw text response."""
        ...

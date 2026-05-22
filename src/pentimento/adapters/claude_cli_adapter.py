"""
Claude subscription adapter — implements `LLMPort` by shelling out to the Claude Code CLI
itself (`claude -p ...`) instead of calling the Anthropic API with a raw token.

Why this, not `anthropic_adapter.py`'s OAuth mode, as the DEFAULT subscription path: the
OAuth token lives in the OS keychain (confirmed present on this machine as
"Claude Code-credentials") and the `claude` binary already knows how to read, refresh, and
send it correctly (beta headers, the required Claude-Code system-prompt block) — this
adapter reuses that instead of re-extracting a secret out of the keychain ourselves. Any
user who already has Claude Code installed and is logged in can run a breadth-pass this
way with ZERO extra setup — no API key, no token to copy anywhere, no separate spend beyond
what their subscription already covers. That portability — everyone runs it on their own
subscription — is the actual point of this adapter, not just a convenience for this machine.

Confirmed working with a real call:
  claude -p "..." --model haiku --tools "" --output-format json --no-session-persistence
returns `{"result": "...", "total_cost_usd": ..., "is_error": false, ...}`.

`--tools ""` disables tool use entirely — a breadth-pass prompt already inlines the full
source, it should never need to read files or run shell commands on the caller's machine.
`--output-format json` surfaces `total_cost_usd` per call (`last_cost_usd` below) — the
same per-call spend visibility the Model Gateway config asks for, via a different
transport. `--no-session-persistence` keeps this a stateless one-shot call, not a resumable
chat session.
"""
from __future__ import annotations

import json
import shutil
import subprocess


class ClaudeCliLLM:
    def __init__(self, claude_bin: str | None = None, timeout: float = 300.0) -> None:
        resolved = claude_bin or shutil.which("claude")
        if not resolved:
            raise RuntimeError(
                "claude CLI not found on PATH — install Claude Code and log in once "
                "(this adapter reuses that existing subscription login, no API key needed)"
            )
        self.claude_bin = resolved
        self.timeout = timeout
        self.last_cost_usd: float | None = None  # set after each complete() call

    def complete(self, prompt: str, *, model: str) -> str:
        result = subprocess.run(
            [
                self.claude_bin,
                "-p",
                prompt,
                "--model",
                model,
                "--tools",
                "",
                "--output-format",
                "json",
                "--no-session-persistence",
            ],
            capture_output=True,
            text=True,
            timeout=self.timeout,
            check=True,
        )
        payload = json.loads(result.stdout)
        if payload.get("is_error"):
            raise RuntimeError(f"claude -p returned an error: {payload}")
        self.last_cost_usd = payload.get("total_cost_usd")
        return str(payload["result"])

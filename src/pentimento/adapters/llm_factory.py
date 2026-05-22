"""
LLM factory — build an `LLMPort` from a `provider:model` spec string. One call covers
every variant a user might have available:

  claude-cli:haiku          -> shells out to the logged-in `claude` CLI (subscription, no
                                API key at all — see claude_cli_adapter.py)
  anthropic:claude-sonnet-5 -> Anthropic API, CLAUDE_CODE_OAUTH_TOKEN (subscription) or
                                ANTHROPIC_API_KEY (API key), whichever is set
  deepseek:deepseek-chat    -> DeepSeek, DEEPSEEK_API_KEY
  openai:gpt-4o-mini        -> OpenAI, OPENAI_API_KEY
  <anything else>:model     -> treated as an OpenAI-compatible provider name (see
                                openai_compat_adapter.py's KNOWN_BASES) or, with base_url
                                given explicitly, any local/self-hosted endpoint

To the caller the result is always the same — an `LLMPort` with one `complete()` method.
This is what makes "run it on your own subscription" a one-flag choice (`--llm <spec>` on
`pentimento breadth-pass`) instead of a code change: whoever runs this tool picks the spec
that matches whatever they already have (a subscription, or any provider's API key).
"""
from __future__ import annotations

from pentimento.adapters.anthropic_adapter import AnthropicLLM
from pentimento.adapters.claude_cli_adapter import ClaudeCliLLM
from pentimento.adapters.openai_compat_adapter import OpenAICompatLLM
from pentimento.ports.llm import LLMPort

_ANTHROPIC = {"anthropic", "claude"}
_CLAUDE_CLI = {"claude-cli", "cli"}


def build_llm(
    spec: str, *, api_key: str | None = None, base_url: str | None = None, timeout: float | None = None
) -> LLMPort:
    """`spec` = `'provider:model'`. Auth is taken from the arguments or from env/keychain
    by whichever adapter gets selected — see the module docstring for the provider list.

    `timeout` is opt-in — every adapter already defaults to 300s on its own, this only
    overrides it when given. Added after a real run hit it: `claude-cli:sonnet`'s own
    deeper reasoning on a large real contract needed ~900s and the default silently killed the
    call with no CLI way to raise it; this closes that specific gap."""
    provider, _, model = spec.partition(":")
    provider = provider.lower().strip()
    model = model.strip()
    if not model:
        raise ValueError(f"'{spec}' is missing a model — expected 'provider:model', e.g. 'deepseek:deepseek-chat'")

    effective_timeout = timeout if timeout is not None else 300.0
    if provider in _CLAUDE_CLI:
        return ClaudeCliLLM(timeout=effective_timeout)
    if provider in _ANTHROPIC:
        return AnthropicLLM(
            api_key=api_key, base_url=base_url or "https://api.anthropic.com/v1", timeout=effective_timeout
        )
    return OpenAICompatLLM(provider=provider, api_key=api_key, base_url=base_url, timeout=effective_timeout)


def model_of(spec: str) -> str:
    """The model half of a 'provider:model' spec — what to pass as `model=` to `complete()`."""
    return spec.partition(":")[2].strip()

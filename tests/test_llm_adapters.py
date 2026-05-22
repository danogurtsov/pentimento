import json
import subprocess
from unittest.mock import MagicMock, patch

import httpx
import pytest

from pentimento.adapters.anthropic_adapter import AnthropicLLM
from pentimento.adapters.claude_cli_adapter import ClaudeCliLLM
from pentimento.adapters.llm_factory import build_llm, model_of
from pentimento.adapters.openai_compat_adapter import OpenAICompatLLM


# --------------------------------------------------------------------------- #
# OpenAICompatLLM (DeepSeek/OpenAI/...)
# --------------------------------------------------------------------------- #
def test_openai_compat_raises_without_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        OpenAICompatLLM(provider="deepseek")


def test_openai_compat_raises_for_unknown_provider_with_no_base_url() -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        OpenAICompatLLM(provider="totally-made-up", api_key="x")


def test_openai_compat_sends_bearer_auth_and_parses_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    llm = OpenAICompatLLM(provider="deepseek")

    fake_response = MagicMock()
    fake_response.json.return_value = {"choices": [{"message": {"content": "the answer"}}]}
    fake_response.raise_for_status.return_value = None

    with patch.object(httpx.Client, "post", return_value=fake_response) as mock_post:
        result = llm.complete("hello", model="deepseek-chat")

    assert result == "the answer"
    _, kwargs = mock_post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer sk-test"
    assert kwargs["json"]["model"] == "deepseek-chat"
    assert kwargs["json"]["messages"] == [{"role": "user", "content": "hello"}]


def test_openai_compat_vllm_needs_no_api_key() -> None:
    # self-hosted inference has no billing/auth infrastructure by default, must not raise
    # the way a real provider missing its key does.
    llm = OpenAICompatLLM(provider="vllm")
    assert llm.base_url == "http://localhost:8000/v1"
    assert llm.api_key == "not-required"


def test_openai_compat_base_url_overrides_the_known_default() -> None:
    llm = OpenAICompatLLM(provider="vllm", base_url="http://10.0.0.5:8000/v1")
    assert llm.base_url == "http://10.0.0.5:8000/v1"


# --------------------------------------------------------------------------- #
# AnthropicLLM (dual auth)
# --------------------------------------------------------------------------- #
def test_anthropic_raises_without_any_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_CODE_OAUTH_TOKEN", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="CLAUDE_CODE_OAUTH_TOKEN"):
        AnthropicLLM()


def test_anthropic_prefers_oauth_over_api_key_when_both_are_set() -> None:
    llm = AnthropicLLM(api_key="sk-ant-x", oauth_token="oauth-x")
    assert llm.auth_mode == "oauth"
    headers = llm._headers()
    assert headers["authorization"] == "Bearer oauth-x"
    assert "x-api-key" not in headers


def test_anthropic_api_key_mode_sends_x_api_key_not_bearer() -> None:
    llm = AnthropicLLM(api_key="sk-ant-x")
    assert llm.auth_mode == "api_key"
    headers = llm._headers()
    assert headers["x-api-key"] == "sk-ant-x"
    assert "authorization" not in headers


def test_anthropic_oauth_mode_injects_the_required_system_block() -> None:
    llm = AnthropicLLM(oauth_token="oauth-x")

    fake_response = MagicMock()
    fake_response.json.return_value = {"content": [{"type": "text", "text": "hi"}]}
    fake_response.raise_for_status.return_value = None

    with patch.object(httpx.Client, "post", return_value=fake_response) as mock_post:
        result = llm.complete("do the thing", model="claude-sonnet-5")

    assert result == "hi"
    _, kwargs = mock_post.call_args
    assert "Claude Code" in kwargs["json"]["system"]


# --------------------------------------------------------------------------- #
# ClaudeCliLLM (subscription via the `claude` binary)
# --------------------------------------------------------------------------- #
def test_claude_cli_raises_when_binary_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _: None)
    with pytest.raises(RuntimeError, match="claude CLI not found"):
        ClaudeCliLLM()


def test_claude_cli_parses_the_result_field_and_records_cost() -> None:
    fake_stdout = json.dumps({"result": "PONG", "is_error": False, "total_cost_usd": 0.03})
    fake_proc = MagicMock(stdout=fake_stdout)

    with patch("shutil.which", return_value="/usr/local/bin/claude"), patch(
        "subprocess.run", return_value=fake_proc
    ) as mock_run:
        llm = ClaudeCliLLM()
        result = llm.complete("ping", model="haiku")

    assert result == "PONG"
    assert llm.last_cost_usd == 0.03
    args = mock_run.call_args[0][0]
    assert args[:3] == ["/usr/local/bin/claude", "-p", "ping"]
    assert "--model" in args and "haiku" in args
    assert "--tools" in args


def test_claude_cli_raises_on_an_error_result() -> None:
    fake_stdout = json.dumps({"is_error": True, "result": None})
    fake_proc = MagicMock(stdout=fake_stdout)

    with patch("shutil.which", return_value="/usr/local/bin/claude"), patch(
        "subprocess.run", return_value=fake_proc
    ):
        llm = ClaudeCliLLM()
        with pytest.raises(RuntimeError, match="returned an error"):
            llm.complete("ping", model="haiku")


def test_claude_cli_propagates_a_real_subprocess_failure() -> None:
    with patch("shutil.which", return_value="/usr/local/bin/claude"), patch(
        "subprocess.run", side_effect=subprocess.CalledProcessError(1, "claude")
    ):
        llm = ClaudeCliLLM()
        with pytest.raises(subprocess.CalledProcessError):
            llm.complete("ping", model="haiku")


# --------------------------------------------------------------------------- #
# build_llm / model_of
# --------------------------------------------------------------------------- #
def test_build_llm_selects_claude_cli() -> None:
    with patch("shutil.which", return_value="/usr/local/bin/claude"):
        llm = build_llm("claude-cli:haiku")
    assert isinstance(llm, ClaudeCliLLM)


def test_build_llm_selects_anthropic() -> None:
    llm = build_llm("anthropic:claude-sonnet-5", api_key="sk-ant-x")
    assert isinstance(llm, AnthropicLLM)


def test_build_llm_selects_openai_compat_for_deepseek(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    llm = build_llm("deepseek:deepseek-chat")
    assert isinstance(llm, OpenAICompatLLM)
    assert llm.base_url == "https://api.deepseek.com/v1"


def test_build_llm_selects_vllm_with_a_custom_base_url() -> None:
    llm = build_llm("vllm:my-served-model", base_url="http://10.0.0.5:8000/v1")
    assert isinstance(llm, OpenAICompatLLM)
    assert llm.base_url == "http://10.0.0.5:8000/v1"
    assert llm.api_key == "not-required"


def test_build_llm_rejects_a_spec_with_no_model() -> None:
    with pytest.raises(ValueError, match="missing a model"):
        build_llm("deepseek")


def test_build_llm_defaults_the_timeout_to_300_seconds() -> None:
    with patch("shutil.which", return_value="/usr/local/bin/claude"):
        llm = build_llm("claude-cli:haiku")
    assert llm.timeout == 300.0


def test_build_llm_passes_through_a_custom_timeout() -> None:
    # a real gap: claude-cli:sonnet needed ~900s on a large real contract and the CLI had
    # no way to raise the default - this closes it.
    with patch("shutil.which", return_value="/usr/local/bin/claude"):
        llm = build_llm("claude-cli:sonnet", timeout=900.0)
    assert llm.timeout == 900.0


def test_model_of_extracts_the_model_half() -> None:
    assert model_of("deepseek:deepseek-chat") == "deepseek-chat"
    assert model_of("claude-cli:haiku") == "haiku"

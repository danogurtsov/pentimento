import subprocess
from pathlib import Path

from pentimento.adapters.foundry_adapter import ForgeAdapter, _sanitized_subprocess_env


def test_strips_every_known_llm_provider_secret(monkeypatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-secret")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-real-secret")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-real-secret")
    monkeypatch.setenv("OPENAI_API_KEY", "oai-real-secret")

    env = _sanitized_subprocess_env()

    assert "ANTHROPIC_API_KEY" not in env
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env
    assert "DEEPSEEK_API_KEY" not in env
    assert "OPENAI_API_KEY" not in env


def test_keeps_ordinary_environment_variables_needed_for_forge_to_run(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/whoever")

    env = _sanitized_subprocess_env()

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/whoever"


def test_no_secrets_present_is_a_no_op_not_an_error(monkeypatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)

    env = _sanitized_subprocess_env()

    assert "ANTHROPIC_API_KEY" not in env
    assert "DEEPSEEK_API_KEY" not in env


def test_run_test_invokes_subprocess_with_a_sanitized_env_not_the_raw_environ(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-secret")
    captured: dict = {}

    class FakeCompleted:
        returncode = 0
        stdout = "[PASS] testExploit()"
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return FakeCompleted()

    monkeypatch.setattr(subprocess, "run", fake_run)
    test_file = tmp_path / "test" / "Poc.t.sol"
    test_file.parent.mkdir()
    test_file.write_text("contract Poc {}")

    ForgeAdapter().run_test(test_file, tmp_path)

    assert "env" in captured
    assert "ANTHROPIC_API_KEY" not in captured["env"]

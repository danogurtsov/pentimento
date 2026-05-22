"""
Real adapter for `ports.poc_executor.PoCExecutorPort` — shells out to a local `forge`
binary. No network calls, no fork: this project's own generated PoC tests are explicitly
instructed (`detection/prompts.build_poc_test_prompt`) to run entirely against locally
deployed contracts in Foundry's own sandboxed EVM, never `vm.createFork(...)` — this adapter
doesn't need to and doesn't pass any RPC configuration.

This subprocess runs the TARGET project's own `forge test` — untrusted, possibly
adversarial code (see `detection/ffi_check.py`'s own docstring on the real `ffi=true` case
already found in this project's own corpus). `subprocess.run` inherits the FULL parent
environment when `env=` is omitted — a real gap, not a hypothetical one, since pentimento's
own process env can carry `ANTHROPIC_API_KEY`/`DEEPSEEK_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN`/
etc. `_sanitized_subprocess_env` strips every LLM-provider secret this project's own
adapters use (derived from `openai_compat_adapter.KNOWN_BASES`, a single source of truth —
a newly added provider is covered automatically) before the target's own code ever gets to
run, whether or not `ffi` is enabled — defense in depth alongside `services/
poc_verification.py`'s own hard refusal on a confirmed `ffi=true` project.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from pentimento.adapters.openai_compat_adapter import KNOWN_BASES
from pentimento.ports.poc_executor import ForgeRunResult

_ADDITIONAL_SECRET_ENV_VARS = ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN")


def _sanitized_subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    secret_vars = {v for _, v in KNOWN_BASES.values() if v} | set(_ADDITIONAL_SECRET_ENV_VARS)
    for var in secret_vars:
        env.pop(var, None)
    return env


class ForgeNotFoundError(RuntimeError):
    pass


class ForgeAdapter:
    def __init__(self, forge_path: str = "forge", timeout_seconds: float = 300.0) -> None:
        self.forge_path = forge_path
        self.timeout_seconds = timeout_seconds

    def run_test(self, test_file: Path, project_root: Path) -> ForgeRunResult:
        relative_path = test_file.relative_to(project_root)
        try:
            result = subprocess.run(  # noqa: S603
                [self.forge_path, "test", "--match-path", str(relative_path)],
                cwd=project_root,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                env=_sanitized_subprocess_env(),
            )
        except FileNotFoundError as e:
            raise ForgeNotFoundError(f"forge binary not found at {self.forge_path!r}") from e

        return ForgeRunResult(exit_code=result.returncode, output=f"{result.stdout}\n{result.stderr}")

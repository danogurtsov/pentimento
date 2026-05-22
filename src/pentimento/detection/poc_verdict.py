"""
Level 1 deterministic PoC oracle — Phase 6's strongest verification tier: a differential
fork-PoC, where the model does NOT decide whether the check passed — code does. Pure
text/regex parsing of `forge test`'s own raw output, no LLM, no I/O itself — same
"port returns raw, a pure function here decides" split as `detection/routing.py`/
`detection/verdict.py` already use for their own LLM-facing parsers.

**Current scope**: only the FIRST half of "differential" fork-PoC is built — does the
exploit reproduce against the REAL, currently-vulnerable source, confirmed by actual
`forge test` execution (not an LLM's own claim that it would)? The SECOND half (auto-apply
the finding's proposed fix to a clean copy, re-run, confirm the same test now FAILS) needs
real patch-generation and a second full compile cycle — a genuinely separate, larger
feature. This is still real, code-decided evidence for the "exploit reproduces" half of the
claim — the half `verdict.py`'s Gate 4 (`poc_validation`) has NO independent check for at
all otherwise, only the model's own self-report.
"""
from __future__ import annotations

import re
from enum import StrEnum


class PoCOutcome(StrEnum):
    REPRODUCED = "reproduced"  # compiled AND passed - exploit confirmed by real execution
    NOT_REPRODUCED = "not_reproduced"  # compiled but failed/reverted - claim not reproduced
    COMPILE_ERROR = "compile_error"  # never ran at all - inconclusive, not evidence either way
    REFUSED_UNTRUSTED_FFI = "refused_untrusted_ffi"  # target's own foundry.toml has ffi=true -
    # never even attempted, forge test was never invoked (see detection/ffi_check.py)


# forge's own error vocabulary for a build that never reached test execution at all -
# checked BEFORE exit-code interpretation, since a compile failure and a real test failure
# both produce a nonzero exit code and must not be conflated.
_COMPILE_ERROR_MARKERS = (
    "Compiler run failed",
    "ParserError",
    "DeclarationError",
    "TypeError:",
    "error[",
)


def parse_forge_output(exit_code: int, output: str) -> PoCOutcome:
    if any(marker in output for marker in _COMPILE_ERROR_MARKERS):
        return PoCOutcome.COMPILE_ERROR
    return PoCOutcome.REPRODUCED if exit_code == 0 else PoCOutcome.NOT_REPRODUCED


_SOLIDITY_BLOCK_RE = re.compile(r"```solidity\s*\n(.*?)```", re.DOTALL)


def extract_solidity_block(raw_response: str) -> str | None:
    """The single ```solidity fenced block `detection/prompts.build_poc_test_prompt`
    instructs the model to respond with — `None` if the model didn't follow that format
    (a real possibility with a small/cheap model, recorded honestly by the caller rather
    than guessed at)."""
    match = _SOLIDITY_BLOCK_RE.search(raw_response)
    return match.group(1).strip() if match else None

"""
Phase 6 orchestration: the Level 1 deterministic PoC oracle. One LLM call generates an
executable Foundry test for a finding a prior verification pass already rated
TRUE_POSITIVE; a real `forge test` execution then decides the outcome
(`detection/poc_verdict.py`'s `parse_forge_output`) — the model never gets to assert
"reproduced" itself. See that module's own docstring for the scope of this slice.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pentimento.detection.ffi_check import foundry_toml_has_ffi
from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome, extract_solidity_block, parse_forge_output
from pentimento.detection.prompts import build_poc_test_prompt
from pentimento.detection.verdict import FindingVerdict, Verdict
from pentimento.domain.models import CDVUnit
from pentimento.ports.llm import LLMPort
from pentimento.ports.poc_executor import PoCExecutorPort


@dataclass(frozen=True)
class PoCVerificationResult:
    finding_id: str
    outcome: PoCOutcome
    test_source: str | None
    forge_output: str | None


def _sanitized_contract_name(finding_id: str) -> str:
    return f"PentimentoPoC_{finding_id.replace('-', '')}"


def _test_file_name(finding_id: str) -> str:
    return f"_pentimento_poc_{finding_id.replace('-', '').lower()}.t.sol"


def find_existing_test_reference(unit: CDVUnit, project_root: Path, test_dir: str = "test") -> str | None:
    """Best-effort: the first existing test file (under `project_root/test_dir`) that
    already references this unit's own contract name — grounding for `build_poc_test_
    prompt` so it can reuse a real, already-working `setUp()` instead of the model
    inventing constructor wiring from scratch. Returns None (not an error) when there's no
    test directory or no match — an honest limitation for projects with no test suite of
    their own to borrow from, not silently papered over."""
    test_root = project_root / test_dir
    if not test_root.is_dir():
        return None
    needle = unit.contract_name
    for path in sorted(test_root.rglob("*.sol")):
        if needle in path.read_text():
            return path.read_text()
    return None


def run_poc_verification(
    finding: Finding,
    finding_verdict: FindingVerdict,
    unit: CDVUnit,
    project_root: Path,
    llm: LLMPort,
    model: str,
    executor: PoCExecutorPort,
    test_dir: str = "test",
    allow_ffi: bool = False,
) -> PoCVerificationResult | None:
    """Only runs for a TRUE_POSITIVE verdict — no point spending a compile+execute cycle on
    a claim the Standard-path gate review already rejected. Returns None otherwise, so
    callers can filter without a separate check. A model response that never produces a
    parseable ```solidity block (`extract_solidity_block` returns None) is recorded as
    COMPILE_ERROR too — it never reached `forge test` either way, same "inconclusive, not
    evidence" bucket as a real solc compile failure (see `poc_verdict.py`).

    `allow_ffi` (default False, a real security default, not a convenience default): if the
    target project's own `foundry.toml` enables the `ffi` cheatcode under any profile
    (`detection/ffi_check.py` — real, not hypothetical: `_external/
    scabench-minimal-delegation` already has this set), `forge test` could execute arbitrary
    shell commands during this exact phase. Refused BEFORE the LLM call (no point spending
    on a PoC that will never run) with a distinct `REFUSED_UNTRUSTED_FFI` outcome — never
    silently downgraded into COMPILE_ERROR or skipped without a trace."""
    if finding_verdict.verdict != Verdict.TRUE_POSITIVE:
        return None

    if not allow_ffi and foundry_toml_has_ffi(project_root):
        note = (
            "Refused: this project's own foundry.toml enables the `ffi` cheatcode, which "
            "lets `forge test` execute arbitrary shell commands — running the PoC oracle "
            "here without an explicit override would let untrusted target code run "
            "commands on this machine. Pass allow_ffi=True (CLI: --allow-ffi) only if you "
            "trust this specific project's own test suite."
        )
        return PoCVerificationResult(finding.id, PoCOutcome.REFUSED_UNTRUSTED_FFI, None, note)

    contract_name = _sanitized_contract_name(finding.id)
    source_code = "\n\n".join((project_root / f).read_text() for f in unit.source_files)
    reference = find_existing_test_reference(unit, project_root, test_dir)
    prompt = build_poc_test_prompt(finding, unit, source_code, contract_name, reference)
    raw = llm.complete(prompt, model=model)
    test_source = extract_solidity_block(raw)

    if test_source is None:
        # Real failure mode found on a live run against EulerEarn: the raw
        # response was silently discarded here, leaving a totally undiagnosable
        # COMPILE_ERROR with no trace of what the model actually said. Keeping the raw
        # response in `forge_output` (it never reached forge, but this is the only place
        # left to preserve it) turns a black box into something a human can actually read.
        note = f"[no ```solidity block found — never reached forge] Raw response:\n{raw}"
        return PoCVerificationResult(finding.id, PoCOutcome.COMPILE_ERROR, None, note)

    test_file = project_root / test_dir / _test_file_name(finding.id)
    test_file.write_text(test_source)
    try:
        run_result = executor.run_test(test_file, project_root)
    finally:
        test_file.unlink(missing_ok=True)

    outcome = parse_forge_output(run_result.exit_code, run_result.output)
    return PoCVerificationResult(finding.id, outcome, test_source, run_result.output)

from pathlib import Path

from pentimento.detection.findings import Finding
from pentimento.detection.verdict import Verdict, VerificationRoute
from pentimento.domain.models import CDVUnit, NodeType
from pentimento.services.verification import run_verification, run_verification_pass

# a 2-distinct-.sol-file location deterministically routes to DEEP
# (detection/verdict.py::decide_verification_route) - the least ambiguous way to force it.
_CROSS_CONTRACT_LOCATION = "VaultA.sol#L10, VaultB.sol#L20"


class FakeLLM:
    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or ["GATE process: PASS — ok"]
        self.calls: list[tuple[str, str]] = []

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls.append((prompt, model))
        return self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]


_ALL_PASS = "\n".join(
    [
        "GATE process: PASS — every step documented",
        "GATE reachability: PASS — attacker controls the input",
        "GATE real_impact: PASS — funds can be drained",
        "GATE poc_validation: PASS — pseudocode shows the drain",
        "GATE math_bounds: PASS — not a bounds claim, N/A",
        "GATE environment: PASS — no reentrancy guard present",
    ]
)


def _finding(**overrides) -> Finding:
    defaults = dict(
        id="F-1",
        title="Reentrancy in withdraw()",
        severity="Critical",
        confidence=90,
        location="Vault.sol#L40, withdraw()",
        root_cause="State is written after the external call, allowing reentrant withdrawal.",
        exploit="Deposit, call withdraw, reenter from the token callback before state updates.",
        impact="Attacker drains the vault.",
        fix="Move the state write before the external call.",
        poc=None,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_run_verification_sends_the_units_source_and_returns_a_true_positive(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM([_ALL_PASS])

    result = run_verification(_finding(), unit, tmp_path, llm, "verifier-model")

    assert llm.calls[0][1] == "verifier-model"
    assert "contract Vault { function withdraw() external {} }" in llm.calls[0][0]
    assert result.finding_id == "F-1"
    assert result.route == VerificationRoute.STANDARD
    assert result.bug_class == "reentrancy"
    assert result.verdict == Verdict.TRUE_POSITIVE
    assert len(result.gate_results) == 6


def test_run_verification_returns_false_positive_when_a_gate_fails(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    raw = _ALL_PASS.replace(
        "GATE reachability: PASS — attacker controls the input",
        "GATE reachability: FAIL — caller already validates this",
    )
    llm = FakeLLM([raw])

    result = run_verification(_finding(), unit, tmp_path, llm, "verifier-model")

    assert result.verdict == Verdict.FALSE_POSITIVE


def test_run_verification_pass_verifies_every_finding_independently(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM([_ALL_PASS, _ALL_PASS])
    findings = [_finding(id="F-1"), _finding(id="F-2", title="Second bug")]

    results = run_verification_pass(findings, unit, tmp_path, llm, "verifier-model")

    assert [r.finding_id for r in results] == ["F-1", "F-2"]
    assert len(llm.calls) == 2


# --------------------------------------------------------------------------- #
# second, independent verifier (multi-model jury, opt-in)
# --------------------------------------------------------------------------- #
def test_no_second_verifier_by_default_no_extra_call_no_secondary_gates(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM([_ALL_PASS])

    result = run_verification(_finding(), unit, tmp_path, llm, "verifier-model")

    assert result.secondary_gate_results is None
    assert result.verdict == Verdict.TRUE_POSITIVE
    assert len(llm.calls) == 1


def test_second_verifier_agreeing_confirms_true_positive(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    primary_llm = FakeLLM([_ALL_PASS])
    second_llm = FakeLLM([_ALL_PASS])

    result = run_verification(
        _finding(), unit, tmp_path, primary_llm, "verifier-model", second_llm, "second-verifier-model"
    )

    assert result.verdict == Verdict.TRUE_POSITIVE
    assert result.secondary_gate_results is not None
    assert len(second_llm.calls) == 1
    assert second_llm.calls[0][1] == "second-verifier-model"
    # both verifiers get the EXACT SAME prompt - genuinely independent, no shared state
    assert primary_llm.calls[0][0] == second_llm.calls[0][0]


def test_second_verifier_dissenting_flips_true_positive_to_false_positive(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    dissenting_raw = _ALL_PASS.replace(
        "GATE reachability: PASS — attacker controls the input",
        "GATE reachability: FAIL — second verifier finds this unreachable",
    )
    primary_llm = FakeLLM([_ALL_PASS])  # says TRUE_POSITIVE alone
    second_llm = FakeLLM([dissenting_raw])  # disagrees

    result = run_verification(
        _finding(), unit, tmp_path, primary_llm, "verifier-model", second_llm, "second-verifier-model"
    )

    assert result.verdict == Verdict.FALSE_POSITIVE
    # the primary's own gate results are preserved verbatim, not overwritten by the dissent
    assert all(g.passed for g in result.gate_results)
    assert result.secondary_gate_results is not None
    assert not all(g.passed for g in result.secondary_gate_results)


# --------------------------------------------------------------------------- #
# Phase 6 Deep path — actually executed, not just routed-and-recorded
# --------------------------------------------------------------------------- #
def test_a_cross_contract_finding_routes_to_deep_and_makes_4_calls_not_1(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM(["dataflow report text", "exploitability report text", "poc report text", _ALL_PASS])

    result = run_verification(_finding(location=_CROSS_CONTRACT_LOCATION), unit, tmp_path, llm, "verifier-model")

    assert result.route == VerificationRoute.DEEP
    assert len(llm.calls) == 4
    assert result.verdict == Verdict.TRUE_POSITIVE  # decided from the 4th (final) call only
    assert all(g.passed for g in result.gate_results)


def test_deep_path_feeds_each_phase_report_forward_into_the_next_prompt(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM(["DATAFLOW_MARKER_XYZ", "EXPLOITABILITY_MARKER_ABC", "POC_MARKER_123", _ALL_PASS])

    run_verification(_finding(location=_CROSS_CONTRACT_LOCATION), unit, tmp_path, llm, "verifier-model")

    dataflow_prompt, exploitability_prompt, poc_prompt, gate_prompt = (c[0] for c in llm.calls)
    assert "DATAFLOW_MARKER_XYZ" not in dataflow_prompt  # phase 1 has no prior phase to receive
    assert "DATAFLOW_MARKER_XYZ" in exploitability_prompt  # phase 2 receives phase 1's own output
    assert "DATAFLOW_MARKER_XYZ" in poc_prompt and "EXPLOITABILITY_MARKER_ABC" in poc_prompt
    assert all(m in gate_prompt for m in ("DATAFLOW_MARKER_XYZ", "EXPLOITABILITY_MARKER_ABC", "POC_MARKER_123"))


def test_deep_path_records_the_3_phase_reports_on_the_verdict(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM(["dataflow report", "exploitability report", "poc report", _ALL_PASS])

    result = run_verification(_finding(location=_CROSS_CONTRACT_LOCATION), unit, tmp_path, llm, "verifier-model")

    assert result.deep_phase_reports == {
        "dataflow": "dataflow report",
        "exploitability": "exploitability report",
        "poc": "poc report",
    }


def test_standard_path_verdict_has_no_phase_reports(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM([_ALL_PASS])

    result = run_verification(_finding(), unit, tmp_path, llm, "verifier-model")

    assert result.route == VerificationRoute.STANDARD
    assert result.deep_phase_reports is None
    assert len(llm.calls) == 1


def test_deep_path_combined_with_a_second_verifier_makes_8_calls_total(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    primary = FakeLLM(["d1", "e1", "p1", _ALL_PASS])
    second = FakeLLM(["d2", "e2", "p2", _ALL_PASS])

    result = run_verification(
        _finding(location=_CROSS_CONTRACT_LOCATION), unit, tmp_path, primary, "verifier-model", second, "second-model"
    )

    assert len(primary.calls) == 4
    assert len(second.calls) == 4
    assert result.verdict == Verdict.TRUE_POSITIVE  # both independently agreed
    assert result.deep_phase_reports == {"dataflow": "d1", "exploitability": "e1", "poc": "p1"}  # primary's own


def test_deep_path_second_verifier_dissent_still_flips_to_false_positive(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    dissenting = _ALL_PASS.replace(
        "GATE reachability: PASS — attacker controls the input",
        "GATE reachability: FAIL — deep second verifier finds this unreachable",
    )
    primary = FakeLLM(["d1", "e1", "p1", _ALL_PASS])
    second = FakeLLM(["d2", "e2", "p2", dissenting])

    result = run_verification(
        _finding(location=_CROSS_CONTRACT_LOCATION), unit, tmp_path, primary, "verifier-model", second, "second-model"
    )

    assert result.verdict == Verdict.FALSE_POSITIVE


# --------------------------------------------------------------------------- #
# Deep-path model escalation: a cheap model can produce substantial Deep phase reports
# but never emit a parseable GATE line on the final call
# --------------------------------------------------------------------------- #
def test_deep_path_uses_the_strong_model_instead_of_the_base_one_when_given(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    base_llm = FakeLLM(["should never be used"])
    strong_llm = FakeLLM(["d1", "e1", "p1", _ALL_PASS])

    result = run_verification(
        _finding(location=_CROSS_CONTRACT_LOCATION),
        unit,
        tmp_path,
        base_llm,
        "cheap-model",
        strong_llm=strong_llm,
        strong_model="strong-model",
    )

    assert base_llm.calls == []  # the cheap model is never called at all on the Deep route
    assert len(strong_llm.calls) == 4
    assert all(call[1] == "strong-model" for call in strong_llm.calls)
    assert result.verdict == Verdict.TRUE_POSITIVE


def test_standard_path_never_escalates_even_with_a_strong_model_available(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    base_llm = FakeLLM([_ALL_PASS])
    strong_llm = FakeLLM(["should never be used"])

    run_verification(
        _finding(), unit, tmp_path, base_llm, "cheap-model", strong_llm=strong_llm, strong_model="strong-model"
    )

    assert len(base_llm.calls) == 1
    assert strong_llm.calls == []  # Standard is already the "easy" path - never escalates

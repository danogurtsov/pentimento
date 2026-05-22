from pathlib import Path

from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.verdict import FindingVerdict, Gate, GateResult, RestatedClaim, Verdict, VerificationRoute
from pentimento.domain.models import CDVUnit, NodeType
from pentimento.ports.poc_executor import ForgeRunResult
from pentimento.services.poc_verification import find_existing_test_reference, run_poc_verification


class FakeLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls.append((prompt, model))
        return self.response


class FakeExecutor:
    def __init__(self, result: ForgeRunResult) -> None:
        self.result = result
        self.calls: list[tuple[Path, Path]] = []

    def run_test(self, test_file: Path, project_root: Path) -> ForgeRunResult:
        self.calls.append((test_file, project_root))
        assert test_file.exists()  # the service must have written it before calling the executor
        return self.result


def _finding() -> Finding:
    return Finding(
        id="F-1",
        title="Reentrancy in withdraw()",
        severity="Critical",
        confidence=90,
        location="Vault.sol#L40, withdraw()",
        root_cause="State is written after the external call.",
        exploit="Deposit, call withdraw, reenter from the token callback.",
        impact="Attacker drains the vault.",
        fix="Move the state write before the external call.",
        poc=None,
    )


def _true_positive_verdict() -> FindingVerdict:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    gates = tuple(GateResult(g, True, "ok") for g in Gate)
    return FindingVerdict("F-1", VerificationRoute.STANDARD, "reentrancy", claim, gates, Verdict.TRUE_POSITIVE)


def _false_positive_verdict() -> FindingVerdict:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    gates = tuple(
        GateResult(g, g != Gate.REACHABILITY, "n/a" if g != Gate.REACHABILITY else "unreachable") for g in Gate
    )
    return FindingVerdict("F-1", VerificationRoute.STANDARD, "reentrancy", claim, gates, Verdict.FALSE_POSITIVE)


def test_skips_a_false_positive_finding_no_llm_call_no_forge_run(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM("```solidity\ncontract X {}\n```")
    executor = FakeExecutor(ForgeRunResult(0, "should never run"))

    result = run_poc_verification(_finding(), _false_positive_verdict(), unit, tmp_path, llm, "poc-model", executor)

    assert result is None
    assert llm.calls == []
    assert executor.calls == []


def test_true_positive_writes_the_test_runs_it_and_cleans_up(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
    (tmp_path / "test").mkdir()
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    generated_test = "// SPDX-License-Identifier: MIT\ncontract PentimentoPoC_F1 {}"
    llm = FakeLLM(f"```solidity\n{generated_test}\n```")
    executor = FakeExecutor(ForgeRunResult(0, "Ran 1 test\n[PASS] testExploit()"))

    result = run_poc_verification(_finding(), _true_positive_verdict(), unit, tmp_path, llm, "poc-model", executor)

    assert result is not None
    assert result.outcome == PoCOutcome.REPRODUCED
    assert result.test_source == generated_test
    assert len(executor.calls) == 1
    # cleaned up afterward - the scratch file must not linger in the real project tree
    assert not (tmp_path / "test" / "_pentimento_poc_f1.t.sol").exists()


def test_a_model_response_with_no_parseable_code_block_is_recorded_as_compile_error(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM("I'm not able to write this test.")
    executor = FakeExecutor(ForgeRunResult(0, "should never run"))

    result = run_poc_verification(_finding(), _true_positive_verdict(), unit, tmp_path, llm, "poc-model", executor)

    assert result is not None
    assert result.outcome == PoCOutcome.COMPILE_ERROR
    assert executor.calls == []  # never even tried to run forge
    # a real bug: the raw response used to be discarded here, leaving a totally
    # undiagnosable failure - it must be preserved for a human to actually read why the
    # model didn't produce a parseable test.
    assert result.forge_output is not None
    assert "I'm not able to write this test." in result.forge_output


def test_refuses_an_ffi_enabled_project_before_any_llm_call(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    (tmp_path / "foundry.toml").write_text("[profile.default]\nffi = true\n")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    llm = FakeLLM("```solidity\ncontract X {}\n```")
    executor = FakeExecutor(ForgeRunResult(0, "should never run"))

    result = run_poc_verification(_finding(), _true_positive_verdict(), unit, tmp_path, llm, "poc-model", executor)

    assert result is not None
    assert result.outcome == PoCOutcome.REFUSED_UNTRUSTED_FFI
    assert llm.calls == []  # refused before spending on the PoC-generation call
    assert executor.calls == []


def test_allow_ffi_true_lets_an_ffi_enabled_project_run_anyway(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
    (tmp_path / "test").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\nffi = true\n")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])
    generated_test = "// SPDX-License-Identifier: MIT\ncontract PentimentoPoC_F1 {}"
    llm = FakeLLM(f"```solidity\n{generated_test}\n```")
    executor = FakeExecutor(ForgeRunResult(0, "Ran 1 test\n[PASS] testExploit()"))

    result = run_poc_verification(
        _finding(), _true_positive_verdict(), unit, tmp_path, llm, "poc-model", executor, allow_ffi=True
    )

    assert result is not None
    assert result.outcome == PoCOutcome.REPRODUCED
    assert len(executor.calls) == 1


def test_find_existing_test_reference_matches_by_contract_name(tmp_path: Path) -> None:
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "VaultTest.sol").write_text("contract VaultTest is BaseTest { function setUp() public {} }")
    unit = CDVUnit(unit_id="Vault", contract_name="Vault")

    reference = find_existing_test_reference(unit, tmp_path)

    assert reference is not None
    assert "VaultTest" in reference


def test_find_existing_test_reference_returns_none_without_a_test_dir(tmp_path: Path) -> None:
    unit = CDVUnit(unit_id="Vault", contract_name="Vault")
    assert find_existing_test_reference(unit, tmp_path) is None

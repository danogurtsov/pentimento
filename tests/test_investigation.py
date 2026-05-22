from pathlib import Path

from pentimento.detection.guard_analysis import GuardAnomaly
from pentimento.detection.state_invariants import StateSyncAnomaly
from pentimento.detection.verdict import Gate
from pentimento.domain.models import CDVGraph, CDVUnit, NodeType
from pentimento.ports.poc_executor import ForgeRunResult
from pentimento.services.breadth_pass import BreadthPassResult
from pentimento.services.investigation import (
    InvestigationGraph,
    UnitRecord,
    UnitStatus,
    decide_escalation,
    run_investigation,
)


class FakeLLM:
    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = responses or ["no findings"]
        self.calls: list[tuple[str, str]] = []

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls.append((prompt, model))
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        return response


def _guard(severity: str) -> GuardAnomaly:
    return GuardAnomaly(
        state_variable="balance",
        guard="whenNotPaused",
        guard_frequency=0.8,
        invariant_strength="strong",
        violating_function="emergencyWithdraw",
        severity=severity,
    )


def _sync(severity: str) -> StateSyncAnomaly:
    return StateSyncAnomaly(
        variable_a="available",
        variable_b="locked",
        relationship="conservation",
        comod_frequency=0.8,
        violating_function="forceUnlock",
        missing_variable="available",
        severity=severity,
    )


# --------------------------------------------------------------------------- #
# decide_escalation
# --------------------------------------------------------------------------- #
def test_escalates_on_a_critical_pre_flagged_guard_anomaly() -> None:
    result = BreadthPassResult("Vault", "prompt", "no findings", guard_anomalies=[_guard("critical")])
    reason = decide_escalation(result)
    assert reason is not None
    assert "1 pre-flagged critical/high anomaly" in reason


def test_does_not_escalate_on_a_medium_pre_flagged_anomaly() -> None:
    result = BreadthPassResult("Vault", "prompt", "no findings", guard_anomalies=[_guard("medium")])
    assert decide_escalation(result) is None


def test_escalates_on_a_high_pre_flagged_state_sync_anomaly() -> None:
    result = BreadthPassResult("Treasury", "prompt", "no findings", state_sync_anomalies=[_sync("high")])
    reason = decide_escalation(result)
    assert reason is not None and "1 pre-flagged" in reason


def test_escalates_when_the_scout_response_itself_reports_a_high_finding() -> None:
    result = BreadthPassResult("Vault", "prompt", "### [F-1] Title\nSeverity: High | Confidence: 80%")
    reason = decide_escalation(result)
    assert reason == "scout pass reported a High finding"


def test_does_not_escalate_a_clean_scout_pass() -> None:
    result = BreadthPassResult("Vault", "prompt", "### [F-1] Title\nSeverity: Low | Confidence: 20%")
    assert decide_escalation(result) is None


# --------------------------------------------------------------------------- #
# run_investigation
# --------------------------------------------------------------------------- #
def test_escalated_unit_gets_a_deep_pass_when_a_strategist_llm_is_given(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text(
        """
        contract Vault {
            uint256 public balance;
            modifier whenNotPaused() { require(!paused, "paused"); _; }
            function deposit(uint256 a) external whenNotPaused { balance += a; }
            function withdraw(uint256 a) external whenNotPaused { balance -= a; }
            function transfer(uint256 a) external whenNotPaused { balance -= a; }
            function emergencyWithdraw(uint256 a) external { balance -= a; }
        }
        """
    )
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(["### [F-1] Title\nSeverity: High | Confidence: 80%"])
    strategist_llm = FakeLLM(["CONFIRMED: real gap."])

    investigation = run_investigation(
        graph, tmp_path, scout_llm, "scout-model", strategist_llm=strategist_llm, strategist_model="deep-model"
    )

    record = investigation.units["Vault"]
    assert record.status == UnitStatus.INVESTIGATED
    assert record.escalation_reason == "scout pass reported a High finding"
    assert record.deep_response == "CONFIRMED: real gap."
    assert strategist_llm.calls[0][1] == "deep-model"
    assert "Deep Investigation: Vault" in strategist_llm.calls[0][0]


def test_escalated_unit_without_a_strategist_llm_stays_escalated_not_investigated(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(["### [F-1] Title\nSeverity: Critical | Confidence: 90%"])

    investigation = run_investigation(graph, tmp_path, scout_llm, "scout-model")

    record = investigation.units["Vault"]
    assert record.status == UnitStatus.ESCALATED
    assert record.deep_response is None


def test_verification_is_off_by_default_no_finding_verdicts(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(
        [
            "### [F-1] Title\nSeverity: Low | Confidence: 20%\nLocation: x\n"
            "Root Cause: y z w q\nExploit: a b c d\nImpact: i\nFix: f"
        ]
    )

    investigation = run_investigation(graph, tmp_path, scout_llm, "scout-model")

    assert investigation.units["Vault"].finding_verdicts == []


def test_verifier_llm_verifies_findings_parsed_from_the_scout_response_when_not_escalated(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_response = (
        "### [F-1] Low severity issue\n"
        "Severity: Low | Confidence: 20%\n"
        "Location: Vault.sol#L1, f()\n"
        "Root Cause: minor issue here explained fully\n"
        "Exploit: step one two three four\n"
        "Impact: minor impact\n"
        "Fix: minor fix"
    )
    scout_llm = FakeLLM([scout_response])
    verifier_llm = FakeLLM(
        [
            "\n".join(
                [
                    "GATE process: PASS — documented",
                    "GATE reachability: FAIL — not attacker-reachable",
                    "GATE real_impact: PASS — n/a",
                    "GATE poc_validation: FAIL — n/a",
                    "GATE math_bounds: PASS — n/a",
                    "GATE environment: PASS — n/a",
                ]
            )
        ]
    )

    investigation = run_investigation(
        graph, tmp_path, scout_llm, "scout-model", verifier_llm=verifier_llm, verifier_model="verifier-model"
    )

    record = investigation.units["Vault"]
    assert len(record.finding_verdicts) == 1
    assert record.finding_verdicts[0]["finding_id"] == "F-1"
    assert record.finding_verdicts[0]["verdict"] == "false_positive"
    assert verifier_llm.calls[0][1] == "verifier-model"


def test_verifier_llm_verifies_findings_from_the_deep_response_when_escalated(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(
        [
            "### [F-1] Title\nSeverity: Critical | Confidence: 90%\nLocation: x\n"
            "Root Cause: y z w q\nExploit: a b c d\nImpact: i\nFix: f"
        ]
    )
    deep_response = (
        "### [F-1] Confirmed critical issue\n"
        "Severity: Critical | Confidence: 90%\n"
        "Location: Vault.sol#L1, f()\n"
        "Root Cause: confirmed real root cause here\n"
        "Exploit: step one two three four\n"
        "Impact: real impact\n"
        "Fix: real fix"
    )
    strategist_llm = FakeLLM([deep_response])
    verifier_llm = FakeLLM(
        [
            "\n".join(
                [
                    "GATE process: PASS — documented",
                    "GATE reachability: PASS — reachable",
                    "GATE real_impact: PASS — real",
                    "GATE poc_validation: PASS — shown",
                    "GATE math_bounds: PASS — n/a",
                    "GATE environment: PASS — n/a",
                ]
            )
        ]
    )

    investigation = run_investigation(
        graph,
        tmp_path,
        scout_llm,
        "scout-model",
        strategist_llm=strategist_llm,
        strategist_model="deep-model",
        verifier_llm=verifier_llm,
        verifier_model="verifier-model",
    )

    record = investigation.units["Vault"]
    assert len(record.finding_verdicts) == 1
    assert record.finding_verdicts[0]["verdict"] == "true_positive"
    # verified against the DEEP response's finding, not the scout's earlier one
    assert "Confirmed critical issue" in verifier_llm.calls[0][0]


class FakePoCExecutor:
    def __init__(self, result: ForgeRunResult) -> None:
        self.result = result
        self.calls: list[tuple[Path, Path]] = []

    def run_test(self, test_file: Path, project_root: Path) -> ForgeRunResult:
        self.calls.append((test_file, project_root))
        return self.result


def test_poc_llm_is_off_by_default_even_with_a_true_positive_verdict(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(
        [
            "### [F-1] Title\nSeverity: Critical | Confidence: 90%\nLocation: x\n"
            "Root Cause: y z w q\nExploit: a b c d\nImpact: i\nFix: f"
        ]
    )
    verifier_llm = FakeLLM(
        [
            "\n".join(f"GATE {g.value}: PASS — ok" for g in Gate)
        ]
    )

    investigation = run_investigation(
        graph, tmp_path, scout_llm, "scout-model", verifier_llm=verifier_llm, verifier_model="verifier-model"
    )

    assert investigation.units["Vault"].poc_verifications == []


def test_poc_llm_runs_forge_for_a_true_positive_and_records_the_outcome(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    (tmp_path / "test").mkdir()
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(
        [
            "### [F-1] Title\nSeverity: Critical | Confidence: 90%\nLocation: x\n"
            "Root Cause: y z w q\nExploit: a b c d\nImpact: i\nFix: f"
        ]
    )
    verifier_llm = FakeLLM(["\n".join(f"GATE {g.value}: PASS — ok" for g in Gate)])
    poc_llm = FakeLLM(["```solidity\ncontract PentimentoPoC_F1 {}\n```"])
    executor = FakePoCExecutor(ForgeRunResult(0, "[PASS] testExploit()"))

    investigation = run_investigation(
        graph,
        tmp_path,
        scout_llm,
        "scout-model",
        verifier_llm=verifier_llm,
        verifier_model="verifier-model",
        poc_llm=poc_llm,
        poc_model="poc-model",
        poc_executor=executor,
    )

    poc_results = investigation.units["Vault"].poc_verifications
    assert len(poc_results) == 1
    assert poc_results[0]["outcome"] == "reproduced"
    assert len(executor.calls) == 1


def test_poc_llm_refuses_an_ffi_enabled_target_and_never_touches_the_executor(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    (tmp_path / "test").mkdir()
    (tmp_path / "foundry.toml").write_text("[profile.default]\nffi = true\n")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(
        [
            "### [F-1] Title\nSeverity: Critical | Confidence: 90%\nLocation: x\n"
            "Root Cause: y z w q\nExploit: a b c d\nImpact: i\nFix: f"
        ]
    )
    verifier_llm = FakeLLM(["\n".join(f"GATE {g.value}: PASS — ok" for g in Gate)])
    poc_llm = FakeLLM(["```solidity\ncontract PentimentoPoC_F1 {}\n```"])
    executor = FakePoCExecutor(ForgeRunResult(0, "should never run"))

    investigation = run_investigation(
        graph,
        tmp_path,
        scout_llm,
        "scout-model",
        verifier_llm=verifier_llm,
        verifier_model="verifier-model",
        poc_llm=poc_llm,
        poc_model="poc-model",
        poc_executor=executor,
        # poc_allow_ffi defaults to False - this is the real, security-motivated default
    )

    poc_results = investigation.units["Vault"].poc_verifications
    assert len(poc_results) == 1
    assert poc_results[0]["outcome"] == "refused_untrusted_ffi"
    assert executor.calls == []
    assert poc_llm.calls == []  # refused before even spending on the PoC-generation call


def test_clean_unit_stays_scouted(tmp_path: Path) -> None:
    (tmp_path / "Vault.sol").write_text("contract Vault { function f() external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Vault", contract_name="Vault", node_type=NodeType.VAULT, source_files=["Vault.sol"])],
    )
    scout_llm = FakeLLM(["no findings"])

    investigation = run_investigation(graph, tmp_path, scout_llm, "scout-model")

    assert investigation.units["Vault"].status == UnitStatus.SCOUTED


# --------------------------------------------------------------------------- #
# strong_scout_llm (detection/complexity.py model escalation)
# --------------------------------------------------------------------------- #
def test_scout_model_decision_is_recorded_even_without_a_strong_scout_llm(tmp_path: Path) -> None:
    imports = "\n".join(f'import "./Dep{i}.sol";' for i in range(20))
    (tmp_path / "Complex.sol").write_text(f"{imports}\ncontract Complex {{ function f() external {{}} }}")
    graph = CDVGraph(
        generator="test",
        units=[
            CDVUnit(
                unit_id="Complex", contract_name="Complex", node_type=NodeType.UNKNOWN, source_files=["Complex.sol"]
            )
        ],
    )
    scout_llm = FakeLLM(["no findings"])

    investigation = run_investigation(graph, tmp_path, scout_llm, "scout-model")

    decision = investigation.units["Complex"].scout_model_decision
    assert decision is not None
    assert decision["recommended_escalation"] is True
    assert decision["escalated"] is False
    assert decision["model_used"] == "scout-model"


def test_strong_scout_llm_escalates_a_flagged_unit(tmp_path: Path) -> None:
    imports = "\n".join(f'import "./Dep{i}.sol";' for i in range(20))
    (tmp_path / "Complex.sol").write_text(f"{imports}\ncontract Complex {{ function f() external {{}} }}")
    graph = CDVGraph(
        generator="test",
        units=[
            CDVUnit(
                unit_id="Complex", contract_name="Complex", node_type=NodeType.UNKNOWN, source_files=["Complex.sol"]
            )
        ],
    )
    scout_llm = FakeLLM(["no findings"])
    strong_scout_llm = FakeLLM(["### [F-1] Found by the strong model"])

    investigation = run_investigation(
        graph,
        tmp_path,
        scout_llm,
        "scout-model",
        strong_scout_llm=strong_scout_llm,
        strong_scout_model="strong-model",
    )

    assert scout_llm.calls == []
    assert len(strong_scout_llm.calls) == 1
    record = investigation.units["Complex"]
    assert record.scout_response == "### [F-1] Found by the strong model"
    assert record.scout_model_decision["escalated"] is True
    assert record.scout_model_decision["model_used"] == "strong-model"


# --------------------------------------------------------------------------- #
# router_llm (a real, found gap: Phase 5 routing was unreachable from investigate at all)
# --------------------------------------------------------------------------- #
class FakeRouterLLM:
    def __init__(self, response: str) -> None:
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def complete(self, prompt: str, *, model: str) -> str:
        self.calls.append((prompt, model))
        return self.response


def test_routing_is_off_by_default_in_investigate_too(tmp_path: Path) -> None:
    (tmp_path / "Earn.sol").write_text("contract Earn { function reallocate(uint256 a) external {} }")
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Earn", contract_name="Earn", node_type=NodeType.VAULT, source_files=["Earn.sol"])],
    )
    scout_llm = FakeLLM(["no findings"])

    investigation = run_investigation(graph, tmp_path, scout_llm, "scout-model")

    assert investigation.units["Earn"].scout_routing_decision is None


def test_router_llm_activates_a_domain_skill_for_the_scout_pass(tmp_path: Path) -> None:
    (tmp_path / "Earn.sol").write_text(
        """
        contract Earn {
            function setSupplyQueue(address[] calldata q) external {}
            function reallocate(uint256[] calldata a) external {}
        }
        """
    )
    graph = CDVGraph(
        generator="test",
        units=[CDVUnit(unit_id="Earn", contract_name="Earn", node_type=NodeType.VAULT, source_files=["Earn.sol"])],
    )
    scout_llm = FakeLLM(["no findings"])
    router_llm = FakeRouterLLM(
        "\n".join(
            [
                "ROUTE lending: SKIP — no match",
                "ROUTE amm_dex: SKIP — no match",
                "ROUTE yield_vault: ACTIVATE — reallocate + queue management present",
            ]
        )
    )

    investigation = run_investigation(
        graph, tmp_path, scout_llm, "scout-model", router_llm=router_llm, router_model="router-model"
    )

    assert len(router_llm.calls) == 1
    assert router_llm.calls[0][1] == "router-model"
    decision = investigation.units["Earn"].scout_routing_decision
    assert decision is not None
    assert any(a["domain"] == "yield_vault" and a["activated"] for a in decision["activations"])


# --------------------------------------------------------------------------- #
# InvestigationGraph persistence
# --------------------------------------------------------------------------- #
def test_investigation_graph_round_trips_through_json(tmp_path: Path) -> None:
    graph = InvestigationGraph(
        generator="test",
        units={
            "Vault": UnitRecord(
                unit_id="Vault",
                status=UnitStatus.INVESTIGATED,
                scout_response="scout text",
                scout_guard_anomalies=[{"state_variable": "balance"}],
                escalation_reason="scout pass reported a High finding",
                deep_response="deep text",
            )
        },
    )
    path = tmp_path / "investigation.json"

    graph.save(path)
    loaded = InvestigationGraph.load(path)

    assert loaded.units["Vault"].status == UnitStatus.INVESTIGATED
    assert loaded.units["Vault"].deep_response == "deep text"
    assert loaded.units["Vault"].scout_guard_anomalies == [{"state_variable": "balance"}]

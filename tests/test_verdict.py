from pentimento.detection.findings import Finding
from pentimento.detection.verdict import (
    Gate,
    GateResult,
    Verdict,
    VerificationRoute,
    classify_bug_class,
    compute_jury_verdict,
    compute_verdict,
    decide_verification_route,
    parse_gate_results,
    restate_claim,
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


# --------------------------------------------------------------------------- #
# restate_claim (Step 0)
# --------------------------------------------------------------------------- #
def test_restate_claim_is_not_vague_for_a_well_described_finding() -> None:
    claim = restate_claim(_finding())
    assert claim.is_vague is False
    assert claim.vulnerability_claim == "Reentrancy in withdraw()"


def test_restate_claim_flags_a_thin_root_cause_as_vague() -> None:
    claim = restate_claim(_finding(root_cause="bug"))
    assert claim.is_vague is True


def test_restate_claim_flags_a_thin_exploit_as_vague() -> None:
    claim = restate_claim(_finding(exploit="maybe"))
    assert claim.is_vague is True


def test_restate_claim_flags_a_missing_location_as_vague() -> None:
    claim = restate_claim(_finding(location=""))
    assert claim.is_vague is True


# --------------------------------------------------------------------------- #
# classify_bug_class
# --------------------------------------------------------------------------- #
def test_classifies_reentrancy() -> None:
    assert classify_bug_class(_finding(title="Reentrancy in withdraw()")) == "reentrancy"


def test_classifies_access_control() -> None:
    f = _finding(title="Missing access control", root_cause="function lacks onlyOwner check")
    assert classify_bug_class(f) == "access_control"


def test_classifies_oracle_manipulation() -> None:
    f = _finding(title="Spot price used directly", root_cause="reads spot price with no TWAP")
    assert classify_bug_class(f) == "oracle_price_manipulation"


def test_unrecognized_pattern_is_unclassified() -> None:
    f = _finding(title="Weird thing", root_cause="something unusual happens here")
    assert classify_bug_class(f) == "unclassified"


# --------------------------------------------------------------------------- #
# decide_verification_route
# --------------------------------------------------------------------------- #
def test_vague_claim_routes_to_deep() -> None:
    f = _finding(root_cause="bug")
    claim = restate_claim(f)
    assert decide_verification_route(f, claim, "unclassified") == VerificationRoute.DEEP


def test_race_condition_bug_class_routes_to_deep() -> None:
    f = _finding(
        title="setFlowCaps front-running",
        root_cause="An admin cap update can be front-run by a user reallocateTo() call.",
    )
    claim = restate_claim(f)
    bug_class = classify_bug_class(f)
    assert bug_class == "race_condition_toctou"
    assert decide_verification_route(f, claim, bug_class) == VerificationRoute.DEEP


def test_cross_contract_location_routes_to_deep() -> None:
    f = _finding(location="EulerEarn.sol#L1, PublicAllocator.sol#L2")
    claim = restate_claim(f)
    assert decide_verification_route(f, claim, "unclassified") == VerificationRoute.DEEP


def test_clear_single_contract_finding_routes_to_standard() -> None:
    f = _finding()
    claim = restate_claim(f)
    assert decide_verification_route(f, claim, "reentrancy") == VerificationRoute.STANDARD


# --------------------------------------------------------------------------- #
# parse_gate_results / compute_verdict
# --------------------------------------------------------------------------- #
def test_parses_all_gates_when_the_model_addresses_every_one() -> None:
    raw = "\n".join(
        [
            "GATE process: PASS — every step documented",
            "GATE reachability: PASS — attacker controls the input",
            "GATE real_impact: PASS — funds can be drained",
            "GATE poc_validation: PASS — pseudocode shows the drain",
            "GATE math_bounds: PASS — not a bounds claim, N/A",
            "GATE environment: PASS — no reentrancy guard present",
        ]
    )
    results = parse_gate_results(raw)
    assert len(results) == 6
    assert all(g.passed for g in results)
    assert compute_verdict(results) == Verdict.TRUE_POSITIVE


def test_a_single_failing_gate_makes_the_whole_verdict_false_positive() -> None:
    raw = "\n".join(
        [
            "GATE process: PASS — documented",
            "GATE reachability: FAIL — caller already validates this, unreachable",
            "GATE real_impact: PASS — would be real if reachable",
            "GATE poc_validation: FAIL — no PoC survives the reachability gap",
            "GATE math_bounds: PASS — N/A",
            "GATE environment: PASS — N/A",
        ]
    )
    results = parse_gate_results(raw)
    assert compute_verdict(results) == Verdict.FALSE_POSITIVE
    reachability = next(g for g in results if g.gate == Gate.REACHABILITY)
    assert reachability.passed is False
    assert "unreachable" in reachability.reason


def test_a_gate_the_model_never_addresses_defaults_to_fail_not_silent() -> None:
    raw = "GATE process: PASS — documented"  # only 1 of 6 gates addressed

    results = parse_gate_results(raw)

    assert len(results) == 6  # every known gate gets a slot, never dropped
    unaddressed = [g for g in results if g.gate != Gate.PROCESS]
    assert all(g.passed is False for g in unaddressed)
    assert all("never addressed" in g.reason for g in unaddressed)
    assert compute_verdict(results) == Verdict.FALSE_POSITIVE


def test_compute_verdict_never_trusts_a_model_asserted_label_only_gate_results() -> None:
    # compute_verdict's whole signature only accepts GateResults - there is no way to hand
    # it a raw "TRUE POSITIVE" string, by construction (see verdict.py's own docstring).
    all_pass = tuple(GateResult(g, True, "ok") for g in Gate)
    assert compute_verdict(all_pass) == Verdict.TRUE_POSITIVE
    one_fail = tuple(GateResult(g, g != Gate.ENVIRONMENT, "ok") for g in Gate)
    assert compute_verdict(one_fail) == Verdict.FALSE_POSITIVE


# --------------------------------------------------------------------------- #
# compute_jury_verdict (independent jury / multi-model verification)
# --------------------------------------------------------------------------- #
_ALL_PASS = tuple(GateResult(g, True, "ok") for g in Gate)
_ONE_FAIL = tuple(GateResult(g, g != Gate.REACHABILITY, "ok") for g in Gate)


def test_no_secondary_verifier_reduces_to_plain_compute_verdict() -> None:
    # fully backward compatible - a caller that never configures a second verifier sees
    # IDENTICAL behavior to compute_verdict alone.
    assert compute_jury_verdict(_ALL_PASS) == Verdict.TRUE_POSITIVE
    assert compute_jury_verdict(_ONE_FAIL) == Verdict.FALSE_POSITIVE


def test_both_verifiers_agreeing_true_positive_confirms_it() -> None:
    assert compute_jury_verdict(_ALL_PASS, _ALL_PASS) == Verdict.TRUE_POSITIVE


def test_a_single_dissenting_verifier_flips_the_overall_verdict_to_false_positive() -> None:
    # primary says TRUE_POSITIVE, secondary disagrees - one dissent is enough to reject,
    # matching "burden of proof is on the claim" applied across two independent judges.
    assert compute_jury_verdict(_ALL_PASS, _ONE_FAIL) == Verdict.FALSE_POSITIVE
    # order doesn't matter - dissent from either side rejects
    assert compute_jury_verdict(_ONE_FAIL, _ALL_PASS) == Verdict.FALSE_POSITIVE


def test_both_verifiers_rejecting_stays_false_positive() -> None:
    assert compute_jury_verdict(_ONE_FAIL, _ONE_FAIL) == Verdict.FALSE_POSITIVE

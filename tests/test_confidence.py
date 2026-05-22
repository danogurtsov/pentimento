from pentimento.detection.confidence import compute_evidence_confidence
from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.verdict import FindingVerdict, Gate, GateResult, RestatedClaim, Verdict, VerificationRoute


def _finding(confidence: int = 90) -> Finding:
    return Finding(
        id="F-1",
        title="Reentrancy in withdraw()",
        severity="Critical",
        confidence=confidence,
        location="Vault.sol#L40",
        root_cause="State written after external call.",
        exploit="Deposit, withdraw, reenter.",
        impact="Drains the vault.",
        fix="Move state write before the call.",
        poc=None,
    )


def _verdict(verdict: Verdict) -> FindingVerdict:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    passed = verdict == Verdict.TRUE_POSITIVE
    gates = tuple(GateResult(g, passed, "ok") for g in Gate)
    return FindingVerdict("F-1", VerificationRoute.STANDARD, "reentrancy", claim, gates, verdict)


def test_poc_reproduced_is_the_dominant_tier_even_over_a_low_self_report() -> None:
    conf = compute_evidence_confidence(_finding(confidence=10), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.REPRODUCED)
    assert conf.tier == "poc_reproduced"
    assert conf.score > 70  # dominant evidence term wins even with a low self-report nudge


def test_poc_not_reproduced_tanks_confidence_even_with_a_true_positive_verdict() -> None:
    conf = compute_evidence_confidence(
        _finding(confidence=95), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.NOT_REPRODUCED
    )
    assert conf.tier == "poc_not_reproduced"
    assert conf.score < 30  # real executed evidence against the claim dominates


def test_verified_true_positive_without_any_poc_run() -> None:
    conf = compute_evidence_confidence(_finding(), _verdict(Verdict.TRUE_POSITIVE), None)
    assert conf.tier == "verified_true_positive"


def test_verified_false_positive_scores_low() -> None:
    conf = compute_evidence_confidence(_finding(confidence=90), _verdict(Verdict.FALSE_POSITIVE), None)
    assert conf.tier == "verified_false_positive"
    assert conf.score < 30


def test_never_verified_falls_to_the_weakest_tier_regardless_of_self_report() -> None:
    conf = compute_evidence_confidence(_finding(confidence=99), None, None)
    assert conf.tier == "unverified_llm_self_report_only"
    assert conf.score < 40  # a 99% self-report alone must not read as high confidence


def test_inconclusive_poc_outcomes_fall_through_to_the_verification_only_tier() -> None:
    # COMPILE_ERROR/REFUSED_UNTRUSTED_FFI are "inconclusive, not evidence either way" -
    # same philosophy as poc_verdict.py itself - must not be treated as evidence for OR
    # against the claim.
    compile_error = compute_evidence_confidence(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.COMPILE_ERROR)
    refused = compute_evidence_confidence(
        _finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.REFUSED_UNTRUSTED_FFI
    )
    no_poc = compute_evidence_confidence(_finding(), _verdict(Verdict.TRUE_POSITIVE), None)
    assert compile_error.tier == refused.tier == no_poc.tier == "verified_true_positive"
    assert compile_error.score == refused.score == no_poc.score


def test_self_report_only_nudges_the_score_within_one_tier() -> None:
    low = compute_evidence_confidence(_finding(confidence=0), _verdict(Verdict.TRUE_POSITIVE), None)
    high = compute_evidence_confidence(_finding(confidence=100), _verdict(Verdict.TRUE_POSITIVE), None)
    assert low.tier == high.tier == "verified_true_positive"
    assert high.score - low.score == 20.0  # exactly the 20% self-report weight, no more

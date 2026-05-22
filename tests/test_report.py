from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.report import ReportStatus, classify_finding, render_report
from pentimento.detection.verdict import FindingVerdict, Gate, GateResult, RestatedClaim, Verdict, VerificationRoute


def _finding(**overrides) -> Finding:
    defaults = dict(
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
    defaults.update(overrides)
    return Finding(**defaults)


def _verdict(
    verdict: Verdict, route: VerificationRoute = VerificationRoute.STANDARD, finding_id: str = "F-1"
) -> FindingVerdict:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    all_pass = verdict == Verdict.TRUE_POSITIVE
    gates = tuple(GateResult(g, all_pass, "ok" if all_pass else "unreachable") for g in Gate)
    return FindingVerdict(finding_id, route, "reentrancy", claim, gates, verdict)


# --------------------------------------------------------------------------- #
# classify_finding
# --------------------------------------------------------------------------- #
def test_never_verified_is_a_lead() -> None:
    item = classify_finding(_finding(), None, None)
    assert item.status == ReportStatus.LEAD
    assert "never verified" in item.reason


def test_false_positive_is_rejected_dropped_from_both() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.FALSE_POSITIVE), None)
    assert item.status == ReportStatus.REJECTED


def test_true_positive_on_standard_route_with_no_poc_is_a_finding() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), None)
    assert item.status == ReportStatus.FINDING


def test_true_positive_on_deep_route_is_a_finding_not_demoted() -> None:
    # Deep path actually executes a real 4-phase pipeline, so a DEEP-route TRUE_POSITIVE is
    # no longer treated as less trustworthy than a Standard one.
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE, VerificationRoute.DEEP), None)
    assert item.status == ReportStatus.FINDING
    assert "Deep path" in item.reason


def test_true_positive_contradicted_by_a_not_reproduced_poc_is_a_lead() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.NOT_REPRODUCED)
    assert item.status == ReportStatus.LEAD
    assert "contradiction" in item.reason


def test_true_positive_with_a_reproduced_poc_is_a_finding() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.REPRODUCED)
    assert item.status == ReportStatus.FINDING


def test_true_positive_with_an_inconclusive_compile_error_is_still_a_finding() -> None:
    # a compile error is "inconclusive", not evidence AGAINST the finding - see report.py's
    # own module docstring: only NOT_REPRODUCED demotes, COMPILE_ERROR doesn't.
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.COMPILE_ERROR)
    assert item.status == ReportStatus.FINDING


# --------------------------------------------------------------------------- #
# render_report
# --------------------------------------------------------------------------- #
def test_render_report_includes_confirmed_findings_with_full_detail() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.REPRODUCED)

    report = render_report([item], "TestProject")

    assert "Security Report: TestProject" in report
    assert "Reentrancy in withdraw()" in report
    assert "Move the state write before the external call." in report
    assert "reproduced" in report
    assert "PASS" in report


def test_render_report_includes_the_evidence_weighted_confidence_alongside_self_report() -> None:
    item = classify_finding(_finding(), _verdict(Verdict.TRUE_POSITIVE), PoCOutcome.REPRODUCED)

    report = render_report([item], "TestProject")

    assert "Confidence (model self-report):" in report
    assert "Confidence (evidence-weighted, code-computed):" in report
    assert "poc_reproduced" in report


def test_render_report_shows_deep_path_phase_reports_and_jury_when_present() -> None:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    all_pass = tuple(GateResult(g, True, "ok") for g in Gate)
    verdict = FindingVerdict(
        "F-1",
        VerificationRoute.DEEP,
        "reentrancy",
        claim,
        all_pass,
        Verdict.TRUE_POSITIVE,
        secondary_gate_results=all_pass,
        deep_phase_reports={"dataflow": "DATAFLOW_TEXT", "exploitability": "EXPLOIT_TEXT", "poc": "POC_TEXT"},
    )
    item = classify_finding(_finding(), verdict, None)

    report = render_report([item], "TestProject")

    assert "(deep path)" in report
    assert "Independent second verifier (jury):" in report
    assert "DATAFLOW_TEXT" in report
    assert "EXPLOIT_TEXT" in report
    assert "POC_TEXT" in report


def test_render_report_puts_leads_in_a_disclaimed_appendix() -> None:
    item = classify_finding(_finding(), None, None)

    report = render_report([item], "TestProject")

    assert "Appendix: Unverified Leads" in report
    assert "Disclaimer" in report
    assert "NOT confirmed findings" in report


def test_render_report_omits_rejected_findings_entirely() -> None:
    item = classify_finding(_finding(title="A refuted claim"), _verdict(Verdict.FALSE_POSITIVE), None)

    report = render_report([item], "TestProject")

    assert "A refuted claim" not in report


def test_render_report_sorts_findings_by_severity() -> None:
    low = classify_finding(
        _finding(id="F-1", title="Low bug", severity="Low"), _verdict(Verdict.TRUE_POSITIVE, finding_id="F-1"), None
    )
    critical = classify_finding(
        _finding(id="F-2", title="Critical bug", severity="Critical"),
        _verdict(Verdict.TRUE_POSITIVE, finding_id="F-2"),
        None,
    )

    report = render_report([low, critical], "TestProject")

    assert report.index("Critical bug") < report.index("Low bug")

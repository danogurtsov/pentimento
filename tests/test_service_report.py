from dataclasses import asdict

from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.report import ReportStatus
from pentimento.detection.verdict import FindingVerdict, Gate, GateResult, RestatedClaim, Verdict, VerificationRoute
from pentimento.services.investigation import InvestigationGraph, UnitRecord, UnitStatus
from pentimento.services.poc_verification import PoCVerificationResult
from pentimento.services.report import build_report_items, request_approval


def _verdict(finding_id: str, verdict: Verdict) -> FindingVerdict:
    claim = RestatedClaim("claim", "root", "trigger", "impact", is_vague=False)
    passed = verdict == Verdict.TRUE_POSITIVE
    gates = tuple(GateResult(g, passed, "ok") for g in Gate)
    return FindingVerdict(finding_id, VerificationRoute.STANDARD, "reentrancy", claim, gates, verdict)


def _scout_response(finding_id: str, title: str) -> str:
    return (
        f"### [{finding_id}] {title}\n"
        "Severity: Critical | Confidence: 90%\n"
        "Location: Vault.sol#L1, f()\n"
        "Root Cause: root cause explained fully here\n"
        "Exploit: step one two three four\n"
        "Impact: impact\n"
        "Fix: fix"
    )


def test_build_report_items_classifies_using_the_units_finding_verdicts_and_poc_results() -> None:
    verdict = _verdict("F-1", Verdict.TRUE_POSITIVE)
    poc = PoCVerificationResult("F-1", PoCOutcome.REPRODUCED, "contract X {}", "[PASS]")
    graph = InvestigationGraph(
        generator="test",
        units={
            "Vault": UnitRecord(
                unit_id="Vault",
                status=UnitStatus.SCOUTED,
                scout_response=_scout_response("F-1", "Confirmed bug"),
                finding_verdicts=[asdict(verdict)],
                poc_verifications=[asdict(poc)],
            )
        },
    )

    items = build_report_items(graph)

    assert len(items) == 1
    assert items[0].status == ReportStatus.FINDING
    assert items[0].finding.title == "Confirmed bug"
    assert items[0].poc_outcome == PoCOutcome.REPRODUCED


def test_build_report_items_uses_the_deep_response_when_one_exists() -> None:
    graph = InvestigationGraph(
        generator="test",
        units={
            "Vault": UnitRecord(
                unit_id="Vault",
                status=UnitStatus.INVESTIGATED,
                scout_response=_scout_response("F-1", "Original scout finding"),
                deep_response=_scout_response("F-1", "Confirmed by strategist"),
            )
        },
    )

    items = build_report_items(graph)

    assert len(items) == 1
    assert items[0].finding.title == "Confirmed by strategist"


def test_build_report_items_a_finding_with_no_verdict_is_an_unverified_lead() -> None:
    graph = InvestigationGraph(
        generator="test",
        units={
            "Vault": UnitRecord(
                unit_id="Vault",
                status=UnitStatus.SCOUTED,
                scout_response=_scout_response("F-1", "Unverified finding"),
            )
        },
    )

    items = build_report_items(graph)

    assert items[0].status == ReportStatus.LEAD


# --------------------------------------------------------------------------- #
# request_approval (the blocking gate)
# --------------------------------------------------------------------------- #
def test_no_approver_means_not_approved() -> None:
    record = request_approval("# Report\nsome content", None)
    assert record.approved is False
    assert record.approved_by == ""


def test_an_explicit_approver_means_approved_and_recorded() -> None:
    record = request_approval("# Report\nsome content", "Dan")
    assert record.approved is True
    assert record.approved_by == "Dan"
    assert record.approved_at  # a real timestamp was recorded


def test_context_hash_changes_if_the_report_text_changes() -> None:
    a = request_approval("# Report v1", "Dan")
    b = request_approval("# Report v2", "Dan")
    assert a.context_hash != b.context_hash


def test_context_hash_is_stable_for_the_same_text() -> None:
    a = request_approval("# Report v1", "Dan")
    b = request_approval("# Report v1", "Dan")
    assert a.context_hash == b.context_hash

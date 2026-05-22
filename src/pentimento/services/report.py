"""
Phase 7 orchestration: assembles a report from an already-saved `InvestigationGraph`, and
enforces a BLOCKING approval gate literally — no final,
client-ready report file is written without an explicit, recorded human approval. Reads
already-computed facts only; makes no new LLM calls at all (this phase is assembly and
governance, not detection).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from pentimento.detection.findings import parse_findings
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.report import ReportItem, classify_finding
from pentimento.detection.verdict import FindingVerdict, Gate, GateResult, RestatedClaim, Verdict, VerificationRoute
from pentimento.services.investigation import InvestigationGraph


def _verdict_from_dict(d: dict) -> FindingVerdict:
    claim = RestatedClaim(**d["restated_claim"])
    gates = tuple(GateResult(Gate(g["gate"]), g["passed"], g["reason"]) for g in d["gate_results"])
    return FindingVerdict(
        finding_id=d["finding_id"],
        route=VerificationRoute(d["route"]),
        bug_class=d["bug_class"],
        restated_claim=claim,
        gate_results=gates,
        verdict=Verdict(d["verdict"]),
    )


def build_report_items(investigation: InvestigationGraph) -> list[ReportItem]:
    """One `ReportItem` per Finding parsed out of every unit's FINAL response (the deep
    pass's if one ran, else the scout's — same "final response" convention `run_
    investigation` itself uses for verification), classified against whatever verification/
    PoC evidence that unit's record already holds."""
    items: list[ReportItem] = []
    for record in investigation.units.values():
        final_response = record.deep_response or record.scout_response
        findings = parse_findings(final_response)
        verdicts_by_id = {v["finding_id"]: _verdict_from_dict(v) for v in record.finding_verdicts}
        poc_by_id = {p["finding_id"]: PoCOutcome(p["outcome"]) for p in record.poc_verifications}
        for finding in findings:
            items.append(classify_finding(finding, verdicts_by_id.get(finding.id), poc_by_id.get(finding.id)))
    return items


@dataclass(frozen=True)
class ApprovalRecord:
    """Answers 4 mandatory audit-trail questions (not the usual 2 — "who approved"
    alone is legally meaningless without the other three)."""

    attempted: str  # what the agent tried to do
    approved_by: str  # who approved (empty string when nobody did)
    context_hash: str  # sha256 of the EXACT report text shown at approval time
    approved_at: str  # ISO-8601 UTC timestamp — whether it actually happened, and when
    approved: bool


def request_approval(report_text: str, approved_by: str | None) -> ApprovalRecord:
    """The BLOCKING gate itself. `approved_by` is None unless a human explicitly supplied
    one (CLI `--approve <name>`) — there is no implicit/default-approved path; the caller
    (`cli.py`) is responsible for refusing to write a final report when `approved` is
    False. `context_hash` is computed over the EXACT text being approved, not a summary or
    a claim that a report "exists" — a reviewer must be shown the real
    content, not just told it was available."""
    return ApprovalRecord(
        attempted=f"assembled a {len(report_text.splitlines())}-line report for human review",
        approved_by=approved_by or "",
        context_hash=hashlib.sha256(report_text.encode()).hexdigest(),
        approved_at=datetime.now(UTC).isoformat(),
        approved=approved_by is not None,
    )

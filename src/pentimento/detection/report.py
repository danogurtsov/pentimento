"""
Report assembly — Phase 7, adopting a pashov-style Finding/Lead split literally, on top
of what Phase 6 already computes rather than a new detection technique. Pure data
classification + text rendering — no LLM, no I/O (the CLI layer, `services/report.py`, is
what actually reads an `InvestigationGraph` off disk).

Three-way split, not a naive true/false binary:
- **FINDING** — went through Phase 6 verification (`detection/verdict.py`, Standard OR
  Deep — the Deep path actually executes a real 4-phase pipeline instead of being
  recorded-but-skipped, so a DEEP-route TRUE_POSITIVE is no less trustworthy than a
  Standard one) and came out TRUE_POSITIVE, with no contradicting executed PoC. Earns
  a place in the main, client-facing report.
- **LEAD** — genuinely UNKNOWN status: never verified this run at all, OR the gate review
  said TRUE_POSITIVE while a real, executed PoC did NOT reproduce it (a genuine contradiction
  between Phase 6's two verification layers, not something to silently resolve one way).
  Appendix only, with an explicit disclaimer, for a human to look at.
- **REJECTED** — actively refuted (FALSE_POSITIVE, with sound gate-based reasoning). Dropped
  entirely from both sections — reporting a disproven claim, even disclaimed, is just noise
  for the human who still has to read the whole report.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pentimento.detection.confidence import compute_evidence_confidence
from pentimento.detection.findings import Finding
from pentimento.detection.poc_verdict import PoCOutcome
from pentimento.detection.verdict import FindingVerdict, Verdict, VerificationRoute


class ReportStatus(StrEnum):
    FINDING = "finding"
    LEAD = "lead"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ReportItem:
    finding: Finding
    status: ReportStatus
    verdict: FindingVerdict | None
    poc_outcome: PoCOutcome | None
    reason: str


def classify_finding(
    finding: Finding, verdict: FindingVerdict | None, poc_outcome: PoCOutcome | None
) -> ReportItem:
    if verdict is None:
        return ReportItem(finding, ReportStatus.LEAD, None, None, "never verified this run — status unknown")

    if verdict.verdict == Verdict.FALSE_POSITIVE:
        return ReportItem(finding, ReportStatus.REJECTED, verdict, poc_outcome, "refuted by Phase 6 gate review")

    if poc_outcome == PoCOutcome.NOT_REPRODUCED:
        return ReportItem(
            finding,
            ReportStatus.LEAD,
            verdict,
            poc_outcome,
            "gate review confirmed this finding, but the real executed PoC did NOT reproduce "
            "the exploit — a genuine contradiction between verification stages, needs a "
            "human look rather than silently picking a side",
        )

    route_note = (
        " via the Deep path (4-phase task-based verification: Data Flow → Exploitability "
        "→ PoC → Impact/Devil's-Advocate/Gate Review)"
        if verdict.route == VerificationRoute.DEEP
        else ""
    )
    return ReportItem(finding, ReportStatus.FINDING, verdict, poc_outcome, f"verified TRUE_POSITIVE{route_note}")


_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def render_report(items: list[ReportItem], project_name: str) -> str:
    findings = sorted(
        (i for i in items if i.status == ReportStatus.FINDING),
        key=lambda i: _SEVERITY_ORDER.get(i.finding.severity, 99),
    )
    leads = [i for i in items if i.status == ReportStatus.LEAD]

    lines = [
        f"# Security Report: {project_name}",
        "",
        f"{len(findings)} confirmed finding(s), {len(leads)} unverified lead(s) in the appendix.",
        "",
    ]
    for n, item in enumerate(findings, start=1):
        f = item.finding
        ev_conf = compute_evidence_confidence(f, item.verdict, item.poc_outcome)
        lines.extend(
            [
                f"## [{f.severity}] {n}. {f.title}",
                f"**Confidence (model self-report):** {f.confidence}%  |  "
                f"**Confidence (evidence-weighted, code-computed):** {ev_conf.score}% "
                f"[{ev_conf.tier}]  |  **Location:** {f.location}",
                "",
                f"**Root Cause:** {f.root_cause}",
                "",
                f"**Exploit:** {f.exploit}",
                "",
                f"**Impact:** {f.impact}",
                "",
                f"**Recommended Fix:** {f.fix}",
            ]
        )
        if item.verdict is not None:
            gate_summary = ", ".join(
                f"{g.gate.value}={'PASS' if g.passed else 'FAIL'}" for g in item.verdict.gate_results
            )
            route_label = f" ({item.verdict.route.value} path)"
            lines.append(f"\n**Phase 6 gate review{route_label}:** {gate_summary}")
            if item.verdict.secondary_gate_results is not None:
                jury_summary = ", ".join(
                    f"{g.gate.value}={'PASS' if g.passed else 'FAIL'}" for g in item.verdict.secondary_gate_results
                )
                lines.append(f"\n**Independent second verifier (jury):** {jury_summary}")
            if item.verdict.deep_phase_reports is not None:
                lines.append("\n<details><summary>Deep path phase reports (click to expand)</summary>\n")
                for phase_name in ("dataflow", "exploitability", "poc"):
                    lines.append(f"\n**Phase — {phase_name}:**\n\n{item.verdict.deep_phase_reports[phase_name]}\n")
                lines.append("</details>")
        if item.poc_outcome is not None:
            lines.append(
                f"\n**Executed PoC (Level 1 deterministic oracle — code-decided, not "
                f"self-reported):** {item.poc_outcome.value}"
            )
        lines.append("")

    if leads:
        lines.extend(
            [
                "---",
                "",
                "## Appendix: Unverified Leads",
                "",
                "**Disclaimer:** the items below did NOT complete Phase 6 verification, or "
                "produced a genuine contradiction between verification stages. They are NOT "
                "confirmed findings — included here for human review only, not as "
                "established bugs.",
                "",
            ]
        )
        for item in leads:
            f = item.finding
            ev_conf = compute_evidence_confidence(f, item.verdict, item.poc_outcome)
            lines.extend(
                [
                    f"### {f.title}",
                    f"Why unverified: {item.reason}",
                    f"Root Cause (unverified claim): {f.root_cause}",
                    f"Confidence (model self-report): {f.confidence}% | "
                    f"Confidence (evidence-weighted, code-computed): {ev_conf.score}% [{ev_conf.tier}]",
                    "",
                ]
            )

    return "\n".join(lines)

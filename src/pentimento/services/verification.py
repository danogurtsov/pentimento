"""
Phase 6 orchestration: Trail of Bits fp-check, Standard AND Deep paths.

An OPTIONAL second, independent verifier (`second_llm`/`second_model`) implements the
multi-model-jury / independent-refuter pattern: no finding is published without independent
review from at least two different judges. Off by
default (a real second LLM call per finding), same opt-in shape as every other multi-call
feature in this codebase (`--route`, `strong_llm`, `poc_llm`). When configured, the SAME
prompt goes to both models — genuinely independent calls, no shared state — and `verdict.
compute_jury_verdict` decides the final verdict from both sets of gate results.

When `detection.verdict.decide_verification_route`
returns DEEP (ambiguous claim, cross-component path, race/concurrency, or a logic bug
without a clear spec), this module actually EXECUTES the reference's own 4-phase Deep
pipeline (`detection/prompts.py`'s `build_deep_dataflow_prompt`/`build_deep_exploitability_
prompt`/`build_deep_poc_prompt`/`build_deep_gate_review_prompt` — 4 sequential calls, each
phase's raw output fed forward as grounding into the next) instead of Standard's single
linear pass — automatically, not behind a further opt-in flag, since the routing decision
itself already IS the opt-in (a caller who wants verification at all already accepts the
per-finding cost; Deep only ever triggers on the subset of findings that actually need it,
and the existing `SharedBudget`/`BudgetedLLM` cost ceiling already bounds total spend).
Both paths still produce the exact same `FindingVerdict` shape (same `GATE <name>: PASS|
FAIL` output format on the final call, parsed by the same `parse_gate_results`) — every
downstream consumer (jury, PoC oracle, report rendering) works identically regardless of
which path produced a verdict; only `deep_phase_reports` (`None` for Standard) differs."""
from __future__ import annotations

from pathlib import Path

from pentimento.detection.findings import Finding
from pentimento.detection.prompts import (
    build_deep_dataflow_prompt,
    build_deep_exploitability_prompt,
    build_deep_gate_review_prompt,
    build_deep_poc_prompt,
    build_verification_prompt,
)
from pentimento.detection.verdict import (
    FindingVerdict,
    GateResult,
    RestatedClaim,
    VerificationRoute,
    classify_bug_class,
    compute_jury_verdict,
    decide_verification_route,
    parse_gate_results,
    restate_claim,
)
from pentimento.domain.models import CDVUnit
from pentimento.ports.llm import LLMPort


def _run_standard_gates(
    finding: Finding, claim: RestatedClaim, bug_class: str, source_code: str, llm: LLMPort, model: str
) -> tuple[GateResult, ...]:
    prompt = build_verification_prompt(finding, claim, bug_class, source_code)
    raw = llm.complete(prompt, model=model)
    return parse_gate_results(raw)


def _run_deep_pipeline(
    finding: Finding, claim: RestatedClaim, bug_class: str, source_code: str, llm: LLMPort, model: str
) -> tuple[tuple[GateResult, ...], dict[str, str]]:
    """The reference's own 4-phase Deep path, executed as 4 sequential calls to the SAME
    model — each phase's raw text feeds forward as grounding into the next, never
    re-derived. Returns the final Gate Review's parsed results plus all 3 upstream phase
    reports (for `FindingVerdict.deep_phase_reports`'s own transparency/audit purpose)."""
    dataflow_prompt = build_deep_dataflow_prompt(finding, claim, bug_class, source_code)
    dataflow_report = llm.complete(dataflow_prompt, model=model)

    exploitability_prompt = build_deep_exploitability_prompt(finding, claim, bug_class, source_code, dataflow_report)
    exploitability_report = llm.complete(exploitability_prompt, model=model)

    poc_prompt = build_deep_poc_prompt(
        finding, claim, bug_class, source_code, dataflow_report, exploitability_report
    )
    poc_report = llm.complete(poc_prompt, model=model)

    gate_prompt = build_deep_gate_review_prompt(
        finding, claim, bug_class, source_code, dataflow_report, exploitability_report, poc_report
    )
    gate_raw = llm.complete(gate_prompt, model=model)
    gate_results = parse_gate_results(gate_raw)

    phase_reports = {"dataflow": dataflow_report, "exploitability": exploitability_report, "poc": poc_report}
    return gate_results, phase_reports


def _run_gates_for_route(
    route: VerificationRoute,
    finding: Finding,
    claim: RestatedClaim,
    bug_class: str,
    source_code: str,
    llm: LLMPort,
    model: str,
    strong_llm: LLMPort | None = None,
    strong_model: str | None = None,
) -> tuple[tuple[GateResult, ...], dict[str, str] | None]:
    if route == VerificationRoute.DEEP:
        active_llm, active_model = llm, model
        if strong_llm is not None and strong_model is not None:
            active_llm, active_model = strong_llm, strong_model
        gate_results, phase_reports = _run_deep_pipeline(
            finding, claim, bug_class, source_code, active_llm, active_model
        )
        return gate_results, phase_reports
    return _run_standard_gates(finding, claim, bug_class, source_code, llm, model), None


def run_verification(
    finding: Finding,
    unit: CDVUnit,
    project_root: Path,
    llm: LLMPort,
    model: str,
    second_llm: LLMPort | None = None,
    second_model: str | None = None,
    strong_llm: LLMPort | None = None,
    strong_model: str | None = None,
) -> FindingVerdict:
    """One verification for ONE finding (two, if `second_llm`/`second_model` are both
    given) — 1 call on the Standard route, 4 on the Deep route (see module docstring), times
    2 if a second verifier is configured. `unit`/`project_root` are used only to read the
    unit's own source code back for the verifier to trace against — the same source the
    finding was originally raised from.

    `strong_llm`/`strong_model` are opt-in (both or neither): when route is DEEP, the Deep
    pipeline runs on this stronger model instead of `llm`/`model` — same "cheap model can
    lose the strict output format on a long, multi-phase prompt" finding already
    made for the scout stage (`detection/complexity.py`), now confirmed for Deep
    verification too: `claude-cli:haiku` produced substantial, correct-looking Phase 1/2/4
    reports but never emitted a single parseable `GATE ...` line on the final synthesis call
    (defaulting, safely, to FAIL on all 6 gates — the mechanism degrades safely, but that's
    not useful); the IDENTICAL prompt chain on `claude-cli:sonnet` produced all 6 gates in
    the exact required format and the correct TRUE_POSITIVE verdict. Standard route never
    escalates (it's the "already easy" path by construction). Applies only to the PRIMARY
    verifier — a `second_llm` configured for jury verification runs its own Deep pipeline on
    its own given model, no separate strong variant for it yet (an honest, named scope
    limit, not an oversight)."""
    claim = restate_claim(finding)
    bug_class = classify_bug_class(finding)
    route = decide_verification_route(finding, claim, bug_class)
    source_code = "\n\n".join((project_root / f).read_text() for f in unit.source_files)

    gate_results, phase_reports = _run_gates_for_route(
        route, finding, claim, bug_class, source_code, llm, model, strong_llm, strong_model
    )

    secondary_gate_results = None
    if second_llm is not None and second_model is not None:
        secondary_gate_results, _ = _run_gates_for_route(
            route, finding, claim, bug_class, source_code, second_llm, second_model
        )

    return FindingVerdict(
        finding_id=finding.id,
        route=route,
        bug_class=bug_class,
        restated_claim=claim,
        gate_results=gate_results,
        secondary_gate_results=secondary_gate_results,
        verdict=compute_jury_verdict(gate_results, secondary_gate_results),
        deep_phase_reports=phase_reports,
    )


def run_verification_pass(
    findings: list[Finding],
    unit: CDVUnit,
    project_root: Path,
    llm: LLMPort,
    model: str,
    second_llm: LLMPort | None = None,
    second_model: str | None = None,
    strong_llm: LLMPort | None = None,
    strong_model: str | None = None,
) -> list[FindingVerdict]:
    """Verifies every finding for one unit. Mirrors the reference's own "Batch Triage"
    principle of running Step 0 for every finding up front (`restate_claim` inside
    `run_verification` is deterministic and cheap regardless of call order, so a plain loop
    already gets that property without separate batching machinery). `second_llm`/
    `second_model` and `strong_llm`/`strong_model` are opt-in — passed straight through to
    every `run_verification` call."""
    return [
        run_verification(finding, unit, project_root, llm, model, second_llm, second_model, strong_llm, strong_model)
        for finding in findings
    ]

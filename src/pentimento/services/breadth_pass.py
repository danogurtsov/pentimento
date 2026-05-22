"""
Phase 4 orchestration: for each CDV unit, select engines + run Semantic Guard Analysis +
State Synchronization Analysis (all domain-level, free, no LLM) then ask an LLM to run a
BSA breadth-pass — the first actual detection layer downstream of the CDV converter
(Phase 1-3). Fully testable against a fake `LLMPort` (see `ports/llm.py`'s docstring).

Optionally runs Phase 5's functional-primitive routing first (`router_llm`, opt-in — see
`services/routing.py`'s own docstring for why this is a genuine second call, not silently
folded into the main pass) and folds any ACTIVATED domain skill's checklist into the BSA
prompt as extra Phase 2 checks.

Optionally escalates a unit to a STRONGER model (`strong_llm`, also opt-in) when
`detection/complexity.py`'s cheap, deterministic signal recommends it — directly motivated
by a measured finding: the identical fixed prompt caught a real bug on
`claude-cli:sonnet` but missed it twice on `claude-cli:haiku` on one real, complex contract.
The recommendation is always recorded (`ModelDecision`), even when no `strong_llm` was
configured to actually act on it.

Always runs `detection/injection_scan.py`'s cheap deterministic prompt-injection pre-scan
over each unit's own source (no opt-in needed — pure text/regex, no LLM spend) and folds any
signal into the prompt as a named warning — pentimento's first independent defense layer
against its own day-one threat-model assumption, addressing a gap found through testing: a
fixed prompt-injection test case in the detection golden fixtures first surfaced this exact
weakness.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pentimento.detection.complexity import ModelDecision, measure_complexity, should_escalate
from pentimento.detection.engine_selection import select_engines
from pentimento.detection.guard_analysis import GuardAnomaly, analyze_guard_consistency_in_file
from pentimento.detection.injection_scan import InjectionSignal, scan_for_injection
from pentimento.detection.prompts import build_breadth_pass_prompt
from pentimento.detection.routing import RoutingDecision
from pentimento.detection.skills import DomainSkill, skill_for
from pentimento.detection.state_invariants import StateSyncAnomaly, analyze_state_sync_in_file
from pentimento.domain.models import CDVGraph, CDVUnit
from pentimento.ports.llm import LLMPort
from pentimento.services.routing import run_routing


@dataclass(frozen=True)
class BreadthPassResult:
    unit_id: str
    prompt: str
    raw_response: str
    guard_anomalies: list[GuardAnomaly] = field(default_factory=list)
    state_sync_anomalies: list[StateSyncAnomaly] = field(default_factory=list)
    routing_decision: RoutingDecision | None = None
    model_decision: ModelDecision | None = None
    injection_signals: list[InjectionSignal] = field(default_factory=list)


def _guard_anomalies_for(source_files: list[str], project_root: Path) -> list[GuardAnomaly]:
    anomalies: list[GuardAnomaly] = []
    for f in source_files:
        anomalies.extend(analyze_guard_consistency_in_file((project_root / f).read_text()))
    return anomalies


def _state_sync_anomalies_for(source_files: list[str], project_root: Path) -> list[StateSyncAnomaly]:
    anomalies: list[StateSyncAnomaly] = []
    for f in source_files:
        anomalies.extend(analyze_state_sync_in_file((project_root / f).read_text()))
    return anomalies


def _active_skills(
    unit: CDVUnit, project_root: Path, router_llm: LLMPort, router_model: str
) -> tuple[RoutingDecision, list[DomainSkill]]:
    decision = run_routing(unit, project_root, router_llm, router_model)
    skills = [skill_for(d) for d in decision.activated_domains()]
    return decision, skills


def run_breadth_pass(
    graph: CDVGraph,
    project_root: Path,
    llm: LLMPort,
    model: str,
    router_llm: LLMPort | None = None,
    router_model: str | None = None,
    strong_llm: LLMPort | None = None,
    strong_model: str | None = None,
) -> list[BreadthPassResult]:
    """One breadth-pass call per unit. `project_root` must be the same directory the CDV
    manifest's `source_files` are reported relative to (see `cli.py`'s own resolution).
    Both static analyses run per SOURCE FILE (never on the unit's concatenated multi-file
    blob, which would mix unrelated files' state variables/writers together) — the
    `*_in_file` entry points each handle a file's own real declaration(s) correctly
    regardless of imports/multiple contracts, see their own docstrings.

    `router_llm`/`router_model` are opt-in (both or neither): when given, Phase 5's routing
    runs first for the unit (`services/routing.py`) and any ACTIVATED domain skill's
    checklist is folded into the BSA prompt — a genuine second LLM call per unit, so this
    stays off by default rather than silently doubling every existing caller's spend.

    `strong_llm`/`strong_model` are opt-in (both or neither): when `detection.complexity.
    should_escalate` recommends it for a unit AND these are given, that unit's BSA call uses
    the stronger model instead of `llm`/`model` — the recommendation itself is always
    computed and recorded on the result regardless, so "this unit was flagged but stayed on
    the cheap model" is visible, never silent."""
    results: list[BreadthPassResult] = []
    for unit in graph.units:
        source_code = "\n\n".join((project_root / f).read_text() for f in unit.source_files)
        selection = select_engines(unit.node_type, unit.proxy_kind)
        guard_anomalies = _guard_anomalies_for(unit.source_files, project_root)
        state_sync_anomalies = _state_sync_anomalies_for(unit.source_files, project_root)
        injection_signals = scan_for_injection(source_code)

        routing_decision: RoutingDecision | None = None
        active_skills: list[DomainSkill] | None = None
        if router_llm is not None and router_model is not None:
            routing_decision, active_skills = _active_skills(unit, project_root, router_llm, router_model)

        metrics = measure_complexity(source_code)
        recommended = should_escalate(metrics)
        active_llm: LLMPort = llm
        active_model: str = model
        escalated = False
        if recommended and strong_llm is not None and strong_model is not None:
            active_llm, active_model = strong_llm, strong_model
            escalated = True
        model_decision = ModelDecision(metrics, recommended, active_model, escalated)

        prompt = build_breadth_pass_prompt(
            unit,
            source_code,
            selection,
            guard_anomalies=guard_anomalies,
            state_sync_anomalies=state_sync_anomalies,
            active_skills=active_skills,
            injection_signals=injection_signals,
        )
        raw_response = active_llm.complete(prompt, model=active_model)
        results.append(
            BreadthPassResult(
                unit.unit_id,
                prompt,
                raw_response,
                guard_anomalies,
                state_sync_anomalies,
                routing_decision,
                model_decision,
                injection_signals,
            )
        )
    return results

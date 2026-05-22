"""
Phase 5 orchestration: functional-primitive routing as a dedicated LLM call.

Routing runs as a single unified routing step — its own call, not
folded into the BSA breadth-pass call — same separation-of-concerns precedent as
`services/investigation.py`'s scout/strategist split. Kept OPT-IN in `services/
breadth_pass.py` (a `router_llm` the caller must explicitly pass, mirroring `investigate`'s
optional `strategist_llm`) since it's a genuine second LLM call per unit — a real, visible
cost decision, not something to double silently under an existing command's default
behavior.
"""
from __future__ import annotations

from pathlib import Path

from pentimento.detection.domain_signals import DomainSignal, detect_domain_signals_in_file
from pentimento.detection.prompts import build_routing_prompt
from pentimento.detection.routing import RoutingDecision, parse_routing_response
from pentimento.detection.skills import all_skill_ids
from pentimento.detection.solidity_functions import extract_state_variables_and_functions, for_each_declaration
from pentimento.domain.models import CDVUnit
from pentimento.ports.llm import LLMPort


def _function_signatures(source_files: list[str], project_root: Path) -> list[str]:
    signatures: list[str] = []
    for f in source_files:
        raw = (project_root / f).read_text()
        for scoped in for_each_declaration(raw):
            _, functions = extract_state_variables_and_functions(scoped)
            signatures.extend(fn.signature.strip() for fn in functions)
    return signatures


def _domain_signals_for(source_files: list[str], project_root: Path) -> list[DomainSignal]:
    signals: list[DomainSignal] = []
    for f in source_files:
        signals.extend(detect_domain_signals_in_file((project_root / f).read_text()))
    return signals


def run_routing(unit: CDVUnit, project_root: Path, llm: LLMPort, model: str) -> RoutingDecision:
    """One routing call per unit: cheap pre-flagged smells (`domain_signals.py`) + function
    signatures only (never full bodies, see `build_routing_prompt`'s own docstring) sent to
    `llm`, parsed into a typed `RoutingDecision` covering every known skill explicitly."""
    signatures = _function_signatures(unit.source_files, project_root)
    signals = _domain_signals_for(unit.source_files, project_root)
    skill_ids = all_skill_ids()
    prompt = build_routing_prompt(unit, signatures, signals, skill_ids)
    raw = llm.complete(prompt, model=model)
    return parse_routing_response(raw, unit.unit_id, skill_ids)

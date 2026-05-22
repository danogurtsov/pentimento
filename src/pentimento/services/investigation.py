"""
Scout/strategist investigation with a persistent graph — Phase 4,
a hound-style scout/strategist pattern with a persistent graph.

hound (github.com/muellerberndt/hound) runs a cheap SCOUT pass across a whole codebase, then a STRATEGIST decides which
findings deserve a more expensive DEEP pass — asymmetric effort, not the same expensive
analysis everywhere. This mirrors that shape on top of what already exists rather than
building a parallel system: the scout IS `services/breadth_pass.py` (already the cheap
per-unit pass, already tested, already run live). This module adds:

1. The STRATEGIST decision (`decide_escalation`) — deterministic, no LLM call, same "decide
   whether to spend more, don't spend more to decide" principle as engine selection and the
   two static anomaly detectors: a unit escalates if its pre-flagged guard/state-sync
   anomalies already reached critical/high severity, OR the scout's own response reported a
   Critical/High finding.
2. A DEEP investigation prompt (`build_deep_investigation_prompt` in `prompts.py`) that
   feeds an escalated unit's scout findings back in as context to VERIFY, not rediscover
   from scratch — a small, deliberately scoped step toward Phase 6's "independent verification",
   not an attempt at that whole phase here.
3. A PERSISTENT `InvestigationGraph` — serializable to/from JSON, so a later run can inspect
   what was already scouted/escalated/investigated without re-running the scout pass, and
   so the record survives past a single CLI invocation the way hound's own substrate does.

Deliberately NOT built here: hound's own richer graph (cross-unit relationships, a
knowledge base that accumulates across MULTIPLE runs of MULTIPLE projects, a spellbook with
a regression gate for its own heuristics). This is the first slice — one run's scout
results plus one deterministic escalation decision plus one optional deep pass — not the
full architecture.

Optionally runs Phase 6's Trail-of-Bits-style verification (`verifier_llm`, opt-in — see
`services/verification.py`'s own docstring) over every parsed Finding from a unit's FINAL
response (the deep pass's response if one ran, else the scout's) — a third, genuinely
separate LLM call per FINDING (not per unit), so this stays off by default.

Optionally, ON TOP of that, runs the Level 1 deterministic PoC oracle (`poc_llm`/
`poc_executor`, also opt-in — see `services/poc_verification.py`'s own docstring) for every
finding verification rated TRUE_POSITIVE — a real `forge test` compile+execute cycle per
such finding, the strongest and most expensive tier, so it only ever runs on top of an
already-given `verifier_llm` and stays off by default too.

`second_verifier_llm`/`second_verifier_model` (opt-in, requires `verifier_llm`
too) run a genuinely independent SECOND verifier per finding — see `services/
verification.py`'s own docstring for the multi-model-jury pattern this implements.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

from pentimento.detection.findings import parse_findings
from pentimento.detection.prompts import build_deep_investigation_prompt
from pentimento.domain.models import CDVGraph
from pentimento.ports.llm import LLMPort
from pentimento.ports.poc_executor import PoCExecutorPort
from pentimento.services.breadth_pass import BreadthPassResult, run_breadth_pass
from pentimento.services.poc_verification import run_poc_verification
from pentimento.services.verification import run_verification_pass

_ESCALATE_SEVERITIES = {"critical", "high"}
_RAW_RESPONSE_SEVERITY_RE = re.compile(r"Severity:\s*(Critical|High)\b", re.IGNORECASE)


class UnitStatus(StrEnum):
    SCOUTED = "scouted"  # scout pass done, not escalated
    ESCALATED = "escalated"  # strategist flagged for a deep pass, none run yet
    INVESTIGATED = "investigated"  # deep pass done


@dataclass
class UnitRecord:
    unit_id: str
    status: UnitStatus
    scout_response: str
    scout_guard_anomalies: list[dict] = field(default_factory=list)
    scout_state_sync_anomalies: list[dict] = field(default_factory=list)
    escalation_reason: str | None = None
    deep_response: str | None = None
    finding_verdicts: list[dict] = field(default_factory=list)
    poc_verifications: list[dict] = field(default_factory=list)
    scout_model_decision: dict | None = None
    scout_routing_decision: dict | None = None
    scout_injection_signals: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict) -> UnitRecord:
        return cls(
            unit_id=data["unit_id"],
            status=UnitStatus(data["status"]),
            scout_response=data["scout_response"],
            scout_guard_anomalies=data.get("scout_guard_anomalies", []),
            scout_state_sync_anomalies=data.get("scout_state_sync_anomalies", []),
            escalation_reason=data.get("escalation_reason"),
            deep_response=data.get("deep_response"),
            finding_verdicts=data.get("finding_verdicts", []),
            poc_verifications=data.get("poc_verifications", []),
            scout_model_decision=data.get("scout_model_decision"),
            scout_routing_decision=data.get("scout_routing_decision"),
            scout_injection_signals=data.get("scout_injection_signals", []),
        )


@dataclass
class InvestigationGraph:
    generator: str
    units: dict[str, UnitRecord] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"generator": self.generator, "units": {uid: r.to_dict() for uid, r in self.units.items()}}

    @classmethod
    def from_dict(cls, data: dict) -> InvestigationGraph:
        return cls(
            generator=data["generator"],
            units={uid: UnitRecord.from_dict(r) for uid, r in data["units"].items()},
        )

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: Path) -> InvestigationGraph:
        return cls.from_dict(json.loads(path.read_text()))


def decide_escalation(result: BreadthPassResult) -> str | None:
    """A human-readable escalation reason if this unit's scout pass warrants a deeper
    investigation, else None. Deterministic, no LLM call."""
    critical_count = sum(1 for a in result.guard_anomalies if a.severity in _ESCALATE_SEVERITIES)
    critical_count += sum(1 for a in result.state_sync_anomalies if a.severity in _ESCALATE_SEVERITIES)
    if critical_count:
        return f"{critical_count} pre-flagged critical/high anomaly(ies) before scout verification"
    match = _RAW_RESPONSE_SEVERITY_RE.search(result.raw_response)
    if match:
        return f"scout pass reported a {match.group(1)} finding"
    return None


def run_investigation(
    graph: CDVGraph,
    project_root: Path,
    scout_llm: LLMPort,
    scout_model: str,
    strategist_llm: LLMPort | None = None,
    strategist_model: str | None = None,
    verifier_llm: LLMPort | None = None,
    verifier_model: str | None = None,
    poc_llm: LLMPort | None = None,
    poc_model: str | None = None,
    poc_executor: PoCExecutorPort | None = None,
    poc_test_dir: str = "test",
    poc_allow_ffi: bool = False,
    strong_scout_llm: LLMPort | None = None,
    strong_scout_model: str | None = None,
    router_llm: LLMPort | None = None,
    router_model: str | None = None,
    second_verifier_llm: LLMPort | None = None,
    second_verifier_model: str | None = None,
    strong_verifier_llm: LLMPort | None = None,
    strong_verifier_model: str | None = None,
) -> InvestigationGraph:
    """Runs the scout pass (`run_breadth_pass`) over every unit, then the strategist
    decision over every result. If `strategist_llm` is given, escalated units also get an
    immediate deep pass (`build_deep_investigation_prompt`); if not, escalation is still
    recorded (a real, useful result on its own — "here's what needs a second look") without
    spending on a second call.

    `router_llm`/`router_model` are opt-in: passed straight through to the scout pass's own
    `run_breadth_pass` as its `router_llm`/`router_model` — same Phase 5 functional-primitive
    routing `breadth-pass --route` already offers, previously unreachable from `investigate`
    at all (a real gap: the scout IS `run_breadth_pass`, but this parameter was never
    threaded through here until now).

    If `verifier_llm` is given, every Finding parsed out of a unit's FINAL response (the
    deep pass's response if one ran, else the scout's) goes through Phase 6's Trail-of-Bits
    verification (`services/verification.py` — Standard OR Deep path, chosen automatically
    per finding by `detection.verdict.decide_verification_route`) — 1 real LLM call per
    finding on Standard, 4 on Deep, so this stays off by default rather than silently
    multiplying every existing caller's spend.

    If `poc_llm`+`poc_executor` are ALSO given (both required together), every finding
    verification rated TRUE_POSITIVE additionally goes through the Level 1 deterministic
    PoC oracle (`services/poc_verification.py`) — a real `forge test` compile+execute cycle,
    the strongest and most expensive tier, so it only ever runs on top of `verifier_llm` and
    stays off by default.

    `strong_scout_llm`/`strong_scout_model` are opt-in: passed straight through to the scout
    pass's own `run_breadth_pass` as its `strong_llm`/`strong_model` — a unit `detection.
    complexity.should_escalate` flags gets scouted with the stronger model instead of
    `scout_llm`/`scout_model` (measured evidence motivates this).

    `poc_allow_ffi` (default False) is passed straight through to `run_poc_verification`'s
    own `allow_ffi` — see that function's docstring for why refusing an ffi-enabled target
    project is the real, security-motivated default, not a convenience one.

    `second_verifier_llm`/`second_verifier_model` are opt-in (both or neither, and only
    meaningful alongside `verifier_llm`): passed straight through to `run_verification_pass`
    as its own `second_llm`/`second_model` — a genuinely independent second verifier call
    per finding, see `services/verification.py`'s own docstring for the jury/dissent rule.

    `strong_verifier_llm`/`strong_verifier_model` are opt-in: passed straight through to
    `run_verification_pass` as its own `strong_llm`/`strong_model` — used instead of
    `verifier_llm`/`verifier_model` whenever a finding routes to Deep verification (a
    measured finding: a cheap model can produce substantial-looking Deep phase reports
    but fail to emit the required `GATE ...` format on the final synthesis call; the
    identical prompt chain on a stronger model does not)."""
    scout_results = run_breadth_pass(
        graph,
        project_root,
        scout_llm,
        model=scout_model,
        strong_llm=strong_scout_llm,
        strong_model=strong_scout_model,
        router_llm=router_llm,
        router_model=router_model,
    )
    units_by_id = {u.unit_id: u for u in graph.units}
    investigation = InvestigationGraph(generator="pentimento-investigation/0.0.1")

    for result in scout_results:
        record = UnitRecord(
            unit_id=result.unit_id,
            status=UnitStatus.SCOUTED,
            scout_response=result.raw_response,
            scout_guard_anomalies=[asdict(a) for a in result.guard_anomalies],
            scout_state_sync_anomalies=[asdict(a) for a in result.state_sync_anomalies],
            scout_model_decision=asdict(result.model_decision) if result.model_decision else None,
            scout_routing_decision=asdict(result.routing_decision) if result.routing_decision else None,
            scout_injection_signals=[asdict(s) for s in result.injection_signals],
        )
        reason = decide_escalation(result)
        if reason:
            record.status = UnitStatus.ESCALATED
            record.escalation_reason = reason
            if strategist_llm is not None and strategist_model is not None:
                unit = units_by_id[result.unit_id]
                source_code = "\n\n".join((project_root / f).read_text() for f in unit.source_files)
                deep_prompt = build_deep_investigation_prompt(unit, source_code, result.raw_response, reason)
                record.deep_response = strategist_llm.complete(deep_prompt, model=strategist_model)
                record.status = UnitStatus.INVESTIGATED

        if verifier_llm is not None and verifier_model is not None:
            final_response = record.deep_response or record.scout_response
            findings = parse_findings(final_response)
            if findings:
                unit = units_by_id[result.unit_id]
                verdicts = run_verification_pass(
                    findings,
                    unit,
                    project_root,
                    verifier_llm,
                    verifier_model,
                    second_verifier_llm,
                    second_verifier_model,
                    strong_verifier_llm,
                    strong_verifier_model,
                )
                record.finding_verdicts = [asdict(v) for v in verdicts]

                if poc_llm is not None and poc_model is not None and poc_executor is not None:
                    findings_by_id = {f.id: f for f in findings}
                    poc_results = []
                    for finding_verdict in verdicts:
                        poc_result = run_poc_verification(
                            findings_by_id[finding_verdict.finding_id],
                            finding_verdict,
                            unit,
                            project_root,
                            poc_llm,
                            poc_model,
                            poc_executor,
                            test_dir=poc_test_dir,
                            allow_ffi=poc_allow_ffi,
                        )
                        if poc_result is not None:
                            poc_results.append(asdict(poc_result))
                    record.poc_verifications = poc_results

        investigation.units[result.unit_id] = record

    return investigation

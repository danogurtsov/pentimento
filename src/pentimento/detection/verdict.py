"""
Typed verification schema — Phase 6, adopting Trail of Bits' own fp-check protocol as the
explicit starting template for this stage, not a parallel structure invented from scratch.

**Standard path.** The real, typed Step 0 restate-claim + Standard/Deep ROUTING DECISION
(`decide_verification_route`) — its recommendation is always computed and recorded (same
"signal built, action deferred" precedent as Phase 5's routing recording every domain
explicitly). 13-question Devil's Advocate, PoC pseudocode sketch (4.1 only — 4.2/4.3
executable/unit-test PoC require actual code execution tooling this text-only verifier
doesn't have), and the 6 mandatory gates are all in the single Standard-path prompt
(`prompts.build_verification_prompt`) — the reference document's own architecture diagram
literally describes Standard as ONE linear pass through these steps, not parallel
sub-agents.

**Independent jury verification (opt-in, off by default)**: `compute_jury_verdict` lets a
SECOND, independent verifier's gate results override a lone verifier's own TRUE_POSITIVE
into FALSE_POSITIVE on dissent — the multi-model-jury / independent-refuter pattern this
project's verification design names as core. See that function's own docstring.

**The Deep path is fully executed, not just routed and recorded.**
`services/verification.py::_run_deep_pipeline` runs the reference's own 4-phase "full
task-based orchestration" (Data Flow → Exploitability → PoC → [Impact + Devil's Advocate +
Gate Review]) as 4 sequential calls, each phase's raw output feeding forward into the next
— see `detection/prompts.py`'s own Deep-path prompt builders. Both paths produce the exact
same `FindingVerdict` shape; only `deep_phase_reports` (new field below) differs.

**The verdict is computed by CODE, never asserted by the model** — `compute_verdict` is the
ONLY place TRUE_POSITIVE/FALSE_POSITIVE gets decided, from parsed per-gate PASS/FAIL alone.
This mirrors digger's own `decide_valid_finding` being architecturally unavailable to the
LLM, and the reference's own literal rule ("ALL must pass for TRUE POSITIVE. Any failure =
FALSE POSITIVE") — same "typed decision the model feeds facts into, never the verdict text
itself" discipline as Phase 5's `RoutingDecision`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pentimento.detection.findings import Finding


class Gate(StrEnum):
    """Verbatim the reference's own 6 mandatory gates, in their own table order."""

    PROCESS = "process"
    REACHABILITY = "reachability"
    REAL_IMPACT = "real_impact"
    POC_VALIDATION = "poc_validation"
    MATH_BOUNDS = "math_bounds"
    ENVIRONMENT = "environment"


ALL_GATES: tuple[Gate, ...] = tuple(Gate)


class VerificationRoute(StrEnum):
    STANDARD = "standard"
    DEEP = "deep"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True)
class RestatedClaim:
    vulnerability_claim: str
    root_cause: str
    trigger: str
    claimed_impact: str
    is_vague: bool


@dataclass(frozen=True)
class GateResult:
    gate: Gate
    passed: bool
    reason: str


@dataclass(frozen=True)
class FindingVerdict:
    finding_id: str
    route: VerificationRoute
    bug_class: str
    restated_claim: RestatedClaim
    gate_results: tuple[GateResult, ...]
    verdict: Verdict
    # Second independent verifier's own gate results, when one ran (opt-in — see
    # `compute_jury_verdict`). `None` (the default) means only one verifier ran — every
    # existing caller that never configures a second verifier sees IDENTICAL behavior,
    # this field simply stays absent, `verdict` reduces to the single-verifier decision.
    secondary_gate_results: tuple[GateResult, ...] | None = None
    # The 3 raw Deep-path phase reports (dataflow/exploitability/poc), keyed by name, when
    # `route == VerificationRoute.DEEP` actually executed the deep pipeline (see
    # `services/verification.py::_run_deep_pipeline`). `None` for a Standard-path verdict -
    # there's nothing to show, not an omission. Kept for transparency/auditability, same
    # "don't throw away evidence you gathered" discipline as everything else here.
    deep_phase_reports: dict[str, str] | None = None


_MIN_WORDS_NOT_VAGUE = 4


def restate_claim(finding: Finding) -> RestatedClaim:
    """Step 0, deterministic, no LLM call — reformats a Finding's OWN already-structured
    fields into the reference's restate-claim shape rather than re-deriving them. `is_vague`
    is the reference's own "half of FPs collapse here" signal computed BEFORE any
    verification spend: a root cause, exploit description, or location too thin to mean
    anything is a real, cheap pre-flag, same "cheap signal narrows expensive reasoning"
    principle as `domain_signals.py`/`guard_analysis.py`."""
    vague = (
        len(finding.root_cause.split()) < _MIN_WORDS_NOT_VAGUE
        or len(finding.exploit.split()) < _MIN_WORDS_NOT_VAGUE
        or not finding.location.strip()
    )
    return RestatedClaim(
        vulnerability_claim=finding.title,
        root_cause=finding.root_cause,
        trigger=finding.exploit,
        claimed_impact=finding.impact,
        is_vague=vague,
    )


# Deterministic, keyword-based — a real classification grounded in the reference's own
# "Bug-Class-Specific Verification" categories, narrowed to the ones that actually apply to
# Solidity (their memory-corruption/crypto/deserialization categories target C/Java-shaped
# bugs, not smart contracts) rather than invented from scratch.
_BUG_CLASS_KEYWORDS: dict[str, tuple[str, ...]] = {
    "reentrancy": ("reentran", "callback", "read-only reentran"),
    "access_control": ("onlyowner", "access control", "unauthorized", "privileg", "role-gated", "role check"),
    "integer_arithmetic": ("overflow", "underflow", "rounding", "precision loss", "truncat", "downcast"),
    "race_condition_toctou": ("front-run", "frontrun", "race condition", "toctou", "reorder", "sandwich"),
    "oracle_price_manipulation": ("oracle", "price manipulation", "twap", "spot price", "flash loan"),
    "logic_state_integrity": ("invariant", "accounting", "desync", "double-count", "double count", "state"),
}


def classify_bug_class(finding: Finding) -> str:
    lowered = f"{finding.title} {finding.root_cause}".lower()
    for bug_class, keywords in _BUG_CLASS_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return bug_class
    return "unclassified"


_SOL_FILE_RE = re.compile(r"[\w./-]+\.sol")


def decide_verification_route(finding: Finding, claim: RestatedClaim, bug_class: str) -> VerificationRoute:
    """Verbatim the reference's own routing bullets (`## Routing Decision`): DEEP when the
    claim is ambiguous (this repo's own `is_vague` signal), the bug path crosses 2+
    contracts, it's a race/TOCTOU class, or it's a logic/state-integrity bug without a clear
    spec (their own "logic bugs without a clear spec" bullet) — STANDARD otherwise. Recorded
    regardless of whether the Deep path actually runs (see module docstring)."""
    if claim.is_vague:
        return VerificationRoute.DEEP
    if bug_class in ("race_condition_toctou", "logic_state_integrity"):
        return VerificationRoute.DEEP
    if len(set(_SOL_FILE_RE.findall(finding.location))) >= 2:
        return VerificationRoute.DEEP
    return VerificationRoute.STANDARD


_GATE_LINE_RE = re.compile(r"^GATE\s+(\w+):\s*(PASS|FAIL)\s*[—-]\s*(.+)$", re.IGNORECASE)
_NOT_ADDRESSED_REASON = "verifier response never addressed this gate explicitly"


def parse_gate_results(raw: str) -> tuple[GateResult, ...]:
    """Parses `GATE <name>: PASS|FAIL — <reason>` lines (see
    `detection/prompts.build_verification_prompt`'s own output-format instructions). A gate
    the response never mentions is recorded as an explicit FAIL, never silently dropped or
    assumed to pass — the reference's own "ALL must pass" rule means an unaddressed gate
    cannot be said to have passed (same non-silence discipline as `detection/routing.py`'s
    `parse_routing_response`, adapted: default-to-FAIL here, not default-to-SKIP, since
    passing is the thing that must be proven)."""
    found: dict[Gate, GateResult] = {}
    for line in raw.splitlines():
        match = _GATE_LINE_RE.match(line.strip())
        if not match:
            continue
        name, verdict, reason = match.groups()
        try:
            gate = Gate(name.lower())
        except ValueError:
            continue
        found[gate] = GateResult(gate, verdict.upper() == "PASS", reason.strip())

    return tuple(found.get(gate, GateResult(gate, False, _NOT_ADDRESSED_REASON)) for gate in ALL_GATES)


def compute_verdict(gate_results: tuple[GateResult, ...]) -> Verdict:
    """The ONLY place a TRUE_POSITIVE/FALSE_POSITIVE verdict is decided — by code, from
    gate results alone, never asserted by the model itself (see module docstring)."""
    return Verdict.TRUE_POSITIVE if all(g.passed for g in gate_results) else Verdict.FALSE_POSITIVE


def compute_jury_verdict(
    primary_gates: tuple[GateResult, ...], secondary_gates: tuple[GateResult, ...] | None = None
) -> Verdict:
    """Independent-refuter / multi-model-jury pattern (mnedelchev's clean-context refuter,
    Critikal's multi-model jury), and the exact thing this project's own verification
    design names as core: nothing is published without independent review by at least two
    different judges, ideally different models.

    `secondary_gates=None` (the default) reduces to plain `compute_verdict(primary_gates)` —
    fully backward compatible, every existing single-verifier caller sees no behavior
    change. When a second, independent verifier's gate results ARE given: TRUE_POSITIVE
    requires BOTH verifiers to independently reach TRUE_POSITIVE on their own gates — a
    single dissent from either one is enough to flip the overall verdict to FALSE_POSITIVE.
    Deliberately asymmetric (easier to reject than to confirm), the same "burden of proof is
    on the claim" philosophy `detection/prompts.build_verification_prompt` already states
    within one verifier's own 13 Devil's Advocate questions, applied one level up, across
    two independent judges instead of within one."""
    primary_verdict = compute_verdict(primary_gates)
    if secondary_gates is None:
        return primary_verdict
    secondary_verdict = compute_verdict(secondary_gates)
    if primary_verdict == Verdict.TRUE_POSITIVE and secondary_verdict == Verdict.TRUE_POSITIVE:
        return Verdict.TRUE_POSITIVE
    return Verdict.FALSE_POSITIVE

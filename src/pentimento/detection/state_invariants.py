"""
State Synchronization Analysis — a statically-achievable SUBSET of QuillShield Layer 2
("State Invariant Detection") — Phase 4. Pure text/regex analysis, no AST, no LLM, no I/O,
built on `solidity_functions.py`'s shared extraction primitives.

Honest scope limitation, stated up front rather than buried: QuillShield's own Layer 2
names FIVE relationship types (Sum, Difference/Conservation, Ratio, Monotonic,
Synchronization) and a 3-phase pipeline whose Phase 3 ("Invariant Violation Detection")
explicitly SIMULATES execution — "Before: Capture (stateA, stateB) / Simulate: Execute F /
After: Capture (stateA', stateB')". That is dynamic analysis (an EVM execution engine),
fundamentally out of reach for a pure static/text tool — this repo has no execution engine
and isn't getting one for this. What IS achievable statically, and what this module does:
**Phase 1 (Clustering) verbatim** — co-modification frequency between state variable pairs
— plus a **structural substitute for Phase 2/3**: instead of inferring the exact
mathematical relationship and simulating a violation, this looks at the WRITE OPERATOR
each co-modifying function uses on each variable (increment vs decrement) to classify the
pair as "synchronized" (both variables move the same direction together — Sum type) or
"conservation" (they move opposite directions together — Difference/Conservation type),
then flags any function that touches only ONE side of an established pair as a candidate
gap — the same "frequency anomaly" shape as `guard_analysis.py`'s Consistency Hypothesis,
just applied to a PAIR OF VARIABLES instead of a variable-and-its-guard. Ratio and
Monotonic relationships (types 3/4) aren't attempted at all: a ratio invariant
(`k = reserveA * reserveB`) needs cross-variable ARITHMETIC reasoning this text-level
analysis has no way to recover, and a monotonic invariant (`newValue >= oldValue`) is a
property of a SINGLE variable across calls, not a pairing — neither fits this module's
shape, and guessing at them would be exactly the kind of overreach this project's own
"conservative signal" principle argues against.

Severity is capped deliberately lower than `guard_analysis.py`'s: that module flags a
MISSING explicit security check (a real, if unverified, code fact); this module flags a
STRUCTURAL asymmetry between two variables that COULD indicate an accounting gap but is
never confirmed by actual execution — a weaker, more speculative signal, and its severity
scale says so honestly (capped at "high", never "critical").
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations

from pentimento.detection.solidity_functions import (
    FunctionInfo,
    extract_modifiers,
    extract_state_variables_and_functions,
    for_each_declaration,
    has_decrement,
    has_increment,
    is_externally_reachable,
    is_privileged,
    writes_to,
)

Relationship = str  # "synchronized" | "conservation"
Severity = str  # "high" | "medium" | "low"

_FINANCIAL_VAR_HINTS = ("balance", "supply", "reserve", "amount", "asset", "share", "fund", "collateral", "debt")
_MIN_SAMPLE = 3  # same reasoning as guard_analysis.py: fewer functions can't establish a real pattern
_COMOD_THRESHOLD = 0.6  # verbatim from the reference: "CoMod(A, B) > 0.6 -> A and B are likely related"


def _direction(var: str, body: str) -> str:
    """"increment" | "decrement" | "mixed" | "other" (a plain `x = expr` with no
    recognizable +/- shape, or both an increment and a decrement pattern present) — reuses
    `solidity_functions.has_increment`/`has_decrement` so a write reached through a local
    storage-pointer alias (`Series storage s = _series[id]; s.subscribedLong += x;`, the
    most common way real Solidity accesses per-id struct state) is classified the same way
    a direct write would be."""
    inc = has_increment(var, body)
    dec = has_decrement(var, body)
    if inc and dec:
        return "mixed"
    if inc:
        return "increment"
    if dec:
        return "decrement"
    return "other"


@dataclass(frozen=True)
class StateSyncAnomaly:
    variable_a: str
    variable_b: str
    relationship: Relationship
    comod_frequency: float
    violating_function: str
    missing_variable: str  # which of variable_a/variable_b this function does NOT touch
    severity: Severity


def _severity(variable_a: str, variable_b: str, comod_frequency: float) -> Severity:
    both_financial = all(
        any(h in v.lower() for h in _FINANCIAL_VAR_HINTS) for v in (variable_a, variable_b)
    )
    if both_financial and comod_frequency >= 0.8:
        return "high"
    if comod_frequency >= 0.8:
        return "medium"
    return "low"


def analyze_state_sync(contract_source: str) -> list[StateSyncAnomaly]:
    """`contract_source` must already be scoped to ONE contract declaration (see
    `solidity_functions.extract_state_variables_and_functions`).

    For each pair of state variables with a co-modification frequency >= 0.6 across 3+
    externally-reachable functions that touch either one (constructors and internal/
    private helpers excluded — same `is_externally_reachable` reasoning as
    `guard_analysis.py`'s real false positive on an internal helper, see its docstring)
    (QuillShield's own CoMod threshold, Phase 1), and a majority-agreeing write-direction
    relationship among the co-modifying functions (Sum-like "synchronized" or
    Conservation-like "opposite"), flags any function that writes only ONE side of the pair
    as a candidate gap — UNLESS it sits in a different privilege tier than the majority of
    paired writers (same Privilege Overlay reasoning as `guard_analysis.py`)."""
    state_vars, functions = extract_state_variables_and_functions(contract_source)
    reachable = [f for f in functions if is_externally_reachable(f)]
    privileged_by_name = {f.name: is_privileged(extract_modifiers(f)) for f in reachable}
    by_name: dict[str, FunctionInfo] = {f.name: f for f in reachable}

    anomalies: list[StateSyncAnomaly] = []

    for var_a, var_b in combinations(sorted(state_vars), 2):
        writers_a = {f.name for f in reachable if writes_to(var_a, f.body)}
        writers_b = {f.name for f in reachable if writes_to(var_b, f.body)}
        either = writers_a | writers_b
        both = writers_a & writers_b
        if len(either) < _MIN_SAMPLE or len(both) < 2:
            continue

        comod_frequency = len(both) / len(either)
        if comod_frequency < _COMOD_THRESHOLD:
            continue

        pair_directions = [
            (_direction(var_a, by_name[name].body), _direction(var_b, by_name[name].body)) for name in both
        ]
        relationship_votes: dict[Relationship, int] = {"synchronized": 0, "conservation": 0}
        for dir_a, dir_b in pair_directions:
            if dir_a in ("mixed", "other") or dir_b in ("mixed", "other"):
                continue
            relationship_votes["synchronized" if dir_a == dir_b else "conservation"] += 1
        decided = max(relationship_votes, key=lambda r: relationship_votes[r])
        if relationship_votes[decided] <= len(both) / 2:
            continue  # no majority-agreeing relationship shape - too ambiguous to flag

        majority_privileged = sum(privileged_by_name[name] for name in both) > len(both) / 2

        for name in either - both:
            if privileged_by_name[name] != majority_privileged:
                continue
            missing = var_b if name in writers_a else var_a
            anomalies.append(
                StateSyncAnomaly(
                    variable_a=var_a,
                    variable_b=var_b,
                    relationship=decided,
                    comod_frequency=comod_frequency,
                    violating_function=name,
                    missing_variable=missing,
                    severity=_severity(var_a, var_b, comod_frequency),
                )
            )

    return anomalies


def analyze_state_sync_in_file(raw_source: str) -> list[StateSyncAnomaly]:
    """Entry point for a RAW, unscoped file — see `solidity_functions.for_each_declaration`
    for how each real declaration is found and scoped, regardless of imports or multiple
    contracts in one file."""
    anomalies: list[StateSyncAnomaly] = []
    for scoped in for_each_declaration(raw_source):
        anomalies.extend(analyze_state_sync(scoped))
    return anomalies

"""
Semantic Guard Analysis (QuillShield Layer 1: "the Consistency Hypothesis") — Phase 4.
Pure text/regex analysis, no AST, no LLM, no I/O — built on `solidity_functions.py`'s
shared extraction primitives (see that module's own docstring for why parsing is shared,
not duplicated, between this and `state_invariants.py`).

Core idea, verbatim from QuillShield's own semantic protocol: "A smart contract is
its own specification." If most of the functions that WRITE a given state variable also
check a particular GUARD (a modifier or a `require()`), the minority that don't is a real,
cheap, domain-independent anomaly signal — entirely different from checking against
external rules, and computable BEFORE any LLM call (same "route/flag before you spend"
principle as `detection/engine_selection.py`). Their own canonical example:
`emergencyWithdraw()` writes `balance` with no guard, while every other writer checks
`paused`/`whenNotPaused` — `tests/test_guard_analysis.py`'s own inline fixture reproduces
that exact shape.

Deliberate v1 simplification, a known, documented limitation: a guard is identified by NAME
only (a modifier's own name, or the single identifier a SIMPLE `require()`/`if(...) revert`
condition tests) — this does NOT resolve into a modifier's own body to see what it actually
checks, so two differently-named modifiers that check the same underlying thing are treated
as two unrelated guards. Real parser (solc's own AST) is the upgrade path if this proves too
coarse in practice.

Real bugs found and fixed running this against real code — not just its own fixture, the
same discipline every primitive in this repo has paid off on:
- Two parsing-level bugs (import braces confusing a naive brace scan; NatSpec comments
  hiding the `function` keyword from an anchored match) now live in `solidity_functions.py`
  since every detector built on it needs the same fix, not guard-analysis-specific.
- Solidity's base-constructor-chaining syntax (`constructor(...) ERC20() Ownable(owner)
  { ... }`) is syntactically identical to a function's modifier list, so every base class
  name was treated as a "guard" only the constructor has.
- An internal-only helper (`_pullCollateral()` on real Tremolo/VarianceMarket.sol) was
  flagged for lacking a guard (`nonReentrant`) that its actual PUBLIC callers already
  enforce — an internal helper isn't independently reachable, so it's not a meaningful peer
  for guard-consistency comparison against public entry points at all.
- Fixed by requiring writers to be externally reachable (`solidity_functions.
  is_externally_reachable` — excludes constructors AND internal/private helpers in one
  check) and requiring 3+ such writers (2 can only ever produce a trivial, meaningless
  50/50 split in both directions).
- A LOOSER version of guard-token extraction ("every bare identifier in a require/if
  condition") looked fine on every fixture and on real code with few writers, but once
  real writer counts got large enough (10+, after `solidity_functions.py`'s storage-alias
  fix made previously-invisible writes visible at all) it started finding 100+
  "anomalies" from common tokens (`state`, `s`, even the Solidity type name `State`)
  coincidentally recurring across unrelated conditions like `require(s.state ==
  State.SUBSCRIBING, ...)` often enough to clear the 50% threshold by sheer coincidence.
  Fixed by restricting condition-derived guards to SIMPLE (bare or negated) conditions
  only — a real guard in QuillShield's own sense is a single, deliberately named boolean
  flag, not an arbitrary business-logic comparison.
- A file-wide `declared_names()` bug (also now in `solidity_functions.py`) matched the
  literal word "contract" inside ordinary NatSpec prose ("this **contract holds**...") as
  if it were a real declaration, causing every finding in a file to be silently
  triple/quadruple-counted once each spurious "declaration" independently re-ran the same
  analysis against the fallback (whole-file) text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentimento.detection.solidity_functions import (
    FunctionInfo,
    extract_modifiers,
    extract_state_variables_and_functions,
    for_each_declaration,
    is_externally_reachable,
    is_privileged,
    writes_to,
)

Severity = str  # "critical" | "high" | "medium"
InvariantStrength = str  # "strong" | "weak"

_FINANCIAL_VAR_HINTS = ("balance", "supply", "reserve", "amount", "asset", "share", "fund", "collateral", "debt")
_GUARD_TOKEN_STOPLIST = {"msg", "block", "tx", "this", "true", "false", "address", "uint256", "bytes32"}


@dataclass(frozen=True)
class GuardAnomaly:
    state_variable: str
    guard: str
    guard_frequency: float
    invariant_strength: InvariantStrength
    violating_function: str
    severity: Severity


_SIMPLE_CONDITION_RE = re.compile(r"^!?\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$")


def _guard_condition_identifier(condition: str) -> str | None:
    """The single identifier a SIMPLE (bare or negated) `require()`/`if` condition tests —
    `!paused` -> `paused`, `initialized` -> `initialized`, `!vault.paused` -> `vault.paused`.

    Deliberately conservative — real bug found running this against real Tremolo/
    VarianceMarket.sol, not anticipated from any self-authored fixture: once real writer
    counts got large enough (10+, after the storage-alias fix in solidity_functions.py
    made those writers visible at all), a looser "every identifier in the condition"
    extraction started finding 100+ "anomalies" purely from common tokens (`state`, `s`,
    `timestamp`, even the Solidity type name `State`) coincidentally recurring across
    MULTIPLE UNRELATED conditions like `require(s.state == State.SUBSCRIBING, ...)` at
    high enough frequency to clear the 50% threshold by sheer coincidence. A real guard
    in QuillShield's own sense (`whenNotPaused`/`initialized`) is a single, deliberately
    named boolean flag — not an arbitrary business-logic comparison — so a condition with
    a comparison/logical operator/function call is skipped entirely rather than guessed at."""
    match = _SIMPLE_CONDITION_RE.match(condition.strip())
    return match.group(1) if match else None


def _extract_condition_guards(body: str) -> set[str]:
    guards: set[str] = set()
    for match in re.finditer(r"\b(?:require|if)\s*\(", body):
        depth = 0
        start = match.end() - 1
        for i in range(start, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    condition = body[start + 1 : i]
                    # require(cond, "message") - only the condition, not the message string
                    condition = condition.split(",", 1)[0]
                    guard = _guard_condition_identifier(condition)
                    if guard and guard not in _GUARD_TOKEN_STOPLIST:
                        guards.add(guard)
                    break
    return guards


def _guard_tokens(f: FunctionInfo) -> set[str]:
    return extract_modifiers(f) | _extract_condition_guards(f.body)


def _severity(state_variable: str, strength: InvariantStrength) -> Severity:
    if strength == "strong":
        return "critical" if any(h in state_variable.lower() for h in _FINANCIAL_VAR_HINTS) else "high"
    return "medium"


def analyze_guard_consistency(contract_source: str) -> list[GuardAnomaly]:
    """`contract_source` must already be scoped to ONE contract declaration (see
    `solidity_functions.extract_state_variables_and_functions`) — an unscoped, whole-file
    source would mix unrelated sibling contracts' writers/guards into the same matrix.

    For each state variable with 3+ externally-reachable writer functions (constructors
    and internal/private helpers excluded — see module docstring and
    `solidity_functions.is_externally_reachable`), and each guard token that appears in
    >=50% of those writers, flags the writers WITHOUT that guard as an anomaly — UNLESS the
    violator sits in a different privilege tier (public vs onlyOwner/onlyAdmin/role-gated)
    than the majority of guarded writers, mirroring QuillShield's own Privilege Overlay
    rule: a difference between tiers is an intentional design choice, not an inconsistency.
    """
    state_vars, functions = extract_state_variables_and_functions(contract_source)
    reachable = [f for f in functions if is_externally_reachable(f)]
    guards_by_function = {f.name: _guard_tokens(f) for f in reachable}
    anomalies: list[GuardAnomaly] = []

    for var in state_vars:
        writers = [f for f in reachable if writes_to(var, f.body)]
        if len(writers) < 3:
            continue

        candidate_guards: set[str] = set()
        for f in writers:
            candidate_guards |= guards_by_function[f.name]

        for guard in sorted(candidate_guards):
            with_guard = [f for f in writers if guard in guards_by_function[f.name]]
            frequency = len(with_guard) / len(writers)
            if frequency < 0.5 or frequency >= 1.0:
                continue  # below threshold, or universal (no anomaly to find)

            strength: InvariantStrength = "strong" if frequency >= 0.8 else "weak"
            majority_privileged = sum(is_privileged(guards_by_function[f.name]) for f in with_guard) > len(
                with_guard
            ) / 2

            for f in writers:
                if guard in guards_by_function[f.name] or is_privileged(guards_by_function[f.name]) != (
                    majority_privileged
                ):
                    continue
                anomalies.append(
                    GuardAnomaly(
                        state_variable=var,
                        guard=guard,
                        guard_frequency=frequency,
                        invariant_strength=strength,
                        violating_function=f.name,
                        severity=_severity(var, strength),
                    )
                )

    return anomalies


def analyze_guard_consistency_in_file(raw_source: str) -> list[GuardAnomaly]:
    """Entry point for a RAW, unscoped file (pragma/imports/license header and all) — see
    `solidity_functions.for_each_declaration` for how each real declaration is found and
    scoped, regardless of imports or multiple contracts in one file."""
    anomalies: list[GuardAnomaly] = []
    for scoped in for_each_declaration(raw_source):
        anomalies.extend(analyze_guard_consistency(scoped))
    return anomalies

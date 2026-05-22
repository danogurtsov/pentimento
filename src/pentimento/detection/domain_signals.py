"""
Functional-primitive smell detection — Phase 5's cheap, deterministic first stage.

Routing must key off a contract's own FUNCTIONAL shape, not its self-described category —
the canonical example is a "betting platform" that also happens to accept collateral for
issuance, which should still pull in a lending-risk specialist even though nothing about
the project calls itself a lending protocol. This module is that smell detector: pure
text/regex over function NAMES, no AST, no LLM, no I/O — same "route before you spend"
discipline as `engine_selection.py`, and built on the same shared `solidity_functions.py`
primitives as `guard_analysis.py`/`state_invariants.py`.

A signal only fires on GENUINE CO-OCCURRENCE of two-or-more distinct functional roles in the
same contract, never a single matching function name alone — a single `deposit()` is far too
common (ERC-4626, plain custody, ...) to mean anything on its own; `deposit()` co-occurring
with `borrow()` in the same contract is the actual "collateral in, debt out" smell the
reference example describes.

Three domains, deliberately a first, honestly-scoped slice — not forefy's real 21-category/
187-reference-file library, which is future ingestion work, not faked here:
- LENDING — verbatim the reference's own canonical example (collateral deposit -> debt
  issuance).
- AMM_DEX — forefy's own first-listed category ("DEXes"); the swap + LP-mint + LP-burn
  triple is the textbook AMM shape.
- YIELD_VAULT — forefy's "yield" category; picked specifically because this repo already
  has a REAL, ground-truthed positive example to validate against
  (`_external/euler-earn/src/EulerEarn.sol`'s own `reallocate()`/`setSupplyQueue()`/
  `updateWithdrawQueue()` — a genuine multi-strategy ERC-4626 allocator, not a fixture stand-
  in) and a real negative example (Tremolo's `VarianceMarket.sol`, a derivatives contract
  with none of these three domains' shapes at all).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pentimento.detection.solidity_functions import (
    FunctionInfo,
    extract_state_variables_and_functions,
    for_each_declaration,
)


class DomainId(StrEnum):
    LENDING = "lending"
    AMM_DEX = "amm_dex"
    YIELD_VAULT = "yield_vault"


@dataclass(frozen=True)
class DomainSignal:
    domain: DomainId
    matched_roles: tuple[str, ...]
    matched_functions: tuple[str, ...]  # one per role, same order as matched_roles


@dataclass(frozen=True)
class _Role:
    name: str
    pattern: re.Pattern[str]


# Each domain's roles are ANDed — every role must have at least one matching function name
# in the SAME contract for the domain's signal to fire at all (see module docstring on why
# a single matching name is never enough on its own).
_DOMAIN_ROLES: dict[DomainId, tuple[_Role, ...]] = {
    DomainId.LENDING: (
        _Role("collateral_deposit", re.compile(r"(?i)^(deposit|supply|addcollateral|lockcollateral)\w*$")),
        _Role("debt_issuance", re.compile(r"(?i)^(borrow|takeloan|issueloan|mintdebt)\w*$")),
    ),
    DomainId.AMM_DEX: (
        _Role("swap", re.compile(r"(?i)^swap\w*$")),
        _Role("lp_mint", re.compile(r"(?i)^(addliquidity|mint)$")),
        _Role("lp_burn", re.compile(r"(?i)^(removeliquidity|burn)$")),
    ),
    DomainId.YIELD_VAULT: (
        _Role("reallocation", re.compile(r"(?i)^(reallocate|rebalance)\w*$")),
        _Role(
            "queue_management",
            re.compile(r"(?i)^(setsupplyqueue|setwithdrawqueue|updatewithdrawqueue|updatesupplyqueue)\w*$"),
        ),
    ),
}


def detect_domain_signals(functions: list[FunctionInfo]) -> list[DomainSignal]:
    """`functions` should come from ONE already-scoped contract declaration (see
    `extract_state_variables_and_functions`) — mixing sibling contracts' functions together
    would produce false co-occurrence between roles that never actually appear in the same
    contract."""
    names = [f.name for f in functions]
    signals: list[DomainSignal] = []

    for domain, roles in _DOMAIN_ROLES.items():
        matched_roles: list[str] = []
        matched_functions: list[str] = []
        for role in roles:
            hit = next((n for n in names if role.pattern.match(n)), None)
            if hit is None:
                break
            matched_roles.append(role.name)
            matched_functions.append(hit)
        else:
            signals.append(DomainSignal(domain, tuple(matched_roles), tuple(matched_functions)))

    return signals


def detect_domain_signals_in_file(raw_source: str) -> list[DomainSignal]:
    """Entry point for a RAW, unscoped file — see `solidity_functions.for_each_declaration`
    for how each real declaration is found and scoped regardless of imports or multiple
    contracts in one file."""
    signals: list[DomainSignal] = []
    for scoped in for_each_declaration(raw_source):
        _, functions = extract_state_variables_and_functions(scoped)
        signals.extend(detect_domain_signals(functions))
    return signals

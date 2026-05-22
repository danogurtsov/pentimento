"""
Domain skill registry — Phase 5. Each skill is a short, evidence-grounded checklist attached
to one `DomainId` (`domain_signals.py`), folded into the breadth-pass prompt ONLY when
`services/routing.py`'s router activates it for a given unit — never unconditionally: every
relevant skill activates, however many functional smells matched, not just a single
"primary category" label.

Checklist content is deliberately kept SHORT and grounded in real, already-catalogued
material rather than invented from scratch. Most items cite either:
- a real finding from this repo's own ground-truth corpus
  (`evals/golden/detection/euler_earn.json`) — the strongest possible grounding, an actual
  audited bug this exact check would have caught, or
- a named, independently documented DeFi risk category (OWASP Smart Contract Top 10 /
  SWC-style naming).

This is a first, honest slice — 3 domains, not forefy's real 21-category/187-reference-file
library — ingesting that whole corpus is explicitly future work, not faked here (see
`domain_signals.py`'s own module docstring for the same caveat).
"""
from __future__ import annotations

from dataclasses import dataclass

from pentimento.detection.domain_signals import DomainId


@dataclass(frozen=True)
class DomainSkill:
    domain: DomainId
    label: str
    checklist: tuple[str, ...]


_SKILLS: dict[DomainId, DomainSkill] = {
    DomainId.LENDING: DomainSkill(
        domain=DomainId.LENDING,
        label="Lending / collateralized-debt risk specialist",
        checklist=(
            "Collateral valuation must come from a manipulation-resistant price source, not "
            "a single spot AMM read (OWASP Smart Contract Top 10: Price Oracle Manipulation).",
            "Interest/fees must be accrued BEFORE health-factor or liquidation math reads the "
            "position, not after — a stale pre-accrual read misprices solvency.",
            "Liquidation incentive must not let a borrower profitably self-liquidate.",
            "Collateral must not be withdrawable while it still backs an open debt position.",
        ),
    ),
    DomainId.AMM_DEX: DomainSkill(
        domain=DomainId.AMM_DEX,
        label="AMM / DEX pool risk specialist",
        checklist=(
            "LP mint/burn share pricing must be immune to a first-depositor or "
            "direct-donation share-price manipulation — the exact mechanism behind this "
            "repo's own catalogued EulerEarn L-05, 'Frontrunning in vault enabling process' "
            "(evals/golden/detection/euler_earn.json).",
            "swap() must let the caller bound slippage/deadline, not execute at an "
            "unconstrained price (catalogued EulerEarn L-04, 'Missing slippage and deadline "
            "protection').",
            "The pool invariant (e.g. constant product x*y=k) must be checked non-decreasing "
            "after every swap, not assumed correct from the swap math alone.",
        ),
    ),
    DomainId.YIELD_VAULT: DomainSkill(
        domain=DomainId.YIELD_VAULT,
        label="Multi-strategy yield vault / allocator risk specialist",
        checklist=(
            "A strategy's REAL on-chain share balance and the vault's own INTERNAL "
            "accounting of that strategy must never be read from two different places for "
            "the same decision (catalogued EulerEarn M-01, 'Share tracking issue between "
            "PublicAllocator and EulerEarn affects reallocations' — the direct real-world "
            "motivation for this item).",
            "Supply/withdraw queue reconfiguration must not be fully front-runnable into a "
            "materially different cap outcome than the admin intended (catalogued EulerEarn "
            "L-06, 'setFlowCaps() can be front-run to increase effective cap usage').",
            "Removing a strategy from the queue while it holds dust/rounding-residual shares "
            "must not silently block or misroute that removal (catalogued EulerEarn L-10).",
        ),
    ),
}


def skill_for(domain: DomainId) -> DomainSkill:
    return _SKILLS[domain]


def all_skill_ids() -> tuple[DomainId, ...]:
    return tuple(_SKILLS.keys())

"""
Typed routing decision — Phase 5. Pure parsing, no LLM call itself (see
`services/routing.py` for the orchestration that actually calls one) — same split as
`detection/prompts.py` builds text / `services/breadth_pass.py` spends the call.

The routing OUTPUT is a typed interface (skill-id + which functional signal triggered it),
not free text, specifically so a debugging session or an eval can tell "the router
considered this domain and skipped it" apart from "this domain was never even addressed" —
silence must never look like a real decision. `parse_routing_response` enforces that
literally: every domain in `known_skill_ids` gets an explicit `SkillActivation` in the
result even if the model's own response never mentions it at all — recorded as a SKIP with
a distinct, honest reason, not silently dropped.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from pentimento.detection.domain_signals import DomainId

_ROUTE_LINE_RE = re.compile(r"^ROUTE\s+(\w+):\s*(ACTIVATE|SKIP)\s*[—-]\s*(.+)$", re.IGNORECASE)
_NOT_ADDRESSED_REASON = "router response never addressed this domain explicitly"


@dataclass(frozen=True)
class SkillActivation:
    domain: DomainId
    activated: bool
    reason: str


@dataclass(frozen=True)
class RoutingDecision:
    unit_id: str
    activations: tuple[SkillActivation, ...]

    def activated_domains(self) -> tuple[DomainId, ...]:
        return tuple(a.domain for a in self.activations if a.activated)


def parse_routing_response(raw: str, unit_id: str, known_skill_ids: tuple[DomainId, ...]) -> RoutingDecision:
    """Parses the model's `ROUTE <domain>: ACTIVATE|SKIP — <reason>` lines (see
    `detection/prompts.build_routing_prompt`'s own output-format instructions). Unknown
    domain names in the response are ignored (a model hallucinating a skill-id that was
    never offered isn't a routing decision this repo can act on); a KNOWN domain the
    response never mentions is recorded as an explicit non-activation, never dropped."""
    found: dict[DomainId, SkillActivation] = {}
    for line in raw.splitlines():
        match = _ROUTE_LINE_RE.match(line.strip())
        if not match:
            continue
        domain_str, verdict, reason = match.groups()
        try:
            domain = DomainId(domain_str.lower())
        except ValueError:
            continue
        found[domain] = SkillActivation(domain, verdict.upper() == "ACTIVATE", reason.strip())

    activations = tuple(
        found.get(sid, SkillActivation(sid, False, _NOT_ADDRESSED_REASON)) for sid in known_skill_ids
    )
    return RoutingDecision(unit_id, activations)

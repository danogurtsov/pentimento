"""
Factory detection from SOURCE — pure core (no I/O). Two enumeration mechanisms, deliberately
kept distinct — they're structurally different facts,
not degrees of the same thing:

- **getter-enumerable** (Phase 2, primitive #1): a public array/length getter tracks instances.
- **event-enumerable** (primitive #2): no getter at all — the only way to discover an
  instance is the creation event, the repo-first stand-in for what dandelion's own
  `factory_events.py` already handles on-chain via a topic0 registry (Uniswap-style
  `PairCreated`, Morpho-style `CreateMetaMorpho`). Repo-first has no logs to scan, so the
  static signal is instead: a function that both `new`s the template AND emits an event
  carrying an address, with no enumeration getter anywhere in the contract.

Repo-first has no chain to enumerate real deployed instances against either way (that's
the onchain→CDV converter's job, Phase 3) — what's detected here is the STRUCTURAL fact
that a factory relationship exists and HOW it would be discoverable once deployed.

Identity note (found the hard way on real-world code, not anticipated): a bare contract
NAME is not unique across a batch of independently compiled files — DeFiHackLabs reuses
"ContractTest" as a generic per-exploit test-harness name in 9 of 10 files in a single
directory. `detect_factory_relationships` therefore keys everything by `(source_file,
contract_name)` internally and only falls back to bare-name matching to resolve what a
`new X(...)` expression's X actually refers to — preferring an unambiguous global match,
then a same-file match, and refusing to guess otherwise (see `resolve_bare_name`, also
reused as-is for dispatcher-extension resolution in `converter.py` — same ambiguity shape).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, NamedTuple

EnumerationKind = Literal["getter", "event", "none"]

_NEW_EXPR_RE = re.compile(r"\bnew\s+(\w+)\s*\(")
_ENUM_ARRAY_RE = re.compile(r"\b\w+\[\]\s+public\s+all\w*", re.IGNORECASE)
_ENUM_LENGTH_FN_RE = re.compile(r"function\s+all\w*(?:Length|Count)\s*\(", re.IGNORECASE)
_EVENT_DECL_RE = re.compile(r"\bevent\s+(\w+)\s*\(([^)]*)\)")
_FUNCTION_HEADER_RE = re.compile(r"\bfunction\s+\w+\s*\([^)]*\)[^{;]*\{")


class ContractKey(NamedTuple):
    source_file: str
    contract_name: str


@dataclass(frozen=True)
class FactoryRelationship:
    factory: ContractKey
    template: ContractKey
    enumeration_kind: EnumerationKind


def find_instantiated_contracts(source: str, known_contract_names: set[str]) -> set[str]:
    """Names from `new X(...)` expressions that are themselves compiled contracts
    (not e.g. a library struct constructor or an unrelated identifier)."""
    return {name for name in _NEW_EXPR_RE.findall(source) if name in known_contract_names}


def has_enumeration_getter(source: str) -> bool:
    """A public array tracking instances, or an `allXLength`/`allXCount` getter."""
    return bool(_ENUM_ARRAY_RE.search(source) or _ENUM_LENGTH_FN_RE.search(source))


def _function_bodies(source: str) -> list[str]:
    """Naive brace-matching split into individual function bodies — good enough for
    well-formatted single-purpose fixtures. A full parser (solc AST, already available
    via the adapter) is the natural upgrade path if this proves too fragile on messier
    real-world repos — not needed for the primitives shipped so far."""
    bodies = []
    pos = 0
    while match := _FUNCTION_HEADER_RE.search(source, pos):
        start = match.end() - 1  # the opening brace itself
        depth = 0
        i = start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        bodies.append(source[start : i + 1])
        pos = i + 1
    return bodies


def _address_emitting_event_names(source: str) -> set[str]:
    """Event names declared with at least one `address` parameter."""
    return {name for name, params in _EVENT_DECL_RE.findall(source) if re.search(r"\baddress\b", params)}


def has_event_announcement(source: str) -> bool:
    """A function that both instantiates a contract and emits an address-carrying event —
    the repo-first signal for "discoverable only via creation event, no getter"."""
    address_events = _address_emitting_event_names(source)
    if not address_events:
        return False
    for body in _function_bodies(source):
        if _NEW_EXPR_RE.search(body) and any(
            re.search(rf"\bemit\s+{re.escape(name)}\s*\(", body) for name in address_events
        ):
            return True
    return False


def _enumeration_kind(source: str) -> EnumerationKind:
    if has_enumeration_getter(source):
        return "getter"
    if has_event_announcement(source):
        return "event"
    return "none"


def resolve_bare_name(name: str, from_file: str, by_name: dict[str, list[ContractKey]]) -> ContractKey | None:
    """A bare `new X(...)` name resolved to a specific declaration: unambiguous if X is
    declared in exactly one file across the whole batch; if declared in several (a real
    collision, not hypothetical — see module docstring), only resolved if exactly one of
    them lives in the SAME file as the `new` expression. Otherwise None — refuse to guess
    which of several same-named-but-unrelated contracts was actually meant."""
    candidates = by_name.get(name, [])
    if len(candidates) == 1:
        return candidates[0]
    same_file = [c for c in candidates if c.source_file == from_file]
    return same_file[0] if len(same_file) == 1 else None


def detect_factory_relationships(contracts: list[tuple[ContractKey, str]]) -> list[FactoryRelationship]:
    """`contracts`: one (key, source_text) pair per compiled contract — a LIST, not a
    dict, so that two unrelated files sharing a contract name never silently collapse
    into one entry before analysis even starts."""
    by_name: dict[str, list[ContractKey]] = {}
    for key, _ in contracts:
        by_name.setdefault(key.contract_name, []).append(key)

    out: list[FactoryRelationship] = []
    for factory_key, source in contracts:
        instantiated_names = find_instantiated_contracts(source, set(by_name) - {factory_key.contract_name})
        for template_name in instantiated_names:
            template_key = resolve_bare_name(template_name, factory_key.source_file, by_name)
            if template_key is not None:
                out.append(FactoryRelationship(factory_key, template_key, _enumeration_kind(source)))
    return out

"""
Canonical Deploy View (CDV) — data model.

One unit = one resolved, "as-if-deployed" contract: proxy+implementation merged into a
single logical entity, with explicit flags for the non-trivial cases (factory-instance
classes, multiple implementations, external boundaries) — this is a first slice of a
broader Canonical Deploy View standard.

This module only holds the pure data shapes — no I/O, no solc, no filesystem.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class NodeType(StrEnum):
    PROXY = "proxy"
    IMPLEMENTATION = "implementation"
    TOKEN = "token"
    POOL = "pool"
    VAULT = "vault"
    ROUTER = "router"
    FACTORY = "factory"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    TIMELOCK = "timelock"
    MULTISIG = "multisig"
    UNKNOWN = "unknown"


class ProxyKind(StrEnum):
    NONE = "none"
    EIP1967_TRANSPARENT = "eip1967_transparent"
    EIP1967_UUPS = "eip1967_uups"
    EIP1822 = "eip1822"
    EIP1167_MINIMAL = "eip1167_minimal"
    BEACON = "beacon"
    DIAMOND = "diamond"
    DISPATCHER = "dispatcher"
    CUSTOM = "custom"


class Membership(StrEnum):
    """Control-based, not reference-based — see dandelion's membership.py principle."""
    MEMBER = "member"
    CANDIDATE = "candidate"
    EXTERNAL = "external"


class Origin(StrEnum):
    """Provenance of a fact: was it computed deterministically or proposed by an LLM."""
    DETERMINISTIC = "deterministic"
    LLM = "llm"


@dataclass
class CDVUnit:
    """One CDV unit — proxy+implementation already merged if applicable."""

    unit_id: str
    contract_name: str
    node_type: NodeType = NodeType.UNKNOWN
    proxy_kind: ProxyKind = ProxyKind.NONE
    implementation_of: str | None = None  # unit_id of the proxy this impl was merged into, if any
    factory_creates: str | None = None  # unit_id of the template contract this factory instantiates
    factory_of: str | None = None  # unit_id of the factory that creates instances of this unit
    factory_enumeration: str | None = None  # "getter" | "event" — how instances would be discoverable
    merged_facets: list[str] = field(default_factory=list)  # EIP-2535: facet contracts merged into this unit
    logical_entity_creator: str | None = None  # name of a create* fn minting internal bytes32 entities, not contracts
    membership: Membership = Membership.MEMBER
    origin: Origin = Origin.DETERMINISTIC
    source_files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["node_type"] = self.node_type.value
        d["proxy_kind"] = self.proxy_kind.value
        d["membership"] = self.membership.value
        d["origin"] = self.origin.value
        return d


@dataclass
class CDVGraph:
    """The manifest of a converted project — one CDVGraph per repo→CDV run."""

    generator: str
    units: list[CDVUnit] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"generator": self.generator, "units": [u.to_dict() for u in self.units]}

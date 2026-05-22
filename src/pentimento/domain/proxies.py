"""
Proxy+implementation detection from SOURCE (not live storage) — pure core (no I/O).

This is the repo-first counterpart of dandelion's `proxies.py`, which reads the live
EIP-1967 storage slots of a deployed contract. Here there is no chain to read — the
signal instead is the STATIC shape of the source: the well-known EIP-1967 slot-constant
identifier names (`_IMPLEMENTATION_SLOT`, `_ADMIN_SLOT` — the exact names OpenZeppelin's
ERC1967Upgrade uses, and what custom proxies conventionally copy) plus `delegatecall`
usage marks a contract as a proxy; a function guarded by an `initializer` modifier marks
a contract as an upgradeable-implementation candidate for merging into that proxy's unit
(per the CDV standard's own rule: "proxy+impl as ONE unit").

Phase 2, primitive #4: dispatcher-proxies — ≥4 mechanically
different real implementations found: Fluid InfiniteProxy, Compound III Comet/CometExt,
Synthetix V3 Router, Balancer V3 Vault/VaultExtension). Deliberately NOT byte-for-byte
replicating any one of them (same reasoning as the EIP-1967 slot below: don't hardcode a
detail from memory that could be subtly wrong) — instead detecting the STRUCTURAL shape
common to the simplest of the four (Compound III's plain-extension-address pattern):
a contract with its OWN real logic that ALSO delegatecalls unmatched calls to a second
contract referenced by a plain `*extension*`-named address, with neither the EIP-1967 slot
convention nor a diamond dispatch table — the thing that makes it a distinct primitive
rather than a variant of either.
"""
from __future__ import annotations

import re

from .models import ProxyKind

_IMPLEMENTATION_SLOT_RE = re.compile(r"_?IMPLEMENTATION_SLOT", re.IGNORECASE)
_ADMIN_SLOT_RE = re.compile(r"_?ADMIN_SLOT", re.IGNORECASE)
_BEACON_SLOT_RE = re.compile(r"_?BEACON_SLOT", re.IGNORECASE)
_DELEGATECALL_RE = re.compile(r"\bdelegatecall\s*\(")
_DIAMOND_LOUPE_RE = re.compile(r"\bfacetAddresses\s*\(|\bdiamondCut\s*\(")
_EXTENSION_ADDR_RE = re.compile(
    r"\baddress\s+(?:public\s+|private\s+|internal\s+|external\s+|immutable\s+){0,3}\w*[Ee]xtension\w*\b"
)
_INITIALIZER_MODIFIER_RE = re.compile(r"\binitializer\b")
_INITIALIZE_FN_RE = re.compile(r"\bfunction\s+initialize\s*\(")


def detect_proxy_kind(source: str) -> ProxyKind:
    """Static-marker heuristic — see module docstring. NONE if no proxy shape found."""
    if _DIAMOND_LOUPE_RE.search(source):
        return ProxyKind.DIAMOND
    if _BEACON_SLOT_RE.search(source) and _DELEGATECALL_RE.search(source):
        return ProxyKind.BEACON
    if _IMPLEMENTATION_SLOT_RE.search(source) and _DELEGATECALL_RE.search(source):
        return ProxyKind.EIP1967_TRANSPARENT if _ADMIN_SLOT_RE.search(source) else ProxyKind.EIP1967_UUPS
    if _EXTENSION_ADDR_RE.search(source) and _DELEGATECALL_RE.search(source):
        return ProxyKind.DISPATCHER
    return ProxyKind.NONE


def is_upgradeable_implementation_candidate(source: str) -> bool:
    """A contract guarded by `initializer` with an `initialize(...)` function — the
    repo-first, no-chain analogue of "this is the logic contract behind a live proxy"."""
    return bool(_INITIALIZER_MODIFIER_RE.search(source) and _INITIALIZE_FN_RE.search(source))

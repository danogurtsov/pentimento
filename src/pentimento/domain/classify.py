"""
Contract-type classification from ABI function signatures — pure core (no I/O).

Ported from dandelion's `classify.py` principle (selector presence in bytecode → type),
but simpler here: repo-first CDV has the real compiler-emitted ABI, so we match on
function name + parameter types directly instead of reconstructing 4-byte selectors.
Deterministic, no LLM — classification only escalates to an LLM later, on units this
cannot resolve (see dandelion's routing.py `is_opaque` principle).
"""
from __future__ import annotations

from .models import NodeType

Signature = tuple[str, tuple[str, ...]]  # (function name, parameter types)

# name -> signatures whose presence is evidence for that node type.
# A contract is classified as the type with the most matched signatures (min 1 match),
# ties broken by declaration order below (most specific groups first).
_SIGNATURE_GROUPS: dict[NodeType, list[Signature]] = {
    NodeType.TOKEN: [
        ("transfer", ("address", "uint256")),
        ("balanceOf", ("address",)),
        ("totalSupply", ()),
        ("symbol", ()),
        ("approve", ("address", "uint256")),
        # ERC-6909 (EIP-6909 multi-token accounting) shape — real-world-motivated (Tremolo's
        # VarianceMarket: one singleton, series-as-token-id via solady's ERC6909, instead of
        # one token contract per series). Names overlap with ERC-20 above, but every one of
        # these takes an extra `id` parameter — a genuinely different (name, types) tuple, so
        # it can only add evidence, never double-count with the ERC-20 entries.
        ("balanceOf", ("address", "uint256")),
        ("transfer", ("address", "uint256", "uint256")),
        ("transferFrom", ("address", "address", "uint256", "uint256")),
        ("approve", ("address", "uint256", "uint256")),
        ("allowance", ("address", "address", "uint256")),
        ("isOperator", ("address", "address")),
        ("setOperator", ("address", "bool")),
    ],
    # ERC-4626 vault-share-accounting shape (Phase 2, primitive #5 — interface detection,
    # without deep semantics yet). A real ERC-4626
    # contract ALSO exposes plain ERC20 getters (shares ARE a token) — deliberately picking
    # signatures that DON'T overlap with the TOKEN group at all, so a genuine vault scores
    # higher here (up to 8) than on TOKEN (up to 5, from its inherited ERC20 surface) purely
    # by having more of its OWN distinguishing signatures, not by any special-casing.
    NodeType.VAULT: [
        ("asset", ()),
        ("totalAssets", ()),
        ("convertToShares", ("uint256",)),
        ("convertToAssets", ("uint256",)),
        ("deposit", ("uint256", "address")),
        ("mint", ("uint256", "address")),
        ("withdraw", ("uint256", "address", "address")),
        ("redeem", ("uint256", "address", "address")),
    ],
    NodeType.MULTISIG: [
        ("getOwners", ()),
        ("getThreshold", ()),
        (
            "execTransaction",
            ("address", "uint256", "bytes", "uint8", "uint256", "uint256", "uint256", "address", "address", "bytes"),
        ),
        # Custom propose/approve/execute shape (not Gnosis Safe's own ABI) - real-world
        # gap found via a private TimeLockedMultisig.sol fixture, which classified
        # UNKNOWN despite being a genuine N-of-M multisig, because Safe's own signatures
        # above don't apply to a hand-rolled implementation. `threshold()` + `isSigner()`
        # together are the distinguishing pair (neither means anything alone - `threshold()`
        # also appears on generic rate-limit/config contracts, `isSigner()` alone is too
        # thin); `propose`/`approve`/`execute` add further evidence when present, without
        # colliding with any other group's own (name, types) tuples (GOVERNANCE's own
        # `propose` takes different parameter types entirely).
        ("threshold", ()),
        ("isSigner", ("address",)),
        ("propose", ("address", "uint256", "bytes")),
        ("approve", ("uint256",)),
        ("execute", ("uint256",)),
    ],
    NodeType.TIMELOCK: [
        ("getMinDelay", ()),
        ("schedule", ("address", "uint256", "bytes", "bytes32", "bytes32", "uint256")),
        ("executeBatch", ("address[]", "uint256[]", "bytes[]", "bytes32", "bytes32")),
    ],
    NodeType.GOVERNANCE: [
        ("castVote", ("uint256", "uint8")),
        ("propose", ("address[]", "uint256[]", "bytes[]", "string")),
        ("quorum", ("uint256",)),
    ],
    # `decimals()` deliberately does NOT appear anywhere in the TOKEN group above: real bug
    # found on Tremolo's `IChainlinkAggregator` (a plain Chainlink-shaped price-feed
    # interface exposing only `decimals()` + `latestRoundData()`) — `decimals()` alone was
    # enough for it to tie ORACLE 1-1, and TOKEN silently won every tie by being declared
    # first in this dict. `decimals()` isn't token-specific at all: oracles, vaults, and
    # anything with fixed-point precision expose it too, so it must never be the deciding
    # signature for TOKEN.
    NodeType.ORACLE: [
        ("latestRoundData", ()),
        ("latestAnswer", ()),
    ],
    NodeType.FACTORY: [
        ("createPool", ("address", "address", "uint24")),
        ("allPairsLength", ()),
        ("getPool", ("address", "address", "uint24")),
    ],
}


def _abi_signatures(abi: list[dict]) -> set[Signature]:
    sigs: set[Signature] = set()
    for entry in abi:
        if entry.get("type") != "function":
            continue
        name = entry.get("name")
        if not name:
            continue
        types = tuple(i.get("type", "") for i in entry.get("inputs", []))
        sigs.add((name, types))
    return sigs


def classify(abi: list[dict]) -> NodeType:
    """Deterministic node_type from the contract's own ABI. UNKNOWN if nothing matches."""
    present = _abi_signatures(abi)
    best_type = NodeType.UNKNOWN
    best_score = 0
    for node_type, group in _SIGNATURE_GROUPS.items():
        score = sum(1 for sig in group if sig in present)
        if score > best_score:
            best_score = score
            best_type = node_type
    return best_type

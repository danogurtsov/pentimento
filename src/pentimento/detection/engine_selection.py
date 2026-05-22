"""
Engine Selection Matrix — Phase 4, first concrete piece: decide which QuillShield-style
threat engines run over a CDV unit, and at what depth, BEFORE any LLM call is made.

Pure decision logic, no LLM: cheap enough to run over the whole CDVGraph up front,
narrowing the (expensive) breadth-pass to only the engines a unit's own shape can
plausibly need — same "route before you spend" principle already used for the
node-type/proxy-kind detectors in `domain/`.

Grounded in QuillShield's own "Engine Selection Matrix" (their empirically-validated
table, which placed 2nd of 8 in an independent tool comparison) for the 3 rows that map
directly onto one of our `NodeType` values (Token, DeFi/vault, Governance/DAO).

Their table is keyed on a single flat "contract type" label. Our `CDVUnit` already
separates that into two independent axes — `node_type` and `proxy_kind` — which their
upstream AST-based tool doesn't get for free the same way. So this reuses their PER-ROW
engine weights, not their one-bucket-per-contract structure: a unit's final selection is
the per-engine MAX across whichever rows apply to it (its `node_type` row, AND separately
their "Proxy/Upgradeable" row whenever `proxy_kind != NONE`) — an upgradeable vault
correctly ends up Full on every engine instead of having to fit into a single label.

Node types the reference table has no row for at all (FACTORY, MULTISIG, TIMELOCK, ORACLE,
POOL, ROUTER, PROXY, IMPLEMENTATION, and repo-first's own UNKNOWN) get a reasoned default
below — each documented on its own, not copied from whatever row happens to be nearby.
This module is detection-layer code (Phase 4), deliberately kept out of `domain/`
(Phase 1-3, CDV structure only) — same phase boundary the project's build plan already
draws.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum, StrEnum

from pentimento.domain.models import NodeType, ProxyKind


class ThreatEngine(StrEnum):
    """QuillShield's 3 CORE engines (Economic/AccessControl/StateIntegrity) — the ones
    their own Engine Selection Matrix actually routes between. Their 6 EXTENDED layers
    (Reentrancy, Oracle/FlashLoan, Proxy/Upgrade, Input/Arithmetic, External Calls,
    Signature/Replay, DoS/Griefing) aren't type-routed in their own design either — see
    `ExtendedLayer` below for the two that map cleanly onto an existing CDV fact."""

    ECONOMIC = "economic"  # ETE
    ACCESS_CONTROL = "access_control"  # ACTE
    STATE_INTEGRITY = "state_integrity"  # SITE


class EngineDepth(IntEnum):
    """Ordered so `max()` picks the deeper of two selections for the same engine — the
    whole point of unioning a node_type row with the proxy_kind row (see module doc)."""

    NONE = 0
    LITE = 1
    FULL = 2


class ExtendedLayer(StrEnum):
    """Tags marking that one of QuillShield's extended-layer checklists is worth running
    over this unit — not a depth, just a marker. Only the two layers that map cleanly onto
    an existing CDV fact are wired here (oracle shape / upgradeability) — genuinely
    type-conditional, unlike the other 5 (see `UnconditionalLayer` below, which ARE always
    included, not type-routed at all)."""

    ORACLE_FLASH_LOAN = "oracle_flash_loan"  # Layer 4
    PROXY_UPGRADE = "proxy_upgrade"  # Layer 5


class UnconditionalLayer(StrEnum):
    """The remaining 5 extended layers `ExtendedLayer`'s own docstring names above
    (reentrancy/input-arithmetic/external-call/signature-replay/DoS-griefing) — and asserts
    "belong in the breadth-pass prompt unconditionally". That claim was never actually
    implemented: `prompts.py` never mentioned any of them, on any unit, ever. Found via a
    real live-run gap, not a code review: a ScaBench generalization test missed a
    real bug (`MinimalDelegation.execute()`'s signed payload not binding caller identity,
    enabling front-running) on a unit CDV classifies as `NodeType.UNKNOWN` — which gets
    LITE-only depth on all 3 core engines (`_UNKNOWN_DEFAULT` below) and, because of this
    exact gap, ZERO extended-layer guidance of any kind. Unlike `ExtendedLayer`, these are
    NEVER conditional on node_type/proxy_kind — every unit gets all 5, matching the
    reference's own "apply to nearly every contract" framing literally."""

    REENTRANCY = "reentrancy"  # Layer 3
    INPUT_ARITHMETIC = "input_arithmetic"  # Layer 6
    EXTERNAL_CALL_SAFETY = "external_call_safety"  # Layer 7
    SIGNATURE_REPLAY = "signature_replay"  # Layer 8
    DOS_GRIEFING = "dos_griefing"  # Layer 9


ALL_UNCONDITIONAL_LAYERS: tuple[UnconditionalLayer, ...] = tuple(UnconditionalLayer)


@dataclass(frozen=True)
class EngineSelection:
    economic: EngineDepth
    access_control: EngineDepth
    state_integrity: EngineDepth
    extended_layers: tuple[ExtendedLayer, ...] = ()

    def depth_of(self, engine: ThreatEngine) -> EngineDepth:
        return {
            ThreatEngine.ECONOMIC: self.economic,
            ThreatEngine.ACCESS_CONTROL: self.access_control,
            ThreatEngine.STATE_INTEGRITY: self.state_integrity,
        }[engine]


# Verbatim from QuillShield's own Engine Selection Matrix — the 3 rows that map directly
# onto one of our NodeType values.
_QUILLSHIELD_TABLE: dict[NodeType, EngineSelection] = {
    NodeType.TOKEN: EngineSelection(EngineDepth.FULL, EngineDepth.LITE, EngineDepth.LITE),
    NodeType.VAULT: EngineSelection(EngineDepth.FULL, EngineDepth.FULL, EngineDepth.FULL),
    NodeType.GOVERNANCE: EngineSelection(EngineDepth.LITE, EngineDepth.FULL, EngineDepth.FULL),
}

# Our own reasoned defaults for node types the reference table has no row for at all.
_OUR_DEFAULTS: dict[NodeType, EngineSelection] = {
    # Explicitly named IN the reference's own "DeFi (DEX/lending/vault/staking)" row
    # description, even though `classify()` doesn't emit these node types yet (no POOL/
    # ROUTER signature group exists yet). Kept here for forward-compat with whenever that
    # group is added; same weights as VAULT, the DeFi row's other member.
    NodeType.POOL: EngineSelection(EngineDepth.FULL, EngineDepth.FULL, EngineDepth.FULL),
    NodeType.ROUTER: EngineSelection(EngineDepth.FULL, EngineDepth.FULL, EngineDepth.FULL),
    # A factory's own attack surface is centered on WHO can create instances and whether
    # creation parameters can be manipulated (access control) — not the factory contract's
    # own economic state (it usually holds none) or a complex internal state machine.
    NodeType.FACTORY: EngineSelection(EngineDepth.LITE, EngineDepth.FULL, EngineDepth.LITE),
    # A multisig's own contract has no economic invariants of its own (whatever it CALLS
    # does) — its entire risk surface is who can propose/confirm/execute, and in what order.
    NodeType.MULTISIG: EngineSelection(EngineDepth.NONE, EngineDepth.FULL, EngineDepth.LITE),
    # Delay-gated privileged execution — same access-control-centric shape as multisig, but
    # schedule/cancel/execute sequencing is a real state-machine (SITE) concern a multisig's
    # simpler confirm-then-execute flow mostly isn't.
    NodeType.TIMELOCK: EngineSelection(EngineDepth.NONE, EngineDepth.FULL, EngineDepth.FULL),
    # QuillShield's own design keeps oracle manipulation as a separate EXTENDED layer (4),
    # deliberately NOT a core-3 matrix row — mirrored here: light core-3 coverage (who can
    # update the feed; is state kept consistent across updates), Layer 4's own checklist is
    # what should carry the real weight, flagged via extended_layers below.
    NodeType.ORACLE: EngineSelection(EngineDepth.LITE, EngineDepth.LITE, EngineDepth.LITE),
    # Never assigned by this repo's own classify() (see its module docstring) — kept for
    # forward-compat with dandelion's onchain converter, which may assign these directly.
    # No reasoning to route confidently on an implementation-shape alone; the reference's
    # own "Proxy/Upgradeable" row weight lives in the proxy_kind union below, not here.
    NodeType.IMPLEMENTATION: EngineSelection(EngineDepth.LITE, EngineDepth.LITE, EngineDepth.LITE),
    NodeType.PROXY: EngineSelection(EngineDepth.NONE, EngineDepth.LITE, EngineDepth.LITE),
}

_UNKNOWN_DEFAULT = EngineSelection(EngineDepth.LITE, EngineDepth.LITE, EngineDepth.LITE)

# The reference's own "Proxy/Upgradeable" row — unioned in whenever proxy_kind != NONE,
# regardless of node_type (see module doc: two independent axes, not one flat label).
_PROXY_ROW = EngineSelection(EngineDepth.NONE, EngineDepth.FULL, EngineDepth.FULL)


def select_engines(node_type: NodeType, proxy_kind: ProxyKind) -> EngineSelection:
    """Which threat engines a breadth-pass should run over this unit, and at what depth —
    computed BEFORE any LLM call, so the (expensive) pass only spends tokens on engines
    this unit's own shape can plausibly need."""
    base = _QUILLSHIELD_TABLE.get(node_type) or _OUR_DEFAULTS.get(node_type) or _UNKNOWN_DEFAULT

    access_control = base.access_control
    state_integrity = base.state_integrity
    extended: list[ExtendedLayer] = []

    if proxy_kind != ProxyKind.NONE:
        access_control = max(access_control, _PROXY_ROW.access_control)
        state_integrity = max(state_integrity, _PROXY_ROW.state_integrity)
        extended.append(ExtendedLayer.PROXY_UPGRADE)

    if node_type == NodeType.ORACLE:
        extended.append(ExtendedLayer.ORACLE_FLASH_LOAN)

    return EngineSelection(base.economic, access_control, state_integrity, tuple(extended))

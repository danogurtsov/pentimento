from pentimento.detection.engine_selection import (
    ALL_UNCONDITIONAL_LAYERS,
    EngineDepth,
    ExtendedLayer,
    UnconditionalLayer,
    select_engines,
)
from pentimento.domain.models import NodeType, ProxyKind


def test_token_matches_the_reference_table_exactly() -> None:
    sel = select_engines(NodeType.TOKEN, ProxyKind.NONE)
    assert (sel.economic, sel.access_control, sel.state_integrity) == (
        EngineDepth.FULL,
        EngineDepth.LITE,
        EngineDepth.LITE,
    )
    assert sel.extended_layers == ()


def test_vault_matches_the_reference_table_exactly() -> None:
    sel = select_engines(NodeType.VAULT, ProxyKind.NONE)
    assert (sel.economic, sel.access_control, sel.state_integrity) == (
        EngineDepth.FULL,
        EngineDepth.FULL,
        EngineDepth.FULL,
    )


def test_governance_matches_the_reference_table_exactly() -> None:
    sel = select_engines(NodeType.GOVERNANCE, ProxyKind.NONE)
    assert (sel.economic, sel.access_control, sel.state_integrity) == (
        EngineDepth.LITE,
        EngineDepth.FULL,
        EngineDepth.FULL,
    )


def test_multisig_has_no_economic_engine_but_full_access_control() -> None:
    sel = select_engines(NodeType.MULTISIG, ProxyKind.NONE)
    assert sel.economic == EngineDepth.NONE
    assert sel.access_control == EngineDepth.FULL


def test_oracle_flags_the_extended_flash_loan_layer() -> None:
    sel = select_engines(NodeType.ORACLE, ProxyKind.NONE)
    assert ExtendedLayer.ORACLE_FLASH_LOAN in sel.extended_layers
    assert ExtendedLayer.PROXY_UPGRADE not in sel.extended_layers


def test_unknown_node_type_gets_a_lite_default_everywhere() -> None:
    sel = select_engines(NodeType.UNKNOWN, ProxyKind.NONE)
    assert (sel.economic, sel.access_control, sel.state_integrity) == (
        EngineDepth.LITE,
        EngineDepth.LITE,
        EngineDepth.LITE,
    )


def test_upgradeable_token_unions_in_the_proxy_row_instead_of_replacing_the_token_row() -> None:
    # a token that is ALSO a proxy (both axes true at once) must get the token row's
    # economic weight AND the proxy row's access-control/state-integrity weight - not have
    # to fit into a single "either token or proxy" bucket the way QuillShield's own flat
    # contract-type label would force.
    plain_token = select_engines(NodeType.TOKEN, ProxyKind.NONE)
    upgradeable_token = select_engines(NodeType.TOKEN, ProxyKind.EIP1967_UUPS)

    assert upgradeable_token.economic == plain_token.economic == EngineDepth.FULL
    assert upgradeable_token.access_control == EngineDepth.FULL  # token=LITE, proxy=FULL -> FULL wins
    assert upgradeable_token.state_integrity == EngineDepth.FULL  # token=LITE, proxy=FULL -> FULL wins
    assert ExtendedLayer.PROXY_UPGRADE in upgradeable_token.extended_layers


def test_proxy_union_never_downgrades_an_already_full_engine() -> None:
    # a vault (already FULL/FULL/FULL) that also happens to be upgradeable must stay FULL,
    # not get dragged down by the proxy row's own weaker economic weight (NONE).
    sel = select_engines(NodeType.VAULT, ProxyKind.DIAMOND)
    assert (sel.economic, sel.access_control, sel.state_integrity) == (
        EngineDepth.FULL,
        EngineDepth.FULL,
        EngineDepth.FULL,
    )


def test_all_5_unconditional_layers_are_present_and_ordered() -> None:
    # see UnconditionalLayer's own docstring for the real gap this closes.
    assert ALL_UNCONDITIONAL_LAYERS == (
        UnconditionalLayer.REENTRANCY,
        UnconditionalLayer.INPUT_ARITHMETIC,
        UnconditionalLayer.EXTERNAL_CALL_SAFETY,
        UnconditionalLayer.SIGNATURE_REPLAY,
        UnconditionalLayer.DOS_GRIEFING,
    )

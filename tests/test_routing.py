from pentimento.detection.domain_signals import DomainId
from pentimento.detection.routing import parse_routing_response

_ALL = (DomainId.LENDING, DomainId.AMM_DEX, DomainId.YIELD_VAULT)


def test_parses_activate_and_skip_lines() -> None:
    raw = "\n".join(
        [
            "ROUTE lending: SKIP — no borrow/collateral shape here",
            "ROUTE amm_dex: ACTIVATE — swap+addLiquidity+removeLiquidity present",
            "ROUTE yield_vault: SKIP — no reallocation queue",
        ]
    )

    decision = parse_routing_response(raw, "Unit", _ALL)

    assert decision.activated_domains() == (DomainId.AMM_DEX,)
    lending = next(a for a in decision.activations if a.domain == DomainId.LENDING)
    assert lending.activated is False
    assert "no borrow/collateral shape" in lending.reason


def test_a_domain_the_response_never_mentions_is_recorded_as_an_explicit_non_activation() -> None:
    raw = "ROUTE lending: ACTIVATE — collateral deposit + borrow present"

    decision = parse_routing_response(raw, "Unit", _ALL)

    amm = next(a for a in decision.activations if a.domain == DomainId.AMM_DEX)
    assert amm.activated is False
    assert "never addressed" in amm.reason
    assert len(decision.activations) == 3  # every known domain gets a slot, never dropped


def test_unknown_domain_in_the_response_is_ignored() -> None:
    raw = "\n".join(
        [
            "ROUTE governance: ACTIVATE — has a voting mechanism",
            "ROUTE lending: SKIP — no match",
        ]
    )

    decision = parse_routing_response(raw, "Unit", _ALL)

    assert {a.domain for a in decision.activations} == set(_ALL)


def test_hyphen_and_em_dash_separators_both_parse() -> None:
    raw = "ROUTE lending: ACTIVATE - plain hyphen separator"

    decision = parse_routing_response(raw, "Unit", _ALL)

    assert decision.activated_domains() == (DomainId.LENDING,)

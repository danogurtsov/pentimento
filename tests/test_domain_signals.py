from pentimento.detection.domain_signals import DomainId, detect_domain_signals_in_file


def test_lending_signal_fires_on_collateral_deposit_and_debt_issuance_co_occurrence() -> None:
    source = """
    contract Money {
        function deposit(uint256 a) external {}
        function borrow(uint256 a) external {}
    }
    """
    signals = detect_domain_signals_in_file(source)

    assert any(s.domain == DomainId.LENDING for s in signals)
    lending = next(s for s in signals if s.domain == DomainId.LENDING)
    assert lending.matched_functions == ("deposit", "borrow")


def test_lending_signal_does_not_fire_on_a_bare_deposit_alone() -> None:
    # a single deposit() is far too common (custody, ERC-4626, ...) to mean anything alone -
    # see domain_signals.py's own module docstring on why co-occurrence is required.
    source = "contract Vault { function deposit(uint256 a) external {} }"
    signals = detect_domain_signals_in_file(source)
    assert not any(s.domain == DomainId.LENDING for s in signals)


def test_amm_dex_signal_requires_all_three_roles() -> None:
    source = """
    contract Pool {
        function swap(uint256 a) external {}
        function addLiquidity(uint256 a) external {}
        function removeLiquidity(uint256 a) external {}
    }
    """
    signals = detect_domain_signals_in_file(source)
    assert any(s.domain == DomainId.AMM_DEX for s in signals)


def test_amm_dex_signal_does_not_fire_with_only_swap() -> None:
    source = "contract Router { function swap(uint256 a) external {} }"
    signals = detect_domain_signals_in_file(source)
    assert not any(s.domain == DomainId.AMM_DEX for s in signals)


def test_yield_vault_signal_fires_on_real_euler_earn_shaped_functions() -> None:
    # exact real function names from Euler's EulerEarn.sol, not a made-up fixture - see
    # domain_signals.py's module docstring.
    source = """
    contract EulerEarn {
        function setSupplyQueue(address[] calldata q) external {}
        function updateWithdrawQueue(uint256[] calldata idx) external {}
        function reallocate(uint256[] calldata a) external {}
    }
    """
    signals = detect_domain_signals_in_file(source)
    assert any(s.domain == DomainId.YIELD_VAULT for s in signals)


def test_no_signals_on_a_real_non_matching_derivatives_contract() -> None:
    # real function-name shape from Tremolo's VarianceMarket.sol (a variance-swap
    # settlement contract) - a genuine negative case, none of the 3 domains apply.
    source = """
    contract VarianceMarket {
        function subscribe(uint256 seriesId, uint8 side, uint256 units) external {}
        function unsubscribe(uint256 seriesId, uint8 side, uint256 units) external {}
        function settle(uint256 seriesId) external {}
        function redeem(uint256 seriesId, uint8 side, uint256 units, address to) external {}
    }
    """
    signals = detect_domain_signals_in_file(source)
    assert signals == []


def test_roles_must_co_occur_in_the_same_contract_not_across_siblings() -> None:
    source = """
    contract A { function deposit(uint256 a) external {} }
    contract B { function borrow(uint256 a) external {} }
    """
    signals = detect_domain_signals_in_file(source)
    assert not any(s.domain == DomainId.LENDING for s in signals)

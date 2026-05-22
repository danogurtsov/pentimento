from pentimento.detection.state_invariants import analyze_state_sync, analyze_state_sync_in_file

# Conservation relationship (QuillShield type 2: "totalFunds = availableFunds + lockedFunds"):
# lock/unlock/relock all move `available` and `locked` in OPPOSITE directions together.
# forceUnlock only touches `locked` - a candidate accounting gap.
CONSERVATION_SOURCE = """
contract Treasury {
    uint256 public available;
    uint256 public locked;

    function lock(uint256 amount) external {
        available -= amount;
        locked += amount;
    }

    function unlock(uint256 amount) external {
        available += amount;
        locked -= amount;
    }

    function relock(uint256 amount) external {
        available -= amount;
        locked += amount;
    }

    function forceUnlock(uint256 amount) external {
        locked -= amount;
    }
}
"""

CONSISTENT_CONSERVATION_SOURCE = """
contract Treasury {
    uint256 public available;
    uint256 public locked;

    function lock(uint256 amount) external {
        available -= amount;
        locked += amount;
    }

    function unlock(uint256 amount) external {
        available += amount;
        locked -= amount;
    }

    function relock(uint256 amount) external {
        available -= amount;
        locked += amount;
    }
}
"""

# Synchronized relationship (QuillShield type 1/5: totalSupply moves WITH balanceOf together).
# adminMint only bumps totalSupply, never the recipient's balance - a candidate gap, but
# it's onlyOwner-gated while mint/burn/airdrop are all public - different privilege tier,
# must NOT be flagged (Privilege Overlay).
SYNCHRONIZED_WITH_PRIVILEGED_GAP_SOURCE = """
contract Token {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function burn(address from, uint256 amount) external {
        totalSupply -= amount;
        balanceOf[from] -= amount;
    }

    function airdrop(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
    }

    function adminMint(uint256 amount) external onlyOwner {
        totalSupply += amount;
    }
}
"""

TOO_FEW_WRITERS_SOURCE = """
contract Thing {
    uint256 public a;
    uint256 public b;
    function f() external { a += 1; b += 1; }
}
"""


def test_finds_the_conservation_anomaly() -> None:
    anomalies = analyze_state_sync(CONSERVATION_SOURCE)
    hit = next((a for a in anomalies if a.violating_function == "forceUnlock"), None)
    assert hit is not None
    assert hit.relationship == "conservation"
    assert hit.missing_variable == "available"
    assert {hit.variable_a, hit.variable_b} == {"available", "locked"}


def test_fully_consistent_pair_produces_no_anomaly() -> None:
    assert analyze_state_sync(CONSISTENT_CONSERVATION_SOURCE) == []


def test_privilege_overlay_suppresses_a_different_tier_violator() -> None:
    anomalies = analyze_state_sync(SYNCHRONIZED_WITH_PRIVILEGED_GAP_SOURCE)
    assert not any(a.violating_function == "adminMint" for a in anomalies)


def test_synchronized_relationship_is_labeled_correctly_when_no_gap_is_flagged() -> None:
    # mint/burn/airdrop alone (no adminMint) - all-consistent, same-direction pair.
    consistent_source = SYNCHRONIZED_WITH_PRIVILEGED_GAP_SOURCE.replace(
        """
    function adminMint(uint256 amount) external onlyOwner {
        totalSupply += amount;
    }
""",
        "",
    )
    assert analyze_state_sync(consistent_source) == []


def test_too_few_writers_produces_no_anomaly() -> None:
    assert analyze_state_sync(TOO_FEW_WRITERS_SOURCE) == []


def test_unrelated_variables_are_not_paired() -> None:
    source = """
    contract Thing {
        uint256 public a;
        uint256 public b;
        uint256 public c;
        function f1() external { a += 1; }
        function f2() external { a += 1; }
        function f3() external { a += 1; }
        function g1() external { b += 1; }
        function g2() external { b += 1; }
        function g3() external { b += 1; }
    }
    """
    # a and b are each written by 3 functions, but NEVER together (comod = 0) - must not
    # be paired at all despite both individually passing the sample-size bar.
    assert analyze_state_sync(source) == []


def test_raw_file_with_named_imports_is_not_broken_by_import_braces() -> None:
    raw = f"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {{IERC20}} from "./IERC20.sol";

{CONSERVATION_SOURCE}
"""
    anomalies = analyze_state_sync_in_file(raw)
    assert any(a.violating_function == "forceUnlock" for a in anomalies)

from pentimento.detection.guard_analysis import analyze_guard_consistency, analyze_guard_consistency_in_file

# QuillShield's own canonical example (Layer 1 of its semantic protocol):
# deposit/withdraw/transfer all check whenNotPaused before writing `balance`;
# emergencyWithdraw doesn't - exactly their "<-- ANOMALY" illustration. ownerSweep is a
# SECOND writer with no guard either, but is onlyOwner-gated - a different privilege tier
# from the (public, no owner-ish modifier) majority, so it must NOT be flagged (Privilege
# Overlay: a public/privileged split is a design choice, not an inconsistency).
PAUSE_GUARD_SOURCE = """
contract Vault {
    uint256 public balance;
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function deposit(uint256 amount) external whenNotPaused {
        balance += amount;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balance -= amount;
    }

    function transfer(uint256 amount) external whenNotPaused {
        balance -= amount;
    }

    function emergencyWithdraw(uint256 amount) external {
        balance -= amount;
    }

    function ownerSweep(uint256 amount) external onlyOwner {
        balance -= amount;
    }
}
"""

CONSISTENT_SOURCE = """
contract Vault {
    uint256 public balance;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function deposit(uint256 amount) external whenNotPaused {
        balance += amount;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balance -= amount;
    }

    function transfer(uint256 amount) external whenNotPaused {
        balance -= amount;
    }
}
"""

SINGLE_WRITER_SOURCE = """
contract Thing {
    uint256 public counter;

    function bump() external {
        counter += 1;
    }
}
"""

NO_STATE_VARS_SOURCE = "contract Empty { function noop() external {} }"


def test_finds_the_quillshield_canonical_anomaly() -> None:
    anomalies = analyze_guard_consistency(PAUSE_GUARD_SOURCE)
    hit = next((a for a in anomalies if a.violating_function == "emergencyWithdraw"), None)
    assert hit is not None
    assert hit.state_variable == "balance"
    assert hit.guard == "whenNotPaused"


def test_privilege_overlay_suppresses_a_different_tier_violator() -> None:
    anomalies = analyze_guard_consistency(PAUSE_GUARD_SOURCE)
    assert not any(a.violating_function == "ownerSweep" for a in anomalies)


def test_fully_consistent_guards_produce_no_anomaly() -> None:
    assert analyze_guard_consistency(CONSISTENT_SOURCE) == []


def test_a_single_writer_is_not_enough_to_establish_a_pattern() -> None:
    assert analyze_guard_consistency(SINGLE_WRITER_SOURCE) == []


def test_no_state_variables_at_all() -> None:
    assert analyze_guard_consistency(NO_STATE_VARS_SOURCE) == []


def test_guard_frequency_is_reported_accurately() -> None:
    anomalies = analyze_guard_consistency(PAUSE_GUARD_SOURCE)
    hit = next(a for a in anomalies if a.violating_function == "emergencyWithdraw")
    # balance has 5 writers total (deposit/withdraw/transfer/emergencyWithdraw/ownerSweep) -
    # 3 of the 5 carry whenNotPaused, including ownerSweep in the denominator even though
    # it's excluded from being FLAGGED (different privilege tier).
    assert hit.guard_frequency == 3 / 5
    assert hit.invariant_strength == "weak"
    assert hit.severity == "medium"


# a real bug found running against real EulerEarn.sol, not anticipated from any
# self-authored fixture: a named import's braces (`import {X} from "...";`) are the FIRST
# `{` in almost every real Solidity file - a naive "first `{` to last `}`" scan latches
# onto that instead of the contract's own opening brace, silently finding zero functions
# and garbage "state variables" (type names/import identifiers) on every real file tried.
RAW_FILE_WITH_NAMED_IMPORTS = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {SafeCast} from "./libraries/SafeCast.sol";

contract Vault {
    uint256 public balance;
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function deposit(uint256 amount) external whenNotPaused {
        balance += amount;
    }

    function withdraw(uint256 amount) external whenNotPaused {
        balance -= amount;
    }

    function emergencyWithdraw(uint256 amount) external {
        balance -= amount;
    }
}
"""

TWO_DECLARATIONS_ONE_FILE = """
interface IThing {
    function foo() external view returns (uint256);
}

contract Thing {
    uint256 public balance;
    function a() external { balance += 1; }
    function b() external { balance += 1; }
    function c() external { balance += 1; }
}
"""


def test_raw_file_with_named_imports_is_not_broken_by_import_braces() -> None:
    # this is the actual regression: analyze_guard_consistency() alone (no file-level
    # wrapper) on this exact text used to find zero functions at all.
    anomalies = analyze_guard_consistency_in_file(RAW_FILE_WITH_NAMED_IMPORTS)
    assert any(a.violating_function == "emergencyWithdraw" for a in anomalies)


def test_file_level_entry_point_matches_pre_scoped_result_for_a_plain_file() -> None:
    scoped = analyze_guard_consistency(RAW_FILE_WITH_NAMED_IMPORTS[RAW_FILE_WITH_NAMED_IMPORTS.index("contract") :])
    from_file = analyze_guard_consistency_in_file(RAW_FILE_WITH_NAMED_IMPORTS)
    assert scoped == from_file


def test_file_level_entry_point_handles_multiple_declarations_independently() -> None:
    anomalies = analyze_guard_consistency_in_file(TWO_DECLARATIONS_ONE_FILE)
    # IThing has no function bodies to analyze at all - only Thing's own (consistent,
    # no anomaly) writers should ever be considered.
    assert anomalies == []


# real bug found running against real EulerEarn.sol: `constructor(...) ERC20() Ownable(owner)
# EVCUtil(evc) { ... }` is Solidity's base-constructor-chaining syntax - SYNTACTICALLY
# IDENTICAL to a regular function's modifier list. Before excluding constructors from the
# writer set, ERC20/Ownable/EVCUtil were each treated as a "guard" only the constructor
# has, producing a combinatorial explosion of meaningless 50%-frequency findings between
# the constructor and the one other real writer (setName).
CONSTRUCTOR_CHAINING_SOURCE = """
contract Vault is ERC20, Ownable {
    string private _name;

    constructor(string memory name_) ERC20() Ownable(msg.sender) {
        _name = name_;
    }

    function setName(string memory newName) external onlyOwner {
        _name = newName;
    }
}
"""


def test_constructor_is_excluded_from_the_writer_set_entirely() -> None:
    # only 1 real writer left (setName) once the constructor is excluded - below the
    # minimum sample size, so this must produce zero findings, not a flood of noise.
    assert analyze_guard_consistency(CONSTRUCTOR_CHAINING_SOURCE) == []


def test_two_writers_is_too_small_a_sample_to_establish_a_pattern() -> None:
    # a bare 2-writer split is ALWAYS exactly 50/50 in both directions - never a
    # statistically meaningful "most functions do X" pattern, regardless of which one
    # "wins" the split.
    two_writer_source = """
    contract Vault {
        uint256 public balance;
        modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
        function a() external onlyOwner { balance += 1; }
        function b() external { balance += 1; }
    }
    """
    assert analyze_guard_consistency(two_writer_source) == []


def test_ownersweep_itself_never_becomes_a_finding_via_the_onlyowner_guard() -> None:
    # onlyOwner only covers 1 of 5 writers of `balance` (20%) - below the 50% threshold to
    # even be considered a candidate invariant, so it can never produce a finding either.
    anomalies = analyze_guard_consistency(PAUSE_GUARD_SOURCE)
    assert not any(a.guard == "onlyOwner" for a in anomalies)

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Regression fixture for a real bug found on DeFiHackLabs' Euler_exp.sol: two UNRELATED
// files each declaring their own "Widget" contract (a generic name reused across many
// independently written scripts is common in real-world batches, not a hypothetical).
// This file's Widget must create Target1 — never Target2 from the sibling file below.
contract Target1 {
    function foo() external pure returns (uint256) {
        return 1;
    }
}

contract Widget {
    function make() external returns (address) {
        Target1 x = new Target1();
        return address(x);
    }
}

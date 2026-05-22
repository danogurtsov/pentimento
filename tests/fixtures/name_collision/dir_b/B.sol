// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// See dir_a/A.sol — this "Widget" is UNRELATED to that one despite sharing the name.
// This file's Widget must create Target2 — never Target1 from the sibling file above.
contract Target2 {
    function bar() external pure returns (uint256) {
        return 2;
    }
}

contract Widget {
    function make() external returns (address) {
        Target2 x = new Target2();
        return address(x);
    }
}

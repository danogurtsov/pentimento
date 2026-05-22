// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// A library with an `external` function DOES need to be deployed and delegatecall'd into -
// it has real logic that isn't inlined at every call site, unlike MathLib.sol next to it.
// This is the positive case: deployability must not blanket-exclude every `library`.
library PublicLib {
    function double(uint256 a) external pure returns (uint256) {
        return a * 2;
    }
}

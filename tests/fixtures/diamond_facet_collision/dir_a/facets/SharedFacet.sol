// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// The REAL facet of dir_a/Diamond.sol - lives in the same directory tree as its diamond.
contract SharedFacet {
    string public symbol = "A";

    function transfer(address to, uint256 amount) external returns (bool) {
        return true;
    }
}

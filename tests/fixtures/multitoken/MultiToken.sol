// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Self-contained ERC-6909 SHAPE (EIP-6909 multi-token accounting) - real-world-motivated by
// Tremolo's VarianceMarket (a singleton doing series-as-token-id accounting via solady's
// ERC6909, instead of one token contract per series). Function NAMES overlap with classic
// ERC-20 (transfer/approve/balanceOf/transferFrom/allowance), but every one of them takes
// an extra `id` parameter - a different (name, types) tuple, so before the classify.py fix
// none of it scored anything at all and this came back UNKNOWN.
contract MultiToken {
    function balanceOf(address, uint256) external pure returns (uint256) {
        return 0;
    }

    function allowance(address, address, uint256) external pure returns (uint256) {
        return 0;
    }

    function isOperator(address, address) external pure returns (bool) {
        return false;
    }

    function transfer(address, uint256, uint256) external pure returns (bool) {
        return true;
    }

    function transferFrom(address, address, uint256, uint256) external pure returns (bool) {
        return true;
    }

    function approve(address, uint256, uint256) external pure returns (bool) {
        return true;
    }

    function setOperator(address, bool) external pure returns (bool) {
        return true;
    }
}

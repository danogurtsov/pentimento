// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Storage lives on the Diamond itself in a real EIP-2535 setup (shared diamond storage) —
/// simplified here since this fixture only exercises facet DETECTION/merge, not the
/// storage-layout side of diamonds.
contract TokenFacet {
    string public symbol = "DFT";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        return true;
    }
}

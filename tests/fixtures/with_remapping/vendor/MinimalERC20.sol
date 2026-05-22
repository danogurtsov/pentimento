// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Stand-in for an external dependency (OpenZeppelin/Solmate-shaped) — lives OUTSIDE the
/// target contracts directory (src/), resolved only via remapping. Tests that the
/// converter (a) actually resolves the import at all and (b) does NOT turn this into its
/// own CDV unit — real repos almost always import something like this, and solc reports
/// it as a compiled contract just like any other, so filtering it out is not optional.
contract MinimalERC20 {
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(string memory symbol_) {
        symbol = symbol_;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) public virtual returns (bool) {
        return true;
    }
}

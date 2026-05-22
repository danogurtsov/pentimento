// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Upgradeable logic contract behind Proxy.sol — guarded by an `initializer` modifier,
/// the repo-first stand-in for "this is the impl a live proxy points at".
contract Implementation {
    bool private _initialized;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    modifier initializer() {
        require(!_initialized, "already initialized");
        _initialized = true;
        _;
    }

    function initialize(uint256 initialSupply) external initializer {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

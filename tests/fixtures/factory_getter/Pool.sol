// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Template contract instantiated by Factory.sol — the "getter-enumerable factory" case
/// from step3_cdv_standard.md §3a: no live chain to enumerate real instances against yet,
/// but the STRUCTURAL fact (Factory deploys many of these) is visible from source alone.
contract Pool {
    address public token0;
    address public token1;

    constructor(address tokenA, address tokenB) {
        token0 = tokenA;
        token1 = tokenB;
    }

    function getReserves() external pure returns (uint112, uint112) {
        return (0, 0);
    }
}

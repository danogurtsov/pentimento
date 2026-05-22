// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Pair {
    address public token0;
    address public token1;

    constructor(address tokenA, address tokenB) {
        token0 = tokenA;
        token1 = tokenB;
    }
}

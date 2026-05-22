// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Pool.sol";

contract Factory {
    address[] public allPools;

    function createPool(address tokenA, address tokenB) external returns (address pool) {
        Pool newPool = new Pool(tokenA, tokenB);
        pool = address(newPool);
        allPools.push(pool);
    }

    function allPoolsLength() external view returns (uint256) {
        return allPools.length;
    }
}

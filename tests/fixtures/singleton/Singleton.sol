// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal Morpho-Blue-style singleton: "markets" are bytes32-keyed records inside ONE
/// contract's storage, not separate deployed contracts. createMarket computes a
/// deterministic id via keccak256(abi.encode(...)) and writes a record into a mapping —
/// no `new X(...)` anywhere, which is exactly what makes this a logical entity rather
/// than a factory instance (see step3_cdv_standard.md §3.4 / dandelion's singleton.py,
/// which distinguishes the same thing on-chain by event topic0 instead).
struct MarketParams {
    address loanToken;
    address collateralToken;
    address oracle;
    address irm;
    uint256 lltv;
}

struct Market {
    uint128 totalSupplyAssets;
    uint128 totalBorrowAssets;
    uint128 lastUpdate;
}

contract Singleton {
    mapping(bytes32 => Market) public market;

    function createMarket(MarketParams memory marketParams) external {
        bytes32 id = keccak256(abi.encode(marketParams));
        require(market[id].lastUpdate == 0, "already created");
        market[id].lastUpdate = uint128(block.timestamp);
    }

    function supply(bytes32 id, uint256 assets) external {
        market[id].totalSupplyAssets += uint128(assets);
    }
}

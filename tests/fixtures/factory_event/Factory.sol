// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Pair.sol";

/// Event-only enumerable factory: no allPairs array, no length getter anywhere — the ONLY
/// way to discover a deployed Pair is the PairCreated event. This is the repo-first,
/// no-chain stand-in for the pattern dandelion's `factory_events.py` already handles
/// on-chain via a topic0 registry (Uniswap-style PairCreated / Morpho-style
/// CreateMetaMorpho) — same discovery problem, seen here before any deployment exists.
contract Factory {
    event PairCreated(address indexed tokenA, address indexed tokenB, address pair);

    function createPair(address tokenA, address tokenB) external returns (address pair) {
        Pair newPair = new Pair(tokenA, tokenB);
        pair = address(newPair);
        emit PairCreated(tokenA, tokenB, pair);
    }
}

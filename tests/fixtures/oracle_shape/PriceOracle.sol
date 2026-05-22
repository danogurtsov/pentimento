// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Real-world-motivated fixture (Tremolo's IChainlinkAggregator): before the classify.py
// fix, decimals() alone was strong enough evidence for TOKEN to out-tie a real ORACLE,
// purely because TOKEN happened to be declared first in _SIGNATURE_GROUPS. decimals() is
// not token-specific at all - oracles, vaults, and anything with fixed-point precision
// expose it too - so it must never be able to out-score a dedicated ORACLE signature match.
contract PriceOracle {
    function decimals() external pure returns (uint8) {
        return 8;
    }

    function latestRoundData()
        external
        pure
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (1, 100, 0, 0, 1);
    }
}

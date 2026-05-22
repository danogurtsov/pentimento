// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// UNRELATED facet, in an unrelated directory, that just happens to reuse the exact same
// bare name "SharedFacet" - belongs to some OTHER diamond not present in this fixture at
// all. Must never be merged into dir_a/Diamond.sol. Deliberately ORACLE-shaped (not
// TOKEN-shaped like dir_a's real facet) so a wrong merge would be provable by node_type
// alone, not just by which source file shows up.
contract SharedFacet {
    function latestRoundData() external pure returns (uint80, int256, uint256, uint256, uint80) {
        return (1, 100, 0, 0, 1);
    }

    function latestAnswer() external pure returns (int256) {
        return 100;
    }
}

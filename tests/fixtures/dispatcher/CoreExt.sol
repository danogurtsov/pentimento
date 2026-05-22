// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// The extension half of Core.sol — supplies the rest of the token-like surface that
/// Core doesn't implement directly. Named `<Main>Ext` by the same convention Compound III
/// uses for Comet/CometExt.
contract CoreExt {
    function symbol() external pure returns (string memory) {
        return "COR";
    }

    function decimals() external pure returns (uint8) {
        return 18;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }
}

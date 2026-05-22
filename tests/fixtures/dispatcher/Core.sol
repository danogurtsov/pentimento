// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal dispatcher-proxy: has its OWN real logic (unlike a pure EIP-1967 proxy, which
/// carries almost none) AND falls back to a second "extension" contract for functions not
/// implemented directly here — the repo-first stand-in for Compound III's Comet/CometExt
/// split, the simplest of the >=4 mechanically different real dispatcher patterns
/// catalogued in step2_proxies_upgrades.md (Fluid InfiniteProxy / Synthetix V3 Router /
/// Balancer V3 Vault-VaultExtension being the others — deliberately not replicated here,
/// each is its own distinct future primitive if a real repo needs it).
contract Core {
    address public immutable coreExtension;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address extension_) {
        coreExtension = extension_;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    fallback() external payable {
        address ext = coreExtension;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), ext, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

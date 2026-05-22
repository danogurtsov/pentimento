// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal hand-rolled EIP-1967 UUPS-style proxy (no admin slot — UUPS, not transparent).
contract Proxy {
    // EIP-1967: bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1), computed
    // rather than hardcoded so the value is self-verifying instead of a memorized hex string.
    bytes32 private constant _IMPLEMENTATION_SLOT = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);

    constructor(address implementation_) {
        _setImplementation(implementation_);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    function _implementation() internal view returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        _setImplementation(newImplementation);
        if (data.length > 0) {
            (bool ok, ) = newImplementation.delegatecall(data);
            require(ok, "upgrade call failed");
        }
    }

    fallback() external payable {
        address impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}

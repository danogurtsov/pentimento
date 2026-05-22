// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Minimal EIP-2535 diamond: dispatches by selector to whichever facet registered it via
/// diamondCut. Detected as ProxyKind.DIAMOND purely by the presence of diamondCut/
/// facetAddresses in source (see proxies.py) — no delegatecall pattern requirement, unlike
/// the EIP-1967 case, since a diamond's dispatch table is itself the distinguishing shape.
contract Diamond {
    mapping(bytes4 => address) internal selectorToFacet;

    struct FacetCut {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    function diamondCut(FacetCut[] calldata cuts) external {
        for (uint256 i = 0; i < cuts.length; i++) {
            for (uint256 j = 0; j < cuts[i].functionSelectors.length; j++) {
                selectorToFacet[cuts[i].functionSelectors[j]] = cuts[i].facetAddress;
            }
        }
    }

    function facetAddresses() external pure returns (address[] memory addrs) {
        addrs = new address[](0);
    }

    fallback() external payable {
        address facet = selectorToFacet[msg.sig];
        require(facet != address(0), "no facet for selector");
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Real-world-motivated fixture (Aavegotchi/aavegotchi-contracts): that repo runs 5
// SEPARATE diamonds in one monorepo, each under its own top-level directory, and reuses
// the exact SAME facet name (AavegotchiFacet/BridgeFacet/ItemsFacet) for genuinely
// DIFFERENT facets belonging to different diamonds - their own deploy scripts disambiguate
// by directory/hardcoded address, not by name. dir_b/facets/SharedFacet.sol next to this
// fixture is an UNRELATED facet reusing the same bare name - it must never be pulled into
// THIS diamond.
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

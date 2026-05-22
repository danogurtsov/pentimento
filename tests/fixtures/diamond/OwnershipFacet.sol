// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract OwnershipFacet {
    address public owner;

    function transferOwnership(address newOwner) external {
        owner = newOwner;
    }
}

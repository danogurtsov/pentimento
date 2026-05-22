// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Counter-based logical-entity singleton — real-world-motivated by Uniswap V3's
// NonfungiblePositionManager.mint() (`tokenId = _nextId++`), Aavegotchi's DAOFacet
// (`itemId = itemTypesLength++`), and our own Tremolo's VarianceMarket.createSeries()
// (`seriesId = ++seriesCount`). Unlike Singleton.sol (hash-based id), this one assigns a
// plain incrementing counter - no `new X(...)`, no clone, no assembly create anywhere,
// which is exactly what makes it a logical entity rather than a factory instance.
struct Entry {
    address owner;
    uint256 value;
}

contract Registry {
    uint256 private nextId = 1;
    mapping(uint256 => Entry) public entries;

    function createEntry(address owner, uint256 value) external returns (uint256 entryId) {
        entryId = nextId++;
        entries[entryId] = Entry({owner: owner, value: value});
    }
}

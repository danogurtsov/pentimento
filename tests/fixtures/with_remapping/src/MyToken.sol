// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "lib/MinimalERC20.sol";

/// Our own contract — inherits the whole ERC20-like surface from a remapped external
/// dependency. Its OWN ABI (as solc reports it) already includes the inherited
/// transfer/balanceOf/etc. functions, so classify() needs no special-casing for
/// inheritance — this is the thing being verified, not assumed.
contract MyToken is MinimalERC20 {
    constructor() MinimalERC20("MTK") {}

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}

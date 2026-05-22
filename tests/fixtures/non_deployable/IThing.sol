// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// An interface is never deployed on its own - no bytecode, no address, ever. Real bug found
// on Tremolo: four bare interfaces each became their own top-level CDV unit before the
// deployability.py fix.
interface IThing {
    function foo() external view returns (uint256);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// All-internal library: fully inlined into every caller at compile time, so it never gets
// its own real bytecode - confirmed empirically on Tremolo's VarianceMath (compiling with
// --combined-json abi,bin showed the standard "delegatecall-only, else revert" placeholder
// stub, byte-identical to solady's own all-internal FixedPointMathLib regardless of actual
// function bodies - never real logic, never delegatecall'd, so nothing runs it on chain).
library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IThing} from "./IThing.sol";
import {MathLib} from "./MathLib.sol";

// The only file in this fixture that should end up as its own CDV unit besides PublicLib.
contract Thing is IThing {
    function foo() external pure returns (uint256) {
        return MathLib.add(1, 2);
    }
}

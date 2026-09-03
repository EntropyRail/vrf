// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IL1FeeCalculator} from "../interfaces/IL1FeeCalculator.sol";

/// @dev Local-test adapter only. Production deployments must use a chain-specific calculator.
contract ZeroL1FeeCalculator is IL1FeeCalculator {
    function currentTxL1CostWei() external pure returns (uint256) {
        return 0;
    }
}

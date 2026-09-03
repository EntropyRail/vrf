// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Network adapter for the current fulfillment transaction's L1 data fee.
interface IL1FeeCalculator {
    function currentTxL1CostWei() external view returns (uint256);
}

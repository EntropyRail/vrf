// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {IL1FeeCalculator} from "../interfaces/IL1FeeCalculator.sol";
/// @dev Test-only fee oracle; never use in a deployment.
contract MockL1FeeCalculator is IL1FeeCalculator {
    uint256 public fee;
    function setFee(uint256 value) external { fee = value; }
    function currentTxL1CostWei() external view returns (uint256) { return fee; }
}

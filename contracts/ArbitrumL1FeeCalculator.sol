// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IL1FeeCalculator} from "./interfaces/IL1FeeCalculator.sol";

interface IArbGasInfo {
    function getCurrentTxL1GasFees() external view returns (uint256);
}

/// @notice Reads the exact poster fee charged to the current Robinhood/Arbitrum transaction.
contract ArbitrumL1FeeCalculator is IL1FeeCalculator {
    IArbGasInfo public constant ARB_GAS_INFO =
        IArbGasInfo(0x000000000000000000000000000000000000006C);

    function currentTxL1CostWei() external view returns (uint256) {
        return ARB_GAS_INFO.getCurrentTxL1GasFees();
    }
}

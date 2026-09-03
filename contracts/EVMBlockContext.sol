// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IBlockContext} from "./interfaces/IBlockContext.sol";

/// @notice Native EVM block context for local tests and non-Arbitrum deployments.
contract EVMBlockContext is IBlockContext {
    function blockNumber() external view returns (uint256) {
        return block.number;
    }

    function blockHash(uint256 number) external view returns (bytes32) {
        return blockhash(number);
    }
}

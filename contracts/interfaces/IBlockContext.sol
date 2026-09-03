// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Chain-specific source for the block number and hash used by VRF requests.
interface IBlockContext {
    function blockNumber() external view returns (uint256);

    function blockHash(uint256 blockNumber) external view returns (bytes32);
}

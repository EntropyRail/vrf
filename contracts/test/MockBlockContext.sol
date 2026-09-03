// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IBlockContext} from "../interfaces/IBlockContext.sol";

contract MockBlockContext is IBlockContext {
    uint256 private s_blockNumber;
    mapping(uint256 blockNumber => bytes32 blockHash) private s_hashes;

    constructor(uint256 initialBlockNumber) {
        s_blockNumber = initialBlockNumber;
    }

    function setBlockNumber(uint256 newBlockNumber) external {
        s_blockNumber = newBlockNumber;
    }

    function setBlockHash(uint256 number, bytes32 hash) external {
        s_hashes[number] = hash;
    }

    function blockNumber() external view returns (uint256) {
        return s_blockNumber;
    }

    function blockHash(uint256 number) external view returns (bytes32) {
        return s_hashes[number];
    }
}

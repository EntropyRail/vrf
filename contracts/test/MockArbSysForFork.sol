// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @dev Fork-only stand-in because generic EVM fork engines do not emulate ArbSys precompiles.
contract MockArbSysForFork {
    function arbBlockNumber() external view returns (uint256) {
        return block.number;
    }

    function arbBlockHash(uint256 number) external view returns (bytes32) {
        return blockhash(number);
    }
}

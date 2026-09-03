// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IBlockContext} from "./interfaces/IBlockContext.sol";

interface IArbSys {
    function arbBlockNumber() external view returns (uint256);

    function arbBlockHash(uint256 arbBlockNum) external view returns (bytes32);
}

/// @notice Robinhood/Arbitrum L2 block context backed by the ArbSys precompile.
contract ArbitrumBlockContext is IBlockContext {
    IArbSys private constant ARB_SYS = IArbSys(address(100));

    function blockNumber() external view returns (uint256) {
        return ARB_SYS.arbBlockNumber();
    }

    function blockHash(uint256 number) external view returns (bytes32) {
        try ARB_SYS.arbBlockHash(number) returns (bytes32 observed) {
            return observed;
        } catch {
            return bytes32(0);
        }
    }
}

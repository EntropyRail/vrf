// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IBlockContext} from "./interfaces/IBlockContext.sol";

/// @notice Permissionless archive for block hashes before the EVM's 256-block window closes.
/// @dev Uses an explicit chain context so Robinhood requests are bound to L2, not Ethereum L1.
contract BlockhashStore {
    uint256 public constant BLOCKHASH_WINDOW = 256;

    IBlockContext public immutable blockContext;
    bytes32 public immutable blockContextCodeHash;

    mapping(uint256 blockNumber => bytes32 blockHash) public blockhashes;

    error BlockInFuture(uint256 blockNumber);
    error BlockTooOld(uint256 blockNumber);
    error BlockhashUnavailable(uint256 blockNumber);
    error BlockContextChanged();
    error InvalidBlockContext();
    error ConflictingBlockhash(uint256 blockNumber, bytes32 stored, bytes32 observed);

    event BlockhashStored(uint256 indexed blockNumber, bytes32 indexed blockHash);

    constructor(address blockContextAddress) {
        if (blockContextAddress.code.length == 0) revert InvalidBlockContext();
        blockContext = IBlockContext(blockContextAddress);
        blockContextCodeHash = blockContextAddress.codehash;
    }

    function contextBlockNumber() public view returns (uint256) {
        _checkContext();
        return blockContext.blockNumber();
    }

    function getBlockHash(uint256 blockNumber) external view returns (bytes32 blockHash) {
        blockHash = blockhashes[blockNumber];
        if (blockHash != bytes32(0)) return blockHash;
        _checkContext();
        return blockContext.blockHash(blockNumber);
    }

    function store(uint256 blockNumber) external returns (bytes32 blockHash) {
        bytes32 stored = blockhashes[blockNumber];
        uint256 currentBlock = contextBlockNumber();
        if (blockNumber >= currentBlock) revert BlockInFuture(blockNumber);
        if (currentBlock > blockNumber + BLOCKHASH_WINDOW) revert BlockTooOld(blockNumber);

        blockHash = blockContext.blockHash(blockNumber);
        if (blockHash == bytes32(0)) revert BlockhashUnavailable(blockNumber);
        if (stored != bytes32(0)) {
            if (stored != blockHash) {
                revert ConflictingBlockhash(blockNumber, stored, blockHash);
            }
            return stored;
        }

        blockhashes[blockNumber] = blockHash;
        emit BlockhashStored(blockNumber, blockHash);
    }

    function _checkContext() private view {
        if (address(blockContext).codehash != blockContextCodeHash) revert BlockContextChanged();
    }
}

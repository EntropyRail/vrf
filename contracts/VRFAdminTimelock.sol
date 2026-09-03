// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/// @notice Minimal immutable-delay owner for VRF Coordinator administration.
/// @dev A multisig should own this contract. Execution is permissionless after the delay.
contract VRFAdminTimelock is Ownable2Step {
    uint64 public constant MIN_DELAY = 12 hours;
    uint64 public constant MAX_DELAY = 30 days;
    uint64 public constant EXECUTION_WINDOW = 7 days;

    struct Operation {
        uint64 executeAfter;
        bool executed;
        bool cancelled;
    }

    uint64 public immutable delay;
    uint256 public nonce;
    mapping(bytes32 operationId => Operation operation) public operations;

    error CallFailed(bytes reason);
    error InvalidDelay();
    error InvalidOperation();
    error InvalidTarget();
    error OperationExpired();
    error OperationNotReady();

    event CallScheduled(
        bytes32 indexed operationId,
        address indexed target,
        uint256 value,
        uint64 executeAfter,
        bytes32 dataHash
    );
    event CallCancelled(bytes32 indexed operationId);
    event CallExecuted(bytes32 indexed operationId, address indexed target, uint256 value);

    constructor(address initialOwner, uint64 delaySeconds) Ownable(initialOwner) {
        if (initialOwner == address(0)) revert InvalidTarget();
        if (delaySeconds < MIN_DELAY || delaySeconds > MAX_DELAY) revert InvalidDelay();
        delay = delaySeconds;
    }

    receive() external payable {}

    function hashOperation(
        uint256 operationNonce,
        address target,
        uint256 value,
        bytes calldata data
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                operationNonce,
                target,
                value,
                keccak256(data)
            )
        );
    }

    function schedule(address target, uint256 value, bytes calldata data)
        external
        onlyOwner
        returns (bytes32 operationId)
    {
        if (target.code.length == 0) revert InvalidTarget();
        uint256 operationNonce = ++nonce;
        operationId = hashOperation(operationNonce, target, value, data);
        uint64 executeAfter = uint64(block.timestamp + delay);
        operations[operationId] = Operation({
            executeAfter: executeAfter,
            executed: false,
            cancelled: false
        });
        emit CallScheduled(operationId, target, value, executeAfter, keccak256(data));
    }

    function cancel(bytes32 operationId) external onlyOwner {
        Operation storage operation = operations[operationId];
        if (operation.executeAfter == 0 || operation.executed || operation.cancelled) {
            revert InvalidOperation();
        }
        operation.cancelled = true;
        emit CallCancelled(operationId);
    }

    function execute(
        uint256 operationNonce,
        address target,
        uint256 value,
        bytes calldata data
    ) external returns (bytes memory result) {
        if (target.code.length == 0) revert InvalidTarget();
        bytes32 operationId = hashOperation(operationNonce, target, value, data);
        Operation storage operation = operations[operationId];
        if (operation.executeAfter == 0 || operation.executed || operation.cancelled) {
            revert InvalidOperation();
        }
        if (block.timestamp < operation.executeAfter) revert OperationNotReady();
        if (block.timestamp > uint256(operation.executeAfter) + EXECUTION_WINDOW) {
            revert OperationExpired();
        }
        operation.executed = true;
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) revert CallFailed(returnData);
        emit CallExecuted(operationId, target, value);
        return returnData;
    }
}

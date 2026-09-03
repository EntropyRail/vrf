// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal consumer boundary shared by the single-key and future threshold coordinators.
abstract contract ProofVRFConsumerBase {
    address public immutable vrfCoordinator;

    error OnlyCoordinator(address caller);
    error ZeroAddress();

    constructor(address coordinator) {
        if (coordinator == address(0)) revert ZeroAddress();
        vrfCoordinator = coordinator;
    }

    function rawFulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external {
        if (msg.sender != vrfCoordinator) revert OnlyCoordinator(msg.sender);
        _fulfillRandomWords(requestId, randomWords);
    }

    function _fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal virtual;
}

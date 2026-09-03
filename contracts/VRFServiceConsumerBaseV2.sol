// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IVRFServiceCoordinatorV2} from "./interfaces/IVRFServiceCoordinatorV2.sol";

/// @notice Consumer-side coordinator authentication for the subscription service.
abstract contract VRFServiceConsumerBaseV2 {
    IVRFServiceCoordinatorV2 public immutable vrfCoordinator;

    error OnlyCoordinator(address sender, address coordinator);

    constructor(address coordinator) {
        vrfCoordinator = IVRFServiceCoordinatorV2(coordinator);
    }

    function rawFulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) external {
        if (msg.sender != address(vrfCoordinator)) {
            revert OnlyCoordinator(msg.sender, address(vrfCoordinator));
        }
        fulfillRandomWords(requestId, randomWords);
    }

    function fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal virtual;
}

// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IProofVRFConsumer} from "../interfaces/IProofVRFConsumer.sol";
import {IVRFServiceCoordinatorV2} from "../interfaces/IVRFServiceCoordinatorV2.sol";

interface IRetryPruneCoordinator {
    function pruneRequest(uint256 requestId) external;
}

contract MockReentrantPrunerConsumer is IProofVRFConsumer {
    address public immutable coordinator;
    bool public failCallback = true;
    bool public pruneSucceeded;

    constructor(address coordinatorAddress) {
        coordinator = coordinatorAddress;
    }

    function setFailCallback(bool value) external {
        failCallback = value;
    }

    function request(IVRFServiceCoordinatorV2.RandomWordsRequest calldata parameters)
        external
        returns (uint256)
    {
        return IVRFServiceCoordinatorV2(coordinator).requestRandomWords(parameters);
    }

    function rawFulfillRandomWords(uint256 requestId, uint256[] calldata) external {
        require(msg.sender == coordinator, "only coordinator");
        if (failCallback) revert("initial callback failure");
        try IRetryPruneCoordinator(coordinator).pruneRequest(requestId) {
            pruneSucceeded = true;
        } catch {}
    }
}

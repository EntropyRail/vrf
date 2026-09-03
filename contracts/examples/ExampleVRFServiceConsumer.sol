// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {VRFServiceConsumerBaseV2} from "../VRFServiceConsumerBaseV2.sol";
import {IVRFServiceCoordinatorV2} from "../interfaces/IVRFServiceCoordinatorV2.sol";

contract ExampleVRFServiceConsumer is VRFServiceConsumerBaseV2, Ownable {
    uint256 public lastRequestId;
    bool public revertCallbacks;
    uint256[] private s_lastWords;

    constructor(address coordinator, address initialOwner)
        VRFServiceConsumerBaseV2(coordinator)
        Ownable(initialOwner)
    {}

    function request(IVRFServiceCoordinatorV2.RandomWordsRequest calldata params)
        external
        onlyOwner
        returns (uint256 requestId)
    {
        requestId = vrfCoordinator.requestRandomWords(params);
        lastRequestId = requestId;
    }

    function setRevertCallbacks(bool shouldRevert) external onlyOwner {
        revertCallbacks = shouldRevert;
    }

    function lastWords() external view returns (uint256[] memory) {
        return s_lastWords;
    }

    function fulfillRandomWords(uint256, uint256[] calldata randomWords) internal override {
        if (revertCallbacks) revert("callback disabled");
        delete s_lastWords;
        for (uint256 index; index < randomWords.length; ++index) {
            s_lastWords.push(randomWords[index]);
        }
    }
}

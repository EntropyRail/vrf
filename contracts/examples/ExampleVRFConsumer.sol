// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ProofVRFConsumerBase} from "../ProofVRFConsumerBase.sol";
import {IProofVRFService} from "../interfaces/IProofVRFService.sol";

contract ExampleVRFConsumer is ProofVRFConsumerBase, Ownable {
    IProofVRFService public immutable coordinator;
    bool public revertCallbacks;
    uint256 public lastRequestId;
    uint256[] private s_lastWords;

    event RandomnessReceived(uint256 indexed requestId, uint256[] randomWords);

    constructor(address coordinator_, address initialOwner)
        ProofVRFConsumerBase(coordinator_)
        Ownable(initialOwner)
    {
        coordinator = IProofVRFService(coordinator_);
    }

    function request(
        bytes32 keyHash,
        uint16 confirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external payable returns (uint256 requestId) {
        requestId = coordinator.requestRandomWords{value: msg.value}(
            keyHash, confirmations, callbackGasLimit, numWords
        );
        lastRequestId = requestId;
    }

    function setRevertCallbacks(bool shouldRevert) external onlyOwner {
        revertCallbacks = shouldRevert;
    }

    function lastWords() external view returns (uint256[] memory) {
        return s_lastWords;
    }

    function withdrawRefund(address payable recipient, uint256 amount) external onlyOwner {
        coordinator.withdrawCredits(recipient, amount);
    }

    function _fulfillRandomWords(uint256 requestId, uint256[] calldata randomWords) internal override {
        if (revertCallbacks) revert("callback rejected");
        delete s_lastWords;
        for (uint256 i = 0; i < randomWords.length; ++i) {
            s_lastWords.push(randomWords[i]);
        }
        emit RandomnessReceived(requestId, randomWords);
    }
}

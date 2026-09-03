// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IVRFServiceCoordinatorV2 {
    struct RandomWordsRequest {
        bytes32 keyHash;
        uint256 subscriptionId;
        uint16 requestConfirmations;
        uint32 callbackGasLimit;
        uint32 numWords;
        uint256 maxPayment;
    }

    function requestRandomWords(RandomWordsRequest calldata request)
        external
        returns (uint256 requestId);

    function quoteMaxPayment(
        bytes32 keyHash,
        address consumer,
        uint256 subscriptionId,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external view returns (uint256);
}

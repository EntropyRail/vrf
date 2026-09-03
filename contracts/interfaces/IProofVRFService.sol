// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Stable consumer-facing interface implemented by direct coordinators and the router.
interface IProofVRFService {
    function keyFee(bytes32 keyHash) external view returns (uint256 fee);

    function requestRandomWords(
        bytes32 keyHash,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external payable returns (uint256 requestId);

    function retryCallback(uint256 requestId) external returns (bool success);

    function refundExpired(uint256 requestId) external;

    function withdrawCredits(address payable recipient, uint256 amount) external;
}

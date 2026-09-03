// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {IProofVRFConsumer} from "../interfaces/IProofVRFConsumer.sol";
import {IVRFServiceCoordinatorV2} from "../interfaces/IVRFServiceCoordinatorV2.sol";

/// @dev Test-only adversary. It receives an exact witness for the provisional
///      fulfilled state, so authentication alone cannot mask missing reentrancy protection.
contract MockCompactReentrantConsumer is IProofVRFConsumer {
    address public immutable coordinator;
    bytes public attack;
    bool public failCallback = true;
    bool public attackSucceeded;
    bytes4 public failureSelector;
    constructor(address coordinator_) { coordinator = coordinator_; }
    function arm(bytes calldata data) external { attack = data; failCallback = false; }
    function request(IVRFServiceCoordinatorV2.RandomWordsRequest calldata params) external {
        IVRFServiceCoordinatorV2(coordinator).requestRandomWords(params);
    }
    function rawFulfillRandomWords(uint256, uint256[] calldata) external {
        require(msg.sender == coordinator);
        require(!failCallback, "initial failure");
        bytes memory result;
        (attackSucceeded, result) = coordinator.call(attack);
        if (result.length >= 4) failureSelector = bytes4(result);
    }
}

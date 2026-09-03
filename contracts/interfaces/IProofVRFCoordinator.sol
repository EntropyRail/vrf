// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IProofVRFService} from "./IProofVRFService.sol";

interface IProofVRFCoordinator is IProofVRFService {
    function requestSeed(uint256 requestId) external view returns (uint256 seed);
}

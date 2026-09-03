// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IThresholdBLSBackend} from "../interfaces/IThresholdBLSBackend.sol";

/// @dev Test-only protocol adapter double. It is not a BLS implementation.
contract MockThresholdBLSBackend is IThresholdBLSBackend {
    function validatePublicKey(bytes calldata groupPublicKey)
        external
        pure
        returns (bool)
    {
        return groupPublicKey.length == 192;
    }

    function verify(
        bytes calldata groupPublicKey,
        bytes calldata message,
        bytes calldata signature
    ) external pure returns (bool) {
        return signature.length == 96
            && bytes32(signature) == keccak256(abi.encode(groupPublicKey, message));
    }
}

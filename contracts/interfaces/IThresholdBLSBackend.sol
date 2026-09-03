// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Cryptographic backend for a unique-signature threshold BLS scheme.
/// @dev Implementations must validate subgroup membership and reject infinity points.
interface IThresholdBLSBackend {
    function validatePublicKey(bytes calldata groupPublicKey) external view returns (bool);

    function verify(
        bytes calldata groupPublicKey,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool);
}

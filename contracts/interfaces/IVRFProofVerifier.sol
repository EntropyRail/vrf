// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Scheme-agnostic proof verifier used by the service coordinator.
/// @dev A future threshold-BLS verifier can implement this interface without changing billing.
interface IVRFProofVerifier {
    function schemeId() external pure returns (bytes32);

    /// @notice Exact ABI byte length accepted by verify for this scheme.
    function proofLength() external view returns (uint32);

    function validateKey(bytes32 keyHash, bytes calldata keyData) external view returns (bool);

    function verify(
        bytes32 keyHash,
        uint256 actualSeed,
        uint256 expectedPreSeed,
        bytes calldata proofData
    ) external view returns (uint256 randomness);
}

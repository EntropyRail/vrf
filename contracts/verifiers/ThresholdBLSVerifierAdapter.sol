// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IThresholdBLSBackend} from "../interfaces/IThresholdBLSBackend.sol";
import {IVRFProofVerifier} from "../interfaces/IVRFProofVerifier.sol";

/// @notice Scheme adapter for an externally reviewed threshold-BLS cryptographic backend.
/// @dev This adapter does not make an arbitrary multisignature threshold-BLS. The selected
///      backend must implement a unique-signature scheme whose aggregate is independent of
///      the qualifying share subset.
contract ThresholdBLSVerifierAdapter is IVRFProofVerifier {
    uint32 public constant PROOF_LENGTH = 416;
    bytes32 public constant SCHEME_ID = keccak256("THRESHOLD_BLS_UNIQUE_SIGNATURE_V1");
    bytes32 public constant MESSAGE_DOMAIN =
        keccak256("ROBINHOOD_PROOF_VRF_THRESHOLD_BLS_MESSAGE_V1");
    bytes32 public constant OUTPUT_DOMAIN =
        keccak256("ROBINHOOD_PROOF_VRF_THRESHOLD_BLS_OUTPUT_V1");

    IThresholdBLSBackend public immutable backend;
    bytes32 public immutable backendCodeHash;

    error BackendChanged();
    error InvalidBackend();
    error InvalidGroupKey();
    error InvalidKeyCommitment();
    error InvalidProof();
    error InvalidProofEncoding();

    constructor(address backendAddress) {
        if (backendAddress.code.length == 0) revert InvalidBackend();
        backend = IThresholdBLSBackend(backendAddress);
        backendCodeHash = backendAddress.codehash;
    }

    function schemeId() external pure returns (bytes32) {
        return SCHEME_ID;
    }

    function proofLength() external pure returns (uint32) {
        return PROOF_LENGTH;
    }

    function keyHash(bytes memory groupPublicKey) public pure returns (bytes32) {
        return keccak256(abi.encode(SCHEME_ID, keccak256(groupPublicKey)));
    }

    function validateKey(bytes32 expectedKeyHash, bytes calldata keyData)
        external
        view
        returns (bool)
    {
        _checkBackend();
        if (keyHash(keyData) != expectedKeyHash) revert InvalidKeyCommitment();
        try backend.validatePublicKey(keyData) returns (bool valid) {
            if (!valid) revert InvalidGroupKey();
        } catch {
            revert InvalidGroupKey();
        }
        return true;
    }

    function messageFor(
        bytes32 expectedKeyHash,
        uint256 actualSeed,
        uint256 expectedPreSeed
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            MESSAGE_DOMAIN,
            block.chainid,
            address(this),
            expectedKeyHash,
            actualSeed,
            expectedPreSeed
        ));
    }

    function randomnessFor(bytes32 messageDigest, bytes memory signature)
        public
        pure
        returns (uint256)
    {
        return uint256(keccak256(abi.encode(OUTPUT_DOMAIN, messageDigest, keccak256(signature))));
    }

    /// @dev proofData is abi.encode(groupPublicKey, aggregateSignature).
    function verify(
        bytes32 expectedKeyHash,
        uint256 actualSeed,
        uint256 expectedPreSeed,
        bytes calldata proofData
    ) external view returns (uint256 randomness) {
        _checkBackend();
        if (proofData.length != PROOF_LENGTH) revert InvalidProofEncoding();
        (bytes memory groupPublicKey, bytes memory signature) =
            abi.decode(proofData, (bytes, bytes));
        if (groupPublicKey.length != 192 || signature.length != 96) {
            revert InvalidProofEncoding();
        }
        if (keyHash(groupPublicKey) != expectedKeyHash) revert InvalidKeyCommitment();
        bytes32 messageDigest = messageFor(expectedKeyHash, actualSeed, expectedPreSeed);
        try backend.verify(groupPublicKey, abi.encodePacked(messageDigest), signature)
            returns (bool valid)
        {
            if (!valid) revert InvalidProof();
        } catch {
            revert InvalidProof();
        }
        return randomnessFor(messageDigest, signature);
    }

    function _checkBackend() private view {
        if (address(backend).codehash != backendCodeHash) revert BackendChanged();
    }
}

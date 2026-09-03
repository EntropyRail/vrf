// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {VRF} from "../vendor/chainlink/VRF.sol";
import {IVRFProofVerifier} from "../interfaces/IVRFProofVerifier.sol";

/// @notice Chainlink-compatible secp256k1 ECVRF verifier behind a generic verifier interface.
contract Secp256k1ECVRFVerifier is VRF, IVRFProofVerifier {
    bytes32 public constant SCHEME_ID = keccak256("SECP256K1_ECVRF_V1");
    uint32 public constant PROOF_LENGTH = 416;
    uint256 private constant FIELD_SIZE =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    error InvalidKeyCommitment();
    error InvalidPreSeed();
    error InvalidProofEncoding();
    error InvalidPublicKey();

    function schemeId() external pure returns (bytes32) {
        return SCHEME_ID;
    }

    function proofLength() external pure returns (uint32) {
        return PROOF_LENGTH;
    }

    function keyHash(uint256[2] memory publicKey) public pure returns (bytes32) {
        return keccak256(abi.encode(SCHEME_ID, publicKey));
    }

    function validateKey(bytes32 expectedKeyHash, bytes calldata keyData)
        external
        pure
        returns (bool)
    {
        uint256[2] memory publicKey = abi.decode(keyData, (uint256[2]));
        if (!_isValidPublicKey(publicKey)) revert InvalidPublicKey();
        if (keyHash(publicKey) != expectedKeyHash) revert InvalidKeyCommitment();
        return true;
    }

    function verify(
        bytes32 expectedKeyHash,
        uint256 actualSeed,
        uint256 expectedPreSeed,
        bytes calldata proofData
    ) external view returns (uint256 randomness) {
        if (proofData.length != PROOF_LENGTH) revert InvalidProofEncoding();
        Proof memory proof = abi.decode(proofData, (Proof));
        if (proof.seed != expectedPreSeed) revert InvalidPreSeed();
        if (keyHash(proof.pk) != expectedKeyHash) revert InvalidKeyCommitment();

        _verifyVRFProof(
            proof.pk,
            proof.gamma,
            proof.c,
            proof.s,
            actualSeed,
            proof.uWitness,
            proof.cGammaWitness,
            proof.sHashWitness,
            proof.zInv
        );
        return uint256(keccak256(abi.encode(VRF_RANDOM_OUTPUT_HASH_PREFIX, proof.gamma)));
    }

    function _isValidPublicKey(uint256[2] memory publicKey) private pure returns (bool) {
        if (publicKey[0] == 0 && publicKey[1] == 0) return false;
        if (publicKey[0] >= FIELD_SIZE || publicKey[1] >= FIELD_SIZE) return false;
        return _isOnCurve(publicKey);
    }
}

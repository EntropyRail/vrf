// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {IThresholdBLSBackend} from "../interfaces/IThresholdBLSBackend.sol";
import {BLS2} from "../vendor/randamu/BLS2.sol";

/// @notice Experimental RFC 9380 / EIP-2537 BLS12-381 backend.
/// @dev The vendored library is experimental and unaudited. This contract is for
///      fixed-vector interoperability and testnet shadow operation only.
contract BLS12381Backend is IThresholdBLSBackend {
    bytes public constant DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    uint256 private constant PAIRING_PRECOMPILE = 0x0f;
    uint128 private constant G1_X_HI = 0x17f1d3a73197d7942695638c4fa9ac0f;
    uint256 private constant G1_X_LO =
        0xc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    uint128 private constant G1_Y_HI = 0x08b3f481e3aaa0f1a09e30ed741d8ae4;
    uint256 private constant G1_Y_LO =
        0xfcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
    uint128 private constant NEG_G1_Y_HI = 0x114d1d6855d545a8aa7d76c8cf2e21f2;
    uint256 private constant NEG_G1_Y_LO =
        0x67816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca;

    function validatePublicKey(bytes calldata groupPublicKey)
        external
        view
        returns (bool)
    {
        if (groupPublicKey.length != 192 || _allZero(groupPublicKey)) return false;
        BLS2.PointG2 memory point = BLS2.g2Unmarshal(groupPublicKey);
        // The pairing precompile performs curve and subgroup checks. Pairing a
        // point with G1 and -G1 makes the product one for every valid G2 point,
        // without needing knowledge of the corresponding secret scalar.
        uint256[24] memory input = [
            uint256(G1_X_HI),
            G1_X_LO,
            uint256(G1_Y_HI),
            G1_Y_LO,
            uint256(point.x0_hi),
            point.x0_lo,
            uint256(point.x1_hi),
            point.x1_lo,
            uint256(point.y0_hi),
            point.y0_lo,
            uint256(point.y1_hi),
            point.y1_lo,
            uint256(G1_X_HI),
            G1_X_LO,
            uint256(NEG_G1_Y_HI),
            NEG_G1_Y_LO,
            uint256(point.x0_hi),
            point.x0_lo,
            uint256(point.x1_hi),
            point.x1_lo,
            uint256(point.y0_hi),
            point.y0_lo,
            uint256(point.y1_hi),
            point.y1_lo
        ];
        uint256[1] memory output;
        bool success;
        assembly {
            success := staticcall(gas(), PAIRING_PRECOMPILE, input, 768, output, 32)
        }
        return success && output[0] != 0;
    }

    function verify(
        bytes calldata groupPublicKey,
        bytes calldata message,
        bytes calldata signature
    ) external view returns (bool) {
        if (
            groupPublicKey.length != 192 || signature.length != 96
                || _allZero(groupPublicKey) || _allZero(signature)
        ) return false;
        BLS2.PointG2 memory publicKey = BLS2.g2Unmarshal(groupPublicKey);
        BLS2.PointG1 memory signaturePoint = BLS2.g1Unmarshal(signature);
        BLS2.PointG1 memory messagePoint = BLS2.hashToPoint(DST, message);
        (bool pairingSuccess, bool callSuccess) =
            BLS2.verifySingle(signaturePoint, publicKey, messagePoint);
        return callSuccess && pairingSuccess;
    }

    function _allZero(bytes calldata value) private pure returns (bool) {
        for (uint256 i = 0; i < value.length; ++i) {
            if (value[i] != 0) return false;
        }
        return true;
    }
}

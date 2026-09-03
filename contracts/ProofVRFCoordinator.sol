// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {VRF} from "./vendor/chainlink/VRF.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IProofVRFConsumer} from "./interfaces/IProofVRFConsumer.sol";
import {IProofVRFCoordinator} from "./interfaces/IProofVRFCoordinator.sol";

/// @notice Direct-funded, proof-verified ECVRF coordinator for Robinhood Chain.
/// @dev The secp256k1 verifier is inherited from Chainlink's MIT-licensed VRF.sol. A request is
///      pinned to one public key and one containing L1 block hash. Anyone may relay a valid proof;
///      the fee is credited to the operator pinned when the request was made.
contract ProofVRFCoordinator is VRF, Ownable, ReentrancyGuard, IProofVRFCoordinator {
    uint16 public constant MIN_REQUEST_CONFIRMATIONS = 1;
    uint16 public constant MAX_REQUEST_CONFIRMATIONS = 200;
    uint32 public constant MAX_CALLBACK_GAS_LIMIT = 2_500_000;
    uint32 public constant MAX_NUM_WORDS = 32;
    uint256 public constant BLOCKHASH_WINDOW = 256;

    uint256 private constant SECP256K1_FIELD_SIZE =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    bytes32 private constant REQUEST_DOMAIN = keccak256("PROOF_VRF_REQUEST_V1");

    struct KeyConfig {
        uint256[2] publicKey;
        address operator;
        uint96 fee;
        bool exists;
        bool active;
    }

    struct Request {
        address consumer;
        address operator;
        bytes32 keyHash;
        uint64 requestBlock;
        uint16 confirmations;
        uint32 callbackGasLimit;
        uint32 numWords;
        uint96 feePaid;
        uint32 callbackAttempts;
        bool fulfilled;
        bool refunded;
        bool callbackSucceeded;
        uint256 preSeed;
        uint256 randomness;
    }

    uint256 public nonce;
    mapping(bytes32 keyHash => KeyConfig config) private s_keys;
    mapping(uint256 requestId => Request request) public requests;
    mapping(address account => uint256 amount) public credits;

    error BlockhashUnavailable(uint256 requestBlock);
    error CallbackAlreadySucceeded();
    error ConfirmationsPending(uint256 readyBlock);
    error DuplicateKey(bytes32 keyHash);
    error FeeMismatch(uint256 supplied, uint256 required);
    error InsufficientCredit(uint256 available, uint256 requested);
    error InsufficientGasForCallback(uint256 available, uint256 required);
    error InvalidCallbackGasLimit();
    error InvalidConfirmations();
    error InvalidConsumer();
    error InvalidNumWords();
    error InvalidProofKey();
    error InvalidPublicKey();
    error InvalidSeed();
    error KeyInactive(bytes32 keyHash);
    error KeyNotFound(bytes32 keyHash);
    error NotExpired(uint256 refundableAfterBlock);
    error RequestAlreadyFinalized();
    error RequestNotFulfilled();
    error TransferFailed();
    error UnknownRequest();
    error ZeroAddress();

    event KeyRegistered(
        bytes32 indexed keyHash,
        uint256 publicKeyX,
        uint256 publicKeyY,
        address indexed operator,
        uint256 fee
    );
    event KeyStatusUpdated(bytes32 indexed keyHash, bool active);
    event KeyFeeUpdated(bytes32 indexed keyHash, uint256 fee);
    event KeyOperatorUpdated(bytes32 indexed keyHash, address indexed operator);
    event RandomWordsRequested(
        bytes32 indexed keyHash,
        uint256 indexed requestId,
        address indexed consumer,
        uint256 preSeed,
        uint256 requestBlock,
        uint16 confirmations,
        uint32 callbackGasLimit,
        uint32 numWords,
        uint256 fee
    );
    event ProofVerified(uint256 indexed requestId, bytes32 indexed keyHash, uint256 randomness);
    event CallbackAttempted(uint256 indexed requestId, uint32 indexed attempt, bool success);
    event RequestRefunded(uint256 indexed requestId, address indexed consumer, uint256 amount);
    event CreditsWithdrawn(address indexed account, address indexed recipient, uint256 amount);

    constructor(address initialOwner) Ownable(initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
    }

    function keyHash(uint256[2] memory publicKey) public pure returns (bytes32) {
        return keccak256(abi.encode(publicKey));
    }

    function getKey(bytes32 hash) external view returns (KeyConfig memory) {
        KeyConfig memory config = s_keys[hash];
        if (!config.exists) revert KeyNotFound(hash);
        return config;
    }

    function keyFee(bytes32 hash) external view override returns (uint256) {
        return _requireKey(hash).fee;
    }

    function registerKey(uint256[2] calldata publicKey, address operator, uint96 fee)
        external
        onlyOwner
        returns (bytes32 hash)
    {
        if (operator == address(0)) revert ZeroAddress();
        if (!_isValidPublicKey(publicKey)) revert InvalidPublicKey();
        hash = keyHash(publicKey);
        if (s_keys[hash].exists) revert DuplicateKey(hash);
        s_keys[hash] = KeyConfig(publicKey, operator, fee, true, true);
        emit KeyRegistered(hash, publicKey[0], publicKey[1], operator, fee);
    }

    /// @dev Deactivation affects only new requests. Existing requests stay fulfillable.
    function setKeyActive(bytes32 hash, bool active) external onlyOwner {
        KeyConfig storage config = _requireKey(hash);
        config.active = active;
        emit KeyStatusUpdated(hash, active);
    }

    /// @dev Fee changes affect only new requests because every request stores feePaid.
    function setKeyFee(bytes32 hash, uint96 fee) external onlyOwner {
        KeyConfig storage config = _requireKey(hash);
        config.fee = fee;
        emit KeyFeeUpdated(hash, fee);
    }

    /// @dev Operator changes affect only new requests because every request pins its payee.
    function setKeyOperator(bytes32 hash, address operator) external onlyOwner {
        if (operator == address(0)) revert ZeroAddress();
        KeyConfig storage config = _requireKey(hash);
        config.operator = operator;
        emit KeyOperatorUpdated(hash, operator);
    }

    function requestRandomWords(
        bytes32 hash,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external payable override returns (uint256 requestId) {
        KeyConfig storage config = _requireKey(hash);
        if (!config.active) revert KeyInactive(hash);
        if (msg.sender.code.length == 0) revert InvalidConsumer();
        if (
            requestConfirmations < MIN_REQUEST_CONFIRMATIONS
                || requestConfirmations > MAX_REQUEST_CONFIRMATIONS
        ) revert InvalidConfirmations();
        if (callbackGasLimit == 0 || callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) {
            revert InvalidCallbackGasLimit();
        }
        if (numWords == 0 || numWords > MAX_NUM_WORDS) revert InvalidNumWords();
        if (msg.value != config.fee) revert FeeMismatch(msg.value, config.fee);
        if (block.number > type(uint64).max) revert BlockhashUnavailable(block.number);

        uint256 requestNonce = ++nonce;
        uint256 preSeed = uint256(
            keccak256(
                abi.encode(
                    REQUEST_DOMAIN,
                    block.chainid,
                    address(this),
                    msg.sender,
                    requestNonce,
                    hash
                )
            )
        );
        requestId = uint256(keccak256(abi.encode(preSeed)));

        requests[requestId] = Request({
            consumer: msg.sender,
            operator: config.operator,
            keyHash: hash,
            requestBlock: uint64(block.number),
            confirmations: requestConfirmations,
            callbackGasLimit: callbackGasLimit,
            numWords: numWords,
            feePaid: config.fee,
            callbackAttempts: 0,
            fulfilled: false,
            refunded: false,
            callbackSucceeded: false,
            preSeed: preSeed,
            randomness: 0
        });

        emit RandomWordsRequested(
            hash,
            requestId,
            msg.sender,
            preSeed,
            block.number,
            requestConfirmations,
            callbackGasLimit,
            numWords,
            config.fee
        );
    }

    /// @notice Returns the exact seed an operator must prove after the requested confirmations.
    /// @dev On Arbitrum chains NUMBER/BLOCKHASH expose the L1 block context. Reading the seed via
    ///      this function avoids incorrectly looking up an L2 RPC block with the same number.
    function requestSeed(uint256 requestId) public view override returns (uint256 seed) {
        Request storage request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
        if (request.fulfilled || request.refunded) revert RequestAlreadyFinalized();

        uint256 readyBlock = uint256(request.requestBlock) + request.confirmations;
        if (block.number < readyBlock) revert ConfirmationsPending(readyBlock);
        bytes32 requestBlockHash = blockhash(request.requestBlock);
        if (requestBlockHash == bytes32(0)) revert BlockhashUnavailable(request.requestBlock);
        return uint256(keccak256(abi.encodePacked(bytes32(request.preSeed), requestBlockHash)));
    }

    /// @notice Verifies the ECVRF proof, persists the output, and attempts the consumer callback.
    /// @dev Anyone may relay the proof. The pinned operator receives credit regardless of relayer.
    function fulfillRandomWords(uint256 requestId, Proof calldata proof)
        external
        returns (uint256 randomness, bool callbackSuccess)
    {
        Request storage request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
        if (request.fulfilled || request.refunded) revert RequestAlreadyFinalized();
        if (proof.seed != request.preSeed) revert InvalidSeed();
        if (keyHash(proof.pk) != request.keyHash) revert InvalidProofKey();

        uint256 seed = requestSeed(requestId);
        randomness = _randomValueFromVRFProof(proof, seed);

        request.fulfilled = true;
        request.randomness = randomness;
        credits[request.operator] += request.feePaid;
        emit ProofVerified(requestId, request.keyHash, randomness);

        callbackSuccess = _attemptCallback(requestId, request);
    }

    function retryCallback(uint256 requestId) external override returns (bool success) {
        Request storage request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
        if (!request.fulfilled) revert RequestNotFulfilled();
        if (request.callbackSucceeded) revert CallbackAlreadySucceeded();
        return _attemptCallback(requestId, request);
    }

    function randomWords(uint256 requestId) public view returns (uint256[] memory words) {
        Request storage request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
        if (!request.fulfilled) revert RequestNotFulfilled();
        words = new uint256[](request.numWords);
        for (uint256 i = 0; i < request.numWords; ++i) {
            words[i] = uint256(keccak256(abi.encode(request.randomness, i)));
        }
    }

    /// @notice Returns the fee to the consumer's pull balance after BLOCKHASH can no longer verify.
    function refundExpired(uint256 requestId) external override {
        Request storage request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
        if (request.fulfilled) revert RequestAlreadyFinalized();
        if (request.refunded) return;

        uint256 refundableAfter = uint256(request.requestBlock) + BLOCKHASH_WINDOW;
        if (block.number <= refundableAfter) revert NotExpired(refundableAfter);
        request.refunded = true;
        credits[request.consumer] += request.feePaid;
        emit RequestRefunded(requestId, request.consumer, request.feePaid);
    }

    function withdrawCredits(address payable recipient, uint256 amount)
        external
        override
        nonReentrant
    {
        if (recipient == address(0)) revert ZeroAddress();
        uint256 available = credits[msg.sender];
        if (amount > available) revert InsufficientCredit(available, amount);
        credits[msg.sender] = available - amount;
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
        emit CreditsWithdrawn(msg.sender, recipient, amount);
    }

    function _attemptCallback(uint256 requestId, Request storage request)
        internal
        returns (bool success)
    {
        uint256[] memory words = randomWords(requestId);
        bytes memory callData = abi.encodeWithSelector(
            IProofVRFConsumer.rawFulfillRandomWords.selector, requestId, words
        );

        uint256 requiredGas = uint256(request.callbackGasLimit)
            + uint256(request.callbackGasLimit) / 63 + 10_000;
        if (gasleft() < requiredGas) {
            revert InsufficientGasForCallback(gasleft(), requiredGas);
        }

        address consumer = request.consumer;
        uint256 callbackGasLimit = request.callbackGasLimit;
        assembly ("memory-safe") {
            success := call(
                callbackGasLimit,
                consumer,
                0,
                add(callData, 0x20),
                mload(callData),
                0,
                0
            )
        }

        request.callbackAttempts += 1;
        if (success) request.callbackSucceeded = true;
        emit CallbackAttempted(requestId, request.callbackAttempts, success);
    }

    function _requireKey(bytes32 hash) internal view returns (KeyConfig storage config) {
        config = s_keys[hash];
        if (!config.exists) revert KeyNotFound(hash);
    }

    function _isValidPublicKey(uint256[2] calldata publicKey) internal pure returns (bool) {
        uint256 x = publicKey[0];
        uint256 y = publicKey[1];
        if (x == 0 || y == 0 || x >= SECP256K1_FIELD_SIZE || y >= SECP256K1_FIELD_SIZE) {
            return false;
        }
        uint256 ySquared = mulmod(y, y, SECP256K1_FIELD_SIZE);
        uint256 xCubed = mulmod(x, mulmod(x, x, SECP256K1_FIELD_SIZE), SECP256K1_FIELD_SIZE);
        return ySquared == addmod(xCubed, 7, SECP256K1_FIELD_SIZE);
    }
}

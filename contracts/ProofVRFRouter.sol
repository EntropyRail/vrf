// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IProofVRFConsumer} from "./interfaces/IProofVRFConsumer.sol";
import {IProofVRFCoordinator} from "./interfaces/IProofVRFCoordinator.sol";
import {IProofVRFService} from "./interfaces/IProofVRFService.sol";

/// @notice Stable consumer endpoint routing immutable key hashes to proof-scheme coordinators.
/// @dev A key hash is registered once and cannot be rebound. Future threshold keys can therefore
///      coexist with ECVRF keys without upgrading consumers or changing in-flight requests.
contract ProofVRFRouter is Ownable, ReentrancyGuard, IProofVRFConsumer, IProofVRFService {
    uint32 public constant MAX_NUM_WORDS = 32;
    uint32 public constant MAX_CONSUMER_CALLBACK_GAS = 2_000_000;
    uint32 public constant RECORD_CALLBACK_BASE_GAS = 150_000;
    uint32 public constant RECORD_CALLBACK_GAS_PER_WORD = 25_000;
    bytes32 private constant ROUTER_REQUEST_DOMAIN = keccak256("PROOF_VRF_ROUTER_REQUEST_V1");

    struct Provider {
        address coordinator;
        bytes32 codeHash;
        bool exists;
        bool active;
    }

    struct RoutedRequest {
        address consumer;
        address coordinator;
        uint256 providerRequestId;
        bytes32 keyHash;
        uint96 feePaid;
        uint32 callbackGasLimit;
        uint32 numWords;
        uint32 callbackAttempts;
        bool randomnessReady;
        bool callbackSucceeded;
        bool refunded;
    }

    uint256 public nonce;
    mapping(bytes32 keyHash => Provider provider) public providers;
    mapping(uint256 requestId => RoutedRequest request) public requests;
    mapping(address coordinator => mapping(uint256 providerRequestId => uint256 requestId))
        public providerRequestToRouterRequest;
    mapping(uint256 requestId => uint256[] words) private s_randomWords;
    mapping(address account => uint256 amount) public credits;

    error CallbackAlreadySucceeded();
    error DuplicateProvider(bytes32 keyHash);
    error DuplicateProviderRequest();
    error FeeMismatch(uint256 supplied, uint256 required);
    error IncorrectWordCount(uint256 supplied, uint256 required);
    error InsufficientCredit(uint256 available, uint256 requested);
    error InsufficientGasForCallback(uint256 available, uint256 required);
    error InvalidCallbackGasLimit();
    error InvalidConsumer();
    error InvalidNumWords();
    error ProviderInactive(bytes32 keyHash);
    error ProviderCodeChanged(address coordinator, bytes32 expected, bytes32 actual);
    error ProviderNotFound(bytes32 keyHash);
    error RandomnessNotReady();
    error RefundAmountMismatch(uint256 received, uint256 expected);
    error RequestAlreadyFinalized();
    error TransferFailed();
    error UnauthorizedProvider();
    error UnknownProviderRequest();
    error UnknownRequest();
    error ZeroAddress();

    event ProviderRegistered(bytes32 indexed keyHash, address indexed coordinator, bytes32 codeHash);
    event ProviderStatusUpdated(bytes32 indexed keyHash, bool active);
    event RandomWordsRouted(
        bytes32 indexed keyHash,
        uint256 indexed requestId,
        uint256 indexed providerRequestId,
        address consumer,
        address coordinator,
        uint256 fee
    );
    event RandomnessReady(uint256 indexed requestId, uint256 indexed providerRequestId);
    event CallbackAttempted(uint256 indexed requestId, uint32 indexed attempt, bool success);
    event RequestRefunded(uint256 indexed requestId, address indexed consumer, uint256 amount);
    event CreditsWithdrawn(address indexed account, address indexed recipient, uint256 amount);

    constructor(address initialOwner) Ownable(initialOwner) {
        if (initialOwner == address(0)) revert ZeroAddress();
    }

    receive() external payable {}

    function registerProvider(bytes32 keyHash, address coordinator) external onlyOwner {
        if (coordinator == address(0) || coordinator.code.length == 0) revert ZeroAddress();
        if (providers[keyHash].exists) revert DuplicateProvider(keyHash);
        // Confirms that the coordinator recognizes this exact key before it can receive traffic.
        IProofVRFCoordinator(coordinator).keyFee(keyHash);
        bytes32 codeHash = coordinator.codehash;
        providers[keyHash] = Provider(coordinator, codeHash, true, true);
        emit ProviderRegistered(keyHash, coordinator, codeHash);
    }

    function setProviderActive(bytes32 keyHash, bool active) external onlyOwner {
        Provider storage provider = _requireProvider(keyHash);
        provider.active = active;
        emit ProviderStatusUpdated(keyHash, active);
    }

    function keyFee(bytes32 keyHash) external view override returns (uint256) {
        Provider storage provider = _requireProvider(keyHash);
        _requireProviderCode(provider);
        return IProofVRFCoordinator(provider.coordinator).keyFee(keyHash);
    }

    function requestRandomWords(
        bytes32 keyHash,
        uint16 requestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external payable override nonReentrant returns (uint256 requestId) {
        Provider storage provider = _requireProvider(keyHash);
        _requireProviderCode(provider);
        if (!provider.active) revert ProviderInactive(keyHash);
        if (msg.sender.code.length == 0) revert InvalidConsumer();
        if (callbackGasLimit == 0 || callbackGasLimit > MAX_CONSUMER_CALLBACK_GAS) {
            revert InvalidCallbackGasLimit();
        }
        if (numWords == 0 || numWords > MAX_NUM_WORDS) revert InvalidNumWords();
        uint256 fee = IProofVRFCoordinator(provider.coordinator).keyFee(keyHash);
        if (msg.value != fee || fee > type(uint96).max) revert FeeMismatch(msg.value, fee);

        uint32 recordCallbackGas = RECORD_CALLBACK_BASE_GAS + RECORD_CALLBACK_GAS_PER_WORD * numWords;
        uint256 providerRequestId = IProofVRFCoordinator(provider.coordinator).requestRandomWords{
            value: msg.value
        }(keyHash, requestConfirmations, recordCallbackGas, numWords);

        requestId = uint256(
            keccak256(
                abi.encode(
                    ROUTER_REQUEST_DOMAIN,
                    block.chainid,
                    address(this),
                    ++nonce,
                    msg.sender,
                    provider.coordinator,
                    providerRequestId
                )
            )
        );
        if (providerRequestToRouterRequest[provider.coordinator][providerRequestId] != 0) {
            revert DuplicateProviderRequest();
        }

        requests[requestId] = RoutedRequest({
            consumer: msg.sender,
            coordinator: provider.coordinator,
            providerRequestId: providerRequestId,
            keyHash: keyHash,
            feePaid: uint96(fee),
            callbackGasLimit: callbackGasLimit,
            numWords: numWords,
            callbackAttempts: 0,
            randomnessReady: false,
            callbackSucceeded: false,
            refunded: false
        });
        providerRequestToRouterRequest[provider.coordinator][providerRequestId] = requestId;
        emit RandomWordsRouted(
            keyHash, requestId, providerRequestId, msg.sender, provider.coordinator, fee
        );
    }

    /// @notice Called by the proof coordinator. It records words but never calls application code.
    function rawFulfillRandomWords(uint256 providerRequestId, uint256[] calldata words) external {
        uint256 requestId = providerRequestToRouterRequest[msg.sender][providerRequestId];
        if (requestId == 0) revert UnknownProviderRequest();
        RoutedRequest storage request = requests[requestId];
        if (request.coordinator != msg.sender) revert UnauthorizedProvider();
        _requireProviderCode(providers[request.keyHash]);
        if (request.randomnessReady || request.refunded) revert RequestAlreadyFinalized();
        if (words.length != request.numWords) {
            revert IncorrectWordCount(words.length, request.numWords);
        }

        for (uint256 i = 0; i < words.length; ++i) {
            s_randomWords[requestId].push(words[i]);
        }
        request.randomnessReady = true;
        emit RandomnessReady(requestId, providerRequestId);
    }

    /// @notice Retries the proof coordinator -> router recording callback if it previously failed.
    function retryProviderCallback(uint256 requestId) external returns (bool success) {
        RoutedRequest storage request = _requireRequest(requestId);
        if (request.randomnessReady || request.refunded) revert RequestAlreadyFinalized();
        _requireProviderCode(providers[request.keyHash]);
        return IProofVRFCoordinator(request.coordinator).retryCallback(request.providerRequestId);
    }

    /// @notice Permissionlessly delivers recorded words to the final consumer.
    function retryCallback(uint256 requestId)
        external
        override
        nonReentrant
        returns (bool success)
    {
        RoutedRequest storage request = _requireRequest(requestId);
        if (!request.randomnessReady) revert RandomnessNotReady();
        if (request.callbackSucceeded) revert CallbackAlreadySucceeded();

        bytes memory callData = abi.encodeWithSelector(
            IProofVRFConsumer.rawFulfillRandomWords.selector, requestId, s_randomWords[requestId]
        );
        uint256 requiredGas = uint256(request.callbackGasLimit)
            + uint256(request.callbackGasLimit) / 63 + 10_000;
        if (gasleft() < requiredGas) {
            revert InsufficientGasForCallback(gasleft(), requiredGas);
        }

        address consumer = request.consumer;
        uint256 callbackGas = request.callbackGasLimit;
        assembly ("memory-safe") {
            success := call(callbackGas, consumer, 0, add(callData, 0x20), mload(callData), 0, 0)
        }
        request.callbackAttempts += 1;
        if (success) request.callbackSucceeded = true;
        emit CallbackAttempted(requestId, request.callbackAttempts, success);
    }

    function randomWords(uint256 requestId) external view returns (uint256[] memory) {
        RoutedRequest storage request = _requireRequest(requestId);
        if (!request.randomnessReady) revert RandomnessNotReady();
        return s_randomWords[requestId];
    }

    /// @notice Recovers an expired provider request and credits the original consumer.
    function refundExpired(uint256 requestId) external override nonReentrant {
        RoutedRequest storage request = _requireRequest(requestId);
        if (request.randomnessReady || request.refunded) revert RequestAlreadyFinalized();
        _requireProviderCode(providers[request.keyHash]);

        // The provider refund is idempotent: this call either proves the request has expired or
        // confirms that someone already triggered that exact refund. Other failures must bubble.
        IProofVRFCoordinator(request.coordinator).refundExpired(request.providerRequestId);
        uint256 balanceBefore = address(this).balance;
        IProofVRFCoordinator(request.coordinator).withdrawCredits(
            payable(address(this)), request.feePaid
        );
        uint256 received = address(this).balance - balanceBefore;
        if (received != request.feePaid) revert RefundAmountMismatch(received, request.feePaid);

        request.refunded = true;
        credits[request.consumer] += received;
        emit RequestRefunded(requestId, request.consumer, received);
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

    function _requireProvider(bytes32 keyHash) internal view returns (Provider storage provider) {
        provider = providers[keyHash];
        if (!provider.exists) revert ProviderNotFound(keyHash);
    }

    function _requireProviderCode(Provider storage provider) internal view {
        bytes32 actual = provider.coordinator.codehash;
        if (actual != provider.codeHash) {
            revert ProviderCodeChanged(provider.coordinator, provider.codeHash, actual);
        }
    }

    function _requireRequest(uint256 requestId)
        internal
        view
        returns (RoutedRequest storage request)
    {
        request = requests[requestId];
        if (request.consumer == address(0)) revert UnknownRequest();
    }
}

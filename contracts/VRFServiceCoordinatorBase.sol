// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {BlockhashStore} from "./BlockhashStore.sol";
import {IL1FeeCalculator} from "./interfaces/IL1FeeCalculator.sol";
import {IProofVRFConsumer} from "./interfaces/IProofVRFConsumer.sol";
import {IVRFProofVerifier} from "./interfaces/IVRFProofVerifier.sol";
import {IVRFServiceCoordinatorV2} from "./interfaces/IVRFServiceCoordinatorV2.sol";

/// @notice Shared subscription, pricing, key registry and administration for VRF coordinators.
/// @dev Billing and request routing are verifier-agnostic so a threshold verifier can be added
///      without migrating subscriptions. Administrative ownership should be a timelock in production.
abstract contract VRFServiceCoordinatorBase is
    Ownable2Step,
    ReentrancyGuard,
    IVRFServiceCoordinatorV2
{
    uint16 public constant MIN_REQUEST_CONFIRMATIONS = 1;
    uint16 public constant MAX_REQUEST_CONFIRMATIONS = 200;
    uint16 public constant MAX_PREMIUM_BPS = 10_000;
    uint32 public constant MAX_CALLBACK_GAS_LIMIT = 2_500_000;
    uint32 public constant MIN_VERIFICATION_GAS_LIMIT = 100_000;
    uint32 public constant MAX_VERIFICATION_GAS_LIMIT = 3_000_000;
    uint32 public constant MAX_NUM_WORDS = 32;
    uint32 public constant MAX_PROOF_DATA_LENGTH = 8_192;
    uint32 public constant MAX_CONSUMERS = 100;
    uint32 public constant MIN_REQUEST_TIMEOUT_BLOCKS = 257;
    uint32 public constant MAX_REQUEST_TIMEOUT_BLOCKS = 1_000_000;
    uint32 public constant PRUNE_DELAY_BLOCKS = 50_000;
    uint64 public constant SPONSOR_EPOCH_SECONDS = 1 days;

    bytes32 internal constant REQUEST_DOMAIN = keccak256("ROBINHOOD_VRF_SERVICE_REQUEST_V2");
    uint8 internal constant STATUS_PENDING = 1;
    uint8 internal constant STATUS_FULFILLED = 2;
    uint8 internal constant STATUS_EXPIRED = 3;

    struct PricingConfig {
        uint96 minimumRequestFeeWei;
        uint96 l1FeeReserveWei;
        uint32 fulfillmentOverheadGas;
        uint32 perWordGas;
        uint16 publicPremiumBps;
        uint16 operatorPremiumShareBps;
        uint32 requestTimeoutBlocks;
    }

    struct InitialKeyConfig {
        bytes32 keyHash;
        address verifier;
        bytes keyData;
        address fulfiller;
        address payee;
        uint64 maxGasPriceWei;
        uint32 verificationGasLimit;
    }

    struct KeyConfig {
        address verifier;
        bytes32 verifierCodeHash;
        address fulfiller;
        address payee;
        uint64 maxGasPriceWei;
        uint32 verificationGasLimit;
        uint32 proofDataLength;
        bool exists;
        bool active;
    }

    struct Subscription {
        address owner;
        address pendingOwner;
        uint256 balance;
        uint256 reserved;
        uint32 consumerCount;
        bool active;
    }

    struct ConsumerConfig {
        uint32 maxCallbackGasLimit;
        uint32 maxPendingRequests;
        uint32 pendingRequests;
        bool active;
    }

    struct PremiumOverride {
        uint16 premiumBps;
        bool enabled;
    }

    struct SponsorPolicy {
        uint256 subscriptionId;
        uint64 validUntil;
        uint64 epoch;
        uint32 requestsPerEpoch;
        uint32 requestsInEpoch;
        uint32 maxPendingRequests;
        uint32 pendingRequests;
        uint32 maxCallbackGasLimit;
        uint16 premiumBps;
        bool waiveMinimumFee;
        bool active;
    }

    struct SponsorPolicyConfig {
        uint256 subscriptionId;
        uint64 validUntil;
        uint32 requestsPerEpoch;
        uint32 maxPendingRequests;
        uint32 maxCallbackGasLimit;
        uint16 premiumBps;
        bool waiveMinimumFee;
    }

    struct Request {
        address consumer;
        address verifier;
        bytes32 verifierCodeHash;
        address fulfiller;
        address payee;
        bytes32 keyHash;
        uint256 subscriptionId;
        uint256 preSeed;
        uint256 reservedPayment;
        uint256 randomness;
        uint96 minimumFeeWei;
        uint64 requestBlock;
        uint64 expiresAtBlock;
        uint64 maxGasPriceWei;
        uint32 verificationGasLimit;
        uint32 proofDataLength;
        uint32 callbackGasLimit;
        uint32 numWords;
        uint32 callbackAttempts;
        uint32 fulfillmentOverheadGas;
        uint16 confirmations;
        uint16 premiumBps;
        uint16 operatorPremiumShareBps;
        uint8 status;
        bool sponsored;
        bool waiveMinimumFee;
        bool callbackSucceeded;
    }

    /// @dev Append-only service configuration, shared by all requests using this version.
    ///      Never update or remove a version: pending requests must keep their original
    ///      verifier, fulfiller, payee and gas lane even after administrative changes.
    struct KeyVersion {
        bytes32 keyHash;
        bytes32 verifierCodeHash;
        address verifier;
        uint32 verificationGasLimit;
        uint32 proofDataLength;
        address fulfiller;
        uint64 maxGasPriceWei;
        address payee;
    }

    /// @dev Five slots (four initially nonzero). Key and pricing versions are immutable;
    ///      reserve and expiry are derived exactly from those pinned inputs instead of
    ///      stored again. Request above remains the stable external read ABI.
    ///      This layout is for a NEW deployment, not an in-place storage migration.
    struct StoredRequest {
        address consumer;
        uint64 keyVersion;
        uint32 callbackGasLimit;
        uint256 subscriptionId;
        uint256 preSeed;
        uint256 randomness;
        uint64 requestBlock;
        uint64 pricingVersion;
        uint32 numWords;
        uint32 callbackAttempts;
        uint16 confirmations;
        uint16 premiumBps;
        uint8 status;
        bool sponsored;
        bool waiveMinimumFee;
        bool callbackSucceeded;
    }

    struct BillingContext {
        uint256 subscriptionId;
        uint16 premiumBps;
        bool sponsored;
        bool waiveMinimumFee;
    }

    BlockhashStore public immutable blockhashStore;
    IL1FeeCalculator public immutable l1FeeCalculator;
    bytes32 public immutable l1FeeCalculatorCodeHash;

    PricingConfig public pricing;
    address public guardian;
    bool public requestsPaused;
    uint256 public nextSubscriptionId = 1;
    uint256 public treasuryCredits;

    mapping(bytes32 keyHash => KeyConfig config) internal s_keys;
    mapping(uint256 subscriptionId => Subscription subscription) public subscriptions;
    mapping(uint256 subscriptionId => mapping(address consumer => ConsumerConfig config))
        public consumers;
    mapping(uint256 subscriptionId => PremiumOverride premiumOverride)
        public subscriptionPremiumOverrides;
    mapping(address consumer => SponsorPolicy policy) public sponsorPolicies;
    mapping(uint256 requestId => StoredRequest request) internal s_requests;
    mapping(address payee => uint256 amount) public operatorCredits;
    mapping(uint256 subscriptionId => mapping(address consumer => uint256 nonce))
        public consumerNonces;
    uint64 internal s_nextKeyVersion;
    uint64 internal s_currentPricingVersion;
    mapping(bytes32 keyHash => uint64 version) internal s_currentKeyVersions;
    mapping(uint64 version => KeyVersion config) internal s_keyVersions;
    mapping(uint64 version => PricingConfig config) internal s_pricingVersions;

    error ActualPaymentExceedsReserve(uint256 actual, uint256 reserved);
    error BlockhashUnavailable(uint256 requestBlock);
    error BlockNumberOverflow();
    error CallbackAlreadySucceeded();
    error ConfirmationsPending(uint256 readyBlock);
    error ConsumerAlreadyAdded();
    error ConsumerHasPendingRequests();
    error ConsumerNotAuthorized(address consumer, uint256 subscriptionId);
    error DuplicateKey(bytes32 keyHash);
    error FulfillmentGasPriceTooHigh(uint256 actual, uint256 maximum);
    error InsufficientBalance(uint256 available, uint256 required);
    error InsufficientCallbackGas(uint256 available, uint256 required);
    error InvalidAddress();
    error InvalidCallbackGasLimit();
    error InvalidConfirmations();
    error InvalidConsumer();
    error InvalidKeyConfig();
    error InvalidNumWords();
    error InvalidPricingConfig();
    error InvalidProofDataLength(uint256 actual, uint256 expected);
    error InvalidFulfillmentCalldataLength(uint256 actual, uint256 expected);
    error InvalidSponsorPolicy();
    error KeyInactive(bytes32 keyHash);
    error KeyNotFound(bytes32 keyHash);
    error L1FeeCalculatorChanged();
    error MaxPaymentTooLow(uint256 supplied, uint256 required);
    error NotFulfiller(address supplied, address required);
    error NotSubscriptionOwner();
    error PruneTooEarly(uint256 pruneAfterBlock);
    error RequestAlreadyFinalized();
    error RequestExpired(uint256 expiresAtBlock);
    error RequestNotExpired(uint256 expiresAtBlock);
    error RequestNotFulfilled();
    error RequestStillPending();
    error RequestsPaused();
    error SponsorQuotaExceeded();
    error SubscriptionInactive(uint256 subscriptionId);
    error TransferFailed();
    error UnknownRequest();
    error UnknownSubscription(uint256 subscriptionId);
    error VerifierChanged();

    event PricingUpdated(PricingConfig config);
    event GuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
    event RequestsPauseUpdated(bool paused);
    event KeyRegistered(
        bytes32 indexed keyHash,
        address indexed verifier,
        bytes32 verifierCodeHash,
        address indexed fulfiller,
        address payee,
        uint64 maxGasPriceWei,
        uint32 verificationGasLimit,
        uint32 proofDataLength
    );
    event KeyStatusUpdated(bytes32 indexed keyHash, bool active);
    event KeyServiceUpdated(
        bytes32 indexed keyHash,
        address indexed fulfiller,
        address indexed payee,
        uint64 maxGasPriceWei,
        uint32 verificationGasLimit
    );
    event SubscriptionCreated(uint256 indexed subscriptionId, address indexed owner);
    event SubscriptionFunded(
        uint256 indexed subscriptionId,
        address indexed funder,
        uint256 amount,
        uint256 newBalance
    );
    event SubscriptionWithdrawal(
        uint256 indexed subscriptionId,
        address indexed recipient,
        uint256 amount
    );
    event SubscriptionCancelled(
        uint256 indexed subscriptionId, address indexed recipient, uint256 refundedBalance
    );
    event SubscriptionOwnerTransferRequested(
        uint256 indexed subscriptionId,
        address indexed oldOwner,
        address indexed pendingOwner
    );
    event SubscriptionOwnerTransferred(
        uint256 indexed subscriptionId,
        address indexed oldOwner,
        address indexed newOwner
    );
    event ConsumerConfigured(
        uint256 indexed subscriptionId,
        address indexed consumer,
        uint32 maxCallbackGasLimit,
        uint32 maxPendingRequests
    );
    event ConsumerRemoved(uint256 indexed subscriptionId, address indexed consumer);
    event SubscriptionPremiumOverrideUpdated(
        uint256 indexed subscriptionId,
        uint16 premiumBps,
        bool enabled
    );
    event SponsorPolicyUpdated(address indexed consumer, SponsorPolicy policy);
    event SponsorPolicyRemoved(address indexed consumer);
    event RandomWordsRequested(
        bytes32 indexed keyHash,
        uint256 indexed requestId,
        address indexed consumer,
        uint256 subscriptionId,
        uint256 preSeed,
        uint256 requestBlock,
        uint256 expiresAtBlock,
        uint32 callbackGasLimit,
        uint32 numWords,
        uint256 reservedPayment,
        bool sponsored
    );
    event ProofVerified(uint256 indexed requestId, bytes32 indexed keyHash, uint256 randomness);
    event CallbackAttempted(uint256 indexed requestId, uint32 indexed attempt, bool success);
    event RequestSettled(
        uint256 indexed requestId,
        uint256 networkCost,
        uint256 totalCharge,
        uint256 operatorPayment,
        uint256 treasuryPayment
    );
    event RequestExpiredAndReleased(uint256 indexed requestId, uint256 releasedPayment);
    event RequestPruned(uint256 indexed requestId);
    event OperatorCreditsWithdrawn(
        address indexed payee,
        address indexed recipient,
        uint256 amount
    );
    event TreasuryCreditsWithdrawn(address indexed recipient, uint256 amount);

    constructor(
        address initialOwner,
        address initialGuardian,
        address blockhashStoreAddress,
        address l1FeeCalculatorAddress,
        PricingConfig memory initialPricing,
        InitialKeyConfig memory initialKey
    ) Ownable(initialOwner) {
        if (
            initialOwner == address(0) || initialGuardian == address(0)
                || blockhashStoreAddress.code.length == 0 || l1FeeCalculatorAddress.code.length == 0
        ) revert InvalidAddress();
        _validatePricing(initialPricing);

        guardian = initialGuardian;
        blockhashStore = BlockhashStore(blockhashStoreAddress);
        l1FeeCalculator = IL1FeeCalculator(l1FeeCalculatorAddress);
        l1FeeCalculatorCodeHash = l1FeeCalculatorAddress.codehash;
        pricing = initialPricing;
        _appendPricingVersion(initialPricing);

        emit GuardianUpdated(address(0), initialGuardian);
        emit PricingUpdated(initialPricing);
        _registerKey(
            initialKey.keyHash,
            initialKey.verifier,
            initialKey.keyData,
            initialKey.fulfiller,
            initialKey.payee,
            initialKey.maxGasPriceWei,
            initialKey.verificationGasLimit
        );
    }

    receive() external payable {
        revert();
    }

    function getKey(bytes32 keyHash) external view returns (KeyConfig memory) {
        return _requireKey(keyHash);
    }

    function keyExists(bytes32 keyHash) external view returns (bool) {
        return s_keys[keyHash].exists;
    }

    /// @notice Exposes the exact block-number context used by request expiry and BLOCKHASH.
    function contextBlockNumber() external view returns (uint256) {
        return blockhashStore.contextBlockNumber();
    }

    function setPricing(PricingConfig calldata newPricing) external onlyOwner {
        _validatePricing(newPricing);
        pricing = newPricing;
        _appendPricingVersion(newPricing);
        emit PricingUpdated(newPricing);
    }

    /// @dev Never mutate/delete a historical price: reserves, expiry and settlement
    ///      for existing requests must be independent of future pricing changes.
    function _appendPricingVersion(PricingConfig memory config) internal {
        uint64 version = ++s_currentPricingVersion;
        s_pricingVersions[version] = config;
    }

    function setGuardian(address newGuardian) external onlyOwner {
        if (newGuardian == address(0)) revert InvalidAddress();
        address oldGuardian = guardian;
        guardian = newGuardian;
        emit GuardianUpdated(oldGuardian, newGuardian);
    }

    function pauseRequests() external {
        if (msg.sender != guardian && msg.sender != owner()) revert InvalidAddress();
        requestsPaused = true;
        emit RequestsPauseUpdated(true);
    }

    function unpauseRequests() external onlyOwner {
        requestsPaused = false;
        emit RequestsPauseUpdated(false);
    }

    function registerKey(
        bytes32 keyHash,
        address verifier,
        bytes calldata keyData,
        address fulfiller,
        address payee,
        uint64 maxGasPriceWei,
        uint32 verificationGasLimit
    ) external onlyOwner {
        _registerKey(
            keyHash,
            verifier,
            keyData,
            fulfiller,
            payee,
            maxGasPriceWei,
            verificationGasLimit
        );
    }

    function _registerKey(
        bytes32 keyHash,
        address verifier,
        bytes memory keyData,
        address fulfiller,
        address payee,
        uint64 maxGasPriceWei,
        uint32 verificationGasLimit
    ) internal {
        if (s_keys[keyHash].exists) revert DuplicateKey(keyHash);
        if (
            keyHash == bytes32(0) || verifier.code.length == 0 || fulfiller == address(0)
                || payee == address(0) || maxGasPriceWei == 0 || verificationGasLimit == 0
                || verificationGasLimit < MIN_VERIFICATION_GAS_LIMIT
                || verificationGasLimit > MAX_VERIFICATION_GAS_LIMIT
        ) revert InvalidKeyConfig();
        uint32 proofDataLength = IVRFProofVerifier(verifier).proofLength();
        if (proofDataLength == 0 || proofDataLength > MAX_PROOF_DATA_LENGTH) {
            revert InvalidKeyConfig();
        }
        if (!IVRFProofVerifier(verifier).validateKey(keyHash, keyData)) {
            revert InvalidKeyConfig();
        }

        bytes32 verifierCodeHash = verifier.codehash;
        s_keys[keyHash] = KeyConfig({
            verifier: verifier,
            verifierCodeHash: verifierCodeHash,
            fulfiller: fulfiller,
            payee: payee,
            maxGasPriceWei: maxGasPriceWei,
            verificationGasLimit: verificationGasLimit,
            proofDataLength: proofDataLength,
            exists: true,
            active: true
        });
        _appendKeyVersion(keyHash, s_keys[keyHash]);
        emit KeyRegistered(
            keyHash,
            verifier,
            verifierCodeHash,
            fulfiller,
            payee,
            maxGasPriceWei,
            verificationGasLimit,
            proofDataLength
        );
    }

    /// @dev Deactivation affects new requests only. Existing requests pin all fulfillment fields.
    function setKeyActive(bytes32 keyHash, bool active) external onlyOwner {
        KeyConfig storage key = _requireKey(keyHash);
        key.active = active;
        emit KeyStatusUpdated(keyHash, active);
    }

    function setKeyService(
        bytes32 keyHash,
        address fulfiller,
        address payee,
        uint64 maxGasPriceWei,
        uint32 verificationGasLimit
    ) external onlyOwner {
        if (
            fulfiller == address(0) || payee == address(0) || maxGasPriceWei == 0
                || verificationGasLimit < MIN_VERIFICATION_GAS_LIMIT
                || verificationGasLimit > MAX_VERIFICATION_GAS_LIMIT
        ) revert InvalidKeyConfig();
        KeyConfig storage key = _requireKey(keyHash);
        key.fulfiller = fulfiller;
        key.payee = payee;
        key.maxGasPriceWei = maxGasPriceWei;
        key.verificationGasLimit = verificationGasLimit;
        _appendKeyVersion(keyHash, key);
        emit KeyServiceUpdated(
            keyHash, fulfiller, payee, maxGasPriceWei, verificationGasLimit
        );
    }

    function _appendKeyVersion(bytes32 keyHash, KeyConfig storage key) internal {
        // Checked uint64 increment fails closed instead of reusing an old version.
        uint64 version = ++s_nextKeyVersion;
        s_keyVersions[version] = KeyVersion({
            keyHash: keyHash,
            verifierCodeHash: key.verifierCodeHash,
            verifier: key.verifier,
            verificationGasLimit: key.verificationGasLimit,
            proofDataLength: key.proofDataLength,
            fulfiller: key.fulfiller,
            maxGasPriceWei: key.maxGasPriceWei,
            payee: key.payee
        });
        s_currentKeyVersions[keyHash] = version;
    }

    function createSubscription() external returns (uint256 subscriptionId) {
        subscriptionId = nextSubscriptionId++;
        subscriptions[subscriptionId] = Subscription({
            owner: msg.sender,
            pendingOwner: address(0),
            balance: 0,
            reserved: 0,
            consumerCount: 0,
            active: true
        });
        emit SubscriptionCreated(subscriptionId, msg.sender);
    }

    function fundSubscription(uint256 subscriptionId) external payable nonReentrant {
        Subscription storage subscription = _requireSubscription(subscriptionId);
        if (!subscription.active) revert SubscriptionInactive(subscriptionId);
        if (msg.value == 0) revert InsufficientBalance(0, 1);
        subscription.balance += msg.value;
        emit SubscriptionFunded(subscriptionId, msg.sender, msg.value, subscription.balance);
    }

    function withdrawSubscription(
        uint256 subscriptionId,
        address payable recipient,
        uint256 amount
    ) external nonReentrant {
        Subscription storage subscription = _onlySubscriptionOwner(subscriptionId);
        if (recipient == address(0)) revert InvalidAddress();
        uint256 available = subscription.balance - subscription.reserved;
        if (amount > available) revert InsufficientBalance(available, amount);
        subscription.balance -= amount;
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
        emit SubscriptionWithdrawal(subscriptionId, recipient, amount);
    }

    function cancelSubscription(uint256 subscriptionId, address payable recipient)
        external
        nonReentrant
    {
        Subscription storage subscription = _onlySubscriptionOwner(subscriptionId);
        if (recipient == address(0)) revert InvalidAddress();
        if (subscription.reserved != 0) revert ConsumerHasPendingRequests();
        uint256 refund = subscription.balance;
        subscription.balance = 0;
        subscription.active = false;
        (bool success,) = recipient.call{value: refund}("");
        if (!success) revert TransferFailed();
        emit SubscriptionCancelled(subscriptionId, recipient, refund);
    }

    function requestSubscriptionOwnerTransfer(uint256 subscriptionId, address newOwner) external {
        if (newOwner == address(0)) revert InvalidAddress();
        Subscription storage subscription = _onlySubscriptionOwner(subscriptionId);
        subscription.pendingOwner = newOwner;
        emit SubscriptionOwnerTransferRequested(subscriptionId, msg.sender, newOwner);
    }

    function acceptSubscriptionOwnerTransfer(uint256 subscriptionId) external {
        Subscription storage subscription = _requireSubscription(subscriptionId);
        if (subscription.pendingOwner != msg.sender) revert NotSubscriptionOwner();
        address oldOwner = subscription.owner;
        subscription.owner = msg.sender;
        subscription.pendingOwner = address(0);
        emit SubscriptionOwnerTransferred(subscriptionId, oldOwner, msg.sender);
    }

    function addConsumer(
        uint256 subscriptionId,
        address consumer,
        uint32 maxCallbackGasLimit,
        uint32 maxPendingRequests
    ) external {
        Subscription storage subscription = _onlySubscriptionOwner(subscriptionId);
        if (!subscription.active) revert SubscriptionInactive(subscriptionId);
        if (consumer.code.length == 0) revert InvalidConsumer();
        if (maxCallbackGasLimit == 0 || maxCallbackGasLimit > MAX_CALLBACK_GAS_LIMIT) {
            revert InvalidCallbackGasLimit();
        }
        if (maxPendingRequests == 0) revert InvalidConsumer();

        ConsumerConfig storage config = consumers[subscriptionId][consumer];
        if (config.active) revert ConsumerAlreadyAdded();
        if (subscription.consumerCount >= MAX_CONSUMERS) revert InvalidConsumer();
        config.maxCallbackGasLimit = maxCallbackGasLimit;
        config.maxPendingRequests = maxPendingRequests;
        config.active = true;
        subscription.consumerCount += 1;
        emit ConsumerConfigured(
            subscriptionId, consumer, maxCallbackGasLimit, maxPendingRequests
        );
    }

    function updateConsumer(
        uint256 subscriptionId,
        address consumer,
        uint32 maxCallbackGasLimit,
        uint32 maxPendingRequests
    ) external {
        _onlySubscriptionOwner(subscriptionId);
        ConsumerConfig storage config = consumers[subscriptionId][consumer];
        if (!config.active) revert ConsumerNotAuthorized(consumer, subscriptionId);
        if (
            maxCallbackGasLimit == 0 || maxCallbackGasLimit > MAX_CALLBACK_GAS_LIMIT
                || maxPendingRequests == 0 || maxPendingRequests < config.pendingRequests
        ) revert InvalidConsumer();
        config.maxCallbackGasLimit = maxCallbackGasLimit;
        config.maxPendingRequests = maxPendingRequests;
        emit ConsumerConfigured(
            subscriptionId, consumer, maxCallbackGasLimit, maxPendingRequests
        );
    }

    function removeConsumer(uint256 subscriptionId, address consumer) external {
        Subscription storage subscription = _onlySubscriptionOwner(subscriptionId);
        ConsumerConfig storage config = consumers[subscriptionId][consumer];
        if (!config.active) revert ConsumerNotAuthorized(consumer, subscriptionId);
        if (config.pendingRequests != 0) revert ConsumerHasPendingRequests();
        delete consumers[subscriptionId][consumer];
        subscription.consumerCount -= 1;
        emit ConsumerRemoved(subscriptionId, consumer);
    }

    function setSubscriptionPremiumOverride(
        uint256 subscriptionId,
        uint16 premiumBps,
        bool enabled
    ) external onlyOwner {
        _requireSubscription(subscriptionId);
        if (premiumBps > MAX_PREMIUM_BPS) revert InvalidPricingConfig();
        subscriptionPremiumOverrides[subscriptionId] =
            PremiumOverride({premiumBps: premiumBps, enabled: enabled});
        emit SubscriptionPremiumOverrideUpdated(subscriptionId, premiumBps, enabled);
    }

    function setSponsorPolicy(address consumer, SponsorPolicyConfig calldata policy)
        external
        onlyOwner
    {
        Subscription storage subscription = _requireSubscription(policy.subscriptionId);
        ConsumerConfig storage consumerConfig = consumers[policy.subscriptionId][consumer];
        if (
            consumer.code.length == 0 || !subscription.active || !consumerConfig.active
                || policy.validUntil <= block.timestamp || policy.requestsPerEpoch == 0
                || policy.maxPendingRequests == 0 || policy.maxCallbackGasLimit == 0
                || policy.maxCallbackGasLimit > consumerConfig.maxCallbackGasLimit
                || policy.premiumBps > MAX_PREMIUM_BPS
        ) revert InvalidSponsorPolicy();

        SponsorPolicy storage oldPolicy = sponsorPolicies[consumer];
        if (oldPolicy.pendingRequests != 0) {
            if (oldPolicy.subscriptionId != policy.subscriptionId) {
                revert ConsumerHasPendingRequests();
            }
            if (policy.maxPendingRequests < oldPolicy.pendingRequests) {
                revert ConsumerHasPendingRequests();
            }
        }
        uint64 currentEpoch = uint64(block.timestamp / SPONSOR_EPOCH_SECONDS);
        SponsorPolicy memory configured = SponsorPolicy({
            subscriptionId: policy.subscriptionId,
            validUntil: policy.validUntil,
            epoch: currentEpoch,
            requestsPerEpoch: policy.requestsPerEpoch,
            requestsInEpoch: oldPolicy.active && oldPolicy.epoch == currentEpoch
                ? oldPolicy.requestsInEpoch
                : 0,
            maxPendingRequests: policy.maxPendingRequests,
            pendingRequests: oldPolicy.pendingRequests,
            maxCallbackGasLimit: policy.maxCallbackGasLimit,
            premiumBps: policy.premiumBps,
            waiveMinimumFee: policy.waiveMinimumFee,
            active: true
        });
        sponsorPolicies[consumer] = configured;
        emit SponsorPolicyUpdated(consumer, configured);
    }

    function removeSponsorPolicy(address consumer) external onlyOwner {
        SponsorPolicy storage policy = sponsorPolicies[consumer];
        if (policy.pendingRequests != 0) revert ConsumerHasPendingRequests();
        delete sponsorPolicies[consumer];
        emit SponsorPolicyRemoved(consumer);
    }

    function quoteMaxPayment(
        bytes32 keyHash,
        address consumer,
        uint256 subscriptionId,
        uint32 callbackGasLimit,
        uint32 numWords
    ) public view returns (uint256) {
        KeyConfig storage key = _activeKey(keyHash);
        _validateRequestBounds(callbackGasLimit, numWords);
        BillingContext memory billing =
            _resolveBilling(consumer, subscriptionId, callbackGasLimit);
        return _quoteMaxPayment(key, callbackGasLimit, numWords, billing);
    }

    function _expandRandomWords(uint256 randomness, uint32 numWords)
        internal
        pure
        returns (uint256[] memory words)
    {
        words = new uint256[](numWords);
        for (uint256 index; index < numWords; ++index) {
            words[index] = uint256(keccak256(abi.encode(randomness, index)));
        }
    }

    function withdrawOperatorCredits(address payable recipient, uint256 amount)
        external
        nonReentrant
    {
        if (recipient == address(0)) revert InvalidAddress();
        uint256 available = operatorCredits[msg.sender];
        if (amount > available) revert InsufficientBalance(available, amount);
        operatorCredits[msg.sender] = available - amount;
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
        emit OperatorCreditsWithdrawn(msg.sender, recipient, amount);
    }

    function withdrawTreasuryCredits(address payable recipient, uint256 amount)
        external
        onlyOwner
        nonReentrant
    {
        if (recipient == address(0)) revert InvalidAddress();
        if (amount > treasuryCredits) revert InsufficientBalance(treasuryCredits, amount);
        treasuryCredits -= amount;
        (bool success,) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();
        emit TreasuryCreditsWithdrawn(recipient, amount);
    }

    function _resolveBilling(
        address consumer,
        uint256 suppliedSubscriptionId,
        uint32 callbackGasLimit
    ) internal view returns (BillingContext memory billing) {
        if (suppliedSubscriptionId == 0) {
            SponsorPolicy storage policy = sponsorPolicies[consumer];
            if (!policy.active || block.timestamp > policy.validUntil) {
                revert ConsumerNotAuthorized(consumer, 0);
            }
            if (
                callbackGasLimit > policy.maxCallbackGasLimit
                    || policy.pendingRequests >= policy.maxPendingRequests
            ) revert InvalidSponsorPolicy();
            billing = BillingContext({
                subscriptionId: policy.subscriptionId,
                premiumBps: policy.premiumBps,
                sponsored: true,
                waiveMinimumFee: policy.waiveMinimumFee
            });
        } else {
            PremiumOverride storage premiumOverride =
                subscriptionPremiumOverrides[suppliedSubscriptionId];
            billing = BillingContext({
                subscriptionId: suppliedSubscriptionId,
                premiumBps: premiumOverride.enabled
                    ? premiumOverride.premiumBps
                    : pricing.publicPremiumBps,
                sponsored: false,
                waiveMinimumFee: false
            });
        }

        Subscription storage subscription = _requireSubscription(billing.subscriptionId);
        if (!subscription.active) revert SubscriptionInactive(billing.subscriptionId);
        ConsumerConfig storage config = consumers[billing.subscriptionId][consumer];
        if (!config.active || callbackGasLimit > config.maxCallbackGasLimit) {
            revert ConsumerNotAuthorized(consumer, billing.subscriptionId);
        }
    }

    function _quoteMaxPayment(
        KeyConfig storage key,
        uint32 callbackGasLimit,
        uint32 numWords,
        BillingContext memory billing
    ) internal view returns (uint256) {
        return _quotePayment(
            key.verificationGasLimit, key.maxGasPriceWei, callbackGasLimit, numWords,
            billing.premiumBps, billing.waiveMinimumFee, pricing
        );
    }

    function _quotePayment(
        uint32 verificationGasLimit,
        uint64 maxGasPriceWei,
        uint32 callbackGasLimit,
        uint32 numWords,
        uint16 premiumBps,
        bool waiveMinimumFee,
        PricingConfig memory config
    ) internal pure returns (uint256) {
        uint256 gasUnits = uint256(verificationGasLimit) + callbackGasLimit
            + config.fulfillmentOverheadGas + uint256(config.perWordGas) * numWords;
        uint256 maximumNetworkCost = gasUnits * maxGasPriceWei + config.l1FeeReserveWei;
        return _applyPrice(
            maximumNetworkCost,
            premiumBps,
            waiveMinimumFee ? 0 : config.minimumRequestFeeWei
        );
    }

    function _applyPrice(uint256 networkCost, uint16 premiumBps, uint256 minimumFee)
        internal
        pure
        returns (uint256)
    {
        uint256 priced = Math.mulDiv(
            networkCost, uint256(MAX_PREMIUM_BPS) + premiumBps, MAX_PREMIUM_BPS
        );
        return priced < minimumFee ? minimumFee : priced;
    }

    function _consumeSponsorQuota(address consumer) internal {
        SponsorPolicy storage policy = sponsorPolicies[consumer];
        uint64 currentEpoch = uint64(block.timestamp / SPONSOR_EPOCH_SECONDS);
        if (policy.epoch != currentEpoch) {
            policy.epoch = currentEpoch;
            policy.requestsInEpoch = 0;
        }
        if (policy.requestsInEpoch >= policy.requestsPerEpoch) revert SponsorQuotaExceeded();
        policy.requestsInEpoch += 1;
        policy.pendingRequests += 1;
    }

    function _validateRequestBounds(uint32 callbackGasLimit, uint32 numWords) internal pure {
        if (callbackGasLimit == 0 || callbackGasLimit > MAX_CALLBACK_GAS_LIMIT) {
            revert InvalidCallbackGasLimit();
        }
        if (numWords == 0 || numWords > MAX_NUM_WORDS) revert InvalidNumWords();
    }

    function _validatePricing(PricingConfig memory config) internal pure {
        if (
            config.fulfillmentOverheadGas < 50_000 || config.fulfillmentOverheadGas > 1_000_000
                || config.perWordGas > 100_000 || config.publicPremiumBps > MAX_PREMIUM_BPS
                || config.operatorPremiumShareBps > MAX_PREMIUM_BPS
                || config.requestTimeoutBlocks < MIN_REQUEST_TIMEOUT_BLOCKS
                || config.requestTimeoutBlocks > MAX_REQUEST_TIMEOUT_BLOCKS
        ) revert InvalidPricingConfig();
    }

    function _activeKey(bytes32 keyHash) internal view returns (KeyConfig storage key) {
        key = _requireKey(keyHash);
        if (!key.active) revert KeyInactive(keyHash);
    }

    function _requireKey(bytes32 keyHash) internal view returns (KeyConfig storage key) {
        key = s_keys[keyHash];
        if (!key.exists) revert KeyNotFound(keyHash);
    }

    function _requireSubscription(uint256 subscriptionId)
        internal
        view
        returns (Subscription storage subscription)
    {
        subscription = subscriptions[subscriptionId];
        if (subscription.owner == address(0)) revert UnknownSubscription(subscriptionId);
    }

    function _onlySubscriptionOwner(uint256 subscriptionId)
        internal
        view
        returns (Subscription storage subscription)
    {
        subscription = _requireSubscription(subscriptionId);
        if (subscription.owner != msg.sender) revert NotSubscriptionOwner();
    }

}

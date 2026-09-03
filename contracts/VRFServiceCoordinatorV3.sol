// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {VRFServiceCoordinatorBase} from "./VRFServiceCoordinatorBase.sol";
import {IVRFProofVerifier} from "./interfaces/IVRFProofVerifier.sol";
import {IProofVRFConsumer} from "./interfaces/IProofVRFConsumer.sol";

/// @notice Opt-in witness-based VRF. One state commitment per request, including results.
/// @dev The request/consumer callback API is unchanged, but reads, fulfillment, retry,
///      expiry and pruning REQUIRE the latest full witness from CompactRequestState.
///      This commits REQUEST DATA, not a replacement of ECVRF with commit-reveal RNG.
contract VRFServiceCoordinatorV3 is VRFServiceCoordinatorBase {
    bytes32 private constant COMPACT_DOMAIN = keccak256("ROBINHOOD_VRF_COMPACT_REQUEST_V3");
    mapping(uint256 requestId => bytes32 commitment) public commitments;

    error InvalidWitness();
    error InvalidProofOffset();

    /// @notice Durable full witness. Indexing must include every transition, not only creation.
    event CompactRequestState(
        bytes32 indexed keyHash, uint256 indexed requestId, address indexed consumer, Request request
    );

    constructor(
        address initialOwner,
        address initialGuardian,
        address blockhashStoreAddress,
        address l1FeeCalculatorAddress,
        PricingConfig memory initialPricing,
        InitialKeyConfig memory initialKey
    ) VRFServiceCoordinatorBase(
        initialOwner, initialGuardian, blockhashStoreAddress,
        l1FeeCalculatorAddress, initialPricing, initialKey
    ) {}

    function requestRandomWords(RandomWordsRequest calldata params)
        external
        nonReentrant
        returns (uint256 requestId)
    {
        if (requestsPaused) revert RequestsPaused();
        if (msg.sender.code.length == 0) revert InvalidConsumer();
        if (params.requestConfirmations < MIN_REQUEST_CONFIRMATIONS
            || params.requestConfirmations > MAX_REQUEST_CONFIRMATIONS) revert InvalidConfirmations();
        _validateRequestBounds(params.callbackGasLimit, params.numWords);
        KeyConfig storage key = _activeKey(params.keyHash);
        BillingContext memory billing = _resolveBilling(msg.sender, params.subscriptionId, params.callbackGasLimit);
        uint256 reserve = _quoteMaxPayment(key, params.callbackGasLimit, params.numWords, billing);
        if (params.maxPayment < reserve) revert MaxPaymentTooLow(params.maxPayment, reserve);
        Subscription storage subscription = subscriptions[billing.subscriptionId];
        uint256 available = subscription.balance - subscription.reserved;
        if (available < reserve) revert InsufficientBalance(available, reserve);
        ConsumerConfig storage consumer = consumers[billing.subscriptionId][msg.sender];
        if (consumer.pendingRequests >= consumer.maxPendingRequests) revert ConsumerHasPendingRequests();
        if (billing.sponsored) _consumeSponsorQuota(msg.sender);
        uint256 nonce = ++consumerNonces[billing.subscriptionId][msg.sender];
        uint256 preSeed = uint256(keccak256(abi.encode(
            REQUEST_DOMAIN, block.chainid, address(this), msg.sender, billing.subscriptionId, nonce, params.keyHash
        )));
        requestId = uint256(keccak256(abi.encode(preSeed)));
        uint256 currentBlock = blockhashStore.contextBlockNumber();
        uint256 expiry = currentBlock + pricing.requestTimeoutBlocks;
        if (expiry > type(uint64).max) revert BlockNumberOverflow();
        subscription.reserved += reserve;
        consumer.pendingRequests += 1;

        Request memory request = Request({
            consumer: msg.sender, verifier: key.verifier, verifierCodeHash: key.verifierCodeHash,
            fulfiller: key.fulfiller, payee: key.payee, keyHash: params.keyHash,
            subscriptionId: billing.subscriptionId, preSeed: preSeed, reservedPayment: reserve,
            randomness: 0, minimumFeeWei: billing.waiveMinimumFee ? 0 : pricing.minimumRequestFeeWei,
            requestBlock: uint64(currentBlock), expiresAtBlock: uint64(expiry), maxGasPriceWei: key.maxGasPriceWei,
            verificationGasLimit: key.verificationGasLimit, proofDataLength: key.proofDataLength,
            callbackGasLimit: params.callbackGasLimit, numWords: params.numWords, callbackAttempts: 0,
            fulfillmentOverheadGas: pricing.fulfillmentOverheadGas, confirmations: params.requestConfirmations,
            premiumBps: billing.premiumBps, operatorPremiumShareBps: pricing.operatorPremiumShareBps,
            status: STATUS_PENDING, sponsored: billing.sponsored, waiveMinimumFee: billing.waiveMinimumFee,
            callbackSucceeded: false
        });
        _persist(requestId, request);
        emit CompactRequestState(params.keyHash, requestId, msg.sender, request);
    }

    function hashRequest(Request calldata witness) external view returns (bytes32) {
        return _hash(witness);
    }

    function getRequest(Request calldata witness) external view returns (Request memory) {
        _authenticate(witness);
        return witness;
    }

    function requestSeed(Request calldata witness) external view returns (uint256) {
        _authenticatePending(witness);
        return _seed(witness);
    }

    function fulfillRandomWords(Request calldata witness, bytes calldata proofData)
        external
        nonReentrant
        returns (uint256 randomness, bool callbackSuccess, uint256 charge)
    {
        uint256 startingGas = gasleft();
        uint256 requestId = _authenticatePending(witness);
        if (proofData.length != witness.proofDataLength) {
            revert InvalidProofDataLength(proofData.length, witness.proofDataLength);
        }
        uint256 witnessLength = abi.encode(witness).length;
        uint256 paddedProofLength = (uint256(witness.proofDataLength) + 31) & ~uint256(31);
        uint256 expectedLength = 4 + witnessLength + 64 + paddedProofLength;
        if (msg.data.length != expectedLength) {
            revert InvalidFulfillmentCalldataLength(msg.data.length, expectedLength);
        }
        uint256 proofOffset;
        assembly ("memory-safe") { proofOffset := proofData.offset }
        if (proofOffset != 4 + witnessLength + 64) revert InvalidProofOffset();
        if (msg.sender != witness.fulfiller) revert NotFulfiller(msg.sender, witness.fulfiller);
        if (tx.gasprice > witness.maxGasPriceWei) {
            revert FulfillmentGasPriceTooHigh(tx.gasprice, witness.maxGasPriceWei);
        }
        if (witness.verifier.codehash != witness.verifierCodeHash) revert VerifierChanged();
        if (address(l1FeeCalculator).codehash != l1FeeCalculatorCodeHash) revert L1FeeCalculatorChanged();
        randomness = IVRFProofVerifier(witness.verifier).verify{gas: witness.verificationGasLimit}(
            witness.keyHash, _seed(witness), witness.preSeed, proofData
        );
        Request memory updated = witness;
        updated.status = STATUS_FULFILLED;
        updated.randomness = randomness;
        emit ProofVerified(requestId, witness.keyHash, randomness);
        callbackSuccess = _callback(requestId, updated);
        // Include the full transition event in measured work; otherwise compact mode
        // would shift a material log cost out of the existing billing measurement.
        emit CompactRequestState(updated.keyHash, requestId, updated.consumer, updated);
        uint256 l1Cost = l1FeeCalculator.currentTxL1CostWei();
        uint256 networkCost = (startingGas - gasleft() + witness.fulfillmentOverheadGas) * tx.gasprice + l1Cost;
        charge = _applyPrice(networkCost, witness.premiumBps, witness.minimumFeeWei);
        if (charge > witness.reservedPayment) revert ActualPaymentExceedsReserve(charge, witness.reservedPayment);
        _release(witness);
        subscriptions[witness.subscriptionId].balance -= charge;
        uint256 premium = charge - networkCost;
        uint256 operatorPayment = networkCost
            + Math.mulDiv(premium, witness.operatorPremiumShareBps, MAX_PREMIUM_BPS);
        uint256 treasuryPayment = charge - operatorPayment;
        operatorCredits[witness.payee] += operatorPayment;
        treasuryCredits += treasuryPayment;
        emit RequestSettled(requestId, networkCost, charge, operatorPayment, treasuryPayment);
    }

    function retryCallback(Request calldata witness) external nonReentrant returns (bool success) {
        uint256 requestId = _authenticate(witness);
        if (witness.status != STATUS_FULFILLED) revert RequestNotFulfilled();
        if (witness.callbackSucceeded) revert CallbackAlreadySucceeded();
        Request memory updated = witness;
        success = _callback(requestId, updated);
        emit CompactRequestState(updated.keyHash, requestId, updated.consumer, updated);
    }

    function expireRequest(Request calldata witness) external nonReentrant {
        uint256 requestId = _authenticatePending(witness);
        if (blockhashStore.contextBlockNumber() <= witness.expiresAtBlock) {
            revert RequestNotExpired(witness.expiresAtBlock);
        }
        Request memory updated = witness;
        updated.status = STATUS_EXPIRED;
        _persist(requestId, updated);
        _release(witness);
        emit RequestExpiredAndReleased(requestId, witness.reservedPayment);
        emit CompactRequestState(updated.keyHash, requestId, updated.consumer, updated);
    }

    function pruneRequest(Request calldata witness) external nonReentrant {
        uint256 requestId = _authenticate(witness);
        if (witness.status == STATUS_PENDING) revert RequestStillPending();
        uint256 pruneAfterBlock = uint256(witness.expiresAtBlock) + PRUNE_DELAY_BLOCKS;
        if (blockhashStore.contextBlockNumber() <= pruneAfterBlock) revert PruneTooEarly(pruneAfterBlock);
        delete commitments[requestId];
        emit RequestPruned(requestId);
    }

    function randomWords(Request calldata witness) external view returns (uint256[] memory) {
        _authenticate(witness);
        if (witness.status != STATUS_FULFILLED) revert RequestNotFulfilled();
        return _expandRandomWords(witness.randomness, witness.numWords);
    }

    function _hash(Request memory witness) private view returns (bytes32) {
        return keccak256(abi.encode(COMPACT_DOMAIN, block.chainid, address(this), witness));
    }

    function _persist(uint256 requestId, Request memory witness) private {
        bytes32 digest = _hash(witness);
        if (digest == bytes32(0)) revert InvalidWitness();
        commitments[requestId] = digest;
    }

    function _authenticate(Request calldata witness) private view returns (uint256 requestId) {
        requestId = uint256(keccak256(abi.encode(witness.preSeed)));
        bytes32 stored = commitments[requestId];
        if (stored == bytes32(0)) revert UnknownRequest();
        if (stored != _hash(witness)) revert InvalidWitness();
    }

    function _authenticatePending(Request calldata witness) private view returns (uint256 requestId) {
        requestId = _authenticate(witness);
        if (witness.status != STATUS_PENDING) revert RequestAlreadyFinalized();
    }

    function _seed(Request calldata witness) private view returns (uint256) {
        uint256 currentBlock = blockhashStore.contextBlockNumber();
        if (currentBlock > witness.expiresAtBlock) revert RequestExpired(witness.expiresAtBlock);
        uint256 readyBlock = uint256(witness.requestBlock) + witness.confirmations;
        if (currentBlock < readyBlock) revert ConfirmationsPending(readyBlock);
        bytes32 requestBlockHash = blockhashStore.getBlockHash(witness.requestBlock);
        if (requestBlockHash == bytes32(0)) revert BlockhashUnavailable(witness.requestBlock);
        return uint256(keccak256(abi.encodePacked(bytes32(witness.preSeed), requestBlockHash)));
    }

    function _release(Request calldata witness) private {
        subscriptions[witness.subscriptionId].reserved -= witness.reservedPayment;
        consumers[witness.subscriptionId][witness.consumer].pendingRequests -= 1;
        if (witness.sponsored) sponsorPolicies[witness.consumer].pendingRequests -= 1;
    }

    function _callback(uint256 requestId, Request memory updated) private returns (bool success) {
        uint256 minimumGas = uint256(updated.callbackGasLimit) + uint256(updated.callbackGasLimit) / 63
            + updated.fulfillmentOverheadGas;
        if (gasleft() < minimumGas) revert InsufficientCallbackGas(gasleft(), minimumGas);
        uint256[] memory words = _expandRandomWords(updated.randomness, updated.numWords);
        updated.callbackAttempts += 1;
        // Commit the fulfilled state before the untrusted callback, as in V2.
        _persist(requestId, updated);
        (success,) = updated.consumer.call{gas: updated.callbackGasLimit}(
            abi.encodeCall(IProofVRFConsumer.rawFulfillRandomWords, (requestId, words))
        );
        if (success) {
            updated.callbackSucceeded = true;
            _persist(requestId, updated);
        }
        emit CallbackAttempted(requestId, updated.callbackAttempts, success);
    }
}

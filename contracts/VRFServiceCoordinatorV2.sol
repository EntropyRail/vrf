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

import {VRFServiceCoordinatorBase} from "./VRFServiceCoordinatorBase.sol";

/// @notice Backwards-compatible full-state V2 request path.
contract VRFServiceCoordinatorV2 is VRFServiceCoordinatorBase {
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

    function getRequest(uint256 requestId) external view returns (Request memory request) {
        StoredRequest storage stored = s_requests[requestId];
        if (stored.status == 0) revert UnknownRequest();
        KeyVersion storage key = s_keyVersions[stored.keyVersion];
        PricingConfig memory config = s_pricingVersions[stored.pricingVersion];
        request = Request({
            consumer: stored.consumer,
            verifier: key.verifier,
            verifierCodeHash: key.verifierCodeHash,
            fulfiller: key.fulfiller,
            payee: key.payee,
            keyHash: key.keyHash,
            subscriptionId: stored.subscriptionId,
            preSeed: stored.preSeed,
            reservedPayment: _reservedPayment(stored, key, config),
            randomness: stored.randomness,
            minimumFeeWei: stored.waiveMinimumFee ? 0 : config.minimumRequestFeeWei,
            requestBlock: stored.requestBlock,
            expiresAtBlock: stored.requestBlock + config.requestTimeoutBlocks,
            maxGasPriceWei: key.maxGasPriceWei,
            verificationGasLimit: key.verificationGasLimit,
            proofDataLength: key.proofDataLength,
            callbackGasLimit: stored.callbackGasLimit,
            numWords: stored.numWords,
            callbackAttempts: stored.callbackAttempts,
            fulfillmentOverheadGas: config.fulfillmentOverheadGas,
            confirmations: stored.confirmations,
            premiumBps: stored.premiumBps,
            operatorPremiumShareBps: config.operatorPremiumShareBps,
            status: stored.status,
            sponsored: stored.sponsored,
            waiveMinimumFee: stored.waiveMinimumFee,
            callbackSucceeded: stored.callbackSucceeded
        });
    }

    function requestRandomWords(RandomWordsRequest calldata request)
        external
        nonReentrant
        returns (uint256 requestId)
    {
        if (requestsPaused) revert RequestsPaused();
        if (msg.sender.code.length == 0) revert InvalidConsumer();
        if (
            request.requestConfirmations < MIN_REQUEST_CONFIRMATIONS
                || request.requestConfirmations > MAX_REQUEST_CONFIRMATIONS
        ) revert InvalidConfirmations();
        _validateRequestBounds(request.callbackGasLimit, request.numWords);

        KeyConfig storage key = _activeKey(request.keyHash);
        BillingContext memory billing =
            _resolveBilling(msg.sender, request.subscriptionId, request.callbackGasLimit);
        uint256 reserve =
            _quoteMaxPayment(key, request.callbackGasLimit, request.numWords, billing);
        if (request.maxPayment < reserve) revert MaxPaymentTooLow(request.maxPayment, reserve);

        Subscription storage subscription = subscriptions[billing.subscriptionId];
        uint256 available = subscription.balance - subscription.reserved;
        if (available < reserve) revert InsufficientBalance(available, reserve);

        ConsumerConfig storage consumerConfig = consumers[billing.subscriptionId][msg.sender];
        if (consumerConfig.pendingRequests >= consumerConfig.maxPendingRequests) {
            revert ConsumerHasPendingRequests();
        }
        if (billing.sponsored) _consumeSponsorQuota(msg.sender);

        uint256 requestNonce = ++consumerNonces[billing.subscriptionId][msg.sender];
        uint256 preSeed = uint256(
            keccak256(
                abi.encode(
                    REQUEST_DOMAIN,
                    block.chainid,
                    address(this),
                    msg.sender,
                    billing.subscriptionId,
                    requestNonce,
                    request.keyHash
                )
            )
        );
        requestId = uint256(keccak256(abi.encode(preSeed)));
        uint256 currentBlock = blockhashStore.contextBlockNumber();
        uint256 expirationBlock = currentBlock + pricing.requestTimeoutBlocks;
        if (expirationBlock > type(uint64).max) revert BlockNumberOverflow();
        uint64 requestBlock = uint64(currentBlock);
        uint64 expiresAtBlock = uint64(expirationBlock);

        subscription.reserved += reserve;
        consumerConfig.pendingRequests += 1;
        s_requests[requestId] = StoredRequest({
            consumer: msg.sender,
            keyVersion: s_currentKeyVersions[request.keyHash],
            subscriptionId: billing.subscriptionId,
            preSeed: preSeed,
            randomness: 0,
            requestBlock: requestBlock,
            pricingVersion: s_currentPricingVersion,
            callbackGasLimit: request.callbackGasLimit,
            numWords: request.numWords,
            callbackAttempts: 0,
            confirmations: request.requestConfirmations,
            premiumBps: billing.premiumBps,
            status: STATUS_PENDING,
            sponsored: billing.sponsored,
            waiveMinimumFee: billing.waiveMinimumFee,
            callbackSucceeded: false
        });

        emit RandomWordsRequested(
            request.keyHash,
            requestId,
            msg.sender,
            billing.subscriptionId,
            preSeed,
            requestBlock,
            expiresAtBlock,
            request.callbackGasLimit,
            request.numWords,
            reserve,
            billing.sponsored
        );
    }

    function requestSeed(uint256 requestId) public view returns (uint256) {
        StoredRequest storage request = _pendingRequest(requestId);
        uint256 currentBlock = blockhashStore.contextBlockNumber();
        uint64 expiresAtBlock = _expiresAtBlock(request);
        if (currentBlock > expiresAtBlock) revert RequestExpired(expiresAtBlock);
        uint256 readyBlock = uint256(request.requestBlock) + request.confirmations;
        if (currentBlock < readyBlock) revert ConfirmationsPending(readyBlock);

        bytes32 requestBlockHash = blockhashStore.getBlockHash(request.requestBlock);
        if (requestBlockHash == bytes32(0)) {
            revert BlockhashUnavailable(request.requestBlock);
        }
        return uint256(keccak256(abi.encodePacked(bytes32(request.preSeed), requestBlockHash)));
    }

    function fulfillRandomWords(uint256 requestId, bytes calldata proofData)
        external
        nonReentrant
        returns (uint256 randomness, bool callbackSuccess, uint256 charge)
    {
        uint256 startingGas = gasleft();
        StoredRequest storage request = _pendingRequest(requestId);
        KeyVersion storage key = s_keyVersions[request.keyVersion];
        PricingConfig memory config = s_pricingVersions[request.pricingVersion];
        if (proofData.length != key.proofDataLength) {
            revert InvalidProofDataLength(proofData.length, key.proofDataLength);
        }
        uint256 paddedProofLength =
            (uint256(key.proofDataLength) + 31) & ~uint256(31);
        uint256 expectedCalldataLength = 100 + paddedProofLength;
        if (msg.data.length != expectedCalldataLength) {
            revert InvalidFulfillmentCalldataLength(msg.data.length, expectedCalldataLength);
        }
        if (msg.sender != key.fulfiller) revert NotFulfiller(msg.sender, key.fulfiller);
        if (tx.gasprice > key.maxGasPriceWei) {
            revert FulfillmentGasPriceTooHigh(tx.gasprice, key.maxGasPriceWei);
        }
        if (key.verifier.codehash != key.verifierCodeHash) revert VerifierChanged();
        if (address(l1FeeCalculator).codehash != l1FeeCalculatorCodeHash) {
            revert L1FeeCalculatorChanged();
        }

        uint256 actualSeed = requestSeed(requestId);
        randomness = IVRFProofVerifier(key.verifier).verify{gas: key.verificationGasLimit}(
            key.keyHash, actualSeed, request.preSeed, proofData
        );
        request.status = STATUS_FULFILLED;
        request.randomness = randomness;
        emit ProofVerified(requestId, key.keyHash, randomness);

        callbackSuccess = _attemptCallback(requestId, request, config.fulfillmentOverheadGas);

        uint256 l1Cost = l1FeeCalculator.currentTxL1CostWei();
        uint256 networkCost =
            (startingGas - gasleft() + config.fulfillmentOverheadGas) * tx.gasprice + l1Cost;
        charge = _applyPrice(
            networkCost, request.premiumBps, request.waiveMinimumFee ? 0 : config.minimumRequestFeeWei
        );
        uint256 reservedPayment = _reservedPayment(request, key, config);
        if (charge > reservedPayment) {
            revert ActualPaymentExceedsReserve(charge, reservedPayment);
        }
        _settle(
            requestId, request, key.payee, config.operatorPremiumShareBps,
            reservedPayment, networkCost, charge
        );
    }

    /// @notice Permissionless gas-donation retry. A retry never creates a second service charge.
    function retryCallback(uint256 requestId) external nonReentrant returns (bool success) {
        StoredRequest storage request = s_requests[requestId];
        if (request.status == 0) revert UnknownRequest();
        if (request.status != STATUS_FULFILLED) revert RequestNotFulfilled();
        if (request.callbackSucceeded) revert CallbackAlreadySucceeded();
        return _attemptCallback(
            requestId, request, s_pricingVersions[request.pricingVersion].fulfillmentOverheadGas
        );
    }

    function expireRequest(uint256 requestId) external nonReentrant {
        StoredRequest storage request = _pendingRequest(requestId);
        uint64 expiresAtBlock = _expiresAtBlock(request);
        if (blockhashStore.contextBlockNumber() <= expiresAtBlock) {
            revert RequestNotExpired(expiresAtBlock);
        }
        uint256 reservedPayment = _reservedPayment(
            request, s_keyVersions[request.keyVersion], s_pricingVersions[request.pricingVersion]
        );
        request.status = STATUS_EXPIRED;
        _releaseReservation(request, reservedPayment);
        emit RequestExpiredAndReleased(requestId, reservedPayment);
    }

    function pruneRequest(uint256 requestId) external nonReentrant {
        StoredRequest storage request = s_requests[requestId];
        if (request.status == 0) revert UnknownRequest();
        if (request.status == STATUS_PENDING) revert RequestStillPending();
        uint256 pruneAfterBlock = uint256(_expiresAtBlock(request)) + PRUNE_DELAY_BLOCKS;
        if (blockhashStore.contextBlockNumber() <= pruneAfterBlock) {
            revert PruneTooEarly(pruneAfterBlock);
        }
        delete s_requests[requestId];
        emit RequestPruned(requestId);
    }

    function randomWords(uint256 requestId) public view returns (uint256[] memory words) {
        StoredRequest storage request = s_requests[requestId];
        if (request.status == 0) revert UnknownRequest();
        if (request.status != STATUS_FULFILLED) revert RequestNotFulfilled();
        return _expandRandomWords(request.randomness, request.numWords);
    }

    /// @dev Both creation and reconstruction use the exact same rounding and floor.
    ///      Only append-only snapshots and immutable request fields may enter this path.
    function _reservedPayment(
        StoredRequest storage request,
        KeyVersion storage key,
        PricingConfig memory config
    ) private view returns (uint256) {
        return _quotePayment(
            key.verificationGasLimit, key.maxGasPriceWei, request.callbackGasLimit, request.numWords,
            request.premiumBps, request.waiveMinimumFee, config
        );
    }

    function _expiresAtBlock(StoredRequest storage request) private view returns (uint64) {
        // This sum was checked against uint64.max during request creation.
        return request.requestBlock + s_pricingVersions[request.pricingVersion].requestTimeoutBlocks;
    }

    function _settle(
        uint256 requestId,
        StoredRequest storage request,
        address payee,
        uint16 operatorPremiumShareBps,
        uint256 reservedPayment,
        uint256 networkCost,
        uint256 charge
    ) private {
        Subscription storage subscription = subscriptions[request.subscriptionId];
        subscription.reserved -= reservedPayment;
        subscription.balance -= charge;
        _decrementPending(request);

        uint256 premium = charge - networkCost;
        uint256 operatorPayment = networkCost
            + Math.mulDiv(premium, operatorPremiumShareBps, MAX_PREMIUM_BPS);
        uint256 treasuryPayment = charge - operatorPayment;
        operatorCredits[payee] += operatorPayment;
        treasuryCredits += treasuryPayment;
        emit RequestSettled(
            requestId, networkCost, charge, operatorPayment, treasuryPayment
        );
    }

    function _releaseReservation(StoredRequest storage request, uint256 reservedPayment) private {
        subscriptions[request.subscriptionId].reserved -= reservedPayment;
        _decrementPending(request);
    }

    function _decrementPending(StoredRequest storage request) private {
        consumers[request.subscriptionId][request.consumer].pendingRequests -= 1;
        if (request.sponsored) sponsorPolicies[request.consumer].pendingRequests -= 1;
    }

    function _attemptCallback(
        uint256 requestId,
        StoredRequest storage request,
        uint32 fulfillmentOverheadGas
    ) private returns (bool success) {
        uint256 minimumGas = uint256(request.callbackGasLimit)
            + uint256(request.callbackGasLimit) / 63 + fulfillmentOverheadGas;
        if (gasleft() < minimumGas) {
            revert InsufficientCallbackGas(gasleft(), minimumGas);
        }
        // Both callers have already required/set STATUS_FULFILLED. Expand cached
        // values without repeating public status checks or storage loads per word.
        uint256[] memory words = _expandRandomWords(request.randomness, request.numWords);
        request.callbackAttempts += 1;
        (success,) = request.consumer.call{gas: request.callbackGasLimit}(
            abi.encodeCall(IProofVRFConsumer.rawFulfillRandomWords, (requestId, words))
        );
        if (success) request.callbackSucceeded = true;
        emit CallbackAttempted(requestId, request.callbackAttempts, success);
    }

    function _pendingRequest(uint256 requestId)
        private
        view
        returns (StoredRequest storage request)
    {
        request = s_requests[requestId];
        if (request.status == 0) revert UnknownRequest();
        if (request.status != STATUS_PENDING) revert RequestAlreadyFinalized();
    }
}

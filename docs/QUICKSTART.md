# Integrate EntropyRail

**Testnet only; pre-audit.** Start locally before requesting access to the recorded testnet service. A public address is not a promise that your consumer has been approved or that an operator is continuously available.

## 1. Build the contracts

```bash
git clone https://github.com/EntropyRail/vrf.git
cd vrf
nvm use
npm ci
npm run compile
npm test
```

The repository is standalone. Older design documents may show historical deployment layouts; the commands above need no parent workspace. No npm package has been published.

## 2. Implement a consumer

Use [`VRFServiceConsumerBaseV2.sol`](../contracts/VRFServiceConsumerBaseV2.sol) to authenticate callbacks from the coordinator. Despite its name, this consumer-side interface is also used by V3.

The complete, compiled example is [`ExampleVRFServiceConsumer.sol`](../contracts/examples/ExampleVRFServiceConsumer.sol). Its constructor takes the coordinator and the owner allowed to request randomness. It is a test/example contract, not game logic.

Record each request ID against the application action that requested it. Freeze the relevant application inputs when requesting, tolerate fulfillment out of order, use adequate confirmations, and never introduce a redraw or an alternate result after observing an outcome.

## 3. Create, fund, and authorize

Call `createSubscription()` from the subscription owner, then `fundSubscription(subscriptionId)` with testnet ETH. Read the created ID from the transaction event; do not assume it is `1`.

The subscription owner calls `addConsumer(subscriptionId, consumerAddress, maxCallbackGasLimit, maxPendingRequests)`. Only authorized consumers may spend the subscription's balance. The consumer's request-owner role and the subscription-owner role are separate permissions.

## 4. Quote and request

Use the **current active key** from the selected coordinator's public deployment record and onchain key configuration. Call `quoteMaxPayment(keyHash, consumerAddress, subscriptionId, callbackGasLimit, numWords)` and pass the quote as `maxPayment` in:

```solidity
IVRFServiceCoordinatorV2.RandomWordsRequest({
    keyHash: keyHash,
    subscriptionId: subscriptionId,
    requestConfirmations: confirmations,
    callbackGasLimit: callbackGasLimit,
    numWords: 1,
    maxPayment: maxPayment
})
```

Choose confirmations and callback gas for your application and the key's constraints. The values in the website snippets are illustrative, not universal defaults. Insufficient funding, inactive keys, gas limits, or authorization may reject a request.

The owner of the example consumer passes this structure to its `request` method. The consumer contract then requests randomness from the coordinator. A customer does not need the prover's private key and cannot act as the request's pinned fulfiller.

## 5. Receive or retry the same result

The coordinator verifies the proof, records the result, settles the service cost, and attempts `fulfillRandomWords` on the consumer. Store the result and avoid unbounded or failure-prone work in the callback.

If callback delivery fails, permissionless retry delivers the same result without a second service fee; the retry caller still pays transaction gas. Expiration releases the reservation for an unfulfilled request. It is not a safe justification to redraw an outcome for an application that could selectively prefer one result.

## V3 witness requirements

V3 commits to all 27 fields of request state. Retain `CompactRequestState` events and reconstruct the latest valid witness using [`operator/compact-protocol.mjs`](../operator/compact-protocol.mjs). Cross-check the chain, coordinator, event history, and commitment through independent RPC sources.

V3's `getRequest`, `requestSeed`, `fulfillRandomWords`, `retryCallback`, `expireRequest`, and `pruneRequest` take the full witness. V2's request-ID-only lifecycle calls are **not compatible**. Stale, modified, or incomplete witnesses must fail. V3 is a separate deployment with separate subscription balances, not an in-place V2 migration.

## Sponsored applications

An approved sponsor policy may allow a consumer to pass `subscriptionId = 0`, selecting the configured sponsor subscription. The sponsor funds the service; quotas, expiry, and gas limits still apply. Customers cannot enable their own sponsor exemption, and requesting transactions still need gas.

## Next steps

- [Recorded testnet deployment and canary](DEPLOYMENTS.md)
- [Current limits and readiness](STATUS.md)
- [Security reporting](../SECURITY.md)
- [Experimental threshold protocol](THRESHOLD_PROTOCOL.md)

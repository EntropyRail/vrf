const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { fixture, state, event, PRICING, PROOF_TYPE } = require("./helpers/compact.cjs");

describe("Compact Coordinator V3", () => {
  it("blocks callback reentry with a valid provisional witness even after the prune deadline", async () => {
    const f = await fixture();
    const malicious = await f.ethers.deployContract("MockCompactReentrantConsumer", [f.coordinator.target]);
    await f.coordinator.connect(f.subscriber).addConsumer(1, malicious.target, 300_000, 4);
    const reserve = await f.coordinator.quoteMaxPayment(f.keyHash, malicious.target, 1, 300_000, 1);
    const pending = state(await (await malicious.request({ keyHash: f.keyHash, subscriptionId: 1,
      requestConfirmations: 2, callbackGasLimit: 300_000, numWords: 1, maxPayment: reserve })).wait(), f.coordinator);
    await f.context.setBlockNumber(1_000_002);
    const failed = await f.fulfill(pending.witness);
    await f.context.setBlockNumber(1_050_601);
    const provisional = { ...failed.witness, callbackAttempts: 2n };
    await malicious.arm(f.coordinator.interface.encodeFunctionData("pruneRequest", [provisional]));
    const retried = state(await (await f.coordinator.retryCallback(failed.witness)).wait(), f.coordinator);
    assert.equal(retried.witness.callbackSucceeded, true);
    assert.equal(await malicious.attackSucceeded(), false);
    assert.equal(await malicious.failureSelector(), f.ethers.id("ReentrancyGuardReentrantCall()").slice(0, 10));
    assert.equal(await f.coordinator.commitments(retried.requestId), await f.coordinator.hashRequest(retried.witness));
  });

  it("enforces the minimum fee, accounts for nonzero L1 cost and rolls back over-reserve work", async () => {
    const f = await fixture({ mutableFee: true });
    await f.coordinator.setPricing({ ...PRICING, minimumRequestFeeWei: f.ethers.parseEther("0.01") });
    const floorRequest = await f.request();
    await f.fee.setFee(20_000_000_000_000n);
    await f.context.setBlockNumber(1_000_002);
    const paid = await f.fulfill(floorRequest.witness);
    const bill = event(paid.receipt, f.coordinator, "RequestSettled");
    assert.equal(bill.totalCharge, f.ethers.parseEther("0.01"));
    assert.ok(bill.networkCost >= 20_000_000_000_000n);
    await f.coordinator.setPricing(PRICING);
    await f.context.setBlockNumber(1_000_000);
    const pending = await f.request();
    await f.context.setBlockNumber(1_000_002);
    const { proofData } = await f.proof(pending.witness);
    const previousWords = Array.from(await f.consumer.lastWords());
    const previousBalance = (await f.coordinator.subscriptions(1)).balance;
    await f.fee.setFee(pending.witness.reservedPayment * 2n);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(pending.witness, proofData), /ActualPaymentExceedsReserve/);
    assert.equal((await f.coordinator.subscriptions(1)).balance, previousBalance);
    assert.equal((await f.coordinator.subscriptions(1)).reserved, pending.witness.reservedPayment);
    assert.equal(await f.coordinator.commitments(pending.requestId), await f.coordinator.hashRequest(pending.witness));
    assert.deepEqual(Array.from(await f.consumer.lastWords()), previousWords);
  });

  it("verifies a real 3-of-5 BLS threshold aggregate through the compact contract route", async () => {
    const f = await fixture();
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const crypto = await import("../operator/threshold-crypto.mjs");
    const backend = await f.ethers.deployContract("BLS12381Backend");
    const adapter = await f.ethers.deployContract("ThresholdBLSVerifierAdapter", [backend.target]);
    const coefficients = [123456789n, 99887766n, 44556677n];
    const scalarAt = index => coefficients.reduceRight((v, c) => (v * BigInt(index) + c) % crypto.BLS_SCALAR_ORDER, 0n);
    const wire = point => f.ethers.hexlify(point.toRawBytes(false));
    const groupPublicKey = wire(bls.G2.ProjectivePoint.BASE.multiply(coefficients[0]));
    const keyHash = await adapter.keyHash(groupPublicKey);
    await f.coordinator.registerKey(keyHash, adapter.target, groupPublicKey, f.fulfiller.address, f.payee.address, 20_000_000_000n, 2_100_000);
    const pending = await f.request({ keyHash });
    await f.context.setBlockNumber(1_000_002);
    const seed = await f.coordinator.requestSeed(pending.witness);
    const message = await adapter.messageFor(keyHash, seed, pending.witness.preSeed);
    const messagePoint = bls.G1.hashToCurve(f.ethers.getBytes(message), { DST: crypto.BLS_DST });
    const shares = [1, 3, 5].map(index => ({ index, publicKey: wire(bls.G2.ProjectivePoint.BASE.multiply(scalarAt(index))), signature: wire(messagePoint.multiply(scalarAt(index))) }));
    const aggregate = crypto.aggregateThresholdShares({ message, groupPublicKey, threshold: 3, shares });
    const proofData = f.ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes"], [groupPublicKey, aggregate.signature]);
    const done = state(await (await f.coordinator.connect(f.fulfiller).fulfillRandomWords(pending.witness, proofData)).wait(), f.coordinator);
    assert.equal(done.witness.randomness, await adapter.randomnessFor(message, aggregate.signature));
    assert.equal(done.witness.callbackSucceeded, true);
  });

  it("authenticates all 27 fields; forged billing, randomness and status cannot consume a reservation", async () => {
    const f = await fixture();
    const { witness, requestId } = await f.request();
    const digest = await f.coordinator.commitments(requestId);
    assert.equal(digest, await f.coordinator.hashRequest(witness));
    assert.equal(Object.keys(witness).length, 27);
    for (const [field, value] of Object.entries(witness)) {
      const changed = typeof value === "boolean" ? !value : typeof value === "bigint" ? value + 1n
        : value.length === 42 ? f.outsider.address : f.ethers.id(`tampered-${field}`);
      const forged = { ...witness, [field]: changed };
      for (const invoke of [
        () => f.coordinator.getRequest(forged),
        () => f.coordinator.connect(f.fulfiller).fulfillRandomWords(forged, "0x"),
        () => f.coordinator.expireRequest(forged),
        () => f.coordinator.retryCallback(forged),
        () => f.coordinator.pruneRequest(forged),
      ]) await assert.rejects(invoke, /InvalidWitness|UnknownRequest/);
    }
    assert.equal(await f.coordinator.commitments(requestId), digest);
    assert.equal((await f.coordinator.subscriptions(1)).reserved, witness.reservedPayment);
  });

  it("preserves request API, proof output, callback expansion and exact liabilities; rejects stale witnesses", async () => {
    const f = await fixture();
    const pending = await f.request({ numWords: 3, callbackGasLimit: 300_000 });
    const before = await f.coordinator.subscriptions(1);
    await f.context.setBlockNumber(1_000_002);
    const done = await f.fulfill(pending.witness);
    const settled = event(done.receipt, f.coordinator, "RequestSettled");
    assert.equal(done.witness.randomness, done.output);
    assert.equal(done.witness.callbackSucceeded, true);
    assert.equal(done.witness.callbackAttempts, 1n);
    assert.deepEqual(Array.from(await f.consumer.lastWords()), Array.from(await f.coordinator.randomWords(done.witness)));
    const after = await f.coordinator.subscriptions(1);
    assert.equal(after.balance, before.balance - settled.totalCharge);
    assert.equal(after.reserved, 0n);
    assert.equal((await f.coordinator.consumers(1, await f.consumer.getAddress())).pendingRequests, 0n);
    const credits = await f.coordinator.operatorCredits(f.payee.address) + await f.coordinator.treasuryCredits();
    assert.equal(credits, settled.totalCharge);
    assert.equal(after.balance + credits, await f.ethers.provider.getBalance(await f.coordinator.getAddress()));
    await assert.rejects(() => f.coordinator.getRequest(pending.witness), /InvalidWitness/);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(pending.witness, done.proofData), /InvalidWitness/);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(done.witness, done.proofData), /RequestAlreadyFinalized/);
    await assert.rejects(() => f.coordinator.retryCallback(done.witness), /CallbackAlreadySucceeded/);
    const clone = await f.ethers.deployContract("VRFServiceCoordinatorV3", f.constructorArgs);
    assert.notEqual(await clone.hashRequest(done.witness), await f.coordinator.hashRequest(done.witness));
    await assert.rejects(() => clone.getRequest(done.witness), /UnknownRequest/);
  });

  it("rejects wrong signer, invalid proof, proof/outer padding and non-canonical proof offset without charging", async () => {
    const f = await fixture();
    const { witness, requestId } = await f.request();
    await f.context.setBlockNumber(1_000_002);
    const generated = await f.proof(witness);
    await assert.rejects(() => f.coordinator.connect(f.outsider).fulfillRandomWords(witness, generated.proofData), /NotFulfiller/);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(witness, generated.proofData, { gasPrice: 21_000_000_000n }), /FulfillmentGasPriceTooHigh/);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(witness, `${generated.proofData}00`), /InvalidProofDataLength/);
    const badProof = f.ethers.AbiCoder.defaultAbiCoder().encode([PROOF_TYPE], [{ ...generated.proof, c: generated.proof.c + 1n }]);
    await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(witness, badProof));
    const call = f.coordinator.interface.encodeFunctionData("fulfillRandomWords", [witness, generated.proofData]);
    await assert.rejects(() => f.fulfiller.sendTransaction({ to: f.coordinator.target, data: `${call}00` }), /InvalidFulfillmentCalldataLength/);
    // Point bytes at witness.proofDataLength (field 15, value 416). The decoder
    // accepts this overlapping 416-byte payload, but it is not canonical ABI.
    const offsetStart = 10 + 27 * 64;
    const shifted = call.slice(0, offsetStart) + f.ethers.toBeHex(15 * 32, 32).slice(2) + call.slice(offsetStart + 64);
    await assert.rejects(() => f.fulfiller.sendTransaction({ to: f.coordinator.target, data: shifted }), /InvalidProofOffset/);
    assert.equal(await f.coordinator.commitments(requestId), await f.coordinator.hashRequest(witness));
    assert.equal(await f.coordinator.operatorCredits(f.payee.address), 0n);
    assert.equal((await f.coordinator.subscriptions(1)).reserved, witness.reservedPayment);
  });

  it("pins all price/lane/service data through rotation, deactivation and demand pause", async () => {
    const f = await fixture();
    const first = await f.request();
    await f.coordinator.setPricing({ ...PRICING, publicPremiumBps: 9_000, fulfillmentOverheadGas: 350_000, requestTimeoutBlocks: 257 });
    await f.coordinator.setKeyService(f.keyHash, f.outsider.address, f.guardian.address, 25_000_000_000n, 2_200_000);
    const second = await f.request();
    await f.coordinator.setKeyActive(f.keyHash, false);
    await f.coordinator.connect(f.guardian).pauseRequests();
    await f.context.setBlockNumber(1_000_002);
    for (const [pending, signer, premium, payee] of [[first, f.fulfiller, 2_000n, f.payee], [second, f.outsider, 9_000n, f.guardian]]) {
      const done = await f.fulfill(pending.witness, signer);
      const billed = event(done.receipt, f.coordinator, "RequestSettled");
      assert.equal(billed.totalCharge, billed.networkCost + billed.networkCost * premium / 10_000n);
      assert.equal(await f.coordinator.operatorCredits(payee.address), billed.operatorPayment);
    }
    assert.equal((await f.coordinator.subscriptions(1)).reserved, 0n);
  });

  it("checks verifier and L1 fee calculator runtime hashes", async () => {
    for (const target of ["verifier", "fee"]) {
      const f = await fixture();
      const { witness } = await f.request();
      await f.context.setBlockNumber(1_000_002);
      const { proofData } = await f.proof(witness);
      await f.ethers.provider.send("hardhat_setCode", [await f[target].getAddress(), "0x00"]);
      await assert.rejects(() => f.coordinator.connect(f.fulfiller).fulfillRandomWords(witness, proofData), target === "verifier" ? /VerifierChanged/ : /L1FeeCalculatorChanged/);
    }
  });

  it("retains one unique result across failed callbacks and retries; retry does not bill again", async () => {
    const f = await fixture();
    await f.consumer.connect(f.subscriber).setRevertCallbacks(true);
    const pending = await f.request();
    await f.context.setBlockNumber(1_000_002);
    const failed = await f.fulfill(pending.witness);
    assert.equal(failed.witness.callbackSucceeded, false);
    const balance = (await f.coordinator.subscriptions(1)).balance;
    const again = state(await (await f.coordinator.retryCallback(failed.witness)).wait(), f.coordinator);
    assert.equal(again.witness.callbackAttempts, 2n);
    assert.equal(again.witness.callbackSucceeded, false);
    await assert.rejects(() => f.coordinator.retryCallback(failed.witness), /InvalidWitness/);
    await f.consumer.connect(f.subscriber).setRevertCallbacks(false);
    const success = state(await (await f.coordinator.connect(f.outsider).retryCallback(again.witness)).wait(), f.coordinator);
    assert.equal(success.witness.randomness, failed.output);
    assert.equal(success.witness.callbackAttempts, 3n);
    assert.equal(success.witness.callbackSucceeded, true);
    assert.equal((await f.coordinator.subscriptions(1)).balance, balance);
  });

  it("uses L2 confirmations, pinned expiry/prune boundaries and cannot release a reservation twice", async () => {
    const f = await fixture();
    const pending = await f.request();
    await assert.rejects(() => f.coordinator.requestSeed(pending.witness), /ConfirmationsPending/);
    await f.context.setBlockNumber(1_000_600);
    await assert.rejects(() => f.coordinator.expireRequest(pending.witness), /RequestNotExpired/);
    await f.coordinator.setPricing({ ...PRICING, requestTimeoutBlocks: 1_000_000 });
    await f.context.setBlockNumber(1_000_601);
    await assert.rejects(() => f.coordinator.requestSeed(pending.witness), /RequestExpired/);
    const expired = state(await (await f.coordinator.expireRequest(pending.witness)).wait(), f.coordinator);
    assert.equal(expired.witness.status, 3n);
    assert.equal((await f.coordinator.subscriptions(1)).reserved, 0n);
    assert.equal((await f.coordinator.subscriptions(1)).balance, f.ethers.parseEther("2"));
    await assert.rejects(() => f.coordinator.expireRequest(pending.witness), /InvalidWitness/);
    await assert.rejects(() => f.coordinator.randomWords(expired.witness), /RequestNotFulfilled/);
    await f.context.setBlockNumber(1_050_600);
    await assert.rejects(() => f.coordinator.pruneRequest(expired.witness), /PruneTooEarly/);
    await f.context.setBlockNumber(1_050_601);
    await f.coordinator.pruneRequest(expired.witness);
    assert.equal(await f.coordinator.commitments(expired.requestId), f.ethers.ZeroHash);
    await assert.rejects(() => f.coordinator.expireRequest(pending.witness), /UnknownRequest/);
    await assert.rejects(() => f.coordinator.getRequest(expired.witness), /UnknownRequest/);
    await f.context.setBlockNumber((1n << 64n) - 1n);
    await assert.rejects(() => f.request(), /BlockNumberOverflow/);
  });

  it("uses archived L2 hashes after 256 blocks and fails closed when the hash is missing", async () => {
    const f = await fixture();
    const pending = await f.request();
    await f.context.setBlockNumber(1_000_002);
    const seed = await f.coordinator.requestSeed(pending.witness);
    await f.store.store(pending.witness.requestBlock);
    await f.context.setBlockNumber(1_000_300);
    assert.equal(await f.coordinator.requestSeed(pending.witness), seed);
    await f.fulfill(pending.witness);
    const missing = await f.request();
    await f.context.setBlockNumber(1_000_302);
    await assert.rejects(() => f.coordinator.requestSeed(missing.witness), /BlockhashUnavailable/);
  });

  it("enforces Sponsor quota, pending counts and reserves while keeping waived markup at zero", async () => {
    const f = await fixture();
    const now = (await f.ethers.provider.getBlock("latest")).timestamp;
    await f.coordinator.setSponsorPolicy(await f.consumer.getAddress(), {
      subscriptionId: 1, validUntil: now + 86400, requestsPerEpoch: 3, maxPendingRequests: 2,
      maxCallbackGasLimit: 100_000, premiumBps: 0, waiveMinimumFee: true,
    });
    const first = await f.request({ subscriptionId: 0 });
    const second = await f.request({ subscriptionId: 0 });
    await assert.rejects(() => f.request({ subscriptionId: 0 }), /InvalidSponsorPolicy/);
    assert.equal(first.witness.sponsored, true);
    assert.equal(first.witness.minimumFeeWei, 0n);
    await f.context.setBlockNumber(1_000_002);
    const done = await f.fulfill(first.witness);
    const billed = event(done.receipt, f.coordinator, "RequestSettled");
    assert.equal(billed.networkCost, billed.totalCharge);
    await f.context.setBlockNumber(1_000_601);
    await f.coordinator.expireRequest(second.witness);
    assert.equal((await f.coordinator.sponsorPolicies(f.consumer.target)).pendingRequests, 0n);
    assert.equal((await f.coordinator.subscriptions(1)).reserved, 0n);
    await f.request({ subscriptionId: 0 });
    await assert.rejects(() => f.request({ subscriptionId: 0 }), /SponsorQuotaExceeded/);
  });

  it("maintains liabilities through 12 mixed-price requests settled/expired out of order", async () => {
    const f = await fixture();
    const pending = [];
    let totalReserve = 0n;
    for (let i = 0; i < 12; i += 1) {
      await f.coordinator.setPricing({ ...PRICING, publicPremiumBps: i * 500, requestTimeoutBlocks: 600 + i });
      const req = await f.request({ numWords: 1 + (i % 3), callbackGasLimit: 300_000 });
      totalReserve += req.witness.reservedPayment;
      pending.push(req);
    }
    assert.equal((await f.coordinator.subscriptions(1)).reserved, totalReserve);
    await f.context.setBlockNumber(1_000_002);
    for (const index of [10, 2, 8, 0, 6, 4]) {
      await f.fulfill(pending[index].witness);
      totalReserve -= pending[index].witness.reservedPayment;
      const sub = await f.coordinator.subscriptions(1);
      assert.equal(sub.reserved, totalReserve);
      assert.equal(sub.balance + await f.coordinator.operatorCredits(f.payee.address) + await f.coordinator.treasuryCredits(), await f.ethers.provider.getBalance(f.coordinator.target));
    }
    await f.context.setBlockNumber(1_001_000);
    for (const index of [11, 1, 7, 5, 9, 3]) {
      await f.coordinator.expireRequest(pending[index].witness);
      totalReserve -= pending[index].witness.reservedPayment;
      assert.equal((await f.coordinator.subscriptions(1)).reserved, totalReserve);
    }
    assert.equal(totalReserve, 0n);
    assert.equal((await f.coordinator.consumers(1, f.consumer.target)).pendingRequests, 0n);
  });
});

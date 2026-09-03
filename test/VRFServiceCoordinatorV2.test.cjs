const { parseEther, parseUnits } = require("ethers");
const { before, describe, it } = require("node:test");

let expect;
let ethers;

const VRF_PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";
const PROOF_NONCE = 0x123456789abcdefn;
const CALLBACK_GAS = 300_000;
const CONFIRMATIONS = 2;
const NUM_WORDS = 3;
const MAX_GAS_PRICE = parseUnits("20", "gwei");
const VERIFICATION_GAS = 2_100_000;
const FUNDING = parseEther("2");

const PROOF_TYPE =
  "tuple(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv)";

const PRICING = {
  minimumRequestFeeWei: parseEther("0.00001"),
  l1FeeReserveWei: parseEther("0.00002"),
  fulfillmentOverheadGas: 120_000,
  perWordGas: 500,
  publicPremiumBps: 2_000,
  operatorPremiumShareBps: 5_000,
  requestTimeoutBlocks: 600,
};

let proofTools;

before(async function () {
  ({ expect } = await import("chai"));
  const { network } = await import("hardhat");
  ({ ethers } = await network.create());
  proofTools = await import("../operator/proof.mjs");
});

async function mineBlocks(count) {
  for (let i = 0; i < count; i += 1) {
    await ethers.provider.send("evm_mine", []);
  }
}

function parseEvent(receipt, contract, eventName) {
  for (const log of receipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed?.name === eventName) return parsed;
    } catch {}
  }
  throw new Error(`${eventName} event not found`);
}

function encodeProof(proof) {
  return ethers.AbiCoder.defaultAbiCoder().encode([PROOF_TYPE], [proof]);
}

async function deployFixture(options = {}) {
  const [owner, guardian, fulfiller, payee, subscriber, outsider, recipient] =
    await ethers.getSigners();

  const blockContext = options.mockContext
    ? await ethers.deployContract("MockBlockContext", [options.initialContextBlock ?? 1_000_000])
    : await ethers.deployContract("EVMBlockContext");
  await blockContext.waitForDeployment();
  const blockhashStore = await ethers.deployContract("BlockhashStore", [
    await blockContext.getAddress(),
  ]);
  const feeCalculator = await ethers.deployContract("ZeroL1FeeCalculator");
  const verifier = await ethers.deployContract("Secp256k1ECVRFVerifier");
  await Promise.all([
    blockhashStore.waitForDeployment(),
    feeCalculator.waitForDeployment(),
    verifier.waitForDeployment(),
  ]);

  const publicKey = proofTools.publicKeyFor(VRF_PRIVATE_KEY);
  const keyHash = await verifier.keyHash(publicKey);
  const keyData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [publicKey]);

  const coordinator = await ethers.deployContract("VRFServiceCoordinatorV2", [
    owner.address,
    guardian.address,
    await blockhashStore.getAddress(),
    await feeCalculator.getAddress(),
    PRICING,
    {
      keyHash,
      verifier: await verifier.getAddress(),
      keyData,
      fulfiller: fulfiller.address,
      payee: payee.address,
      maxGasPriceWei: MAX_GAS_PRICE,
      verificationGasLimit: VERIFICATION_GAS,
    },
  ]);
  await coordinator.waitForDeployment();

  const consumer = await ethers.deployContract("ExampleVRFServiceConsumer", [
    await coordinator.getAddress(),
    subscriber.address,
  ]);
  await consumer.waitForDeployment();

  await coordinator.connect(subscriber).createSubscription();
  const subscriptionId = 1n;
  await coordinator.connect(subscriber).fundSubscription(subscriptionId, { value: FUNDING });
  await coordinator.connect(subscriber).addConsumer(
    subscriptionId,
    await consumer.getAddress(),
    CALLBACK_GAS,
    4,
  );

  return {
    owner,
    guardian,
    fulfiller,
    payee,
    subscriber,
    outsider,
    recipient,
    blockhashStore,
    blockContext,
    feeCalculator,
    verifier,
    coordinator,
    consumer,
    publicKey,
    keyHash,
    subscriptionId,
  };
}

async function requestRandomness(fixture, overrides = {}) {
  const { coordinator, consumer, subscriber, keyHash, subscriptionId } = fixture;
  const usedKeyHash = overrides.keyHash ?? keyHash;
  const usedSubscriptionId = overrides.subscriptionId ?? subscriptionId;
  const callbackGasLimit = overrides.callbackGasLimit ?? CALLBACK_GAS;
  const numWords = overrides.numWords ?? NUM_WORDS;
  const quote = await coordinator.quoteMaxPayment(
    usedKeyHash,
    await consumer.getAddress(),
    usedSubscriptionId,
    callbackGasLimit,
    numWords,
  );
  const params = {
    keyHash: usedKeyHash,
    subscriptionId: usedSubscriptionId,
    requestConfirmations: overrides.confirmations ?? CONFIRMATIONS,
    callbackGasLimit,
    numWords,
    maxPayment: overrides.maxPayment ?? quote,
  };
  const tx = await consumer.connect(subscriber).request(params);
  const receipt = await tx.wait();
  const event = parseEvent(receipt, coordinator, "RandomWordsRequested");
  return {
    receipt,
    requestId: event.args.requestId,
    preSeed: event.args.preSeed,
    requestBlock: event.args.requestBlock,
    reserve: event.args.reservedPayment,
  };
}

async function buildProof(coordinator, requestId, preSeed) {
  const actualSeed = await coordinator.requestSeed(requestId);
  return proofTools.generateProof({
    privateKey: VRF_PRIVATE_KEY,
    actualSeed,
    preSeed,
    nonce: PROOF_NONCE,
  });
}

describe("VRFServiceCoordinatorV2", function () {
  it("reserves a maximum, verifies ECVRF, bills actual gas, and splits revenue", async function () {
    const fixture = await deployFixture();
    const {
      owner, coordinator, consumer, fulfiller, payee, recipient, keyHash, subscriptionId,
    } = fixture;
    expect(proofTools.serviceKeyHash(fixture.publicKey)).to.equal(keyHash);
    expect(await coordinator.owner()).to.equal(owner.address);
    expect(await coordinator.pendingOwner()).to.equal(ethers.ZeroAddress);
    expect(await coordinator.keyExists(keyHash)).to.equal(true);
    expect(await coordinator.keyExists(ethers.ZeroHash)).to.equal(false);
    const subscriptionBefore = await coordinator.subscriptions(subscriptionId);
    const { requestId, preSeed, reserve } = await requestRandomness(fixture);
    const reservedSubscription = await coordinator.subscriptions(subscriptionId);
    expect(reservedSubscription.reserved).to.equal(reserve);
    expect(reservedSubscription.balance).to.equal(subscriptionBefore.balance);

    await expect(coordinator.requestSeed(requestId))
      .to.be.revertedWithCustomError(coordinator, "ConfirmationsPending");
    await mineBlocks(CONFIRMATIONS);
    const { proof, output } = await buildProof(coordinator, requestId, preSeed);

    const tx = await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof));
    const receipt = await tx.wait();
    const settled = parseEvent(receipt, coordinator, "RequestSettled");
    expect(settled.args.totalCharge).to.be.lessThanOrEqual(reserve);
    expect(settled.args.operatorPayment + settled.args.treasuryPayment)
      .to.equal(settled.args.totalCharge);
    expect(await coordinator.operatorCredits(payee.address))
      .to.equal(settled.args.operatorPayment);
    expect(await coordinator.treasuryCredits()).to.equal(settled.args.treasuryPayment);

    const request = await coordinator.getRequest(requestId);
    expect(request.status).to.equal(2);
    expect(request.callbackSucceeded).to.equal(true);
    expect(request.randomness).to.equal(output);
    const subscriptionAfter = await coordinator.subscriptions(subscriptionId);
    expect(subscriptionAfter.reserved).to.equal(0);
    expect(subscriptionAfter.balance)
      .to.equal(subscriptionBefore.balance - settled.args.totalCharge);
    expect(await ethers.provider.getBalance(await coordinator.getAddress())).to.equal(
      subscriptionAfter.balance
        + await coordinator.operatorCredits(payee.address)
        + await coordinator.treasuryCredits(),
    );

    const expectedWords = Array.from({ length: NUM_WORDS }, (_, index) => BigInt(
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"], [output, index],
      )),
    ));
    expect(await consumer.lastWords()).to.deep.equal(expectedWords);
    expect(await coordinator.randomWords(requestId)).to.deep.equal(expectedWords);
    expect(request.keyHash).to.equal(keyHash);

    const recipientBefore = await ethers.provider.getBalance(recipient.address);
    await coordinator.connect(payee).withdrawOperatorCredits(
      recipient.address,
      settled.args.operatorPayment,
    );
    await coordinator.connect(owner).withdrawTreasuryCredits(
      recipient.address,
      settled.args.treasuryPayment,
    );
    expect(await ethers.provider.getBalance(recipient.address)).to.equal(
      recipientBefore + settled.args.totalCharge,
    );
    expect(await ethers.provider.getBalance(await coordinator.getAddress()))
      .to.equal(subscriptionAfter.balance);
  });

  it("derives proof nonces deterministically when no test nonce is supplied", async function () {
    const first = proofTools.generateProof({
      privateKey: VRF_PRIVATE_KEY,
      actualSeed: 123n,
      preSeed: 456n,
    });
    const second = proofTools.generateProof({
      privateKey: VRF_PRIVATE_KEY,
      actualSeed: 123n,
      preSeed: 456n,
    });
    expect(JSON.stringify(first, (_, value) => typeof value === "bigint" ? value.toString() : value))
      .to.equal(JSON.stringify(second, (_, value) => typeof value === "bigint" ? value.toString() : value));
  });

  it("uses per-consumer nonces so another consumer cannot advance a request sequence", async function () {
    const fixture = await deployFixture();
    const { coordinator, subscriber, subscriptionId, keyHash, consumer } = fixture;
    const second = await ethers.deployContract("ExampleVRFServiceConsumer", [
      await coordinator.getAddress(),
      subscriber.address,
    ]);
    await second.waitForDeployment();
    await coordinator.connect(subscriber).addConsumer(
      subscriptionId,
      await second.getAddress(),
      CALLBACK_GAS,
      4,
    );

    await requestRandomness(fixture, { numWords: 1 });
    const secondQuote = await coordinator.quoteMaxPayment(
      keyHash,
      await second.getAddress(),
      subscriptionId,
      CALLBACK_GAS,
      1,
    );
    await second.connect(subscriber).request({
      keyHash,
      subscriptionId,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: secondQuote,
    });

    expect(await coordinator.consumerNonces(subscriptionId, await consumer.getAddress())).to.equal(1);
    expect(await coordinator.consumerNonces(subscriptionId, await second.getAddress())).to.equal(1);
  });

  it("derives confirmation, expiry, and seed from the injected L2 block context", async function () {
    const fixture = await deployFixture({ mockContext: true, initialContextBlock: 7_000_000 });
    const { coordinator, blockContext, fulfiller } = fixture;
    const { requestId, preSeed, requestBlock } = await requestRandomness(fixture, { numWords: 1 });
    expect(requestBlock).to.equal(7_000_000n);
    const requestHash = ethers.keccak256(ethers.toUtf8Bytes("mock-robinhood-l2-block"));
    await blockContext.setBlockHash(requestBlock, requestHash);
    await blockContext.setBlockNumber(requestBlock + BigInt(CONFIRMATIONS));
    const expectedSeed = BigInt(ethers.keccak256(ethers.solidityPacked(
      ["bytes32", "bytes32"],
      [ethers.zeroPadValue(ethers.toBeHex(preSeed), 32), requestHash],
    )));
    expect(await coordinator.requestSeed(requestId)).to.equal(expectedSeed);
    const { proof } = proofTools.generateProof({
      privateKey: VRF_PRIVATE_KEY,
      actualSeed: expectedSeed,
      preSeed,
    });
    await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof));
  });

  it("uses a Sponsor subscription for user-free requests and enforces the epoch quota", async function () {
    const fixture = await deployFixture();
    const {
      owner, subscriber, coordinator, consumer, fulfiller, subscriptionId,
    } = fixture;
    const latestBlock = await ethers.provider.getBlock("latest");
    const policy = {
      subscriptionId,
      validUntil: latestBlock.timestamp + 86_400,
      requestsPerEpoch: 1,
      maxPendingRequests: 2,
      maxCallbackGasLimit: CALLBACK_GAS,
      premiumBps: 0,
      waiveMinimumFee: true,
    };
    await coordinator.connect(owner).setSponsorPolicy(await consumer.getAddress(), policy);

    const balanceBefore = (await coordinator.subscriptions(subscriptionId)).balance;
    const sponsored = await requestRandomness(fixture, { subscriptionId: 0n, numWords: 1 });
    expect((await coordinator.getRequest(sponsored.requestId)).sponsored).to.equal(true);
    expect((await coordinator.subscriptions(subscriptionId)).balance).to.equal(balanceBefore);

    const quote = await coordinator.quoteMaxPayment(
      fixture.keyHash,
      await consumer.getAddress(),
      0,
      CALLBACK_GAS,
      1,
    );
    await expect(consumer.connect(subscriber).request({
      keyHash: fixture.keyHash,
      subscriptionId: 0,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: quote,
    })).to.be.revertedWithCustomError(coordinator, "SponsorQuotaExceeded");

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, sponsored.requestId, sponsored.preSeed);
    const receipt = await (
      await coordinator.connect(fulfiller).fulfillRandomWords(
        sponsored.requestId,
        encodeProof(proof),
      )
    ).wait();
    const settled = parseEvent(receipt, coordinator, "RequestSettled");
    expect(settled.args.totalCharge).to.equal(settled.args.networkCost);
    expect(settled.args.treasuryPayment).to.equal(0);
    expect((await coordinator.subscriptions(subscriptionId)).balance)
      .to.equal(balanceBefore - settled.args.totalCharge);
  });

  it("prevents unapproved consumers, reserve underpayment, reserve draining, and proof front-running", async function () {
    const fixture = await deployFixture();
    const {
      subscriber, outsider, coordinator, subscriptionId, keyHash, fulfiller,
    } = fixture;
    const unapproved = await ethers.deployContract("ExampleVRFServiceConsumer", [
      await coordinator.getAddress(),
      outsider.address,
    ]);
    await unapproved.waitForDeployment();
    await expect(unapproved.connect(outsider).request({
      keyHash,
      subscriptionId,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: ethers.MaxUint256,
    })).to.be.revertedWithCustomError(coordinator, "ConsumerNotAuthorized");

    const quote = await coordinator.quoteMaxPayment(
      keyHash,
      await fixture.consumer.getAddress(),
      subscriptionId,
      CALLBACK_GAS,
      1,
    );
    await expect(fixture.consumer.connect(subscriber).request({
      keyHash,
      subscriptionId,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: quote - 1n,
    })).to.be.revertedWithCustomError(coordinator, "MaxPaymentTooLow");

    const { requestId, preSeed } = await requestRandomness(fixture, { numWords: 1 });
    const subscription = await coordinator.subscriptions(subscriptionId);
    const available = subscription.balance - subscription.reserved;
    await expect(coordinator.connect(subscriber).withdrawSubscription(
      subscriptionId,
      subscriber.address,
      available + 1n,
    )).to.be.revertedWithCustomError(coordinator, "InsufficientBalance");

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    await expect(coordinator.connect(outsider).fulfillRandomWords(requestId, encodeProof(proof)))
      .to.be.revertedWithCustomError(coordinator, "NotFulfiller");
    await expect(coordinator.connect(fulfiller).fulfillRandomWords(
      requestId,
      encodeProof(proof),
      { gasPrice: MAX_GAS_PRICE + 1n },
    )).to.be.revertedWithCustomError(coordinator, "FulfillmentGasPriceTooHigh");
    await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof));
  });

  it("rejects a forged proof without charging or consuming the request", async function () {
    const fixture = await deployFixture();
    const { coordinator, fulfiller, subscriptionId } = fixture;
    const { requestId, preSeed, reserve } = await requestRandomness(fixture);
    const balanceBefore = (await coordinator.subscriptions(subscriptionId)).balance;
    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    const forged = { ...proof, c: proof.c + 1n };

    await expect(coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(forged)))
      .to.revert(ethers);
    expect((await coordinator.getRequest(requestId)).status).to.equal(1);
    const subscription = await coordinator.subscriptions(subscriptionId);
    expect(subscription.balance).to.equal(balanceBefore);
    expect(subscription.reserved).to.equal(reserve);
  });

  it("rejects proof and outer calldata padding before any user charge", async function () {
    const fixture = await deployFixture();
    const { coordinator, fulfiller, subscriptionId } = fixture;
    const { requestId, preSeed, reserve } = await requestRandomness(fixture, { numWords: 1 });
    const balanceBefore = (await coordinator.subscriptions(subscriptionId)).balance;
    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    const encoded = encodeProof(proof);
    await expect(coordinator.connect(fulfiller).fulfillRandomWords(
      requestId,
      ethers.concat([encoded, `0x${"ab".repeat(32)}`]),
    )).to.be.revertedWithCustomError(coordinator, "InvalidProofDataLength");

    const normalCall = coordinator.interface.encodeFunctionData(
      "fulfillRandomWords",
      [requestId, encoded],
    );
    await expect(fulfiller.sendTransaction({
      to: await coordinator.getAddress(),
      data: ethers.concat([normalCall, `0x${"cd".repeat(32)}`]),
    })).to.be.revertedWithCustomError(coordinator, "InvalidFulfillmentCalldataLength");
    const subscription = await coordinator.subscriptions(subscriptionId);
    expect(subscription.balance).to.equal(balanceBefore);
    expect(subscription.reserved).to.equal(reserve);
  });

  it("uses an archived block hash after the opcode window", async function () {
    const fixture = await deployFixture();
    const { coordinator, blockhashStore, fulfiller } = fixture;
    const { requestId, preSeed, requestBlock } = await requestRandomness(fixture);
    await mineBlocks(CONFIRMATIONS);
    await expect(blockhashStore.store(requestBlock)).to.emit(blockhashStore, "BlockhashStored");
    await mineBlocks(257);

    const { proof } = await buildProof(coordinator, requestId, preSeed);
    await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof));
    expect((await coordinator.getRequest(requestId)).status).to.equal(2);
  });

  it("releases reservations on expiry without deducting the prepaid balance", async function () {
    const fixture = await deployFixture();
    const { coordinator, subscriber, recipient, subscriptionId } = fixture;
    const balanceBefore = (await coordinator.subscriptions(subscriptionId)).balance;
    const { requestId, reserve } = await requestRandomness(fixture);
    await mineBlocks(PRICING.requestTimeoutBlocks + 1);

    await expect(coordinator.expireRequest(requestId))
      .to.emit(coordinator, "RequestExpiredAndReleased")
      .withArgs(requestId, reserve);
    const subscription = await coordinator.subscriptions(subscriptionId);
    expect(subscription.balance).to.equal(balanceBefore);
    expect(subscription.reserved).to.equal(0);
    expect((await coordinator.getRequest(requestId)).status).to.equal(3);

    await expect(coordinator.connect(subscriber).cancelSubscription(
      subscriptionId,
      recipient.address,
    )).to.emit(coordinator, "SubscriptionCancelled");
    expect((await coordinator.subscriptions(subscriptionId)).active).to.equal(false);
  });

  it("pins pricing for pending requests and permits a gas-donation callback retry", async function () {
    const fixture = await deployFixture();
    const {
      owner, subscriber, coordinator, consumer, fulfiller,
    } = fixture;
    await consumer.connect(subscriber).setRevertCallbacks(true);
    const { requestId, preSeed, reserve } = await requestRandomness(fixture);
    const pinned = await coordinator.getRequest(requestId);
    await coordinator.connect(owner).setPricing({
      ...PRICING,
      minimumRequestFeeWei: ethers.parseEther("1"),
      fulfillmentOverheadGas: 500_000,
    });
    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    const receipt = await (
      await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof))
    ).wait();
    const settled = parseEvent(receipt, coordinator, "RequestSettled");
    expect(settled.args.totalCharge).to.be.lessThanOrEqual(reserve);
    expect((await coordinator.getRequest(requestId)).callbackSucceeded).to.equal(false);
    expect(pinned.minimumFeeWei).to.equal(PRICING.minimumRequestFeeWei);
    expect(pinned.fulfillmentOverheadGas).to.equal(PRICING.fulfillmentOverheadGas);

    await consumer.connect(subscriber).setRevertCallbacks(false);
    await expect(coordinator.retryCallback(requestId))
      .to.emit(coordinator, "CallbackAttempted")
      .withArgs(requestId, 2, true);
  });

  it("pins every service version through repeated rotations, pricing changes and deactivation", async function () {
    const fixture = await deployFixture();
    const { coordinator, fulfiller, payee, outsider, recipient, guardian, keyHash } = fixture;
    const first = await requestRandomness(fixture, { numWords: 1 });
    const firstPinned = await coordinator.getRequest(first.requestId);
    await coordinator.setKeyService(keyHash, outsider.address, recipient.address,
      parseUnits("10", "gwei"), 800_000);
    await coordinator.setPricing({
      ...PRICING, minimumRequestFeeWei: parseEther("0.00002"),
      fulfillmentOverheadGas: 240_000, publicPremiumBps: 3_000,
      operatorPremiumShareBps: 9_000, requestTimeoutBlocks: 800,
    });
    const second = await requestRandomness(fixture, { numWords: 1 });
    const secondPinned = await coordinator.getRequest(second.requestId);
    await coordinator.setKeyService(keyHash, guardian.address, guardian.address,
      parseUnits("5", "gwei"), 900_000);
    await coordinator.setKeyActive(keyHash, false);
    expect(await coordinator.getRequest(first.requestId)).to.deep.equal(firstPinned);
    expect(await coordinator.getRequest(second.requestId)).to.deep.equal(secondPinned);
    expect(firstPinned.fulfiller).to.equal(fulfiller.address);
    expect(firstPinned.payee).to.equal(payee.address);
    expect(firstPinned.maxGasPriceWei).to.equal(MAX_GAS_PRICE);
    expect(firstPinned.verificationGasLimit).to.equal(VERIFICATION_GAS);
    expect(secondPinned.fulfiller).to.equal(outsider.address);
    expect(secondPinned.payee).to.equal(recipient.address);
    expect(secondPinned.maxGasPriceWei).to.equal(parseUnits("10", "gwei"));
    expect(secondPinned.verificationGasLimit).to.equal(800_000);
    expect(secondPinned.fulfillmentOverheadGas).to.equal(240_000);
    expect(secondPinned.premiumBps).to.equal(3_000);
    expect(secondPinned.minimumFeeWei).to.equal(parseEther("0.00002"));
    expect(secondPinned.operatorPremiumShareBps).to.equal(9_000);
    expect(secondPinned.expiresAtBlock - secondPinned.requestBlock).to.equal(800);

    await mineBlocks(CONFIRMATIONS);
    const firstProof = await buildProof(coordinator, first.requestId, first.preSeed);
    const secondProof = await buildProof(coordinator, second.requestId, second.preSeed);
    await expect(coordinator.connect(outsider).fulfillRandomWords(first.requestId, encodeProof(firstProof.proof)))
      .to.be.revertedWithCustomError(coordinator, "NotFulfiller");
    await expect(coordinator.connect(fulfiller).fulfillRandomWords(second.requestId, encodeProof(secondProof.proof)))
      .to.be.revertedWithCustomError(coordinator, "NotFulfiller");
    await expect(coordinator.connect(outsider).fulfillRandomWords(second.requestId, encodeProof(secondProof.proof), {
      gasPrice: parseUnits("11", "gwei"),
    })).to.be.revertedWithCustomError(coordinator, "FulfillmentGasPriceTooHigh");

    for (const [pending, proof, signer, pinned] of [
      [first, firstProof, fulfiller, firstPinned], [second, secondProof, outsider, secondPinned],
    ]) {
      // Both exceed the LATEST lane (5 gwei), but are valid under their pinned lane.
      const receipt = await (await coordinator.connect(signer).fulfillRandomWords(
        pending.requestId, encodeProof(proof.proof), { gasPrice: parseUnits("7", "gwei") },
      )).wait();
      const settlement = parseEvent(receipt, coordinator, "RequestSettled").args;
      expect(settlement.totalCharge).to.equal(
        settlement.networkCost * (10_000n + pinned.premiumBps) / 10_000n,
      );
      expect(settlement.operatorPayment).to.equal(settlement.networkCost
        + (settlement.totalCharge - settlement.networkCost) * pinned.operatorPremiumShareBps / 10_000n);
      expect(await coordinator.operatorCredits(pinned.payee)).to.equal(settlement.operatorPayment);
      expect((await coordinator.getRequest(pending.requestId)).randomness).to.equal(proof.output);
    }
    expect(await coordinator.operatorCredits(guardian.address)).to.equal(0);
    expect((await coordinator.subscriptions(fixture.subscriptionId)).reserved).to.equal(0);
  });

  it("isolates snapshots of separately registered keys and rejects cross-key proofs", async function () {
    const fixture = await deployFixture();
    const { coordinator, keyHash, fulfiller, payee, outsider, recipient } = fixture;
    const first = await requestRandomness(fixture, { numWords: 1 });
    const firstPinned = await coordinator.getRequest(first.requestId);
    const secondPrivateKey = `0x${"22".repeat(32)}`;
    const secondVerifier = await ethers.deployContract("Secp256k1ECVRFVerifier");
    const secondPublicKey = proofTools.publicKeyFor(secondPrivateKey);
    const secondKeyHash = await secondVerifier.keyHash(secondPublicKey);
    await coordinator.registerKey(secondKeyHash, await secondVerifier.getAddress(),
      ethers.AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [secondPublicKey]),
      outsider.address, recipient.address, MAX_GAS_PRICE, VERIFICATION_GAS);
    const second = await requestRandomness(fixture, { keyHash: secondKeyHash, numWords: 1 });
    await coordinator.setKeyService(keyHash, recipient.address, outsider.address, MAX_GAS_PRICE, 900_000);
    expect(await coordinator.getRequest(first.requestId)).to.deep.equal(firstPinned);
    const secondPinned = await coordinator.getRequest(second.requestId);
    expect(secondPinned.keyHash).to.equal(secondKeyHash);
    expect(secondPinned.verifier).to.equal(await secondVerifier.getAddress());
    expect(secondPinned.verifierCodeHash).to.equal(ethers.keccak256(
      await ethers.provider.getCode(await secondVerifier.getAddress()),
    ));
    expect(secondPinned.proofDataLength).to.equal(416);
    await mineBlocks(CONFIRMATIONS);
    const wrongProof = await buildProof(coordinator, second.requestId, second.preSeed);
    await expect(coordinator.connect(outsider).fulfillRandomWords(second.requestId, encodeProof(wrongProof.proof)))
      .to.be.revertedWithCustomError(secondVerifier, "InvalidKeyCommitment");
    const secondProof = proofTools.generateProof({
      privateKey: secondPrivateKey, actualSeed: await coordinator.requestSeed(second.requestId),
      preSeed: second.preSeed, nonce: PROOF_NONCE,
    });
    await coordinator.connect(outsider).fulfillRandomWords(second.requestId, encodeProof(secondProof.proof));
    const firstProof = await buildProof(coordinator, first.requestId, first.preSeed);
    await coordinator.connect(fulfiller).fulfillRandomWords(first.requestId, encodeProof(firstProof.proof));
    expect(await coordinator.operatorCredits(payee.address)).to.be.greaterThan(0);
    expect(await coordinator.operatorCredits(recipient.address)).to.be.greaterThan(0);
    expect(await coordinator.operatorCredits(outsider.address)).to.equal(0);
  });

  it("prunes only the finalized request, retaining shared configuration for later requests", async function () {
    const fixture = await deployFixture({ mockContext: true });
    const { coordinator, blockContext, fulfiller } = fixture;
    const first = await requestRandomness(fixture, { numWords: 1 });
    const firstPinned = await coordinator.getRequest(first.requestId);
    await blockContext.setBlockNumber(firstPinned.expiresAtBlock + 1n);
    await coordinator.expireRequest(first.requestId);
    await blockContext.setBlockNumber(firstPinned.expiresAtBlock + 50_001n);
    const second = await requestRandomness(fixture, { numWords: 1 });
    const secondPinned = await coordinator.getRequest(second.requestId);
    await coordinator.pruneRequest(first.requestId);
    await expect(coordinator.getRequest(first.requestId)).to.be.revertedWithCustomError(coordinator, "UnknownRequest");
    expect(await coordinator.getRequest(second.requestId)).to.deep.equal(secondPinned);
    await blockContext.setBlockHash(second.requestBlock, ethers.id("shared-version-after-prune"));
    await blockContext.setBlockNumber(second.requestBlock + 2n);
    const { proof } = await buildProof(coordinator, second.requestId, second.preSeed);
    await coordinator.connect(fulfiller).fulfillRandomWords(second.requestId, encodeProof(proof));
    expect((await coordinator.getRequest(second.requestId)).status).to.equal(2);
    expect((await coordinator.subscriptions(fixture.subscriptionId)).reserved).to.equal(0);
  });

  it("round-trips packed field bounds without truncation and fails closed on block overflow", async function () {
    const max64 = (1n << 64n) - 1n;
    const max96 = (1n << 96n) - 1n;
    const fixture = await deployFixture({ mockContext: true, initialContextBlock: max64 - 1_000_000n });
    const { coordinator, blockContext, subscriber, consumer, keyHash, fulfiller, payee } = fixture;
    await ethers.provider.send("hardhat_setBalance", [subscriber.address, ethers.toBeHex(1n << 150n)]);
    await coordinator.connect(subscriber).fundSubscription(1, { value: 1n << 130n });
    await coordinator.connect(subscriber).updateConsumer(1, await consumer.getAddress(), 2_500_000, 4);
    await coordinator.setKeyService(keyHash, fulfiller.address, payee.address, max64, 3_000_000);
    await coordinator.setPricing({
      minimumRequestFeeWei: max96, l1FeeReserveWei: max96,
      fulfillmentOverheadGas: 1_000_000, perWordGas: 100_000,
      publicPremiumBps: 10_000, operatorPremiumShareBps: 10_000, requestTimeoutBlocks: 1_000_000,
    });
    const pending = await requestRandomness(fixture, { callbackGasLimit: 2_500_000, confirmations: 200, numWords: 32 });
    const stored = await coordinator.getRequest(pending.requestId);
    expect(stored.consumer).to.equal(await consumer.getAddress());
    expect(stored.minimumFeeWei).to.equal(max96);
    expect(stored.requestBlock).to.equal(max64 - 1_000_000n);
    expect(stored.expiresAtBlock).to.equal(max64);
    expect(stored.maxGasPriceWei).to.equal(max64);
    expect(stored.confirmations).to.equal(200);
    expect(stored.callbackGasLimit).to.equal(2_500_000);
    expect(stored.verificationGasLimit).to.equal(3_000_000);
    expect(stored.numWords).to.equal(32);
    expect(stored.fulfillmentOverheadGas).to.equal(1_000_000);
    expect(stored.premiumBps).to.equal(10_000);
    expect(stored.operatorPremiumShareBps).to.equal(10_000);
    expect(stored.reservedPayment).to.equal(pending.reserve);
    expect(stored.reservedPayment).to.be.greaterThan(max96);
    expect(stored.status).to.equal(1);
    expect(stored.sponsored).to.equal(false);
    expect(stored.callbackSucceeded).to.equal(false);
    await blockContext.setBlockNumber(max64);
    const reservedBefore = (await coordinator.subscriptions(1)).reserved;
    const nonceBefore = await coordinator.consumerNonces(1, await consumer.getAddress());
    await expect(requestRandomness(fixture, { numWords: 1 }))
      .to.be.revertedWithCustomError(coordinator, "BlockNumberOverflow");
    expect((await coordinator.subscriptions(1)).reserved).to.equal(reservedBefore);
    expect(await coordinator.consumerNonces(1, await consumer.getAddress())).to.equal(nonceBefore);
    await blockContext.setBlockNumber(max64 + 1n);
    await coordinator.expireRequest(pending.requestId);
    expect((await coordinator.subscriptions(1)).reserved).to.equal(0);
  });

  it("reconstructs mixed-version reserves exactly while settling and expiring out of order", async function () {
    const fixture = await deployFixture({ mockContext: true });
    const { coordinator, consumer, subscriber, blockContext, keyHash, fulfiller, outsider, payee, recipient } = fixture;
    const consumerAddress = await consumer.getAddress();
    await coordinator.connect(subscriber).updateConsumer(1, consumerAddress, 300_000, 32);
    let state = 0x9715n;
    const next = () => { state = (state * 1_103_515_245n + 12_345n) % (1n << 31n); return state; };
    const pending = [];
    let outstanding = 0n;
    let charged = 0n;
    let sponsorCount = 0;
    const startingBalance = (await coordinator.subscriptions(1)).balance;

    for (let index = 0; index < 12; index += 1) {
      const config = {
        minimumRequestFeeWei: index % 3 === 0 ? parseEther("0.1") : next(),
        l1FeeReserveWei: next(), fulfillmentOverheadGas: 50_000 + Number(next() % 200_001n),
        perWordGas: Number(next() % 1_001n), publicPremiumBps: Number(next() % 10_001n),
        operatorPremiumShareBps: Number(next() % 10_001n), requestTimeoutBlocks: 257 + Number(next() % 1_000n),
      };
      const maxGasPriceWei = parseUnits("2", "gwei") + next();
      const verificationGasLimit = 300_000 + Number(next() % 1_800_001n);
      const signer = index % 3 === 0 ? outsider : fulfiller;
      const destination = index % 3 === 0 ? recipient : payee;
      await coordinator.setPricing(config);
      await coordinator.setKeyService(keyHash, signer.address, destination.address, maxGasPriceWei, verificationGasLimit);
      const overrideBps = Number(next() % 10_001n);
      const overrideEnabled = index % 3 === 1;
      await coordinator.setSubscriptionPremiumOverride(1, overrideBps, overrideEnabled);
      const sponsorBps = Number(next() % 10_001n);
      const waived = index % 4 === 0;
      await coordinator.setSponsorPolicy(consumerAddress, {
        subscriptionId: 1, validUntil: (await ethers.provider.getBlock("latest")).timestamp + 86_400,
        requestsPerEpoch: 100, maxPendingRequests: 32, maxCallbackGasLimit: 300_000,
        premiumBps: sponsorBps, waiveMinimumFee: waived,
      });
      const sponsored = index % 2 === 0;
      const premium = sponsored ? sponsorBps : overrideEnabled ? overrideBps : config.publicPremiumBps;
      const minimumFee = sponsored && waived ? 0n : config.minimumRequestFeeWei;
      const callbackGasLimit = 100_000 + Number(next() % 200_001n);
      const numWords = 1 + Number(next() % 8n);
      const gasUnits = BigInt(verificationGasLimit + callbackGasLimit + config.fulfillmentOverheadGas)
        + BigInt(config.perWordGas * numWords);
      const priced = (gasUnits * maxGasPriceWei + config.l1FeeReserveWei) * BigInt(10_000 + premium) / 10_000n;
      const expectedReserve = priced > minimumFee ? priced : minimumFee;
      const request = await requestRandomness(fixture, {
        subscriptionId: sponsored ? 0 : 1, callbackGasLimit, numWords,
      });
      expect(request.reserve).to.equal(expectedReserve);
      const pinned = await coordinator.getRequest(request.requestId);
      expect(pinned.reservedPayment).to.equal(expectedReserve);
      expect(pinned.expiresAtBlock).to.equal(request.requestBlock + BigInt(config.requestTimeoutBlocks));
      pending.push({ ...request, expectedReserve, pinned, signer, sponsored, finalized: false });
      outstanding += expectedReserve;
      if (sponsored) sponsorCount += 1;
      expect((await coordinator.subscriptions(1)).reserved).to.equal(outstanding);
    }

    // Every current configuration now differs from at least most queued requests.
    // Historical reads and the independent JS model must remain unchanged.
    for (const request of pending) {
      expect(await coordinator.getRequest(request.requestId)).to.deep.equal(request.pinned);
    }
    const assertLiabilities = async () => {
      const subscription = await coordinator.subscriptions(1);
      expect(subscription.reserved).to.equal(outstanding);
      expect(subscription.balance).to.equal(startingBalance - charged);
      expect((await coordinator.consumers(1, consumerAddress)).pendingRequests)
        .to.equal(pending.filter((request) => !request.finalized).length);
      expect((await coordinator.sponsorPolicies(consumerAddress)).pendingRequests).to.equal(sponsorCount);
      expect(await ethers.provider.getBalance(await coordinator.getAddress())).to.equal(
        subscription.balance + await coordinator.operatorCredits(payee.address)
          + await coordinator.operatorCredits(recipient.address) + await coordinator.treasuryCredits(),
      );
    };
    await blockContext.setBlockHash(1_000_000, ethers.id("pricing-version-fuzz-block"));
    await blockContext.setBlockNumber(1_000_002);
    for (const index of [10, 3, 8, 1, 6, 5]) {
      const request = pending[index];
      const { proof } = await buildProof(coordinator, request.requestId, request.preSeed);
      const receipt = await (await coordinator.connect(request.signer).fulfillRandomWords(
        request.requestId, encodeProof(proof), { gasPrice: parseUnits("1", "gwei"), gasLimit: 3_000_000 },
      )).wait();
      const settlement = parseEvent(receipt, coordinator, "RequestSettled").args;
      const priced = settlement.networkCost * (10_000n + request.pinned.premiumBps) / 10_000n;
      expect(settlement.totalCharge).to.equal(priced > request.pinned.minimumFeeWei ? priced : request.pinned.minimumFeeWei);
      expect(settlement.totalCharge).to.be.lessThanOrEqual(request.expectedReserve);
      charged += settlement.totalCharge;
      outstanding -= request.expectedReserve;
      request.finalized = true;
      if (request.sponsored) sponsorCount -= 1;
      expect((await coordinator.getRequest(request.requestId)).reservedPayment).to.equal(request.expectedReserve);
      await assertLiabilities();
    }
    await blockContext.setBlockNumber(1_002_000);
    for (const request of pending.toReversed().filter((item) => !item.finalized)) {
      await expect(coordinator.expireRequest(request.requestId))
        .to.emit(coordinator, "RequestExpiredAndReleased").withArgs(request.requestId, request.expectedReserve);
      outstanding -= request.expectedReserve;
      request.finalized = true;
      if (request.sponsored) sponsorCount -= 1;
      expect((await coordinator.getRequest(request.requestId)).reservedPayment).to.equal(request.expectedReserve);
      await assertLiabilities();
    }
    expect(outstanding).to.equal(0);
  });

  it("keeps expiry and prune boundaries pinned when current pricing becomes shorter or longer", async function () {
    const fixture = await deployFixture({ mockContext: true });
    const { coordinator, blockContext } = fixture;
    const first = await requestRandomness(fixture, { numWords: 1 });
    const firstPinned = await coordinator.getRequest(first.requestId);
    await coordinator.setPricing({ ...PRICING, requestTimeoutBlocks: 257 });
    const second = await requestRandomness(fixture, { numWords: 1 });
    const secondPinned = await coordinator.getRequest(second.requestId);
    await coordinator.setPricing({ ...PRICING, requestTimeoutBlocks: 1_000_000 });
    await blockContext.setBlockNumber(secondPinned.expiresAtBlock);
    await expect(coordinator.expireRequest(second.requestId)).to.be.revertedWithCustomError(coordinator, "RequestNotExpired");
    await blockContext.setBlockNumber(secondPinned.expiresAtBlock + 1n);
    await coordinator.expireRequest(second.requestId);
    await expect(coordinator.expireRequest(first.requestId)).to.be.revertedWithCustomError(coordinator, "RequestNotExpired");
    await blockContext.setBlockNumber(firstPinned.expiresAtBlock);
    await expect(coordinator.expireRequest(first.requestId)).to.be.revertedWithCustomError(coordinator, "RequestNotExpired");
    await blockContext.setBlockNumber(firstPinned.expiresAtBlock + 1n);
    await coordinator.expireRequest(first.requestId);
    const pruneAt = firstPinned.expiresAtBlock + await coordinator.PRUNE_DELAY_BLOCKS();
    await blockContext.setBlockNumber(pruneAt);
    await expect(coordinator.pruneRequest(first.requestId)).to.be.revertedWithCustomError(coordinator, "PruneTooEarly");
    await blockContext.setBlockNumber(pruneAt + 1n);
    await coordinator.pruneRequest(first.requestId);
    await expect(coordinator.getRequest(first.requestId)).to.be.revertedWithCustomError(coordinator, "UnknownRequest");
    expect((await coordinator.getRequest(second.requestId)).reservedPayment).to.equal(second.reserve);
  });

  it("blocks a late callback from pruning the request during a retry", async function () {
    const fixture = await deployFixture();
    const { coordinator, subscriber, subscriptionId, fulfiller, keyHash } = fixture;
    const malicious = await ethers.deployContract("MockReentrantPrunerConsumer", [
      await coordinator.getAddress(),
    ]);
    await malicious.waitForDeployment();
    await coordinator.connect(subscriber).addConsumer(
      subscriptionId,
      await malicious.getAddress(),
      CALLBACK_GAS,
      1,
    );
    const quote = await coordinator.quoteMaxPayment(
      keyHash,
      await malicious.getAddress(),
      subscriptionId,
      CALLBACK_GAS,
      1,
    );
    const requestCall = {
      keyHash,
      subscriptionId,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: quote,
    };
    const requestReceipt = await (await malicious.connect(subscriber).request(requestCall)).wait();
    const requested = parseEvent(requestReceipt, coordinator, "RandomWordsRequested");
    const requestId = requested.args.requestId;
    const preSeed = requested.args.preSeed;
    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    await coordinator.connect(fulfiller).fulfillRandomWords(requestId, encodeProof(proof));
    expect((await coordinator.getRequest(requestId)).callbackSucceeded).to.equal(false);

    const request = await coordinator.getRequest(requestId);
    const context = await coordinator.contextBlockNumber();
    const target = request.expiresAtBlock + await coordinator.PRUNE_DELAY_BLOCKS() + 1n;
    await ethers.provider.send("hardhat_mine", [ethers.toQuantity(target - context)]);
    await malicious.setFailCallback(false);
    expect(await coordinator.retryCallback.staticCall(requestId)).to.equal(true);
    await coordinator.retryCallback(requestId);

    expect(await malicious.pruneSucceeded()).to.equal(false);
    expect((await coordinator.getRequest(requestId)).callbackSucceeded).to.equal(true);
  });

  it("lets the guardian stop new demand while leaving fulfillment available", async function () {
    const fixture = await deployFixture();
    const {
      owner, guardian, subscriber, coordinator, consumer, keyHash, fulfiller,
    } = fixture;
    const pending = await requestRandomness(fixture, { numWords: 1 });
    await coordinator.connect(guardian).pauseRequests();
    const quote = await coordinator.quoteMaxPayment(
      keyHash,
      await consumer.getAddress(),
      fixture.subscriptionId,
      CALLBACK_GAS,
      1,
    );
    await expect(consumer.connect(subscriber).request({
      keyHash,
      subscriptionId: fixture.subscriptionId,
      requestConfirmations: CONFIRMATIONS,
      callbackGasLimit: CALLBACK_GAS,
      numWords: 1,
      maxPayment: quote,
    })).to.be.revertedWithCustomError(coordinator, "RequestsPaused");

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, pending.requestId, pending.preSeed);
    await coordinator.connect(fulfiller).fulfillRandomWords(pending.requestId, encodeProof(proof));
    await coordinator.connect(owner).unpauseRequests();
    expect(await coordinator.requestsPaused()).to.equal(false);
  });

  it("matches the documented reserve formula across callback and word-count boundaries", async function () {
    const fixture = await deployFixture();
    const { owner, subscriber, coordinator, consumer, keyHash, subscriptionId } = fixture;
    const consumerAddress = await consumer.getAddress();
    await coordinator.connect(subscriber).updateConsumer(
      subscriptionId,
      consumerAddress,
      2_500_000,
      4,
    );
    const cases = [
      [50_000, 1],
      [200_000, 2],
      [500_000, 8],
      [1_000_000, 16],
      [2_500_000, 32],
    ];
    for (const [callbackGas, numWords] of cases) {
      const gasUnits = BigInt(VERIFICATION_GAS + callbackGas + PRICING.fulfillmentOverheadGas)
        + BigInt(PRICING.perWordGas * numWords);
      const networkMaximum = gasUnits * MAX_GAS_PRICE + PRICING.l1FeeReserveWei;
      const priced = networkMaximum * 12_000n / 10_000n;
      const expected = priced < PRICING.minimumRequestFeeWei
        ? PRICING.minimumRequestFeeWei
        : priced;
      expect(await coordinator.quoteMaxPayment(
        keyHash,
        consumerAddress,
        subscriptionId,
        callbackGas,
        numWords,
      )).to.equal(expected);
    }

    const publicQuote = await coordinator.quoteMaxPayment(
      keyHash, consumerAddress, subscriptionId, CALLBACK_GAS, 1,
    );
    await coordinator.connect(owner).setSubscriptionPremiumOverride(subscriptionId, 1_000, true);
    const partnerQuote = await coordinator.quoteMaxPayment(
      keyHash, consumerAddress, subscriptionId, CALLBACK_GAS, 1,
    );
    expect(partnerQuote).to.be.lessThan(publicQuote);
  });

  it("preserves subscription and credit liabilities across a deterministic fuzz sequence", async function () {
    const fixture = await deployFixture();
    const {
      coordinator, consumer, fulfiller, payee, subscriptionId,
    } = fixture;
    let randomState = 0x5eed1234n;
    const next = () => {
      randomState = (1_103_515_245n * randomState + 12_345n) % (2n ** 31n);
      return randomState;
    };
    for (let iteration = 0; iteration < 12; iteration += 1) {
      const callbackGasLimit = 50_000 + Number(next() % 150_001n);
      const numWords = 1 + Number(next() % 8n);
      const pending = await requestRandomness(fixture, { callbackGasLimit, numWords });
      await mineBlocks(CONFIRMATIONS);
      const { proof } = await buildProof(coordinator, pending.requestId, pending.preSeed);
      await coordinator.connect(fulfiller).fulfillRandomWords(
        pending.requestId,
        encodeProof(proof),
      );

      const subscription = await coordinator.subscriptions(subscriptionId);
      const liabilities = subscription.balance
        + await coordinator.operatorCredits(payee.address)
        + await coordinator.treasuryCredits();
      expect(await ethers.provider.getBalance(await coordinator.getAddress())).to.equal(liabilities);
      expect(subscription.reserved).to.equal(0);
      expect((await coordinator.consumers(
        subscriptionId,
        await consumer.getAddress(),
      )).pendingRequests).to.equal(0);
    }
  });

  it("routes a threshold-BLS unique-signature adapter without changing subscriptions", async function () {
    const fixture = await deployFixture();
    const { coordinator, fulfiller, payee } = fixture;
    const backend = await ethers.deployContract("MockThresholdBLSBackend");
    await backend.waitForDeployment();
    const adapter = await ethers.deployContract("ThresholdBLSVerifierAdapter", [
      await backend.getAddress(),
    ]);
    await adapter.waitForDeployment();
    const groupPublicKey = `0x${"11".repeat(192)}`;
    const thresholdKeyHash = await adapter.keyHash(groupPublicKey);
    await coordinator.registerKey(
      thresholdKeyHash,
      await adapter.getAddress(),
      groupPublicKey,
      fulfiller.address,
      payee.address,
      MAX_GAS_PRICE,
      VERIFICATION_GAS,
    );

    const { requestId, preSeed } = await requestRandomness(fixture, {
      keyHash: thresholdKeyHash,
    });
    await mineBlocks(CONFIRMATIONS);
    const actualSeed = await coordinator.requestSeed(requestId);
    const messageDigest = await adapter.messageFor(thresholdKeyHash, actualSeed, preSeed);
    const message = ethers.solidityPacked(["bytes32"], [messageDigest]);
    const signatureDigest = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes", "bytes"],
        [groupPublicKey, message],
      ),
    );
    const signature = ethers.concat([signatureDigest, `0x${"00".repeat(64)}`]);
    const proofData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes"],
      [groupPublicKey, signature],
    );
    const expectedRandomness = await adapter.randomnessFor(messageDigest, signature);

    const forgedProofData = ethers.AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes"],
      [groupPublicKey, `0x${"00".repeat(96)}`],
    );
    await expect(
      coordinator.connect(fulfiller).fulfillRandomWords(requestId, forgedProofData),
    ).to.be.revertedWithCustomError(adapter, "InvalidProof");
    expect((await coordinator.getRequest(requestId)).status).to.equal(1);

    await expect(coordinator.connect(fulfiller).fulfillRandomWords(requestId, proofData))
      .to.emit(coordinator, "ProofVerified")
      .withArgs(requestId, thresholdKeyHash, expectedRandomness);
    expect((await coordinator.getRequest(requestId)).randomness).to.equal(expectedRandomness);
  });

  it("verifies an independent RFC 9380 BLS12-381 test vector through EIP-2537", async function () {
    const backend = await ethers.deployContract("BLS12381Backend");
    await backend.waitForDeployment();
    const adapter = await ethers.deployContract("ThresholdBLSVerifierAdapter", [
      await backend.getAddress(),
    ]);
    await adapter.waitForDeployment();
    const publicKey = "0x03cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a01a714f2edb74119a2f2b0d5a7c75ba902d163700a61bc224ededd8e63aef7be1aaf8e93d7a9718b047ccddb3eb5d68b0e5db2b6bfbb01c867749cadffca88b36c24f3012ba09fc4d3022c5c37dce0f977d3adb5d183c7477c442b1f04515273";
    const message = "0xeb26460c7495053b531c3d007789953c47874f3380635090554e0f68619bbbeb";
    const signature = "0x0d2c8bbc37170dbacc5e280a21d4e195cff5f32a19fd6a58633fa4e4670478b5fb39bc13dd8f8c4372c5a76191198ac50823ff37364b4060af65c7ec4dde05a428e4a444713680d95c34a4b109f112af1792643c742b75d85940c4bdcfdfbfa1";

    expect(await backend.validatePublicKey(publicKey)).to.equal(true);
    const keyHash = await adapter.keyHash(publicKey);
    expect(await adapter.validateKey(keyHash, publicKey)).to.equal(true);
    expect(await backend.validatePublicKey("0x")).to.equal(false);
    expect(await backend.validatePublicKey(`0x${"00".repeat(192)}`)).to.equal(false);
    expect(await backend.verify(publicKey, message, signature)).to.equal(true);
    const forged = `${signature.slice(0, -2)}${signature.endsWith("00") ? "01" : "00"}`;
    expect(await backend.verify(publicKey, message, forged)).to.equal(false);
  });

  it("verifies an off-chain 3-of-5 threshold aggregate through EIP-2537", async function () {
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const thresholdTools = await import("../operator/threshold-crypto.mjs");
    const backend = await ethers.deployContract("BLS12381Backend");
    await backend.waitForDeployment();
    const message = ethers.keccak256(ethers.toUtf8Bytes("threshold interoperability"));
    const messagePoint = bls.G1.hashToCurve(ethers.getBytes(message), {
      DST: thresholdTools.BLS_DST,
    });
    const coefficients = [123456789n, 99887766n, 44556677n];
    const scalarAt = (index) => coefficients.reduceRight(
      (value, coefficient) => (
        (value * BigInt(index) + coefficient) % thresholdTools.BLS_SCALAR_ORDER
      ),
      0n,
    );
    const wire = (point) => ethers.hexlify(point.toRawBytes(false));
    const groupPublicKey = wire(
      bls.G2.ProjectivePoint.BASE.multiply(coefficients[0]),
    );
    const shares = [1, 3, 5].map((index) => {
      const scalar = scalarAt(index);
      return {
        index,
        publicKey: wire(bls.G2.ProjectivePoint.BASE.multiply(scalar)),
        signature: wire(messagePoint.multiply(scalar)),
      };
    });
    const aggregate = thresholdTools.aggregateThresholdShares({
      message,
      groupPublicKey,
      threshold: 3,
      shares,
    });

    expect(await backend.validatePublicKey(groupPublicKey)).to.equal(true);
    expect(await backend.verify(groupPublicKey, message, aggregate.signature)).to.equal(true);
  });
});

const { parseEther } = require("ethers");
const { before, describe, it } = require("node:test");

let expect;
let ethers;

// Deliberately not one of Hardhat's transaction keys: proof and relayer keys are separate roles.
const VRF_PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";
const PROOF_NONCE = 0x123456789abcdefn;
const FEE = parseEther("0.000025");
const CALLBACK_GAS = 300_000;
const CONFIRMATIONS = 2;
const NUM_WORDS = 3;

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

async function deployFixture() {
  const [owner, operator, relayer, recipient] = await ethers.getSigners();
  const publicKey = proofTools.publicKeyFor(VRF_PRIVATE_KEY);

  const coordinatorFactory = await ethers.getContractFactory("ProofVRFCoordinator");
  const coordinator = await coordinatorFactory.deploy(owner.address);
  await coordinator.waitForDeployment();
  await coordinator.registerKey(publicKey, operator.address, FEE);
  const keyHash = await coordinator.keyHash(publicKey);

  const consumerFactory = await ethers.getContractFactory("ExampleVRFConsumer");
  const consumer = await consumerFactory.deploy(await coordinator.getAddress(), owner.address);
  await consumer.waitForDeployment();

  return { owner, operator, relayer, recipient, coordinator, consumer, publicKey, keyHash };
}

async function requestRandomness(coordinator, consumer, keyHash, overrides = {}) {
  const transaction = await consumer.request(
    keyHash,
    overrides.confirmations ?? CONFIRMATIONS,
    overrides.callbackGas ?? CALLBACK_GAS,
    overrides.numWords ?? NUM_WORDS,
    { value: overrides.value ?? FEE },
  );
  const receipt = await transaction.wait();
  const event = parseEvent(receipt, coordinator, "RandomWordsRequested");
  return { receipt, requestId: event.args.requestId, preSeed: event.args.preSeed };
}

async function buildProof(coordinator, requestId, preSeed, nonce = PROOF_NONCE) {
  const actualSeed = await coordinator.requestSeed(requestId);
  return proofTools.generateProof({
    privateKey: VRF_PRIVATE_KEY,
    actualSeed,
    preSeed,
    nonce,
  });
}

describe("ProofVRFCoordinator", function () {
  it("verifies a real ECVRF proof and delivers deterministic random words", async function () {
    const { operator, relayer, coordinator, consumer, keyHash } = await deployFixture();
    const { requestId, preSeed } = await requestRandomness(coordinator, consumer, keyHash);

    await expect(coordinator.requestSeed(requestId))
      .to.be.revertedWithCustomError(coordinator, "ConfirmationsPending");
    await mineBlocks(CONFIRMATIONS);

    const { proof, output } = await buildProof(coordinator, requestId, preSeed);
    await expect(coordinator.connect(relayer).fulfillRandomWords(requestId, proof))
      .to.emit(coordinator, "ProofVerified")
      .withArgs(requestId, keyHash, output)
      .and.to.emit(coordinator, "CallbackAttempted")
      .withArgs(requestId, 1, true);

    const request = await coordinator.requests(requestId);
    expect(request.fulfilled).to.equal(true);
    expect(request.callbackSucceeded).to.equal(true);
    expect(request.randomness).to.equal(output);
    expect(await coordinator.credits(operator.address)).to.equal(FEE);

    const expectedWords = Array.from({ length: NUM_WORDS }, (_, index) => BigInt(
      ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(
        ["uint256", "uint256"], [output, index],
      )),
    ));
    expect(await consumer.lastWords()).to.deep.equal(expectedWords);
    expect(await coordinator.randomWords(requestId)).to.deep.equal(expectedWords);
  });

  it("rejects a forged proof without consuming the request", async function () {
    const { relayer, coordinator, consumer, keyHash } = await deployFixture();
    const { requestId, preSeed } = await requestRandomness(coordinator, consumer, keyHash);
    await mineBlocks(CONFIRMATIONS);

    const { proof } = await buildProof(coordinator, requestId, preSeed);
    const forgedProof = { ...proof, c: proof.c + 1n };
    await expect(coordinator.connect(relayer).fulfillRandomWords(requestId, forgedProof))
      .to.revert(ethers);
    expect((await coordinator.requests(requestId)).fulfilled).to.equal(false);

    await coordinator.connect(relayer).fulfillRandomWords(requestId, proof);
    expect((await coordinator.requests(requestId)).fulfilled).to.equal(true);
  });

  it("persists verified randomness when the callback fails and retries permissionlessly", async function () {
    const { owner, relayer, coordinator, consumer, keyHash } = await deployFixture();
    await consumer.connect(owner).setRevertCallbacks(true);
    const { requestId, preSeed } = await requestRandomness(coordinator, consumer, keyHash);
    await mineBlocks(CONFIRMATIONS);
    const { proof, output } = await buildProof(coordinator, requestId, preSeed);

    await coordinator.connect(relayer).fulfillRandomWords(requestId, proof);
    let request = await coordinator.requests(requestId);
    expect(request.fulfilled).to.equal(true);
    expect(request.callbackSucceeded).to.equal(false);
    expect(request.callbackAttempts).to.equal(1);
    expect(request.randomness).to.equal(output);

    await consumer.connect(owner).setRevertCallbacks(false);
    await expect(coordinator.connect(relayer).retryCallback(requestId))
      .to.emit(coordinator, "CallbackAttempted")
      .withArgs(requestId, 2, true);
    request = await coordinator.requests(requestId);
    expect(request.callbackSucceeded).to.equal(true);
    expect(request.callbackAttempts).to.equal(2);
  });

  it("pins existing requests across key deactivation and rejects new requests", async function () {
    const { owner, coordinator, consumer, keyHash } = await deployFixture();
    const { requestId, preSeed } = await requestRandomness(coordinator, consumer, keyHash);
    await coordinator.connect(owner).setKeyActive(keyHash, false);

    await expect(consumer.request(keyHash, CONFIRMATIONS, CALLBACK_GAS, 1, { value: FEE }))
      .to.be.revertedWithCustomError(coordinator, "KeyInactive");

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    await coordinator.fulfillRandomWords(requestId, proof);
    expect((await coordinator.requests(requestId)).fulfilled).to.equal(true);
  });

  it("refunds an expired request to pull credit and cannot be fulfilled afterward", async function () {
    const { owner, recipient, coordinator, consumer, keyHash } = await deployFixture();
    const { requestId, preSeed } = await requestRandomness(coordinator, consumer, keyHash);
    await mineBlocks(257);

    await expect(coordinator.refundExpired(requestId))
      .to.emit(coordinator, "RequestRefunded")
      .withArgs(requestId, await consumer.getAddress(), FEE);
    expect(await coordinator.credits(await consumer.getAddress())).to.equal(FEE);

    const balanceBefore = await ethers.provider.getBalance(recipient.address);
    await consumer.connect(owner).withdrawRefund(recipient.address, FEE);
    expect(await ethers.provider.getBalance(recipient.address)).to.equal(balanceBefore + FEE);
    expect(await coordinator.credits(await consumer.getAddress())).to.equal(0);

    const request = await coordinator.requests(requestId);
    expect(request.refunded).to.equal(true);
    const dummyProof = proofTools.generateProof({
      privateKey: VRF_PRIVATE_KEY,
      actualSeed: 1n,
      preSeed,
      nonce: PROOF_NONCE,
    }).proof;
    await expect(coordinator.fulfillRandomWords(requestId, dummyProof))
      .to.be.revertedWithCustomError(coordinator, "RequestAlreadyFinalized");
  });

  it("enforces exact fees, request bounds, consumer-only callbacks, and pull withdrawals", async function () {
    const { operator, relayer, recipient, coordinator, consumer, keyHash } = await deployFixture();

    await expect(consumer.request(keyHash, CONFIRMATIONS, CALLBACK_GAS, 1, { value: FEE - 1n }))
      .to.be.revertedWithCustomError(coordinator, "FeeMismatch");
    await expect(consumer.request(keyHash, 0, CALLBACK_GAS, 1, { value: FEE }))
      .to.be.revertedWithCustomError(coordinator, "InvalidConfirmations");
    await expect(consumer.request(keyHash, CONFIRMATIONS, 0, 1, { value: FEE }))
      .to.be.revertedWithCustomError(coordinator, "InvalidCallbackGasLimit");
    await expect(consumer.request(keyHash, CONFIRMATIONS, CALLBACK_GAS, 0, { value: FEE }))
      .to.be.revertedWithCustomError(coordinator, "InvalidNumWords");
    await expect(consumer.connect(relayer).rawFulfillRandomWords(1, [1]))
      .to.be.revertedWithCustomError(consumer, "OnlyCoordinator");

    const { requestId, preSeed } = await requestRandomness(
      coordinator, consumer, keyHash, { numWords: 1 },
    );
    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, requestId, preSeed);
    await coordinator.connect(relayer).fulfillRandomWords(requestId, proof);

    const recipientBalance = await ethers.provider.getBalance(recipient.address);
    await expect(coordinator.connect(operator).withdrawCredits(recipient.address, FEE))
      .to.emit(coordinator, "CreditsWithdrawn")
      .withArgs(operator.address, recipient.address, FEE);
    expect(await ethers.provider.getBalance(recipient.address)).to.equal(recipientBalance + FEE);
    expect(await coordinator.credits(operator.address)).to.equal(0);
  });
});

describe("ProofVRFRouter", function () {
  async function deployRoutedFixture() {
    const base = await deployFixture();
    const routerFactory = await ethers.getContractFactory("ProofVRFRouter");
    const router = await routerFactory.deploy(base.owner.address);
    await router.waitForDeployment();
    await router.registerProvider(base.keyHash, await base.coordinator.getAddress());

    const consumerFactory = await ethers.getContractFactory("ExampleVRFConsumer");
    const consumer = await consumerFactory.deploy(await router.getAddress(), base.owner.address);
    await consumer.waitForDeployment();
    return { ...base, router, consumer };
  }

  async function requestRouted(coordinator, router, consumer, keyHash) {
    const transaction = await consumer.request(
      keyHash, CONFIRMATIONS, CALLBACK_GAS, NUM_WORDS, { value: FEE },
    );
    const receipt = await transaction.wait();
    const providerEvent = parseEvent(receipt, coordinator, "RandomWordsRequested");
    const routerEvent = parseEvent(receipt, router, "RandomWordsRouted");
    return {
      preSeed: providerEvent.args.preSeed,
      providerRequestId: providerEvent.args.requestId,
      requestId: routerEvent.args.requestId,
    };
  }

  it("keeps the consumer endpoint stable while routing a verified ECVRF result", async function () {
    const { relayer, coordinator, router, consumer, keyHash } = await deployRoutedFixture();
    const { requestId, providerRequestId, preSeed } = await requestRouted(
      coordinator, router, consumer, keyHash,
    );
    expect(await consumer.lastRequestId()).to.equal(requestId);

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(coordinator, providerRequestId, preSeed);
    await expect(coordinator.connect(relayer).fulfillRandomWords(providerRequestId, proof))
      .to.emit(router, "RandomnessReady")
      .withArgs(requestId, providerRequestId);

    expect((await router.requests(requestId)).randomnessReady).to.equal(true);
    expect(await consumer.lastWords()).to.deep.equal([]);
    const routedWords = await router.randomWords(requestId);

    await expect(router.connect(relayer).retryCallback(requestId))
      .to.emit(router, "CallbackAttempted")
      .withArgs(requestId, 1, true);
    expect(await consumer.lastWords()).to.deep.equal(routedWords);
    expect((await router.requests(requestId)).callbackSucceeded).to.equal(true);
  });

  it("never rebinds a key hash and only deactivates future routed requests", async function () {
    const { owner, coordinator, router, consumer, keyHash } = await deployRoutedFixture();
    const pending = await requestRouted(coordinator, router, consumer, keyHash);

    await expect(router.registerProvider(keyHash, await coordinator.getAddress()))
      .to.be.revertedWithCustomError(router, "DuplicateProvider");
    await router.connect(owner).setProviderActive(keyHash, false);
    await expect(consumer.request(keyHash, CONFIRMATIONS, CALLBACK_GAS, 1, { value: FEE }))
      .to.be.revertedWithCustomError(router, "ProviderInactive");

    await mineBlocks(CONFIRMATIONS);
    const { proof } = await buildProof(
      coordinator, pending.providerRequestId, pending.preSeed,
    );
    await coordinator.fulfillRandomWords(pending.providerRequestId, proof);
    expect((await router.requests(pending.requestId)).randomnessReady).to.equal(true);
  });

  it("recovers provider refunds into the original routed consumer's pull credit", async function () {
    const { owner, recipient, coordinator, router, consumer, keyHash } = await deployRoutedFixture();
    const pending = await requestRouted(coordinator, router, consumer, keyHash);
    await mineBlocks(257);

    // Permissionless callers may trigger the underlying refund first; the router still recovers it.
    await coordinator.refundExpired(pending.providerRequestId);
    expect(await coordinator.credits(await router.getAddress())).to.equal(FEE);
    await router.refundExpired(pending.requestId);
    expect(await coordinator.credits(await router.getAddress())).to.equal(0);
    expect(await router.credits(await consumer.getAddress())).to.equal(FEE);

    const balanceBefore = await ethers.provider.getBalance(recipient.address);
    await consumer.connect(owner).withdrawRefund(recipient.address, FEE);
    expect(await ethers.provider.getBalance(recipient.address)).to.equal(balanceBefore + FEE);
    expect(await router.credits(await consumer.getAddress())).to.equal(0);
  });

  it("cannot consume an older provider credit to refund a request before it expires", async function () {
    const { coordinator, router, consumer, keyHash } = await deployRoutedFixture();
    const expired = await requestRouted(coordinator, router, consumer, keyHash);
    await mineBlocks(257);
    await coordinator.refundExpired(expired.providerRequestId);

    const fresh = await requestRouted(coordinator, router, consumer, keyHash);
    await expect(router.refundExpired(fresh.requestId))
      .to.be.revertedWithCustomError(coordinator, "NotExpired");
    expect((await router.requests(fresh.requestId)).refunded).to.equal(false);
    expect(await coordinator.credits(await router.getAddress())).to.equal(FEE);

    await router.refundExpired(expired.requestId);
    expect((await router.requests(expired.requestId)).refunded).to.equal(true);
    expect(await coordinator.credits(await router.getAddress())).to.equal(0);
  });
});

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { createHash } = require("node:crypto");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");

// Public test key only. No external network, wallet or environment secrets are used.
const TEST_KEY = `0x${"11".repeat(32)}`;
const PROOF_TYPE = "tuple(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv)";
const GAS_PRICE = 1_000_000_000n;
const PRICING = {
  minimumRequestFeeWei: 10_000_000_000_000n,
  l1FeeReserveWei: 20_000_000_000_000n,
  fulfillmentOverheadGas: 150_000,
  perWordGas: 500,
  publicPremiumBps: 2_000,
  operatorPremiumShareBps: 5_000,
  requestTimeoutBlocks: 600,
};

function eventFrom(receipt, contract, name) {
  return receipt.logs.map((log) => {
    try { return contract.interface.parseLog(log); } catch { return null; }
  }).find((event) => event?.name === name);
}

describe("Compact Coordinator deterministic gas benchmark", () => {
  it("measures identical proof inputs, cold and steady-state callbacks, sponsorship and retries", async () => {
    const { network } = await import("hardhat");
    const { ethers } = await network.create();
    const proofTools = await import("../operator/proof.mjs");
    const [owner, guardian, fulfiller, payee, subscriber] = await ethers.getSigners();
    const context = await ethers.deployContract("MockBlockContext", [1_000_000]);
    const store = await ethers.deployContract("BlockhashStore", [await context.getAddress()]);
    const fee = await ethers.deployContract("ZeroL1FeeCalculator");
    const verifier = await ethers.deployContract("Secp256k1ECVRFVerifier");
    const pk = proofTools.publicKeyFor(TEST_KEY);
    const keyHash = await verifier.keyHash(pk);
    const coordinator = await ethers.deployContract("VRFServiceCoordinatorV3", [
      owner.address, guardian.address, await store.getAddress(), await fee.getAddress(),
      PRICING, {
        keyHash, verifier: await verifier.getAddress(),
        keyData: ethers.AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [pk]),
        fulfiller: fulfiller.address, payee: payee.address,
        maxGasPriceWei: 20n * GAS_PRICE, verificationGasLimit: 2_100_000,
      },
    ]);
    const consumer = await ethers.deployContract("ExampleVRFServiceConsumer", [
      await coordinator.getAddress(), subscriber.address,
    ]);
    await coordinator.connect(subscriber).createSubscription();
    await coordinator.connect(subscriber).fundSubscription(1, { value: ethers.parseEther("2") });
    await coordinator.connect(subscriber).addConsumer(1, await consumer.getAddress(), 2_000_000, 4);
    await context.setBlockHash(1_000_000, ethers.id("fixed-gas-benchmark-block"));
    // Set epoch explicitly so sponsor first-use measurements do not depend on wall clock.
    await ethers.provider.send("evm_setNextBlockTimestamp", [2_500_000_000]);
    await coordinator.setSponsorPolicy(await consumer.getAddress(), {
      subscriptionId: 1, validUntil: 2_500_086_400, requestsPerEpoch: 100,
      maxPendingRequests: 4, maxCallbackGasLimit: 2_000_000,
      premiumBps: 0, waiveMinimumFee: true,
    });

    const rows = [];
    async function measure(name, { words = 1, sponsored = false, fail = false } = {}) {
      await context.setBlockNumber(1_000_000);
      await consumer.connect(subscriber).setRevertCallbacks(fail);
      const callbackGas = words === 32 ? 1_000_000 : 100_000;
      const subscriptionId = sponsored ? 0 : 1;
      const reserve = await coordinator.quoteMaxPayment(
        keyHash, await consumer.getAddress(), subscriptionId, callbackGas, words,
      );
      const requestReceipt = await (await consumer.connect(subscriber).request({
        keyHash, subscriptionId, requestConfirmations: 2,
        callbackGasLimit: callbackGas, numWords: words, maxPayment: reserve,
      }, { gasPrice: GAS_PRICE })).wait();
      const request = eventFrom(requestReceipt, coordinator, "CompactRequestState");
      await context.setBlockNumber(1_000_002);
      const witness = request.args.request.toObject();
      const actualSeed = await coordinator.requestSeed(witness);
      const { proof, output } = proofTools.generateProof({
        privateKey: TEST_KEY, actualSeed, preSeed: witness.preSeed,
        nonce: 0x123456789abcdefn,
      });
      const proofData = ethers.AbiCoder.defaultAbiCoder().encode([PROOF_TYPE], [proof]);
      const receipt = await (await coordinator.connect(fulfiller).fulfillRandomWords(
        witness, proofData, { gasPrice: GAS_PRICE, gasLimit: 3_000_000 },
      )).wait();
      const settled = eventFrom(receipt, coordinator, "RequestSettled");
      const finalWitness = eventFrom(receipt, coordinator, "CompactRequestState").args.request.toObject();
      const stored = await coordinator.getRequest(finalWitness);
      assert.equal(stored.randomness, output);
      assert.equal(stored.callbackSucceeded, !fail);
      assert.equal(stored.status, 2n);
      assert.equal((await coordinator.subscriptions(1)).reserved, 0n);
      const row = {
        name, requestId: request.args.requestId.toString(), proofHash: ethers.keccak256(proofData),
        fulfillmentCalldataBytes: (coordinator.interface.encodeFunctionData("fulfillRandomWords", [witness, proofData]).length - 2) / 2,
        requestGas: Number(requestReceipt.gasUsed), fulfillmentGas: Number(receipt.gasUsed),
        totalGas: Number(requestReceipt.gasUsed + receipt.gasUsed),
        billedGas: Number(settled.args.networkCost / GAS_PRICE),
        customerCostWei: (requestReceipt.gasUsed * GAS_PRICE + settled.args.totalCharge).toString(),
      };
      if (fail) {
        await consumer.connect(subscriber).setRevertCallbacks(false);
        const retried = await (await coordinator.retryCallback(finalWitness, {
          gasPrice: GAS_PRICE, gasLimit: 3_000_000,
        })).wait();
        row.retryGas = Number(retried.gasUsed);
        const retriedWitness = eventFrom(retried, coordinator, "CompactRequestState").args.request.toObject();
        assert.equal((await coordinator.getRequest(retriedWitness)).callbackSucceeded, true);
      }
      rows.push(row);
    }

    let snapshot = await ethers.provider.send("evm_snapshot", []);
    for (const [name, options] of [
      ["public-1-word-cold", {}], ["public-1-word-steady", {}],
      ["public-3-words", { words: 3 }], ["public-32-words", { words: 32 }],
    ]) await measure(name, options);
    await ethers.provider.send("evm_revert", [snapshot]);
    snapshot = await ethers.provider.send("evm_snapshot", []);
    await measure("sponsored-1-word-cold", { sponsored: true });
    await measure("sponsored-1-word-steady", { sponsored: true });
    await ethers.provider.send("evm_revert", [snapshot]);
    snapshot = await ethers.provider.send("evm_snapshot", []);
    await measure("failed-callback-and-retry", { fail: true });
    await ethers.provider.send("evm_revert", [snapshot]);

    // Measure the less frequent paths too: request savings must not hide a shift
    // into an unreported expiry, cleanup or administrative transaction.
    const reserve = await coordinator.quoteMaxPayment(keyHash, await consumer.getAddress(), 1, 100_000, 1);
    const expiryRequest = eventFrom(await (await consumer.connect(subscriber).request({
      keyHash, subscriptionId: 1, requestConfirmations: 2,
      callbackGasLimit: 100_000, numWords: 1, maxPayment: reserve,
    }, { gasPrice: GAS_PRICE })).wait(), coordinator, "CompactRequestState");
    const expiryRequestId = expiryRequest.args.request.toObject();
    const getRequestGas = Number(await coordinator.getRequest.estimateGas(expiryRequestId));
    const balanceBeforeExpiry = (await coordinator.subscriptions(1)).balance;
    await context.setBlockNumber(1_000_601);
    const expiryReceipt = await (await coordinator.expireRequest(expiryRequestId, { gasPrice: GAS_PRICE })).wait();
    assert.equal(eventFrom(expiryReceipt, coordinator, "RequestExpiredAndReleased").args.releasedPayment, reserve);
    assert.equal((await coordinator.subscriptions(1)).reserved, 0n);
    assert.equal((await coordinator.subscriptions(1)).balance, balanceBeforeExpiry);
    await context.setBlockNumber(1_050_601);
    const pruneReceipt = await (await coordinator.pruneRequest(eventFrom(expiryReceipt, coordinator, "CompactRequestState").args.request.toObject(), { gasPrice: GAS_PRICE })).wait();
    const pricingReceipt = await (await coordinator.setPricing(PRICING, { gasPrice: GAS_PRICE })).wait();
    const keyServiceReceipt = await (await coordinator.setKeyService(keyHash, fulfiller.address, payee.address,
      20n * GAS_PRICE, 2_100_000, { gasPrice: GAS_PRICE })).wait();

    const sourceHash = createHash("sha256").update(readFileSync(
      join(__dirname, "../contracts/VRFServiceCoordinatorV3.sol"),
    )).digest("hex");
    const runtimeCodeBytes = ((await ethers.provider.getCode(await coordinator.getAddress())).length - 2) / 2;
    assert.ok(runtimeCodeBytes <= 24_576, "coordinator exceeds EIP-170 runtime code limit");
    const report = {
      format: "proof-vrf-compact-local-gas-v1", sourceSha256: sourceHash,
      baseSourceSha256: createHash("sha256").update(readFileSync(join(__dirname, "../contracts/VRFServiceCoordinatorBase.sol"))).digest("hex"),
      runtimeCodeBytes,
      coordinatorAbiSha256: createHash("sha256").update(JSON.stringify(
        coordinator.interface.fragments.map((fragment) => fragment.format("json")).sort(),
      )).digest("hex"),
      environment: "solc 0.8.24, viaIR, optimizer runs 500, Hardhat local, fixed mock L2 hash, zero L1 fee",
      // The mock block context itself has execution overhead: these are comparable
      // local measurements, NOT mainnet fee quotes or a receipt gas calibration.
      coordinatorDeploymentGas: Number((await coordinator.deploymentTransaction().wait()).gasUsed),
      lifecycle: {
        getRequestGas, expireGas: Number(expiryReceipt.gasUsed), pruneGas: Number(pruneReceipt.gasUsed),
        setPricingGas: Number(pricingReceipt.gasUsed), setKeyServiceGas: Number(keyServiceReceipt.gasUsed),
      },
      rows,
    };
    console.log(`VRF_COMPACT_GAS_BENCHMARK ${JSON.stringify(report)}`);

    const baseline = JSON.parse(readFileSync(join(__dirname, "../docs/evidence/gas-optimized-v2-round2-2026-09-03.json"), "utf8"));
    for (const row of rows) {
      const previous = baseline.rows.find((item) => item.name === row.name);
      assert.ok(previous, `missing round-two baseline: ${row.name}`);
      assert.equal(row.requestId, previous.requestId, "request derivation changed");
      assert.equal(row.proofHash, previous.proofHash, "benchmark proof input changed");
      assert.ok(row.requestGas <= previous.requestGas - 55_000, `${row.name}: compact request gas regression`);
      assert.ok(row.totalGas <= previous.totalGas - 75_000, `${row.name}: compact total gas regression`);
      assert.ok(BigInt(row.customerCostWei) < BigInt(previous.customerCostWei), `${row.name}: compact billing regression`);
      if (row.retryGas !== undefined) assert.ok(row.retryGas <= previous.retryGas + 25_000, "compact retry gas regression");
    }
    assert.ok(report.lifecycle.expireGas <= baseline.lifecycle.expireGas + 10_000, "compact expiry gas regression");
    assert.ok(report.lifecycle.pruneGas <= baseline.lifecycle.pruneGas, "compact prune gas regression");
    assert.ok(report.coordinatorDeploymentGas <= baseline.coordinatorDeploymentGas + 400_000, "compact deployment gas regression");
  });
});

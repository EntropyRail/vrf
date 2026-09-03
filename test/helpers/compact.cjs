const assert = require("node:assert/strict");
const TEST_KEY = `0x${"11".repeat(32)}`;
const PROOF_TYPE = "tuple(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv)";
const PRICING = {
  minimumRequestFeeWei: 10_000_000_000_000n, l1FeeReserveWei: 20_000_000_000_000n,
  fulfillmentOverheadGas: 150_000, perWordGas: 500, publicPremiumBps: 2_000,
  operatorPremiumShareBps: 5_000, requestTimeoutBlocks: 600,
};
function event(receipt, contract, name) {
  const found = receipt.logs.map((log) => {
    try { return contract.interface.parseLog(log); } catch { return null; }
  }).find((item) => item?.name === name);
  assert.ok(found, `missing ${name}`);
  return found.args;
}
function state(receipt, coordinator) {
  const parsed = event(receipt, coordinator, "CompactRequestState");
  return { witness: parsed.request.toObject(), requestId: parsed.requestId, receipt };
}
async function fixture(options = {}) {
  const { network } = await import("hardhat");
  const { ethers } = await network.create();
  const proofTools = await import("../../operator/proof.mjs");
  const [owner, guardian, fulfiller, payee, subscriber, outsider] = await ethers.getSigners();
  const context = options.nativeContext ? await ethers.deployContract("EVMBlockContext")
    : await ethers.deployContract("MockBlockContext", [1_000_000]);
  const store = await ethers.deployContract("BlockhashStore", [await context.getAddress()]);
  const fee = await ethers.deployContract(options.mutableFee ? "MockL1FeeCalculator" : "ZeroL1FeeCalculator");
  const verifier = await ethers.deployContract("Secp256k1ECVRFVerifier");
  const pk = proofTools.publicKeyFor(TEST_KEY);
  const keyHash = await verifier.keyHash(pk);
  const constructorArgs = [owner.address, guardian.address, await store.getAddress(), await fee.getAddress(), PRICING, {
    keyHash, verifier: await verifier.getAddress(),
    keyData: ethers.AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [pk]),
    fulfiller: fulfiller.address, payee: payee.address,
    maxGasPriceWei: 20_000_000_000n, verificationGasLimit: 2_100_000,
  }];
  const coordinator = await ethers.deployContract("VRFServiceCoordinatorV3", constructorArgs);
  const consumer = await ethers.deployContract("ExampleVRFServiceConsumer", [await coordinator.getAddress(), subscriber.address]);
  await coordinator.connect(subscriber).createSubscription();
  await coordinator.connect(subscriber).fundSubscription(1, { value: ethers.parseEther("2") });
  await coordinator.connect(subscriber).addConsumer(1, await consumer.getAddress(), 2_000_000, 32);
  if (!options.nativeContext) await context.setBlockHash(1_000_000, ethers.id("compact-test-l2-block"));
  async function request(overrides = {}) {
    const params = { keyHash, subscriptionId: 1, requestConfirmations: 2, callbackGasLimit: 100_000, numWords: 1, ...overrides };
    params.maxPayment ??= await coordinator.quoteMaxPayment(params.keyHash, await consumer.getAddress(), params.subscriptionId, params.callbackGasLimit, params.numWords);
    const receipt = await (await consumer.connect(subscriber).request(params)).wait();
    return state(receipt, coordinator);
  }
  async function proof(witness) {
    const actualSeed = await coordinator.requestSeed(witness);
    const result = proofTools.generateProof({ privateKey: TEST_KEY, actualSeed, preSeed: witness.preSeed, nonce: 0x123456789abcdefn });
    return { ...result, actualSeed, proofData: ethers.AbiCoder.defaultAbiCoder().encode([PROOF_TYPE], [result.proof]) };
  }
  async function fulfill(witness, signer = fulfiller) {
    const generated = await proof(witness);
    const receipt = await (await coordinator.connect(signer).fulfillRandomWords(witness, generated.proofData, { gasLimit: 3_000_000, gasPrice: 1_000_000_000n })).wait();
    return { ...state(receipt, coordinator), ...generated };
  }
  return { ethers, owner, guardian, fulfiller, payee, subscriber, outsider, context, store, fee, verifier, keyHash, coordinator, consumer, constructorArgs, proofTools, request, proof, fulfill };
}
module.exports = { fixture, state, event, PRICING, TEST_KEY, PROOF_TYPE };

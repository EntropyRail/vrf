const { existsSync, readFileSync, writeFileSync } = require("node:fs");

async function main() {
  const { network } = await import("hardhat");
  const { ethers } = await network.create();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 46630 && process.env.VRF_ALLOW_LOCAL_CANARY !== "true") {
    throw new Error("internal no-value canary is restricted to Robinhood testnet chain 46630");
  }
  const manifestPath = process.env.VRF_DEPLOYMENT_MANIFEST;
  const verificationPath = process.env.VRF_DEPLOYMENT_VERIFICATION_REPORT;
  const canaryPath = process.env.VRF_CANARY_MANIFEST;
  if (!manifestPath || !verificationPath || !canaryPath) {
    throw new Error("VRF_DEPLOYMENT_MANIFEST, VRF_DEPLOYMENT_VERIFICATION_REPORT, and VRF_CANARY_MANIFEST are required");
  }
  if (existsSync(canaryPath)) throw new Error("canary manifest already exists; use a new path");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const verification = JSON.parse(readFileSync(verificationPath, "utf8"));
  if (manifest.format !== "robinhood-proof-vrf-deployment/v1"
      || Number(manifest.chainId) !== chainId
      || verification.format !== "robinhood-proof-vrf-deployment-verification/v1"
      || verification.status !== "pass"
      || Number(verification.chainId) !== chainId
      || verification.gitCommit !== manifest.gitCommit
      || verification.coordinator?.toLowerCase()
        !== manifest.contracts.coordinator.address.toLowerCase()) {
    throw new Error("a matching passing deployment verification report is required");
  }
  const [baseCanaryOwner] = await ethers.getSigners();
  if (!baseCanaryOwner) throw new Error("VRF_DEPLOYER_PRIVATE_KEY must provide the canary signer");
  const canaryOwner = new ethers.NonceManager(baseCanaryOwner);
  const canaryOwnerAddress = await canaryOwner.getAddress();
  const coordinatorAddress = manifest.contracts.coordinator.address;
  const coordinator = await ethers.getContractAt(
    "VRFServiceCoordinatorV2",
    coordinatorAddress,
    canaryOwner,
  );
  if (ethers.keccak256(await ethers.provider.getCode(coordinatorAddress))
      !== manifest.contracts.coordinator.runtimeCodeHash) {
    throw new Error("coordinator runtime code does not match the deployment manifest");
  }

  const consumerFactory = await ethers.getContractFactory(
    "ExampleVRFServiceConsumer",
    canaryOwner,
  );
  const consumer = await consumerFactory.deploy(coordinatorAddress, canaryOwnerAddress);
  await consumer.waitForDeployment();
  const consumerDeployment = consumer.deploymentTransaction();
  const consumerReceipt = await consumerDeployment.wait();
  const subscriptionId = await coordinator.nextSubscriptionId();
  const createReceipt = await (await coordinator.createSubscription()).wait();
  const callbackGasLimit = Number(process.env.VRF_CANARY_CALLBACK_GAS_LIMIT || "300000");
  const numWords = Number(process.env.VRF_CANARY_NUM_WORDS || "3");
  const confirmations = Number(process.env.VRF_CANARY_CONFIRMATIONS || "2");
  const consumerReceiptConfig = await (await coordinator.addConsumer(
    subscriptionId,
    await consumer.getAddress(),
    callbackGasLimit,
    4,
  )).wait();
  const quotedPayment = await coordinator.quoteMaxPayment(
    manifest.keyHash,
    await consumer.getAddress(),
    subscriptionId,
    callbackGasLimit,
    numWords,
  );
  const funding = process.env.VRF_CANARY_FUNDING_WEI
    ? BigInt(process.env.VRF_CANARY_FUNDING_WEI)
    : quotedPayment;
  if (funding < quotedPayment) throw new Error("VRF_CANARY_FUNDING_WEI is below the quoted reserve");
  const fundReceipt = await (await coordinator.fundSubscription(
    subscriptionId,
    { value: funding },
  )).wait();
  const requestReceipt = await (await consumer.request({
    keyHash: manifest.keyHash,
    subscriptionId,
    requestConfirmations: confirmations,
    callbackGasLimit,
    numWords,
    maxPayment: quotedPayment,
  })).wait();
  const requestId = await consumer.lastRequestId();
  const canary = {
    format: "robinhood-proof-vrf-testnet-canary/v1",
    generatedAt: new Date().toISOString(),
    status: "awaiting-operator-fulfillment",
    noValueScope: "Robinhood testnet only; no production application or user funds",
    chainId,
    gitCommit: manifest.gitCommit,
    coordinator: coordinatorAddress,
    keyHash: manifest.keyHash,
    canaryOwner: canaryOwnerAddress,
    consumer: {
      address: await consumer.getAddress(),
      transactionHash: consumerDeployment.hash,
      blockNumber: consumerReceipt.blockNumber,
      runtimeCodeHash: ethers.keccak256(await ethers.provider.getCode(await consumer.getAddress())),
    },
    subscriptionId: subscriptionId.toString(),
    fundedWei: funding.toString(),
    requestId: requestId.toString(),
    transactions: {
      createSubscription: createReceipt.hash,
      fundSubscription: fundReceipt.hash,
      addConsumer: consumerReceiptConfig.hash,
      request: requestReceipt.hash,
    },
  };
  writeFileSync(canaryPath, `${JSON.stringify(canary, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  process.stdout.write(`${JSON.stringify(canary, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

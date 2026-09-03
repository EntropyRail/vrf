const { execFileSync } = require("node:child_process");
const { existsSync, readFileSync, renameSync, writeFileSync } = require("node:fs");

function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function atomicWrite(path, value) {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

function integer(name, fallback) {
  const value = process.env[name] ?? fallback;
  if (value === undefined || !/^\d+$/.test(value)) throw new Error(`${name} must be an integer`);
  return BigInt(value);
}

async function main() {
  const { network } = await import("hardhat");
  const { ethers } = await network.create();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 31337 && chainId !== 46630 && chainId !== 4663) {
    throw new Error(`refusing unsupported chain ${chainId}`);
  }
  if (chainId === 4663 && process.env.VRF_ALLOW_MAINNET !== "I_UNDERSTAND_MAINNET_RISK") {
    throw new Error("mainnet deployment requires VRF_ALLOW_MAINNET=I_UNDERSTAND_MAINNET_RISK");
  }

  const [baseDeployer] = await ethers.getSigners();
  if (!baseDeployer) throw new Error("VRF_DEPLOYER_PRIVATE_KEY did not provide a signer");
  const deployer = chainId === 31337 ? baseDeployer : new ethers.NonceManager(baseDeployer);
  const deployerAddress = await deployer.getAddress();
  const deployContract = async (name, args = []) => {
    const factory = await ethers.getContractFactory(name, deployer);
    return factory.deploy(...args);
  };
  const owner = ethers.getAddress(required("VRF_OWNER"));
  const guardian = ethers.getAddress(required("VRF_GUARDIAN"));
  const fulfiller = ethers.getAddress(required("VRF_FULFILLER"));
  const payee = ethers.getAddress(required("VRF_PAYEE"));
  const publicKey = [BigInt(required("VRF_PUBLIC_KEY_X")), BigInt(required("VRF_PUBLIC_KEY_Y"))];
  const { secp256k1 } = await import("@noble/curves/secp256k1");
  secp256k1.ProjectivePoint.fromAffine({ x: publicKey[0], y: publicKey[1] }).assertValidity();

  for (const [name, address] of Object.entries({ owner, guardian, fulfiller, payee })) {
    if (!ethers.isAddress(address) || address === ethers.ZeroAddress) {
      throw new Error(`${name} must be a nonzero address`);
    }
  }
  let governanceSafe = null;
  let timelockDelaySeconds = null;
  if (chainId !== 31337) {
    if ((await ethers.provider.getCode(owner)) === "0x") {
      throw new Error("VRF_OWNER must be a deployed VRFAdminTimelock on public networks");
    }
    const timelock = new ethers.Contract(owner, [
      "function owner() view returns (address)",
      "function delay() view returns (uint64)",
      "function MIN_DELAY() view returns (uint64)",
    ], ethers.provider);
    const [safeAddress, delay, minimumDelay] = await Promise.all([
      timelock.owner(), timelock.delay(), timelock.MIN_DELAY(),
    ]);
    governanceSafe = safeAddress;
    timelockDelaySeconds = delay.toString();
    if ((await ethers.provider.getCode(governanceSafe)) === "0x") {
      throw new Error("VRFAdminTimelock owner must be a deployed Safe/multisig");
    }
    if (delay < minimumDelay || delay < 43_200n) {
      throw new Error("VRFAdminTimelock delay must be at least 12 hours");
    }
    const timelockManifestPath = required("VRF_TIMELOCK_MANIFEST");
    const timelockManifest = JSON.parse(readFileSync(timelockManifestPath, "utf8"));
    if (timelockManifest.format !== "robinhood-proof-vrf-timelock-deployment/v1"
        || Number(timelockManifest.chainId) !== chainId
        || timelockManifest.timelock.toLowerCase() !== owner.toLowerCase()
        || timelockManifest.multisig.toLowerCase() !== governanceSafe.toLowerCase()
        || String(timelockManifest.delaySeconds) !== delay.toString()
        || timelockManifest.runtimeCodeHash.toLowerCase()
          !== ethers.keccak256(await ethers.provider.getCode(owner)).toLowerCase()) {
      throw new Error("VRF_TIMELOCK_MANIFEST does not match the deployed timelock and Safe");
    }
  }
  if (new Set([owner, guardian, fulfiller, payee]
    .map((address) => address.toLowerCase())).size !== 4) {
    throw new Error("VRF_OWNER, VRF_GUARDIAN, VRF_FULFILLER, and VRF_PAYEE must be distinct");
  }
  const manifestPath = process.env.VRF_DEPLOYMENT_MANIFEST;
  if (chainId !== 31337 && !manifestPath) {
    throw new Error("VRF_DEPLOYMENT_MANIFEST is required on public networks");
  }
  if (manifestPath && existsSync(manifestPath)
      && process.env.VRF_OVERWRITE_MANIFEST !== "true") {
    throw new Error("deployment manifest already exists; use a new path");
  }
  let gitCommit = "local-uncommitted";
  try {
    gitCommit = execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8", stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (chainId !== 31337
        && execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()) {
      throw new Error("public deployment requires a clean Git worktree");
    }
  } catch (error) {
    if (chainId !== 31337) throw error;
  }

  const pricing = {
    minimumRequestFeeWei: integer("VRF_MINIMUM_REQUEST_FEE_WEI", "10000000000000"),
    l1FeeReserveWei: integer("VRF_L1_FEE_RESERVE_WEI", "500000000000000"),
    fulfillmentOverheadGas: integer("VRF_FULFILLMENT_OVERHEAD_GAS", "150000"),
    perWordGas: integer("VRF_PER_WORD_GAS", "500"),
    publicPremiumBps: integer("VRF_PUBLIC_PREMIUM_BPS", "2000"),
    operatorPremiumShareBps: integer("VRF_OPERATOR_PREMIUM_SHARE_BPS", "5000"),
    requestTimeoutBlocks: integer("VRF_REQUEST_TIMEOUT_BLOCKS", "7200"),
  };
  if (chainId === 4663) {
    for (const name of [
      "VRF_MINIMUM_REQUEST_FEE_WEI",
      "VRF_L1_FEE_RESERVE_WEI",
      "VRF_MAX_GAS_PRICE_WEI",
    ]) required(name);
  }

  const manifest = {
    format: "robinhood-proof-vrf-deployment/v1",
    status: "deploying",
    generatedAt: new Date().toISOString(),
    chainId,
    gitCommit,
    build: {
      node: process.version,
      solc: "0.8.24",
      optimizer: { enabled: true, runs: 500 },
      viaIR: true,
      evmVersion: "shanghai",
    },
    deployer: deployerAddress,
    configuredOwner: owner,
    configuredOwnerRuntimeCodeHash: ethers.keccak256(await ethers.provider.getCode(owner)),
    governanceSafe,
    timelockDelaySeconds,
    guardian,
    fulfiller,
    payee,
    contracts: {},
    sourceVerification: { status: "pending", url: null },
  };
  const checkpoint = async (name, contract) => {
    const address = await contract.getAddress();
    const deployment = contract.deploymentTransaction();
    const receipt = await deployment.wait();
    manifest.contracts[name] = {
      address,
      transactionHash: deployment.hash,
      blockNumber: receipt.blockNumber,
      runtimeCodeHash: ethers.keccak256(await ethers.provider.getCode(address)),
    };
    manifest.updatedAt = new Date().toISOString();
    if (manifestPath) atomicWrite(manifestPath, manifest);
  };

  const blockContext = await deployContract(
    chainId === 31337 ? "EVMBlockContext" : "ArbitrumBlockContext",
  );
  await blockContext.waitForDeployment();
  await checkpoint("blockContext", blockContext);
  const blockhashStore = await deployContract("BlockhashStore", [
    await blockContext.getAddress(),
  ]);
  await blockhashStore.waitForDeployment();
  await checkpoint("blockhashStore", blockhashStore);
  const l1FeeCalculator = await deployContract("ArbitrumL1FeeCalculator");
  await l1FeeCalculator.waitForDeployment();
  await checkpoint("l1FeeCalculator", l1FeeCalculator);
  const verifier = await deployContract("Secp256k1ECVRFVerifier");
  await verifier.waitForDeployment();
  await checkpoint("verifier", verifier);

  const keyHash = await verifier.keyHash(publicKey);
  const keyData = ethers.AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [publicKey]);
  const maxGasPriceWei = integer("VRF_MAX_GAS_PRICE_WEI", "20000000000");
  const verificationGasLimit = integer("VRF_VERIFICATION_GAS_LIMIT", "2100000");

  const coordinator = await deployContract("VRFServiceCoordinatorV2", [
    owner,
    guardian,
    await blockhashStore.getAddress(),
    await l1FeeCalculator.getAddress(),
    pricing,
    {
      keyHash,
      verifier: await verifier.getAddress(),
      keyData,
      fulfiller,
      payee,
      maxGasPriceWei,
      verificationGasLimit,
    },
  ]);
  await coordinator.waitForDeployment();
  await checkpoint("coordinator", coordinator);

  Object.assign(manifest, {
    status: "deployed",
    ownershipStatus: "timelock-is-owner-at-deployment",
    keyRegistrationMode: "constructor-atomic",
    keyHash,
    publicKey: publicKey.map(String),
    keyConfig: {
      maxGasPriceWei: maxGasPriceWei.toString(),
      verificationGasLimit: verificationGasLimit.toString(),
      proofDataLength: Number(await verifier.proofLength()),
    },
    keyRegistrationTransactionHash: coordinator.deploymentTransaction().hash,
    pricing: Object.fromEntries(Object.entries(pricing).map(([key, value]) => [key, value.toString()])),
    updatedAt: new Date().toISOString(),
  });
  if (manifestPath) atomicWrite(manifestPath, manifest);
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

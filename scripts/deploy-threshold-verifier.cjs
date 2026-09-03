const { execFileSync } = require("node:child_process");
const { existsSync, renameSync, writeFileSync } = require("node:fs");

function atomicWrite(path, value) {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

async function main() {
  const { network } = await import("hardhat");
  const { ethers } = await network.create();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (![31337, 46630, 4663].includes(chainId)) {
    throw new Error(`refusing unsupported chain ${chainId}`);
  }
  if (chainId === 4663 && process.env.VRF_ALLOW_MAINNET !== "I_UNDERSTAND_MAINNET_RISK") {
    throw new Error("mainnet deployment requires VRF_ALLOW_MAINNET=I_UNDERSTAND_MAINNET_RISK");
  }
  const manifestPath = process.env.VRF_THRESHOLD_VERIFIER_MANIFEST;
  if (chainId !== 31337 && !manifestPath) {
    throw new Error("VRF_THRESHOLD_VERIFIER_MANIFEST is required on public networks");
  }
  if (manifestPath && existsSync(manifestPath)) {
    throw new Error("threshold verifier manifest already exists; use a new path");
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

  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error("VRF_DEPLOYER_PRIVATE_KEY did not provide a signer");
  const manifest = {
    format: "robinhood-proof-vrf-threshold-verifier-deployment/v1",
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
    deployer: deployer.address,
    contracts: {},
    precompileInterop: { status: "pending" },
    sourceVerification: { status: "pending", urls: {} },
  };
  if (manifestPath) atomicWrite(manifestPath, manifest);
  const capture = async (name, contract) => {
    const address = await contract.getAddress();
    const transaction = contract.deploymentTransaction();
    const receipt = await transaction.wait();
    manifest.contracts[name] = {
      address,
      transactionHash: transaction.hash,
      blockNumber: receipt.blockNumber,
      runtimeCodeHash: ethers.keccak256(await ethers.provider.getCode(address)),
    };
    manifest.updatedAt = new Date().toISOString();
    if (manifestPath) atomicWrite(manifestPath, manifest);
  };

  const backend = await ethers.deployContract("BLS12381Backend");
  await backend.waitForDeployment();
  await capture("backend", backend);
  const adapter = await ethers.deployContract("ThresholdBLSVerifierAdapter", [
    await backend.getAddress(),
  ]);
  await adapter.waitForDeployment();
  await capture("adapter", adapter);

  const { bls12_381: bls } = await import("@noble/curves/bls12-381");
  const secret = 42n;
  const message = ethers.getBytes(`0x${"a5".repeat(32)}`);
  const groupPublicKey = ethers.hexlify(
    bls.G2.ProjectivePoint.BASE.multiply(secret).toRawBytes(false),
  );
  const signature = ethers.hexlify(
    bls.G1.hashToCurve(message, {
      DST: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
    }).multiply(secret).toRawBytes(false),
  );
  if (!await backend.validatePublicKey(groupPublicKey)
      || !await backend.verify(groupPublicKey, message, signature)) {
    throw new Error("BLS12-381 precompile interoperability probe failed on this chain");
  }
  const keyHash = await adapter.keyHash(groupPublicKey);
  if (!await adapter.validateKey(keyHash, groupPublicKey)) {
    throw new Error("threshold adapter key-validation probe failed");
  }

  Object.assign(manifest, {
    status: "deployed-pending-source-verification",
    proofDataLength: Number(await adapter.proofLength()),
    precompileInterop: {
      status: "pass",
      publicKeyValidation: true,
      hashToCurveAndPairing: true,
    },
    updatedAt: new Date().toISOString(),
  });
  if (manifestPath) {
    atomicWrite(manifestPath, manifest);
  }
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

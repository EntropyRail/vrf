const { execFileSync } = require("node:child_process");
const { existsSync, writeFileSync } = require("node:fs");

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
  const multisig = process.env.VRF_GOVERNANCE_MULTISIG;
  if (!multisig || !ethers.isAddress(multisig) || multisig === ethers.ZeroAddress) {
    throw new Error("VRF_GOVERNANCE_MULTISIG must be a nonzero address");
  }
  if (chainId !== 31337 && (await ethers.provider.getCode(multisig)) === "0x") {
    throw new Error("VRF_GOVERNANCE_MULTISIG must be a deployed contract on public networks");
  }
  const delay = BigInt(process.env.VRF_TIMELOCK_DELAY_SECONDS || "86400");
  const manifestPath = process.env.VRF_TIMELOCK_MANIFEST;
  if (chainId !== 31337 && !manifestPath) {
    throw new Error("VRF_TIMELOCK_MANIFEST is required on public networks");
  }
  if (manifestPath && existsSync(manifestPath)) {
    throw new Error("timelock deployment manifest already exists; use a new path");
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
  const timelock = await ethers.deployContract("VRFAdminTimelock", [multisig, delay]);
  await timelock.waitForDeployment();
  const deployment = timelock.deploymentTransaction();
  const receipt = await deployment.wait();
  const address = await timelock.getAddress();
  const manifest = {
    format: "robinhood-proof-vrf-timelock-deployment/v1",
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
    multisig,
    delaySeconds: delay.toString(),
    timelock: address,
    transactionHash: deployment.hash,
    blockNumber: receipt.blockNumber,
    runtimeCodeHash: ethers.keccak256(await ethers.provider.getCode(address)),
  };
  if (manifestPath) {
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
  }
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

#!/usr/bin/env node
import { readFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import {
  Contract,
  Interface,
  JsonRpcProvider,
  getAddress,
  keccak256,
} from "ethers";
import { validateGroupManifest } from "../operator/threshold-group.mjs";

const COORDINATOR_ABI = [
  "function owner() view returns (address)",
  "function keyExists(bytes32 keyHash) view returns (bool)",
  "function registerKey(bytes32 keyHash,address verifier,bytes keyData,address fulfiller,address payee,uint64 maxGasPriceWei,uint32 verificationGasLimit)",
];
const ADAPTER_ABI = [
  "function keyHash(bytes groupPublicKey) view returns (bytes32)",
  "function proofLength() view returns (uint32)",
];
const TIMELOCK_ABI = [
  "function owner() view returns (address)",
  "function delay() view returns (uint64)",
  "function MIN_DELAY() view returns (uint64)",
  "function nonce() view returns (uint256)",
  "function hashOperation(uint256 operationNonce,address target,uint256 value,bytes data) view returns (bytes32)",
  "function schedule(address target,uint256 value,bytes data) returns (bytes32 operationId)",
  "function execute(uint256 operationNonce,address target,uint256 value,bytes data) returns (bytes result)",
];

function readJson(path, name) {
  if (!path) throw new Error(`${name} path is required`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function unsigned(value, name, maximum) {
  if (!/^\d+$/.test(String(value))) throw new Error(`${name} must be an unsigned integer`);
  const parsed = BigInt(value);
  if (parsed > maximum) throw new Error(`${name} exceeds its contract field`);
  return parsed;
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      "rpc-url": { type: "string" },
      coordinator: { type: "string" },
      timelock: { type: "string" },
      manifest: { type: "string" },
      previous: { type: "string" },
      "trusted-previous-hash": { type: "string" },
      "verifier-manifest": { type: "string" },
      "verifier-verification-report": { type: "string" },
      "coordinator-verification-report": { type: "string" },
      fulfiller: { type: "string" },
      payee: { type: "string" },
      "max-gas-price-wei": { type: "string" },
      "verification-gas-limit": { type: "string", default: "2900000" },
    },
    strict: true,
  });
  const provider = new JsonRpcProvider(values["rpc-url"]);
  const network = await provider.getNetwork();
  const manifest = readJson(values.manifest, "threshold group manifest");
  const previousManifest = values.previous
    ? readJson(values.previous, "previous threshold manifest")
    : undefined;
  const group = validateGroupManifest(manifest, {
    previousManifest,
    trustedPreviousManifestHash: values["trusted-previous-hash"],
  });
  if (network.chainId !== BigInt(group.manifest.chainId)) {
    throw new Error("threshold manifest chainId does not match the RPC");
  }
  const verifierManifest = readJson(values["verifier-manifest"], "threshold verifier manifest");
  const verifierVerification = readJson(
    values["verifier-verification-report"],
    "threshold verifier verification report",
  );
  if (verifierManifest.format !== "robinhood-proof-vrf-threshold-verifier-deployment/v1"
      || BigInt(verifierManifest.chainId) !== network.chainId
      || verifierManifest.precompileInterop?.status !== "pass") {
    throw new Error("threshold verifier deployment manifest is invalid or has no precompile pass");
  }
  if (verifierVerification.format
        !== "robinhood-proof-vrf-threshold-verifier-verification/v1"
      || verifierVerification.status !== "pass"
      || BigInt(verifierVerification.chainId) !== network.chainId
      || verifierVerification.gitCommit !== verifierManifest.gitCommit) {
    throw new Error("a matching passing threshold verifier verification report is required");
  }
  const adapterAddress = getAddress(verifierManifest.contracts.adapter.address);
  if (adapterAddress.toLowerCase() !== group.manifest.verifierAdapter.toLowerCase()) {
    throw new Error("group manifest is not bound to the deployed threshold adapter");
  }
  if (verifierVerification.adapter.toLowerCase() !== adapterAddress.toLowerCase()) {
    throw new Error("threshold verifier verification report is for a different adapter");
  }
  const adapterCode = await provider.getCode(adapterAddress);
  if (adapterCode === "0x"
      || keccak256(adapterCode) !== verifierManifest.contracts.adapter.runtimeCodeHash) {
    throw new Error("threshold adapter runtime code does not match the deployment manifest");
  }
  const adapter = new Contract(adapterAddress, ADAPTER_ABI, provider);
  const [onchainKeyHash, proofLength] = await Promise.all([
    adapter.keyHash(group.manifest.groupPublicKey),
    adapter.proofLength(),
  ]);
  if (onchainKeyHash.toLowerCase() !== group.keyHash.toLowerCase() || Number(proofLength) !== 416) {
    throw new Error("threshold adapter key hash or proof length is incompatible");
  }

  const coordinatorAddress = getAddress(values.coordinator);
  const timelockAddress = getAddress(values.timelock);
  const fulfiller = getAddress(values.fulfiller);
  const payee = getAddress(values.payee);
  if (new Set([timelockAddress, fulfiller, payee].map((item) => item.toLowerCase())).size !== 3) {
    throw new Error("timelock, fulfiller, and payee must be distinct");
  }
  const maxGasPriceWei = unsigned(
    values["max-gas-price-wei"],
    "max-gas-price-wei",
    (1n << 64n) - 1n,
  );
  const verificationGasLimit = unsigned(
    values["verification-gas-limit"],
    "verification-gas-limit",
    (1n << 32n) - 1n,
  );
  if (verificationGasLimit < 100_000n || verificationGasLimit > 3_000_000n) {
    throw new Error("verification-gas-limit must be within the Coordinator 100000..3000000 range");
  }
  const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
  const [owner, existing] = await Promise.all([
    coordinator.owner(),
    coordinator.keyExists(group.keyHash),
  ]);
  if (owner.toLowerCase() !== timelockAddress.toLowerCase()) {
    throw new Error("coordinator owner is not the supplied timelock");
  }
  if (existing) throw new Error("threshold key is already registered");

  const coordinatorVerification = readJson(
    values["coordinator-verification-report"],
    "Coordinator deployment verification report",
  );
  if (coordinatorVerification.format !== "robinhood-proof-vrf-deployment-verification/v1"
      || coordinatorVerification.status !== "pass"
      || BigInt(coordinatorVerification.chainId) !== network.chainId
      || coordinatorVerification.coordinator.toLowerCase() !== coordinatorAddress.toLowerCase()) {
    throw new Error("a matching passing Coordinator deployment verification report is required");
  }

  const coordinatorInterface = new Interface(COORDINATOR_ABI);
  const registerData = coordinatorInterface.encodeFunctionData("registerKey", [
    group.keyHash,
    adapterAddress,
    group.manifest.groupPublicKey,
    fulfiller,
    payee,
    maxGasPriceWei,
    verificationGasLimit,
  ]);
  const timelock = new Contract(timelockAddress, TIMELOCK_ABI, provider);
  const [governanceSafe, currentNonce, timelockDelay, minimumDelay] = await Promise.all([
    timelock.owner(),
    timelock.nonce(),
    timelock.delay(),
    timelock.MIN_DELAY(),
  ]);
  if ((await provider.getCode(governanceSafe)) === "0x"
      || timelockDelay < minimumDelay || timelockDelay < 43_200n) {
    throw new Error("timelock must have at least 12 hours delay and be owned by a deployed Safe");
  }
  const operationNonce = currentNonce + 1n;
  const operationId = await timelock.hashOperation(
    operationNonce,
    coordinatorAddress,
    0,
    registerData,
  );
  const timelockInterface = new Interface(TIMELOCK_ABI);
  process.stdout.write(`${JSON.stringify({
    format: "robinhood-proof-vrf-threshold-registration-plan/v1",
    generatedAt: new Date().toISOString(),
    chainId: network.chainId.toString(),
    manifestHash: group.manifestHash,
    keyHash: group.keyHash,
    adapter: adapterAddress,
    coordinator: coordinatorAddress,
    fulfiller,
    payee,
    governanceSafe,
    timelockDelaySeconds: timelockDelay.toString(),
    operationNonce: operationNonce.toString(),
    operationId,
    scheduleSafeTransaction: {
      to: timelockAddress,
      value: "0",
      data: timelockInterface.encodeFunctionData(
        "schedule",
        [coordinatorAddress, 0, registerData],
      ),
    },
    permissionlessExecuteTransactionAfterDelay: {
      to: timelockAddress,
      value: "0",
      data: timelockInterface.encodeFunctionData(
        "execute",
        [operationNonce, coordinatorAddress, 0, registerData],
      ),
    },
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.shortMessage || error.message || String(error)}\n`);
  process.exitCode = 1;
});

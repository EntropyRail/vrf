#!/usr/bin/env node
import process from "node:process";
import { parseArgs } from "node:util";
import {
  Contract,
  JsonRpcProvider,
  Wallet,
  formatEther,
  getAddress,
  keccak256,
  parseEther,
} from "ethers";
import pg from "pg";
import { createProofProvider } from "./proof-provider.mjs";
import { isMain } from "./entrypoint.mjs";
import { normalizeRpcUrls, rpcOriginCount } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";

const { Client } = pg;
const COORDINATOR_ABI = [
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function guardian() view returns (address)",
  "function blockhashStore() view returns (address)",
  "function l1FeeCalculator() view returns (address)",
  "function l1FeeCalculatorCodeHash() view returns (bytes32)",
  "function getKey(bytes32 keyHash) view returns ((address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,bool exists,bool active) config)",
];
const TIMELOCK_ABI = [
  "function owner() view returns (address)",
  "function delay() view returns (uint64)",
  "function MIN_DELAY() view returns (uint64)",
];
const STORE_ABI = [
  "function blockContext() view returns (address)",
  "function blockContextCodeHash() view returns (bytes32)",
];

function safeUrl(value, kind) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${kind} URL is invalid`);
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
  if (kind === "RPC" && parsed.protocol !== "https:"
      && !(loopback && parsed.protocol === "http:")) {
    throw new Error("remote RPC endpoints must use HTTPS");
  }
  if (kind === "PostgreSQL") {
    if (!/^postgres(?:ql)?:$/.test(parsed.protocol)) {
      throw new Error("database URL must use postgresql://");
    }
    const sslMode = parsed.searchParams.get("sslmode");
    if (!loopback && !["require", "verify-ca", "verify-full"].includes(sslMode)) {
      throw new Error("remote PostgreSQL requires sslmode=require, verify-ca, or verify-full");
    }
  }
  return parsed;
}

function positiveInteger(value, name, fallback, minimum = 0) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) {
    throw new Error(`${name} must be an integer of at least ${minimum}`);
  }
  return parsed;
}

function minimumRelayerBalance(value) {
  return parseEther(value ?? "0.002");
}

function optionsFrom(argv) {
  return parseArgs({
    args: argv,
    options: {
      coordinator: { type: "string" },
      "from-block": { type: "string" },
      keystore: { type: "string" },
      "prover-url": { type: "string" },
      "threshold-manifest": { type: "string" },
      "threshold-previous-manifest": { type: "string" },
      "threshold-trusted-previous-hash": { type: "string" },
      "threshold-client-cert": { type: "string" },
      "threshold-client-key": { type: "string" },
      "threshold-ca": { type: "string" },
      "proof-key-hash": { type: "string" },
      "prover-client-cert": { type: "string" },
      "prover-client-key": { type: "string" },
      "prover-ca": { type: "string" },
      "expected-chain-id": { type: "string", default: "46630" },
      "minimum-rpc-count": { type: "string", default: "2" },
      "minimum-relayer-balance-eth": { type: "string", default: "0.002" },
      "prover-timeout-ms": { type: "string", default: "15000" },
    },
    strict: true,
  }).values;
}

export async function checkReadiness(options) {
  const coordinatorAddress = getAddress(options.coordinator);
  const deploymentBlock = positiveInteger(options["from-block"], "from-block");
  const expectedChainId = BigInt(options["expected-chain-id"]);
  const minimumRpcCount = positiveInteger(
    options["minimum-rpc-count"],
    "minimum-rpc-count",
    2,
    1,
  );
  const allowSharedRpcOrigin = process.env.VRF_ALLOW_SHARED_RPC_ORIGIN === "true"
    && expectedChainId === 46630n
    && !options["threshold-manifest"];
  const rpcUrls = normalizeRpcUrls(readSecret("VRF_RPC_URLS"), {
    minimum: minimumRpcCount,
    label: "readiness",
    allowSharedOrigin: allowSharedRpcOrigin,
  });

  const rpcStates = await Promise.all(rpcUrls.map(async (rpcUrl) => {
    const provider = new JsonRpcProvider(rpcUrl);
    const [network, head] = await Promise.all([provider.getNetwork(), provider.getBlockNumber()]);
    if (network.chainId !== expectedChainId) {
      throw new Error(`RPC returned chain ${network.chainId}; expected ${expectedChainId}`);
    }
    return { provider, head };
  }));
  const heads = rpcStates.map(({ head }) => head);
  if (Math.max(...heads) - Math.min(...heads) > 8) {
    throw new Error("RPC heads differ by more than eight blocks");
  }
  if (deploymentBlock > Math.min(...heads)) throw new Error("from-block is above an RPC head");
  const provider = rpcStates[0].provider;

  const [coordinatorCode, databaseUrl] = await Promise.all([
    provider.getCode(coordinatorAddress),
    Promise.resolve(readSecret("VRF_DATABASE_URL", { required: true })),
  ]);
  if (coordinatorCode === "0x") throw new Error("coordinator has no runtime code");
  const database = safeUrl(databaseUrl, "PostgreSQL");
  const databaseClient = new Client({
    connectionString: database.toString(),
    application_name: "proof-vrf-readiness",
    connectionTimeoutMillis: 10_000,
  });
  let postgresVersion;
  try {
    await databaseClient.connect();
    const result = await databaseClient.query("SHOW server_version_num");
    postgresVersion = Number(result.rows[0].server_version_num);
    if (!Number.isSafeInteger(postgresVersion) || postgresVersion < 140000) {
      throw new Error("PostgreSQL 14 or newer is required");
    }
  } finally {
    await databaseClient.end().catch(() => {});
  }

  const proverUrl = options["prover-url"] || process.env.VRF_PROVER_URL;
  if ([options.keystore, proverUrl, options["threshold-manifest"]].filter(Boolean).length !== 1) {
    throw new Error("configure exactly one of --keystore, --prover-url, or --threshold-manifest");
  }
  const proofProvider = await createProofProvider({
    keyPath: options.keystore,
    password: readSecret("VRF_KEY_PASSWORD"),
    proverUrl,
    bearerToken: options["threshold-manifest"]
      ? readSecret("VRF_THRESHOLD_NODE_TOKEN")
      : readSecret("VRF_PROVER_BEARER_TOKEN"),
    timeoutMs: positiveInteger(options["prover-timeout-ms"], "prover-timeout-ms", 15_000, 100),
    expectedKeyHash: options["proof-key-hash"],
    proverClientCertificatePath: options["prover-client-cert"],
    proverClientKeyPath: options["prover-client-key"],
    proverCaCertificatePath: options["prover-ca"],
    thresholdManifestPath: options["threshold-manifest"],
    previousManifestPath: options["threshold-previous-manifest"],
    trustedPreviousManifestHash: options["threshold-trusted-previous-hash"],
    clientCertificatePath: options["threshold-client-cert"],
    clientKeyPath: options["threshold-client-key"],
    caCertificatePath: options["threshold-ca"],
  });
  const relayer = new Wallet(readSecret("VRF_TX_PRIVATE_KEY", { required: true }), provider);
  if (proofProvider.proofKeyAddress
      && relayer.address.toLowerCase() === proofProvider.proofKeyAddress.toLowerCase()) {
    throw new Error("proof key and relayer key must be different");
  }

  const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
  const [owner, pendingOwner, guardian, blockhashStore, l1FeeCalculator, pinnedL1CodeHash, key] =
    await Promise.all([
      coordinator.owner(),
      coordinator.pendingOwner(),
      coordinator.guardian(),
      coordinator.blockhashStore(),
      coordinator.l1FeeCalculator(),
      coordinator.l1FeeCalculatorCodeHash(),
      coordinator.getKey(proofProvider.keyHash),
    ]);
  const timelock = new Contract(owner, TIMELOCK_ABI, provider);
  const store = new Contract(blockhashStore, STORE_ABI, provider);
  const [
    ownerCode,
    blockhashCode,
    l1Code,
    verifierCode,
    relayerBalance,
    governanceSafe,
    timelockDelay,
    minimumTimelockDelay,
    blockContext,
    pinnedBlockContextCodeHash,
  ] = await Promise.all([
    provider.getCode(owner),
    provider.getCode(blockhashStore),
    provider.getCode(l1FeeCalculator),
    provider.getCode(key.verifier),
    provider.getBalance(relayer.address),
    timelock.owner(),
    timelock.delay(),
    timelock.MIN_DELAY(),
    store.blockContext(),
    store.blockContextCodeHash(),
  ]);
  const [governanceSafeCode, blockContextCode] = await Promise.all([
    provider.getCode(governanceSafe),
    provider.getCode(blockContext),
  ]);
  if (ownerCode === "0x" || timelockDelay < minimumTimelockDelay || timelockDelay < 43_200n) {
    throw new Error("coordinator owner must be a deployed timelock with at least 12 hours delay");
  }
  if (governanceSafeCode === "0x") {
    throw new Error("timelock owner must be a deployed governance Safe/multisig");
  }
  if (pendingOwner !== "0x0000000000000000000000000000000000000000") {
    throw new Error("coordinator ownership transfer has not been accepted");
  }
  if (blockhashCode === "0x" || blockContextCode === "0x"
      || l1Code === "0x" || verifierCode === "0x") {
    throw new Error("a coordinator dependency has no runtime code");
  }
  if (keccak256(blockContextCode) !== pinnedBlockContextCodeHash) {
    throw new Error("block context code hash changed");
  }
  if (keccak256(l1Code) !== pinnedL1CodeHash) throw new Error("L1 fee calculator code hash changed");
  if (keccak256(verifierCode) !== key.verifierCodeHash) throw new Error("verifier code hash changed");
  if (!key.exists || !key.active) throw new Error("proof key is missing or inactive");
  if (Number(key.proofDataLength) !== 416) throw new Error("registered proof length is not 416 bytes");
  if (key.fulfiller.toLowerCase() !== relayer.address.toLowerCase()) {
    throw new Error("relayer is not the configured fulfiller");
  }
  const roles = [owner, guardian, key.fulfiller, key.payee].map((address) => address.toLowerCase());
  if (new Set(roles).size !== roles.length) {
    throw new Error("timelock, guardian, fulfiller, and payee must be distinct roles");
  }
  const minimumBalance = minimumRelayerBalance(options["minimum-relayer-balance-eth"]);
  if (relayerBalance < minimumBalance) {
    throw new Error(`relayer balance ${formatEther(relayerBalance)} ETH is below the minimum`);
  }

  return {
    status: rpcOriginCount(rpcUrls) === rpcUrls.length ? "ready" : "ready-degraded",
    chainId: expectedChainId.toString(),
    rpcCount: rpcUrls.length,
    rpcOriginCount: rpcOriginCount(rpcUrls),
    rpcDiversity: rpcOriginCount(rpcUrls) === rpcUrls.length ? "independent-origins" : "shared-origin",
    rpcHeadMinimum: Math.min(...heads),
    rpcHeadMaximum: Math.max(...heads),
    postgresVersion,
    coordinator: coordinatorAddress,
    owner,
    governanceSafe,
    timelockDelaySeconds: timelockDelay.toString(),
    guardian,
    keyHash: proofProvider.keyHash,
    proofProvider: proofProvider.mode,
    relayer: relayer.address,
    relayerBalanceEth: formatEther(relayerBalance),
    deploymentBlock,
  };
}

async function main() {
  const report = await checkReadiness(optionsFrom(process.argv.slice(2)));
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.shortMessage || error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({
  minimumRelayerBalance,
  optionsFrom,
  positiveInteger,
  safeUrl,
});

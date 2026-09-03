#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { Contract, JsonRpcProvider, getAddress, keccak256 } from "ethers";
import { isMain } from "./entrypoint.mjs";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";
import { canonicalJson } from "./threshold-group.mjs";

const ABI = [
  "event RandomWordsRequested(bytes32 indexed keyHash,uint256 indexed requestId,address indexed consumer,uint256 subscriptionId,uint256 preSeed,uint256 requestBlock,uint256 expiresAtBlock,uint32 callbackGasLimit,uint32 numWords,uint256 reservedPayment,bool sponsored)",
  "event ProofVerified(uint256 indexed requestId,bytes32 indexed keyHash,uint256 randomness)",
  "event CallbackAttempted(uint256 indexed requestId,uint32 indexed attempt,bool success)",
  "event RequestSettled(uint256 indexed requestId,uint256 networkCost,uint256 totalCharge,uint256 operatorPayment,uint256 treasuryPayment)",
  "event RequestExpiredAndReleased(uint256 indexed requestId,uint256 releasedPayment)",
  "function contextBlockNumber() view returns (uint256)",
];

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) {
      throw new Error(`invalid argument near ${argv[index] || "end of command"}`);
    }
    options[argv[index].slice(2)] = argv[index + 1];
  }
  return options;
}

function integer(value, name, fallback, minimum = 0) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) throw new Error(`invalid --${name}`);
  return parsed;
}

function percentile(values, percent) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left - right);
  return sorted[Math.max(0, Math.ceil((percent / 100) * sorted.length) - 1)];
}

async function queryInRanges(contract, filter, fromBlock, toBlock, blockRange) {
  const events = [];
  for (let start = fromBlock; start <= toBlock; start += blockRange) {
    events.push(...await contract.queryFilter(filter, start, Math.min(toBlock, start + blockRange - 1)));
  }
  return events;
}

function rateBps(numerator, denominator) {
  return denominator === 0 ? null : Math.floor((numerator * 10_000) / denominator);
}

function countOverdueRequests(requests, settledById, expiredIds, contextBlockNumber) {
  return [...requests.entries()].filter(([requestId, request]) => (
    !settledById.has(requestId)
      && !expiredIds.has(requestId)
      && contextBlockNumber > request.expiresAtBlock
  )).length;
}

function eventFingerprint(events) {
  return events.map((event) => ({
    blockNumber: event.blockNumber,
    blockHash: event.blockHash.toLowerCase(),
    transactionHash: event.transactionHash.toLowerCase(),
    index: event.index,
    topics: event.topics.map((topic) => topic.toLowerCase()),
    data: event.data.toLowerCase(),
  }));
}

function readJson(path, name) {
  if (!path) throw new Error(`--${name} is required`);
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.coordinator || options["from-block"] === undefined) {
    throw new Error("--coordinator and --from-block are required");
  }
  const manifest = readJson(options.manifest, "manifest");
  const verification = readJson(options["verification-report"], "verification-report");
  const smoke = readJson(options["smoke-report"], "smoke-report");
  const coordinatorAddress = getAddress(options.coordinator);
  if (manifest.format !== "robinhood-proof-vrf-deployment/v1"
      || verification.format !== "robinhood-proof-vrf-deployment-verification/v1"
      || verification.status !== "pass"
      || smoke.format !== "robinhood-proof-vrf-smoke-report/v1"
      || smoke.status !== "pass"
      || String(verification.chainId) !== String(manifest.chainId)
      || String(smoke.chainId) !== String(manifest.chainId)
      || verification.gitCommit !== manifest.gitCommit
      || smoke.gitCommit !== manifest.gitCommit
      || verification.coordinator.toLowerCase() !== coordinatorAddress.toLowerCase()
      || smoke.coordinator.toLowerCase() !== coordinatorAddress.toLowerCase()
      || manifest.contracts.coordinator.address.toLowerCase() !== coordinatorAddress.toLowerCase()) {
    throw new Error("matching passing deployment and smoke reports are required");
  }
  const rpcUrls = normalizeRpcUrls([
    ...(readSecret("VRF_RPC_URLS") || "").split(","),
    options["rpc-url"],
    options["rpc-url-secondary"],
  ], { minimum: 2, label: "soak verification" });
  const providers = rpcUrls.map((url) => new JsonRpcProvider(url));
  const networks = await Promise.all(providers.map((provider) => provider.getNetwork()));
  if (networks.some((network) => network.chainId !== BigInt(manifest.chainId))) {
    throw new Error("an RPC returned a chainId that differs from the deployment manifest");
  }
  const fromBlock = integer(options["from-block"], "from-block", undefined);
  if (fromBlock < Number(smoke.checkedThroughBlock)) {
    throw new Error("--from-block must be at or after the passing smoke report's checked block");
  }
  const heads = await Promise.all(providers.map((provider) => provider.getBlockNumber()));
  const toBlock = options["to-block"] === undefined
    ? Math.min(...heads)
    : integer(options["to-block"], "to-block", undefined);
  if (heads.some((head) => head < toBlock)) throw new Error("--to-block is above an RPC head");
  const blockRange = integer(options["block-range"], "block-range", 2_000, 1);
  const expectedDays = integer(options["expected-days"], "expected-days", 30, 1);
  const minimumRequests = integer(options["minimum-requests"], "minimum-requests", 1_000, 1);
  const minimumFulfillmentRateBps = integer(
    options["minimum-fulfillment-rate-bps"], "minimum-fulfillment-rate-bps", 9_990, 0,
  );
  const minimumCallbackRateBps = integer(
    options["minimum-callback-rate-bps"], "minimum-callback-rate-bps", 9_990, 0,
  );
  if (toBlock < fromBlock) throw new Error("--to-block must not be below --from-block");

  const states = await Promise.all(providers.map(async (provider) => {
    const code = await provider.getCode(coordinatorAddress);
    if (code === "0x" || keccak256(code).toLowerCase()
        !== manifest.contracts.coordinator.runtimeCodeHash.toLowerCase()) {
      throw new Error("coordinator runtime code does not match the deployment manifest");
    }
    const coordinator = new Contract(coordinatorAddress, ABI, provider);
    const filters = coordinator.filters;
    const [requested, verified, callbacks, settled, expired, startBlock, endBlock, contextBlock] =
      await Promise.all([
        queryInRanges(coordinator, filters.RandomWordsRequested(), fromBlock, toBlock, blockRange),
        queryInRanges(coordinator, filters.ProofVerified(), fromBlock, toBlock, blockRange),
        queryInRanges(coordinator, filters.CallbackAttempted(), fromBlock, toBlock, blockRange),
        queryInRanges(coordinator, filters.RequestSettled(), fromBlock, toBlock, blockRange),
        queryInRanges(coordinator, filters.RequestExpiredAndReleased(), fromBlock, toBlock, blockRange),
        provider.getBlock(fromBlock),
        provider.getBlock(toBlock),
        coordinator.contextBlockNumber({ blockTag: toBlock }),
      ]);
    if (!startBlock || !endBlock) throw new Error("an RPC could not resolve the soak boundary blocks");
    const fingerprint = canonicalJson({
      startBlockHash: startBlock.hash.toLowerCase(),
      endBlockHash: endBlock.hash.toLowerCase(),
      contextBlock: contextBlock.toString(),
      requested: eventFingerprint(requested),
      verified: eventFingerprint(verified),
      callbacks: eventFingerprint(callbacks),
      settled: eventFingerprint(settled),
      expired: eventFingerprint(expired),
    });
    return {
      requested, verified, callbacks, settled, expired, startBlock, endBlock, contextBlock,
      fingerprint,
    };
  }));
  if (states.some((state) => state.fingerprint !== states[0].fingerprint)) {
    throw new Error("independent RPC endpoints disagree on the soak range or events");
  }
  const {
    requested, verified, callbacks, settled, expired, startBlock, endBlock, contextBlock,
  } = states[0];

  const requests = new Map(requested.map((event) => [event.args.requestId.toString(), {
    blockNumber: event.blockNumber,
    expiresAtBlock: Number(event.args.expiresAtBlock),
  }]));
  const settledById = new Map(settled.map((event) => [event.args.requestId.toString(), event]));
  const expiredIds = new Set(expired.map((event) => event.args.requestId.toString()));
  const finalCallback = new Map();
  for (const event of callbacks) {
    finalCallback.set(event.args.requestId.toString(), Boolean(event.args.success));
  }
  const overdue = countOverdueRequests(
    requests,
    settledById,
    expiredIds,
    Number(contextBlock),
  );
  const finalizedDenominator = settled.length + expired.length + overdue;
  const successfulCallbacks = [...settledById.keys()].filter(
    (requestId) => finalCallback.get(requestId) === true,
  ).length;
  const latencyBlocks = [...settledById.entries()].flatMap(([requestId, event]) => {
    const request = requests.get(requestId);
    return request ? [event.blockNumber - request.blockNumber] : [];
  });
  const durationSeconds = Math.max(0, endBlock.timestamp - startBlock.timestamp);
  const observedDays = durationSeconds / 86_400;
  const fulfillmentRateBps = rateBps(settled.length, finalizedDenominator);
  const callbackSuccessRateBps = rateBps(successfulCallbacks, settled.length);
  const durationSatisfied = observedDays >= expectedDays;
  const volumeSatisfied = requested.length >= minimumRequests;
  const fulfillmentSatisfied = fulfillmentRateBps !== null
    && fulfillmentRateBps >= minimumFulfillmentRateBps;
  const callbackSatisfied = callbackSuccessRateBps !== null
    && callbackSuccessRateBps >= minimumCallbackRateBps;
  const chainMetricsPass = durationSatisfied
    && volumeSatisfied
    && fulfillmentSatisfied
    && callbackSatisfied
    && overdue === 0;

  const report = {
    format: "proof-vrf-testnet-soak-report-v1",
    generatedAt: new Date().toISOString(),
    chainId: String(manifest.chainId),
    gitCommit: manifest.gitCommit,
    coordinator: coordinatorAddress,
    rpcCount: rpcUrls.length,
    range: {
      fromBlock,
      toBlock,
      startTimestamp: startBlock.timestamp,
      endTimestamp: endBlock.timestamp,
      contextBlockNumber: Number(contextBlock),
      observedDays,
    },
    thresholds: {
      expectedDays,
      minimumRequests,
      minimumFulfillmentRateBps,
      minimumCallbackRateBps,
    },
    counts: {
      requested: requested.length,
      proofVerified: verified.length,
      settled: settled.length,
      expired: expired.length,
      overdueUnfinalized: overdue,
      callbackAttempts: callbacks.length,
      successfulFinalCallbacks: successfulCallbacks,
    },
    ratesBps: { fulfillment: fulfillmentRateBps, callbackSuccess: callbackSuccessRateBps },
    fulfillmentLatencyBlocks: {
      p50: percentile(latencyBlocks, 50),
      p95: percentile(latencyBlocks, 95),
      p99: percentile(latencyBlocks, 99),
      max: percentile(latencyBlocks, 100),
    },
    gates: {
      durationSatisfied,
      volumeSatisfied,
      fulfillmentSatisfied,
      callbackSatisfied,
      noOverdueRequests: overdue === 0,
      rpcConsensus: true,
      deploymentVerificationPassed: true,
      smokePassedBeforeSoak: true,
      chainMetricsPass,
    },
    status: chainMetricsPass ? "chain-metrics-pass" : "insufficient-or-failed",
    limitations: [
      "This report proves only on-chain duration and outcomes.",
      "RPC split, reorg, gas-spike, backup-relayer, and disaster-recovery drills require separate signed evidence.",
      "A passing report is not a security audit or production approval.",
    ],
  };
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    if (existsSync(options.out) && options.overwrite !== "true") {
      throw new Error("output exists; pass --overwrite true to replace it");
    }
    writeFileSync(options.out, output, { flag: options.overwrite === "true" ? "w" : "wx" });
  }
  process.stdout.write(output);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({
  countOverdueRequests,
  eventFingerprint,
  percentile,
  rateBps,
});

#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { Contract, getAddress, keccak256 } from "ethers";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";
import { canonicalJson } from "./threshold-group.mjs";
import { rpcProvider } from "./rpc.mjs";
import { isMain } from "./entrypoint.mjs";
import { errorMessage } from "./errors.mjs";

const COORDINATOR_ABI = [
  "function getRequest(uint256 requestId) view returns ((address consumer,address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,bytes32 keyHash,uint256 subscriptionId,uint256 preSeed,uint256 reservedPayment,uint256 randomness,uint96 minimumFeeWei,uint64 requestBlock,uint64 expiresAtBlock,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,uint32 callbackGasLimit,uint32 numWords,uint32 callbackAttempts,uint32 fulfillmentOverheadGas,uint16 confirmations,uint16 premiumBps,uint16 operatorPremiumShareBps,uint8 status,bool sponsored,bool waiveMinimumFee,bool callbackSucceeded) request)",
  "event ProofVerified(uint256 indexed requestId,bytes32 indexed keyHash,uint256 randomness)",
  "event CallbackAttempted(uint256 indexed requestId,uint32 indexed attempt,bool success)",
  "event RequestSettled(uint256 indexed requestId,uint256 networkCost,uint256 totalCharge,uint256 operatorPayment,uint256 treasuryPayment)",
];

function requestFingerprint(request) {
  return canonicalJson(Object.fromEntries(Object.entries(request.toObject()).filter(
    ([key]) => !/^\d+$/.test(key),
  ).map(([key, value]) => [
    key,
    typeof value === "bigint" ? value.toString() : String(value).toLowerCase(),
  ])));
}

export function assertEventConsensus(eventSets) {
  const fingerprints = eventSets.map((events) => canonicalJson(events.map((event) => ({
    blockNumber: event.blockNumber, blockHash: event.blockHash,
    transactionHash: event.transactionHash, index: event.index,
    topics: event.topics, data: event.data,
  }))));
  if (!fingerprints.length || fingerprints.some((value) => value !== fingerprints[0])) {
    throw new Error("independent RPCs disagree on smoke events");
  }
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      manifest: { type: "string" },
      "verification-report": { type: "string" },
      "request-id": { type: "string" },
      consumer: { type: "string" },
      out: { type: "string" },
      overwrite: { type: "boolean", default: false },
    },
    strict: true,
  });
  if (!/^\d+$/.test(String(values["request-id"]))) {
    throw new Error("request-id must be an unsigned integer");
  }
  const rpcUrls = normalizeRpcUrls(readSecret("VRF_RPC_URLS"), {
    minimum: 2,
    label: "smoke verification",
  });
  const manifest = JSON.parse(readFileSync(values.manifest, "utf8"));
  const verification = JSON.parse(readFileSync(values["verification-report"], "utf8"));
  if (manifest.format !== "robinhood-proof-vrf-deployment/v1"
      || verification.format !== "robinhood-proof-vrf-deployment-verification/v1"
      || verification.status !== "pass"
      || String(verification.chainId) !== String(manifest.chainId)
      || verification.gitCommit !== manifest.gitCommit
      || verification.coordinator?.toLowerCase()
        !== manifest.contracts.coordinator.address.toLowerCase()) {
    throw new Error("a passing deployment verification report is required");
  }
  const coordinatorAddress = getAddress(manifest.contracts.coordinator.address);
  const requestId = BigInt(values["request-id"]);
  const expectedConsumer = getAddress(values.consumer);
  const providers = rpcUrls.map((url) => rpcProvider(url));
  try {
    const heads = await Promise.all(providers.map((provider) => provider.getBlockNumber()));
    if (Math.max(...heads) - Math.min(...heads) > 32) throw new Error("smoke RPC head skew");
    const toBlock = Math.min(...heads) - 12;
    if (toBlock < manifest.contracts.coordinator.blockNumber) throw new Error("waiting for smoke confirmations");
    const states = await Promise.all(providers.map(async (provider) => {
      const [network, boundary, code] = await Promise.all([
        provider.getNetwork(),
        provider.getBlock(toBlock),
        provider.getCode(coordinatorAddress, toBlock),
      ]);
      if (network.chainId !== BigInt(manifest.chainId)) throw new Error("RPC chainId mismatch");
      if (keccak256(code) !== manifest.contracts.coordinator.runtimeCodeHash) {
        throw new Error("coordinator runtime code hash mismatch");
      }
      const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
      if (!boundary?.hash) throw new Error("missing smoke boundary block");
      const request = await coordinator.getRequest(requestId, { blockTag: toBlock });
      return { provider, coordinator, boundary: boundary.hash, request, fingerprint: requestFingerprint(request) };
    }));
    if (states.some((state) => state.fingerprint !== states[0].fingerprint || state.boundary !== states[0].boundary)) {
      throw new Error("independent RPCs disagree on the fulfilled request");
    }
    const { request } = states[0];
    // Query the request's L2 block onward, not the whole deployment on every check.
    const fromBlock = Number(request.requestBlock);
    if (!Number.isSafeInteger(fromBlock) || fromBlock < manifest.contracts.coordinator.blockNumber || fromBlock > toBlock) {
      throw new Error("invalid or unconfirmed smoke request block");
    }
    const eventTypes = ["ProofVerified", "CallbackAttempted", "RequestSettled"];
    const evidence = await Promise.all(states.map(async ({ coordinator }) => Promise.all(eventTypes.map(async (name) => {
      const events = [];
      for (let start = fromBlock; start <= toBlock; start += 2000) {
        events.push(...await coordinator.queryFilter(coordinator.filters[name](requestId), start, Math.min(toBlock, start + 1999)));
      }
      return events;
    }))));
    eventTypes.forEach((_, index) => assertEventConsensus(evidence.map((events) => events[index])));
    const [proofEvents, callbackEvents, settlementEvents] = evidence[0];
    const proof = proofEvents[0]?.args;
    const settlement = settlementEvents[0]?.args;
    const checks = {
      rpcConsensus: true,
      rpcEventConsensus: true,
      deploymentVerificationPassed: true,
      fulfilled: Number(request.status) === 2,
      consumer: request.consumer.toLowerCase() === expectedConsumer.toLowerCase(),
      callbackSucceeded: request.callbackSucceeded === true,
      callbackWasAttempted: Number(request.callbackAttempts) > 0 && callbackEvents.length > 0,
      exactlyOneProof: proofEvents.length === 1,
      exactlyOneSettlement: settlementEvents.length === 1,
      proofMatchesState: proofEvents.length === 1
        && proof.keyHash.toLowerCase() === request.keyHash.toLowerCase()
        && proof.randomness === request.randomness,
      finalCallbackSucceeded: callbackEvents.length > 0
        && callbackEvents.at(-1).args.success === true,
      settlementConserved: settlementEvents.length === 1
        && settlement.totalCharge === settlement.operatorPayment + settlement.treasuryPayment
        && settlement.networkCost <= settlement.totalCharge
        && settlement.totalCharge <= request.reservedPayment,
      keyMatchesDeployment: request.keyHash.toLowerCase() === manifest.keyHash.toLowerCase(),
    };
    const pass = Object.values(checks).every(Boolean);
    const report = {
      format: "robinhood-proof-vrf-smoke-report/v1",
      generatedAt: new Date().toISOString(),
      status: pass ? "pass" : "fail",
      chainId: String(manifest.chainId),
      gitCommit: manifest.gitCommit,
      coordinator: coordinatorAddress,
      requestId: requestId.toString(),
      consumer: request.consumer,
      keyHash: request.keyHash,
      requestBlock: request.requestBlock.toString(),
      checkedThroughBlock: toBlock,
      checkedThroughBlockHash: states[0].boundary,
      eventConfirmations: 12,
      rpcCount: rpcUrls.length,
      checks,
      callbackAttempts: Number(request.callbackAttempts),
      settlement: settlement ? {
        networkCost: settlement.networkCost.toString(),
        totalCharge: settlement.totalCharge.toString(),
        operatorPayment: settlement.operatorPayment.toString(),
        treasuryPayment: settlement.treasuryPayment.toString(),
        transactionHash: settlementEvents[0].transactionHash,
      } : null,
    };
    if (values.out) {
      if (existsSync(values.out) && !values.overwrite) throw new Error("output report exists");
      writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`, {
        flag: values.overwrite ? "w" : "wx",
        mode: 0o600,
      });
    }
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    if (!pass) process.exitCode = 1;
  } finally { providers.forEach((provider) => provider.destroy()); }
}

if (isMain(import.meta.url)) main().catch((error) => {
  process.stderr.write(`${errorMessage(error)}\n`);
  process.exitCode = 1;
});

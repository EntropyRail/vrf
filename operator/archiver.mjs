#!/usr/bin/env node
import { existsSync, lstatSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync } from "node:fs";
import { dirname } from "node:path";
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { Contract, Wallet, keccak256, getAddress } from "ethers";
import { parseArgs } from "node:util";
import { isMain } from "./entrypoint.mjs";
import { internals as operator } from "./cli.mjs";
import { PostgresOperatorStore } from "./postgres-store.mjs";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { rpcProvider } from "./rpc.mjs";
import { readSecret } from "./secrets.mjs";
import { errorDetails } from "./errors.mjs";

const ZERO = `0x${"00".repeat(32)}`;
const json = (value) => JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item);
function atomic(path, value) {
  const temporary = `${path}.tmp`;
  const fd = openSync(temporary, "w", 0o600);
  try { writeFileSync(fd, `${json(value)}\n`); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temporary, path);
  const dir = openSync(dirname(path), "r");
  try { fsyncSync(dir); } finally { closeSync(dir); }
}
function consensus(values, name) {
  if (!values.length || values.some((value) => json(value) !== json(values[0]))) {
    throw new Error(`ArchiverRpcDisagreement:${name}`);
  }
  return values[0];
}

// One systemd instance owns this local journal. Reservations are fsynced BEFORE
// broadcast and never refunded automatically, including uncertain broadcasts.
// This intentionally underuses, rather than accidentally exceeds, the test budget.
export class ArchiveBudget {
  constructor(path, identity, maximumWei) {
    this.path = path;
    if (maximumWei <= 0n) throw new Error("archive budget must be positive");
    if (existsSync(path)) {
      const metadata = lstatSync(path);
      if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077)) throw new Error("unsafe archive state file");
      this.state = JSON.parse(readFileSync(path, "utf8"));
      if (this.state.format !== "proof-vrf-archiver-state/v1"
          || json(this.state.identity) !== json(identity)
          || this.state.maximumWei !== maximumWei.toString()) throw new Error("archive identity/budget differs from durable state");
    } else {
      this.state = { format: "proof-vrf-archiver-state/v1", identity, maximumWei: maximumWei.toString(),
        reservedWei: "0", transactions: [], lastHead: null, coverageGap: null };
      atomic(path, this.state);
    }
    if (BigInt(this.state.reservedWei) < 0n || BigInt(this.state.reservedWei) > maximumWei) throw new Error("invalid archived budget");
  }
  get remaining() { return BigInt(this.state.maximumWei) - BigInt(this.state.reservedWei); }
  reserve({ gasLimit, gasPriceWei, transactionHash }) {
    const cost = gasLimit * gasPriceWei;
    if (gasLimit <= 0n || gasPriceWei <= 0n) throw new Error("invalid archive fee reservation");
    if (cost > this.remaining) {
      this.state.budgetBlocked = true;
      atomic(this.path, this.state);
      throw new Error("ArchiveBudgetExhausted");
    }
    this.state.reservedWei = (BigInt(this.state.reservedWei) + cost).toString();
    this.state.transactions.push({ transactionHash, maximumFeeWei: cost.toString(), at: new Date().toISOString() });
    atomic(this.path, this.state);
  }
  checkpoint(head) {
    if (this.state.lastHead !== null && head - this.state.lastHead > 192) {
      this.state.coverageGap ||= { afterBlock: this.state.lastHead, resumedBlock: head };
    }
    this.state.lastHead = head;
    atomic(this.path, this.state);
  }
  recordMissed(requestId) {
    this.state.missedRequestIds ||= [];
    if (!this.state.missedRequestIds.includes(requestId)) {
      this.state.missedRequestIds.push(requestId);
      atomic(this.path, this.state);
    }
  }
  recordReview(requestId) {
    this.state.reviewRequestIds ||= [];
    if (!this.state.reviewRequestIds.includes(String(requestId))) {
      this.state.reviewRequestIds.push(String(requestId));
      atomic(this.path, this.state);
    }
  }
}

export function archiveDecision(request, storedHash, head, archiveAfterBlocks = 32) {
  if (Number(request.status) !== 1) return "finalized";
  if (storedHash !== ZERO) return "protected";
  const age = BigInt(head) - BigInt(request.requestBlock);
  if (age > 256n) return "missed-window";
  return age >= BigInt(archiveAfterBlocks) ? "archive" : "young";
}

async function snapshot(providers, manifest) {
  const heads = await Promise.all(providers.map((provider) => provider.getBlockNumber()));
  if (Math.max(...heads) - Math.min(...heads) > 32) throw new Error("ArchiverRpcHeadSkew");
  const head = Math.min(...heads) - 2;
  const fromBlock = Math.max(manifest.contracts.coordinator.blockNumber, head - 511);
  if (head < fromBlock) throw new Error("ArchiverWaitingForConfirmations");
  const results = await Promise.all(providers.map(async (provider) => {
    const coordinator = new Contract(manifest.contracts.coordinator.address, operator.SERVICE_ABI, provider);
    const [boundary, context, events] = await Promise.all([
      provider.getBlock(head), coordinator.contextBlockNumber({ blockTag: head }),
      coordinator.queryFilter(coordinator.filters.RandomWordsRequested(manifest.keyHash), fromBlock, head),
    ]);
    if (!boundary || context !== BigInt(head)) throw new Error("ArchiverL2BlockContextMismatch");
    return { boundary: boundary.hash, events: events.map((event) => ({ requestId: event.args.requestId.toString(),
      blockNumber: event.blockNumber, blockHash: event.blockHash, transactionHash: event.transactionHash,
      index: event.index, topics: event.topics, data: event.data })) };
  }));
  const result = consensus(results, "recent requests and boundary");
  return { head, events: result.events };
}

export async function archiveCycle({ providers, manifest, budget, sendArchive, archiveAfterBlocks = 32 }) {
  const { head, events } = await snapshot(providers, manifest);
  const stats = { head, cursor: head + 1, pending: 0, archived: 0, protected: 0, missedWindow: 0, errors: [] };
  // Oldest eligible requests first; archival does not claim Operator request/scan leases.
  for (const event of events) {
    try {
      const observations = await Promise.all(providers.map(async (provider) => {
        const coordinator = new Contract(manifest.contracts.coordinator.address, operator.SERVICE_ABI, provider);
        const request = await coordinator.getRequest(event.requestId, { blockTag: head });
        if (request.keyHash.toLowerCase() !== manifest.keyHash.toLowerCase()) throw new Error("ArchiverKeyMismatch");
        const archive = new Contract(manifest.contracts.blockhashStore.address, operator.BLOCKHASH_STORE_ABI, provider);
        return { request: Array.from(request), requestBlock: request.requestBlock.toString(), status: Number(request.status),
          maxGasPriceWei: request.maxGasPriceWei.toString(), storedHash: await archive.blockhashes(request.requestBlock) };
      }));
      const observed = consensus(observations, "request and archive");
      if (observed.status !== 1) continue;
      stats.pending += 1;
      // Refresh height after RPC reads. A slow read must not make us submit a now-expired block.
      const freshHead = Math.max(...await Promise.all(providers.map((provider) => provider.getBlockNumber())));
      const action = archiveDecision(observed, observed.storedHash, freshHead, archiveAfterBlocks);
      if (action === "protected") stats.protected += 1;
      if (action === "missed-window") {
        stats.missedWindow += 1;
        budget.recordMissed?.(event.requestId);
      }
      if (action === "archive") {
        await sendArchive({ requestId: event.requestId, requestBlock: observed.requestBlock,
          maxGasPriceWei: BigInt(observed.maxGasPriceWei), budget });
        stats.archived += 1;
      }
    } catch (error) { stats.errors.push({ requestId: event.requestId, error: errorDetails(error) }); }
  }
  budget.checkpoint(head);
  return stats;
}

async function main() {
  const { values } = parseArgs({ options: {
    manifest: { type: "string" }, state: { type: "string" }, "health-file": { type: "string" },
    "maximum-total-fee-wei": { type: "string" }, "maximum-gas-price-wei": { type: "string", default: "15000000" },
    "archive-after-blocks": { type: "string", default: "32" }, "poll-ms": { type: "string", default: "1000" },
    once: { type: "boolean", default: false },
  }, strict: true });
  if (!values.manifest || !values.state || !values["health-file"] || !/^\d+$/.test(values["maximum-total-fee-wei"] || "")) {
    throw new Error("manifest, state, health-file, and explicit maximum-total-fee-wei are required");
  }
  const manifest = JSON.parse(readFileSync(values.manifest, "utf8"));
  if (manifest.format !== "robinhood-proof-vrf-deployment/v1" || Number(manifest.chainId) !== 46630) {
    throw new Error("archiver release is restricted to a Robinhood testnet deployment manifest");
  }
  const after = Number(values["archive-after-blocks"]);
  const pollMs = Number(values["poll-ms"]);
  const maximumGasPrice = BigInt(values["maximum-gas-price-wei"]);
  if (!Number.isInteger(after) || after < 2 || after > 64) throw new Error("archive-after-blocks must be 2..64");
  if (!Number.isInteger(pollMs) || pollMs < 250 || pollMs > 2000) throw new Error("poll-ms must be 250..2000");
  if (maximumGasPrice <= 0n) throw new Error("maximum gas price must be positive");
  const urls = normalizeRpcUrls(readSecret("VRF_RPC_URLS", { required: true }), { minimum: 2, label: "independent archiver" });
  const providers = urls.map((url) => rpcProvider(url, 5_000));
  const provider = operator.createProvider(urls);
  let store;
  const instanceId = `archiver:${hostname()}:${process.pid}:${randomUUID()}`;
  try {
    for (const rpc of providers) {
      if ((await rpc.getNetwork()).chainId !== 46630n) throw new Error("archiver RPC chain mismatch");
      for (const name of ["coordinator", "blockhashStore"]) {
        const expected = manifest.contracts[name];
        if (keccak256(await rpc.getCode(expected.address)) !== expected.runtimeCodeHash) throw new Error(`archiver ${name} code mismatch`);
      }
      const coordinator = new Contract(manifest.contracts.coordinator.address, operator.SERVICE_ABI, rpc);
      if (getAddress(await coordinator.blockhashStore()) !== getAddress(manifest.contracts.blockhashStore.address)) throw new Error("archiver store mismatch");
    }
    const wallet = new Wallet(readSecret("VRF_TX_PRIVATE_KEY", { required: true }), provider);
    const identity = { chainId: "46630", coordinator: manifest.contracts.coordinator.address.toLowerCase(),
      relayer: wallet.address.toLowerCase(), keyHash: manifest.keyHash.toLowerCase() };
    const budget = new ArchiveBudget(values.state, identity, BigInt(values["maximum-total-fee-wei"]));
    store = await PostgresOperatorStore.connect({ databaseUrl: readSecret("VRF_DATABASE_URL", { required: true }),
      identity: { ...identity, deploymentBlock: manifest.contracts.coordinator.blockNumber } });
    const archive = new Contract(manifest.contracts.blockhashStore.address, operator.BLOCKHASH_STORE_ABI, wallet);
    const sendArchive = async ({ requestId, requestBlock, maxGasPriceWei }) => {
      // Permissionless archive only; this process has no proof-key or prover credentials.
      if (await archive.blockhashes(requestBlock) !== ZERO) return;
      if (await provider.getBalance(wallet.address) < 2_000_000_000_000_000n) throw new Error("ArchiverRelayerBalanceFloor");
      const receipt = await operator.sendPostgresTransaction({ store, instanceId, wallet, provider,
        transactionRequest: await archive.store.populateTransaction(requestBlock),
        maxGasPrice: maxGasPriceWei < maximumGasPrice ? maxGasPriceWei : maximumGasPrice,
        timeoutMs: 5_000, maximumAttempts: 1, requestId, transactionKind: "independent-blockhash-archive",
        rpcProviders: providers, beforeBroadcast: (transaction) => budget.reserve(transaction) });
      process.stdout.write(`${json({ status: "independently-archived", instanceId, requestId, requestBlock,
        transactionHash: receipt.hash, blockNumber: receipt.blockNumber, budgetRemainingWei: budget.remaining })}\n`);
    };
    let lastWarning = 0;
    for (;;) {
      try {
        const stats = await archiveCycle({ providers, manifest, budget, sendArchive, archiveAfterBlocks: after });
        const healthy = !stats.missedWindow && !stats.errors.length && !budget.state.coverageGap
          && !budget.state.budgetBlocked && !budget.state.missedRequestIds?.length && budget.remaining > 0n;
        const health = { status: healthy ? "healthy" : "unhealthy", mode: "independent-archiver", instanceId,
          coordinator: identity.coordinator, keyHash: identity.keyHash, ...stats,
          budgetRemainingWei: budget.remaining.toString(), coverageGap: budget.state.coverageGap,
          budgetBlocked: Boolean(budget.state.budgetBlocked), missedRequestIds: budget.state.missedRequestIds || [], updatedAt: new Date().toISOString() };
        atomic(values["health-file"], health);
        if (!healthy && Date.now() - lastWarning > 60_000) {
          process.stderr.write(`${json(health)}\n`); lastWarning = Date.now();
        }
      } catch (error) {
        const health = { status: "unhealthy", mode: "independent-archiver", instanceId, error: errorDetails(error), updatedAt: new Date().toISOString() };
        atomic(values["health-file"], health); process.stderr.write(`${json(health)}\n`);
        if (values.once) throw error;
      }
      if (values.once) return;
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  } finally {
    await store?.close(); provider.destroy(); providers.forEach((rpc) => rpc.destroy());
  }
}

if (isMain(import.meta.url)) main().catch((error) => {
  process.stderr.write(`${json({ status: "archiver-fatal-error", error: errorDetails(error) })}\n`);
  process.exitCode = 1;
});

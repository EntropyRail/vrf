#!/usr/bin/env node
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { parseArgs } from "node:util";
import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { Wallet, Contract, keccak256, getAddress } from "ethers";
import { ArchiveBudget } from "./archiver.mjs";
import { internals as operator } from "./cli.mjs";
import { PostgresOperatorStore } from "./postgres-store.mjs";
import { RemoteProofProvider } from "./proof-provider.mjs";
import { compactScan, fulfillCompactClaim, compactArchiveCycle, initializeWitnessStore, saveWitnessEvents } from "./compact-worker.mjs";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { rpcProvider } from "./rpc.mjs";
import { readSecret } from "./secrets.mjs";
import { errorDetails } from "./errors.mjs";
import { isMain } from "./entrypoint.mjs";

const json = v => JSON.stringify(v, (_, x) => typeof x === "bigint" ? String(x) : x);
const FLOOR = 2_000_000_000_000_000n;
export function validateCompactManifest(manifest) {
  if (manifest.format !== "robinhood-proof-vrf-deployment/v3" || Number(manifest.chainId) !== 46630
      || !["deployed", "verified"].includes(manifest.status) || !/^[a-f0-9]{40}$/.test(manifest.gitCommit)) throw new Error("V3 testnet deployment manifest required");
  for (const name of ["coordinator", "blockhashStore", "verifier", "blockContext", "l1FeeCalculator", "timelock", "safe"]) {
    const c = manifest.contracts?.[name];
    if (!c || !/^0x[0-9a-f]{64}$/i.test(c.runtimeCodeHash) || !Number.isSafeInteger(c.blockNumber)) throw new Error(`missing ${name} deployment evidence`);
    getAddress(c.address);
  }
  for (const name of ["fulfiller", "archiver", "guardian", "payee"]) getAddress(manifest[name]);
  if (!/^0x[0-9a-f]{64}$/i.test(manifest.keyHash)) throw new Error("missing key hash");
  return manifest;
}

async function main() {
  const { values: v } = parseArgs({ strict: true, options: {
    manifest: { type: "string" }, state: { type: "string" }, "health-file": { type: "string" },
    mode: { type: "string" }, "maximum-total-fee-wei": { type: "string" },
    "prover-url": { type: "string" }, "prover-client-cert": { type: "string" },
    "prover-client-key": { type: "string" }, "prover-ca": { type: "string" }, once: { type: "boolean", default: false },
  } });
  if (!["operator", "archiver"].includes(v.mode) || !v.state || !v["health-file"]
      || !/^\d+$/.test(v["maximum-total-fee-wei"] ?? "")) throw new Error("mode, manifest, private state, health-file and explicit budget required");
  const manifest = validateCompactManifest(JSON.parse(readFileSync(v.manifest, "utf8")));
  const urls = normalizeRpcUrls(readSecret("VRF_RPC_URLS", { required: true }), { minimum: 2, label: "V3 runtime" });
  const providers = urls.map(u => rpcProvider(u, 10_000)), provider = operator.createProvider(urls);
  const wallet = new Wallet(readSecret("VRF_TX_PRIVATE_KEY", { required: true }), provider);
  if (getAddress(wallet.address) !== getAddress(manifest[v.mode === "operator" ? "fulfiller" : "archiver"])) throw new Error("V3 relayer role mismatch");
  const identity = { chainId: "46630", coordinator: manifest.contracts.coordinator.address.toLowerCase(),
    keyHash: manifest.keyHash.toLowerCase(), relayer: wallet.address.toLowerCase() };
  const instanceId = `v3-${v.mode}:${hostname()}:${process.pid}:${randomUUID()}`;
  const budget = new ArchiveBudget(v.state, identity, BigInt(v["maximum-total-fee-wei"]));
  let store, proofProvider;
  const health = data => {
    const value = { mode: `compact-${v.mode}`, instanceId, coordinator: identity.coordinator,
      budgetRemainingWei: String(budget.remaining), coverageGap: budget.state.coverageGap,
      missedRequestIds: budget.state.missedRequestIds ?? [], budgetBlocked: !!budget.state.budgetBlocked,
      reviewRequestIds: budget.state.reviewRequestIds ?? [],
      ...data, updatedAt: new Date().toISOString() };
    writeFileSync(`${v["health-file"]}.tmp`, json(value) + "\n", { mode: 0o600 });
    renameSync(`${v["health-file"]}.tmp`, v["health-file"]);
  };
  try {
    for (const p of providers) {
      if ((await p.getNetwork()).chainId !== 46630n) throw new Error("V3 RPC chain mismatch");
      for (const c of Object.values(manifest.contracts)) {
        if (keccak256(await p.getCode(c.address)) !== c.runtimeCodeHash) throw new Error("V3 runtime code mismatch");
      }
      const coordinator = new Contract(identity.coordinator, [...operator.SERVICE_ABI,
        "function owner() view returns(address)", "function guardian() view returns(address)"], p);
      const key = await coordinator.getKey(manifest.keyHash);
      if ((await coordinator.owner()).toLowerCase() !== manifest.contracts.timelock.address.toLowerCase()
          || (await coordinator.guardian()).toLowerCase() !== manifest.guardian.toLowerCase()
          || (await coordinator.blockhashStore()).toLowerCase() !== manifest.contracts.blockhashStore.address.toLowerCase()
          || !key.active || !key.exists || key.fulfiller.toLowerCase() !== manifest.fulfiller.toLowerCase()
          || key.payee.toLowerCase() !== manifest.payee.toLowerCase()
          || key.verifier.toLowerCase() !== manifest.contracts.verifier.address.toLowerCase()) throw new Error("V3 pinned configuration mismatch");
    }
    store = await PostgresOperatorStore.connect({ databaseUrl: readSecret("VRF_DATABASE_URL", { required: true }),
      identity: { ...identity, deploymentBlock: manifest.contracts.coordinator.blockNumber } });
    await initializeWitnessStore(store);
    if (v.mode === "operator") {
      if (!v["prover-url"]?.startsWith("https://") || !v["prover-client-cert"] || !v["prover-client-key"] || !v["prover-ca"]) throw new Error("V3 prover requires mTLS");
      proofProvider = new RemoteProofProvider({ baseUrl: v["prover-url"], timeoutMs: 30_000,
        bearerToken: readSecret("VRF_PROVER_BEARER_TOKEN", { required: true }),
        clientCertificatePath: v["prover-client-cert"], clientKeyPath: v["prover-client-key"], caCertificatePath: v["prover-ca"] });
      await proofProvider.initialize(manifest.keyHash);
    }
    const send = async ({ transaction, requestId, maxGasPriceWei, kind }) => {
      if (transaction.value && BigInt(transaction.value) !== 0n) throw new Error("runtime may not transfer value");
      return operator.sendPostgresTransaction({ store, instanceId, wallet, provider, transactionRequest: transaction,
        maxGasPrice: maxGasPriceWei < 15_000_000n ? maxGasPriceWei : 15_000_000n,
        timeoutMs: 15_000, maximumAttempts: 1, requestId, transactionKind: kind, rpcProviders: providers,
        beforeBroadcast: async tx => {
          const balances = await Promise.all(providers.map(p => p.getBalance(wallet.address, "pending")));
          if (balances.some(b => b - tx.gasLimit * tx.gasPriceWei < FLOOR)) throw new Error("V3 relayer balance floor");
          budget.reserve(tx);
        } });
    };
    for (;;) {
      try {
        let stats;
        if (v.mode === "archiver") stats = await compactArchiveCycle({ providers, manifest, budget, send,
          saveEvents: events => saveWitnessEvents(store, manifest, events) });
        else {
          stats = await compactScan({ providers, manifest, store, instanceId });
          for (const requestId of stats.reviewRequestIds ?? []) budget.recordReview(requestId);
          const pending = await store.claimRequest({ instanceId, leaseSeconds: 360 });
          if (pending) {
            try {
              const gas = await Promise.all(providers.map(p => p.send("eth_gasPrice", []).then(BigInt)));
              const gasPriceWei = gas.reduce((a, b) => a > b ? a : b);
              if (gasPriceWei > 15_000_000n) throw new Error("V3 gas price cap");
              const result = await fulfillCompactClaim({ providers, manifest, pending, from: wallet.address, proofProvider, gasPriceWei, send });
              // A failed callback remains visible in durable witness evidence; no automatic paid retries.
              if (!result.callbackSucceeded) budget.recordReview(pending.requestId);
              await store.completeRequest(pending.requestId, instanceId);
              process.stdout.write(json({ status: "compact-fulfilled", requestId: pending.requestId, ...result }) + "\n");
            } catch (error) {
              await store.retryRequest(pending.requestId, instanceId, json(errorDetails(error)), 10);
              throw error;
            }
          }
          stats.queue = await store.summary();
        }
        const okay = !budget.state.coverageGap && !budget.state.budgetBlocked && !budget.state.missedRequestIds?.length
          && !budget.state.reviewRequestIds?.length && budget.remaining > 0n;
        await store.heartbeat(instanceId, { ...identity, mode: v.mode, ...stats });
        health({ status: okay ? "healthy" : "unhealthy", ...stats });
      } catch (error) {
        health({ status: "unhealthy", error: errorDetails(error) });
        process.stderr.write(json({ status: "compact-cycle-error", error: errorDetails(error) }) + "\n");
        if (v.once) throw error;
      }
      if (v.once) break;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  } finally { await store?.close(); provider.destroy(); providers.forEach(p => p.destroy()); }
}
if (isMain(import.meta.url)) main().catch(error => {
  process.stderr.write(json({ status: "compact-fatal", error: errorDetails(error) }) + "\n"); process.exitCode = 1;
});

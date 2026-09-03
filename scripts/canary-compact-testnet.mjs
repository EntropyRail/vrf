#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { Contract, ContractFactory, getAddress, toQuantity, keccak256 } from "ethers";
import { ReleaseSender, loadRoleWallet, durableJson } from "./deploy-compact-testnet.mjs";
import { validateCompactManifest } from "../operator/run-compact.mjs";
import { recoverCompactRequest } from "../operator/compact-protocol.mjs";
import { normalizeRpcUrls } from "../operator/rpc-policy.mjs";
import { rpcProvider } from "../operator/rpc.mjs";
import { readSecret } from "../operator/secrets.mjs";
import { errorDetails } from "../operator/errors.mjs";

async function main() {
  const { values: v } = parseArgs({ strict: true, options: {
    manifest: { type: "string" }, "wallet-directory": { type: "string" }, out: { type: "string" },
    request: { type: "boolean", default: false }, report: { type: "boolean", default: false },
  } });
  const manifest = validateCompactManifest(JSON.parse(readFileSync(v.manifest, "utf8")));
  const providers = normalizeRpcUrls(readSecret("VRF_RPC_URLS", { required: true }), { minimum: 2 }).map(u => rpcProvider(u, 15_000));
  const { artifacts } = await import("hardhat");
  const ca = await artifacts.readArtifact("VRFServiceCoordinatorV3"), a = await artifacts.readArtifact("ExampleVRFServiceConsumer");
  const coordinator = new Contract(manifest.contracts.coordinator.address, ca.abi, providers[0]);
  try {
    for (const p of providers) {
      if ((await p.getNetwork()).chainId !== 46630n || keccak256(await p.getCode(coordinator.target)) !== manifest.contracts.coordinator.runtimeCodeHash) throw new Error("canary chain/code mismatch");
    }
    let result;
    if (v.report) result = JSON.parse(readFileSync(v.out, "utf8"));
    else {
      const wallet = await loadRoleWallet(v["wallet-directory"], "canary-subscription", providers[0]);
      if (getAddress(wallet.address) !== getAddress(manifest.canary)) throw new Error("canary wallet mismatch");
      const sender = new ReleaseSender({ wallet, providers, journalPath: `${v.out}.transactions.private.json`, maximumWei: 200_000_000_000_000n,
        identity: { coordinator: coordinator.target, gitCommit: manifest.gitCommit, role: "canary", address: wallet.address } });
      const factory = new ContractFactory(a.abi, a.bytecode);
      const receipt = await sender.send("consumer", await factory.getDeployTransaction(coordinator.target, wallet.address));
      const consumer = new Contract(receipt.contractAddress, a.abi, providers[0]);
      const subscriptionReceipt = await sender.send("subscription", await coordinator.createSubscription.populateTransaction());
      const created = subscriptionReceipt.logs.map(l => { try { return coordinator.interface.parseLog(l); } catch { return null; } }).find(l => l?.name === "SubscriptionCreated");
      if (!created) throw new Error("missing subscription receipt");
      const subscriptionId = created.args.subscriptionId;
      await sender.send("fund", await coordinator.fundSubscription.populateTransaction(subscriptionId, { value: 170_000_000_000_000n }));
      await sender.send("register-consumer", await coordinator.addConsumer.populateTransaction(subscriptionId, consumer.target, 100_000, 2));
      result = { format: "proof-vrf-compact-canary/v1", chainId: 46630, coordinator: coordinator.target, consumer: consumer.target,
        consumerDeploymentTransactionHash: receipt.hash, subscriptionId: String(subscriptionId), fundedWei: "170000000000000", status: "prepared" };
      durableJson(v.out, result);
      if (v.request) {
        const quote = await coordinator.quoteMaxPayment(manifest.keyHash, consumer.target, subscriptionId, 100_000, 1);
        const request = await sender.send("one-request", await consumer.request.populateTransaction({ keyHash: manifest.keyHash, subscriptionId,
          requestConfirmations: 2, callbackGasLimit: 100_000, numWords: 1, maxPayment: quote }));
        const event = request.logs.map(l => { try { return coordinator.interface.parseLog(l); } catch { return null; } }).find(l => l?.name === "CompactRequestState");
        if (!event) throw new Error("missing compact creation event");
        Object.assign(result, { status: "requested", quoteWei: String(quote), requestId: String(event.args.requestId), requestTransactionHash: request.hash,
          requestBlockNumber: request.blockNumber, requestGasUsed: String(request.gasUsed), requestFeeWei: String(request.fee) });
        durableJson(v.out, result);
      }
    }
    if (v.report) {
      if (result.coordinator !== coordinator.target || !result.requestId) throw new Error("canary report identity mismatch");
      const recovered = await recoverCompactRequest({ providers, chainId: 46630, coordinatorAddress: coordinator.target, keyHash: manifest.keyHash,
        requestId: result.requestId, fromBlock: result.requestBlockNumber });
      if (recovered.request.status !== 2n || !recovered.request.callbackSucceeded || recovered.transitionCount !== 2) throw new Error("canary has not fulfilled exactly once");
      const head = Math.min(...await Promise.all(providers.map(p => p.send("eth_blockNumber", []).then(x => Number(BigInt(x)))))) - 12;
      const tag = toQuantity(head);
      const evidence = await Promise.all(providers.map(async p => {
        const c = coordinator.connect(p), consumer = new Contract(result.consumer, a.abi, p);
        const logs = [];
        for (let start = result.requestBlockNumber; start <= head; start += 2000) logs.push(...await p.send("eth_getLogs", [{ address: coordinator.target,
          fromBlock: toQuantity(start), toBlock: toQuantity(Math.min(head, start + 1999)) }]));
        const relevant = logs.flatMap(log => {
          const parsed = c.interface.parseLog(log);
          return parsed?.args.requestId === BigInt(result.requestId) ? [{ name: parsed.name, log, args: parsed.args }] : [];
        });
        const proofs = relevant.filter(e => e.name === "ProofVerified"), callbacks = relevant.filter(e => e.name === "CallbackAttempted"), settlements = relevant.filter(e => e.name === "RequestSettled");
        if (proofs.length !== 1 || callbacks.length !== 1 || settlements.length !== 1 || !callbacks[0].args.success) throw new Error("smoke event count/callback mismatch");
        const settled = settlements[0], sub = await c.subscriptions(result.subscriptionId, { blockTag: tag });
        const words = await consumer.lastWords({ blockTag: tag }), expected = await c.randomWords(recovered.request, { blockTag: tag });
        if (String(words) !== String(expected) || words.length !== 1 || sub.reserved !== 0n
            || BigInt(result.fundedWei) - sub.balance !== settled.args.totalCharge
            || settled.args.operatorPayment + settled.args.treasuryPayment !== settled.args.totalCharge) throw new Error("smoke accounting/words mismatch");
        const receipt = await p.send("eth_getTransactionReceipt", [settled.log.transactionHash]);
        const blockHash = (await p.send("eth_getBlockByNumber", [tag, false])).hash;
        return { blockHash, logs: relevant.map(e => e.log), callbackWords: words.map(String), subscriptionBalanceWei: String(sub.balance),
          reservedWei: String(sub.reserved), totalChargeWei: String(settled.args.totalCharge), operatorPaymentWei: String(settled.args.operatorPayment),
          fulfillmentTransactionHash: receipt.transactionHash, fulfillmentGasUsed: String(BigInt(receipt.gasUsed)),
          fulfillmentFeeWei: String(BigInt(receipt.gasUsed) * BigInt(receipt.effectiveGasPrice)) };
      }));
      if (evidence.some(e => JSON.stringify(e) !== JSON.stringify(evidence[0]))) throw new Error("smoke RPC evidence disagreement");
      for (const p of providers) if ((await p.send("eth_getBlockByNumber", [tag, false])).hash !== evidence[0].blockHash) throw new Error("smoke anchor reorg");
      Object.assign(result, { status: "pass", confirmedBlock: head, independentRpcCount: providers.length,
        ...evidence[0], updatedAt: new Date().toISOString() });
      durableJson(v.out, result);
    }
    console.log(JSON.stringify(Object.fromEntries(Object.entries(result).filter(([key]) => key !== "logs"))));
  } finally { providers.forEach(p => p.destroy()); }
}
main().catch(e => { console.error(JSON.stringify(errorDetails(e))); process.exitCode = 1; });

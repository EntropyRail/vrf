#!/usr/bin/env node
// Fork rehearsal is READ-ONLY against upstream RPC. All sends go to in-process EDR.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { ContractFactory, Contract, getAddress } from "ethers";
import { SAFE, ReleaseSender, loadRoleWallet, deployCompactSuite, durableJson } from "./deploy-compact-testnet.mjs";
import { readSecret } from "../operator/secrets.mjs";
import { normalizeRpcUrls } from "../operator/rpc-policy.mjs";
import { publicKeyFor, generateProof } from "../operator/proof.mjs";
import { compactEvents, fulfillCompactClaim, compactArchiveCycle } from "../operator/compact-worker.mjs";
import { errorDetails } from "../operator/errors.mjs";

async function main() {
  const { values } = parseArgs({ options: { "wallet-directory": { type: "string" } }, strict: true });
  const { network, artifacts } = await import("hardhat");
  const urls = normalizeRpcUrls(readSecret("VRF_RPC_URLS", { required: true }), { minimum: 2 });
  const connection = await network.create({ network: "robinhoodFork", override: { forking: { url: urls[0] } } });
  const { ethers } = connection;
  const p = ethers.provider;
  const directory = mkdtempSync(join(tmpdir(), "vrf-v3-fork-"));
  try {
    const arb = await artifacts.readArtifact("MockArbSysForFork");
    await p.send("hardhat_setCode", ["0x0000000000000000000000000000000000000064", arb.deployedBytecode]);
    // Native Nitro fee accounting is NOT emulated by EDR; explicit zero-fee stub.
    await p.send("hardhat_setCode", ["0x000000000000000000000000000000000000006c", "0x600060005260206000f3"]);
    const wrapped = () => new Proxy(p, { get(target, key) {
      if (key === "send") return async (method, args) => method === "eth_gasPrice" ? "0x989680" : p.send(method, args);
      if (key === "broadcastTransaction") return async raw => {
        await p.send("hardhat_setNextBlockBaseFeePerGas", ["0x0"]);
        const tx = await p.broadcastTransaction(raw);
        await p.send("evm_mine", []); await p.send("evm_mine", []);
        return tx;
      };
      const value = target[key]; return typeof value === "function" ? value.bind(target) : value;
    } });
    const providers = [wrapped(), wrapped()];
    const accounts = JSON.parse(readFileSync(join(values["wallet-directory"], "addresses.json"), "utf8"));
    const roles = Object.fromEntries(accounts.accounts.map(a => [a.role, getAddress(a.address)]));
    const wallet = await loadRoleWallet(values["wallet-directory"], "deployer", providers[0]);
    const sender = new ReleaseSender({ wallet, providers, journalPath: join(directory, "transactions.private.json"), maximumWei: 500_000_000_000_000n,
      identity: { kind: "local-fork-only", signer: wallet.address } });
    const testKey = `0x${"11".repeat(32)}`;
    const manifest = await deployCompactSuite({ artifacts, sender, roles, publicKey: publicKeyFor(testKey), gitCommit: "0".repeat(40), out: join(directory, "manifest.json") });
    const canaryWallet = await loadRoleWallet(values["wallet-directory"], "canary-subscription", providers[0]);
    const canarySender = new ReleaseSender({ wallet: canaryWallet, providers, journalPath: join(directory, "canary.private.json"), maximumWei: 200_000_000_000_000n,
      identity: { kind: "local-fork-only-canary" } });
    const ca = await artifacts.readArtifact("VRFServiceCoordinatorV3");
    const coordinator = new Contract(manifest.contracts.coordinator.address, ca.abi, providers[0]);
    const a = await artifacts.readArtifact("ExampleVRFServiceConsumer"), factory = new ContractFactory(a.abi, a.bytecode);
    const consumerReceipt = await canarySender.send("consumer", await factory.getDeployTransaction(coordinator.target, roles["canary-subscription"]));
    const consumer = new Contract(consumerReceipt.contractAddress, a.abi, providers[0]);
    await canarySender.send("subscription", await coordinator.createSubscription.populateTransaction());
    await canarySender.send("fund", await coordinator.fundSubscription.populateTransaction(1, { value: 170_000_000_000_000n }));
    await canarySender.send("consumer-register", await coordinator.addConsumer.populateTransaction(1, consumer.target, 100_000, 2));
    const quote = await coordinator.quoteMaxPayment(manifest.keyHash, consumer.target, 1, 100_000, 1);
    const request = await canarySender.send("request", await consumer.request.populateTransaction({ keyHash: manifest.keyHash, subscriptionId: 1,
      requestConfirmations: 2, callbackGasLimit: 100_000, numWords: 1, maxPayment: quote }));
    const events = await compactEvents({ providers, manifest, fromBlock: request.blockNumber, toBlock: request.blockNumber });
    const pending = events[0];
    // Exercise independent V3 archival and recover outside the 256-block native window.
    for (let i = 0; i < 40; i++) await p.send("evm_mine", []);
    const archiverWallet = await loadRoleWallet(values["wallet-directory"], "archiver", providers[0]);
    const archiveSender = new ReleaseSender({ wallet: archiverWallet, providers, journalPath: join(directory, "archive.private.json"), maximumWei: 10_000_000_000_000n,
      identity: { kind: "local-fork-only-archive" } });
    const archived = await compactArchiveCycle({ providers, manifest, budget: { checkpoint() {}, recordMissed() { throw new Error("fork missed archive"); } },
      send: ({ transaction }) => archiveSender.send("archive", transaction) });
    for (let i = 0; i < 260; i++) await p.send("evm_mine", []);
    const fulfiller = await loadRoleWallet(values["wallet-directory"], "fulfiller", providers[0]);
    const fulfillerSender = new ReleaseSender({ wallet: fulfiller, providers, journalPath: join(directory, "fulfiller.private.json"), maximumWei: 50_000_000_000_000n,
      identity: { kind: "local-fork-only-fulfiller" } });
    const result = await fulfillCompactClaim({ providers, manifest, pending, from: fulfiller.address, gasPriceWei: 10_000_000n,
      proofProvider: { prove: args => generateProof({ privateKey: testKey, actualSeed: args.actualSeed, preSeed: args.preSeed }) },
      send: ({ transaction }) => fulfillerSender.send("fulfill", transaction) });
    if (!result.callbackSucceeded || archived.archived !== 1 || (await consumer.lastWords()).length !== 1
        || (await coordinator.subscriptions(1)).reserved !== 0n) throw new Error("fork canary failed");
    const report = { status: "pass", scope: "local Robinhood fork only; synthetic ArbSys and zero Nitro L1 fee; duplicated local RPC wrappers are NOT independent providers",
      upstreamTransactionsSent: 0, directory, safeRuntimePinned: SAFE.proxyHash, coordinator: manifest.contracts.coordinator.address,
      deploymentGas: Object.values(manifest.contracts).reduce((n, c) => n + Number(c.gasUsed), 0),
      simulatedDeploymentFeeWei: manifest.totalDeploymentFeeWei, quoteWei: String(quote), archived, result };
    durableJson(join(directory, "report.json"), report); console.log(JSON.stringify(report));
  } finally { await connection.close(); }
}
main().catch(e => { console.error(JSON.stringify(errorDetails(e))); process.exitCode = 1; });

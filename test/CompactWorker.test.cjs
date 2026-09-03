const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { fixture, TEST_KEY } = require("./helpers/compact.cjs");

async function setup() {
  const f = await fixture({ nativeContext: true });
  const worker = await import("../operator/compact-worker.mjs");
  const p = f.ethers.provider;
  const wrap = transform => new Proxy(p, { get(target, key) {
    if (key === "send") return async (m, args) => {
      const result = await p.send(m, args); return transform ? transform(m, result) : result;
    };
    const value = target[key]; return typeof value === "function" ? value.bind(target) : value;
  } });
  const providers = [wrap(), wrap()];
  const created = await f.request();
  await p.send("hardhat_mine", ["0x4"]);
  const manifest = { chainId: 31337, keyHash: f.keyHash, contracts: {
    coordinator: { address: f.coordinator.target, blockNumber: (await f.coordinator.deploymentTransaction().wait()).blockNumber },
    blockhashStore: { address: f.store.target } } };
  const pending = { requestId: String(created.requestId), eventBlockNumber: created.receipt.blockNumber };
  return { ...f, worker, providers, manifest, created, pending, wrap };
}
describe("V3 isolated worker", () => {
  it("scans canonical full witnesses with two RPCs and rejects omission, reorg, duplicate and L2 mismatch", async () => {
    const f = await setup();
    const options = { providers: f.providers, manifest: f.manifest, fromBlock: f.manifest.contracts.coordinator.blockNumber,
      toBlock: await f.worker.compactHead(f.providers, 31337) };
    const events = await f.worker.compactEvents(options);
    assert.equal(events.length, 1); assert.equal(events[0].witness.status, "1");
    assert.equal(events[0].requestId, f.pending.requestId);
    await assert.rejects(f.worker.compactEvents({ ...options, providers: [f.providers[0]] }), /two distinct/);
    await assert.rejects(f.worker.compactEvents({ ...options, providers: [f.providers[0], f.wrap((m, r) => m === "eth_getLogs" ? [] : r)] }), /Disagreement/);
    await assert.rejects(f.worker.compactEvents({ ...options, providers: [f.wrap((m, r) => m === "eth_getLogs" ? [...r, ...r] : r), f.providers[1]] }), /duplicate/);
    let reads = 0;
    await assert.rejects(f.worker.compactEvents({ ...options, providers: [f.wrap((m, r) => m === "eth_getBlockByNumber" && ++reads > 1 ? { ...r, hash: f.ethers.ZeroHash } : r), f.providers[1]] }), /reorg/);
  });
  it("persists witness evidence before committing a scan, releases a failed lease", async () => {
    const f = await setup(), calls = [];
    const store = { pool: { query: async () => calls.push("persist") },
      claimScan: async () => ({ fromBlock: f.manifest.contracts.coordinator.blockNumber, toBlock: await f.worker.compactHead(f.providers, 31337) }),
      commitScan: async value => { calls.push("commit"); assert.equal(value.requested[0].requestId, f.pending.requestId); },
      releaseScan: async () => calls.push("release") };
    await f.worker.compactScan({ providers: f.providers, manifest: f.manifest, store, instanceId: "test" });
    assert.deepEqual(calls, ["persist", "commit"]);
    store.pool.query = async () => { throw new Error("database disconnected"); };
    await assert.rejects(f.worker.compactScan({ providers: f.providers, manifest: f.manifest, store, instanceId: "test" }), /disconnected/);
    assert.equal(calls.at(-1), "release");
  });
  it("fulfills using a witness-bound proof, then recognizes a duplicate claim without a second transaction", async () => {
    const f = await setup(); let sent = 0;
    const options = { providers: f.providers, manifest: f.manifest, pending: f.pending, from: f.fulfiller.address,
      gasPriceWei: 1_000_000_000n, proofProvider: { prove: args => f.proofTools.generateProof({ privateKey: TEST_KEY, actualSeed: args.actualSeed, preSeed: args.preSeed }) },
      send: async ({ transaction }) => { sent++; return (await f.fulfiller.sendTransaction(transaction)).wait(); } };
    const result = await f.worker.fulfillCompactClaim(options);
    assert.equal(result.callbackSucceeded, true);
    assert.equal((await f.worker.fulfillCompactClaim(options)).finalized, true);
    assert.equal(sent, 1); assert.equal((await f.consumer.lastWords()).length, 1);
  });
  it("archives independently of the Operator queue, and does not duplicate an existing archive", async () => {
    const f = await setup();
    // EDR fast-mining has synthetic intermediate blocks; archive reads historic state.
    for (let i = 0; i < 40; i++) await f.ethers.provider.send("evm_mine", []);
    let sent = 0, saved = 0;
    const options = { providers: f.providers, manifest: f.manifest, budget: { checkpoint() {}, recordMissed() { throw new Error("unexpected miss"); } },
      saveEvents: async events => { saved += events.length; },
      send: async ({ transaction }) => { sent++; return (await f.outsider.sendTransaction(transaction)).wait(); } };
    assert.equal((await f.worker.compactArchiveCycle(options)).archived, 1);
    assert.equal((await f.worker.compactArchiveCycle(options)).archived, 0);
    assert.equal(sent, 1); assert.equal(saved, 2);
    assert.notEqual(await f.store.blockhashes(f.created.witness.requestBlock), f.ethers.ZeroHash);
  });
  it("rejects V2 and mainnet deployment manifests", async () => {
    const { validateCompactManifest } = await import("../operator/run-compact.mjs");
    assert.throws(() => validateCompactManifest({ format: "robinhood-proof-vrf-deployment/v1", chainId: 46630 }), /V3 testnet/);
    assert.throws(() => validateCompactManifest({ format: "robinhood-proof-vrf-deployment/v3", chainId: 4663 }), /V3 testnet/);
  });
});

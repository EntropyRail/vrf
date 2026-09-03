const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { createServer } = require("node:http");
const { fixture, state, TEST_KEY } = require("./helpers/compact.cjs");

async function setup() {
  const f = await fixture();
  const sdk = await import("../operator/compact-protocol.mjs");
  const pending = await f.request();
  await f.context.setBlockNumber(1_000_002);
  const proxy = transform => ({ send: async (method, params) => {
    const result = await f.ethers.provider.send(method, params);
    return transform ? transform(method, result, params) : result;
  } });
  const options = { providers: [proxy(), proxy()], chainId: (await f.ethers.provider.getNetwork()).chainId,
    coordinatorAddress: f.coordinator.target, requestId: pending.requestId, keyHash: f.keyHash,
    fromBlock: (await f.coordinator.deploymentTransaction().wait()).blockNumber,
  };
  return { ...f, sdk, pending, proxy, options };
}

describe("Compact witness protocol and read-only transaction preparation", () => {
  it("remote proof client sends a canonical witness without trusting or forwarding a client-selected seed", async () => {
    const f = await setup();
    const { RemoteProofProvider } = await import("../operator/proof-provider.mjs");
    const remote = new RemoteProofProvider({ baseUrl: "http://127.0.0.1:1", timeoutMs: 1_000 });
    const generated = await f.proof(f.pending.witness);
    remote.request = async (path, payload) => {
      if (path === "/v1/status") return { serviceKeyHash: f.keyHash, publicKey: f.proofTools.publicKeyFor(TEST_KEY).map(String) };
      assert.deepEqual(Object.keys(payload).sort(), ["chainId", "compactWitness", "coordinator", "requestId", "scheme", "serviceKeyHash"]);
      assert.deepEqual(payload.compactWitness, f.sdk.serializeCompactWitness(f.pending.witness));
      return { serviceKeyHash: f.keyHash, actualSeed: String(generated.actualSeed), preSeed: String(f.pending.witness.preSeed), proof: generated.proof };
    };
    await remote.initialize(f.keyHash);
    const result = await remote.prove({ actualSeed: generated.actualSeed, preSeed: f.pending.witness.preSeed,
      requestId: f.pending.requestId, coordinator: f.coordinator.target, chainId: f.options.chainId,
      compactWitness: f.pending.witness });
    assert.equal(result.output, generated.output);
  });

  it("round-trips the exact Solidity commitment, validates JSON types/bounds and binds chain/address", async () => {
    const f = await setup();
    const serialized = f.sdk.serializeCompactWitness(f.pending.witness);
    assert.equal(f.sdk.compactCommitment(serialized, f.options.chainId, f.coordinator.target), await f.coordinator.commitments(f.pending.requestId));
    assert.equal(f.sdk.compactRequestId(serialized), f.pending.requestId);
    assert.notEqual(f.sdk.compactCommitment(serialized, f.options.chainId + 1n, f.coordinator.target), await f.coordinator.commitments(f.pending.requestId));
    for (const invalid of [null, [], {}, { ...serialized, extra: 1 }, { ...serialized, status: "256" },
      { ...serialized, sponsored: "false" }, { ...serialized, reservedPayment: Number.MAX_SAFE_INTEGER + 1 },
      { ...serialized, callbackAttempts: "-1" }, { ...serialized, preSeed: "0x123" }]) {
      assert.throws(() => f.sdk.normalizeCompactWitness(invalid));
    }
    assert.ok(JSON.stringify(serialized).length < 3_500);
  });

  it("recovers pending/failed/retried state from events and prepares an independently simulated ECVRF fulfillment", async () => {
    const f = await setup();
    await f.consumer.connect(f.subscriber).setRevertCallbacks(true);
    const recovered = await f.sdk.recoverCompactRequest({ ...f.options, includeSeed: true });
    assert.equal(recovered.transitionCount, 1);
    assert.equal(recovered.actualSeed, await f.coordinator.requestSeed(f.pending.witness));
    let proves = 0;
    const proofProvider = { prove: async args => {
      proves++;
      assert.equal(args.compactWitness.preSeed, String(f.pending.witness.preSeed));
      return f.proofTools.generateProof({ privateKey: TEST_KEY, actualSeed: args.actualSeed, preSeed: args.preSeed });
    } };
    const prepared = await f.sdk.prepareCompactTransaction({ ...f.options, proofProvider,
      from: f.fulfiller.address, gasPriceWei: 1_000_000_000n });
    assert.equal(proves, 1);
    assert.equal((await f.coordinator.getRequest(f.pending.witness)).status, 1n, "preparation must not broadcast");
    const receipt = await (await f.fulfiller.sendTransaction(prepared.transaction)).wait();
    const failed = state(receipt, f.coordinator);
    assert.equal(failed.witness.callbackSucceeded, false);
    const after = await f.sdk.recoverCompactRequest(f.options);
    assert.equal(after.transitionCount, 2);
    assert.equal(after.request.randomness, failed.witness.randomness);
    await f.consumer.connect(f.subscriber).setRevertCallbacks(false);
    const retry = await f.sdk.prepareCompactTransaction({ ...f.options, action: "retryCallback",
      from: f.outsider.address, gasPriceWei: 1_000_000_000n });
    await (await f.outsider.sendTransaction(retry.transaction)).wait();
    const final = await f.sdk.recoverCompactRequest(f.options);
    assert.equal(final.transitionCount, 3);
    assert.equal(final.request.callbackAttempts, 2n);
    assert.equal(final.request.callbackSucceeded, true);
    await assert.rejects(f.sdk.verifyCompactWitnessConsensus({ ...f.options, witness: failed.witness }), /commitment mismatch/);
  });

  it("fails closed on omitted creation/final events, missing middle transitions, duplicates and disagreement", async () => {
    const f = await setup();
    await f.consumer.connect(f.subscriber).setRevertCallbacks(true);
    const failed = await f.fulfill(f.pending.witness);
    await f.coordinator.retryCallback(failed.witness);
    for (const [filter, error] of [
      [logs => [], /creation event/],
      [logs => logs.slice(1), /creation event/],
      [logs => logs.slice(0, -1), /commitment mismatch/],
      [logs => [logs[0], logs[2]], /state transition/],
      [logs => [...logs, logs[0]], /duplicate compact event/],
    ]) {
      const provider = () => f.proxy((method, result) => method === "eth_getLogs" ? filter(result) : result);
      await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, providers: [provider(), provider()] }), error);
    }
    await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, providers: [f.proxy(), f.proxy((m, r) => m === "eth_getLogs" ? r.slice(0, -1) : r)] }), /history disagreement/);
    const states = [f.pending.witness, failed.witness, { ...failed.witness, callbackAttempts: 2n, payee: f.outsider.address }];
    assert.throws(() => f.sdk.validateCompactTransitions(states), /immutable fields/);
  });

  it("rejects one RPC, chain mismatch, forked anchors, mid-read reorg and canonical-seed disagreement", async () => {
    const f = await setup();
    await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, providers: [f.proxy()] }), /two distinct providers/);
    await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, chainId: 1n }), /chainId mismatch/);
    const wrongHash = f.ethers.id("fork");
    await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, providers: [f.proxy(), f.proxy((m, r) => m === "eth_getBlockByNumber" ? { ...r, hash: wrongHash } : r)] }), /anchor disagreement/);
    let reads = 0;
    const reorg = f.proxy((m, r) => m === "eth_getBlockByNumber" && ++reads > 1 ? { ...r, hash: wrongHash } : r);
    await assert.rejects(f.sdk.recoverCompactRequest({ ...f.options, providers: [f.proxy(), reorg] }), /anchor changed/);
    const iface = new f.ethers.Interface(f.sdk.COMPACT_ABI);
    const malicious = f.proxy((m, r, p) => m === "eth_call" && p[0].data.startsWith(iface.getFunction("requestSeed").selector)
      ? iface.encodeFunctionResult("requestSeed", [123]) : r);
    await assert.rejects(f.sdk.verifyCompactWitnessConsensus({ ...f.options, providers: [f.proxy(), malicious], witness: f.pending.witness, includeSeed: true }), /seed disagreement/);
  });

  it("refuses transaction preparation after a concurrent settlement or without threshold witness support", async () => {
    const f = await setup();
    await assert.rejects(f.sdk.prepareCompactTransaction({ ...f.options, proofProvider: { mode: "threshold-bls" }, from: f.fulfiller.address, gasPriceWei: 1n }), /not integrated/);
    await assert.rejects(f.sdk.prepareCompactTransaction({ ...f.options, from: f.outsider.address, gasPriceWei: 1n }), /not the pinned fulfiller/);
    const proofProvider = { prove: async () => {
      const result = await f.fulfill(f.pending.witness);
      return result;
    } };
    await assert.rejects(f.sdk.prepareCompactTransaction({ ...f.options, proofProvider, from: f.fulfiller.address, gasPriceWei: 1n }), /commitment mismatch/);
  });

  it("prepares expiry/pruning without a proof key and refuses recovery after prune", async () => {
    const f = await setup();
    await f.context.setBlockNumber(1_000_601);
    const expire = await f.sdk.prepareCompactTransaction({ ...f.options, action: "expireRequest", from: f.outsider.address, gasPriceWei: 1_000_000_000n });
    await (await f.outsider.sendTransaction(expire.transaction)).wait();
    assert.equal((await f.sdk.recoverCompactRequest(f.options)).request.status, 3n);
    await f.context.setBlockNumber(1_050_601);
    const prune = await f.sdk.prepareCompactTransaction({ ...f.options, action: "pruneRequest", from: f.outsider.address, gasPriceWei: 1_000_000_000n });
    await (await f.outsider.sendTransaction(prune.transaction)).wait();
    await assert.rejects(f.sdk.recoverCompactRequest(f.options), /commitment mismatch/);
  });

  it("isolated prover resolves the compact witness via two HTTP RPCs and rejects client seed/status forgery", async t => {
    const f = await setup();
    const urls = [];
    for (let i = 0; i < 2; i++) {
      const server = createServer(async (req, res) => {
        const chunks = [];
        for await (const chunk of req) chunks.push(chunk);
        const payload = JSON.parse(Buffer.concat(chunks).toString());
        const process = async call => {
          try { return { jsonrpc: "2.0", id: call.id, result: await f.ethers.provider.send(call.method, call.params) }; }
          catch { return { jsonrpc: "2.0", id: call.id, error: { code: -32000, message: "local RPC rejected call" } }; }
        };
        const results = Array.isArray(payload) ? await Promise.all(payload.map(process)) : await process(payload);
        res.setHeader("content-type", "application/json"); res.end(JSON.stringify(results));
      });
      await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
      t.after(() => new Promise(resolve => server.close(resolve)));
      urls.push(`http://127.0.0.1:${server.address().port}`);
    }
    const { resolveProofRequest } = await import("../operator/prover-server.mjs");
    const options = { rpcUrls: urls, coordinatorAddress: f.coordinator.target, chainId: f.options.chainId,
      keyHash: f.keyHash, requestId: f.pending.requestId, compactWitness: f.sdk.serializeCompactWitness(f.pending.witness) };
    const result = await resolveProofRequest(options);
    assert.equal(result.actualSeed, await f.coordinator.requestSeed(f.pending.witness));
    await assert.rejects(resolveProofRequest({ ...options, compactWitness: { ...options.compactWitness, preSeed: "42" } }), /requestId mismatch/);
    await assert.rejects(resolveProofRequest({ ...options, compactWitness: { ...options.compactWitness, status: "2" } }), /commitment mismatch/);
  });
});

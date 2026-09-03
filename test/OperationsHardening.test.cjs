const assert = require("node:assert/strict");
const { before, describe, it } = require("node:test");
const { mkdtempSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { Interface } = require("ethers");
let errors, rpc, archive, operator;
before(async () => {
  errors = await import("../operator/errors.mjs");
  rpc = await import("../operator/rpc.mjs");
  archive = await import("../operator/archiver.mjs");
  ({ internals: operator } = await import("../operator/cli.mjs"));
});

describe("operational error evidence", () => {
  it("preserves the nested RPC reason without disclosing URLs, keys, headers, or params", () => {
    const error = { code: "UNKNOWN_ERROR", shortMessage: "could not coalesce error",
      message: "request https://rpc.example/token-secret failed", info: {
        error: { code: -32000, message: "nonce too low; Bearer hidden-token; privateKey=hidden-key" },
        payload: { method: "eth_sendRawTransaction", params: ["never-print-raw-tx"] },
      }, privateKey: "do-not-print", request: { headers: { authorization: "never-print-header" } } };
    const result = JSON.stringify(errors.errorDetails(error));
    assert.match(result, /nonce too low/);
    assert.match(result, /eth_sendRawTransaction/);
    for (const secret of ["token-secret", "hidden-token", "hidden-key", "never-print", "do-not-print"]) {
      assert.equal(result.includes(secret), false);
    }
    assert.match(errors.errorMessage(error), /nonce too low/);
  });
  it("handles cycles, huge messages and private-key-shaped hex", () => {
    const error = new Error(`postgresql://user:secret@db/test 0x${"12".repeat(32)}`);
    error.cause = error;
    const out = JSON.stringify(errors.errorDetails(error));
    assert.equal(out.includes("secret"), false);
    assert.equal(out.includes("12".repeat(32)), false);
    assert.ok(errors.redactText("x".repeat(5000)).length <= 1200);
  });
});

describe("nonce failover safety", () => {
  it("reads fresh pending nonces and rejects RPC disagreement", async () => {
    const provider = value => ({ send: async (method, args) => {
      assert.equal(method, "eth_getTransactionCount"); assert.equal(args[1], "pending"); return value;
    } });
    assert.equal(await rpc.pendingNonceConsensus([provider("0x7"), provider("0x7")], "address"), 7);
    await assert.rejects(rpc.pendingNonceConsensus([provider("0x7"), provider("0x8")], "address"), /Disagreement/);
    await assert.rejects(rpc.pendingNonceConsensus([provider("0x20000000000000")], "address"), /InvalidRpcNonce/);
  });
  it("does not broadcast after the database nonce lease is lost", async () => {
    let broadcasts = 0;
    await assert.rejects(operator.sendWithReplacement({
      wallet: { address: "0x1111111111111111111111111111111111111111", getNonce: async () => 1,
        populateTransaction: async x => x, signTransaction: async () => "0x1234" },
      provider: { estimateGas: async () => 100n, getFeeData: async () => ({ gasPrice: 1n }),
        broadcastTransaction: async () => { broadcasts++; } },
      transactionRequest: {}, maxGasPrice: 10n, timeoutMs: 100, maximumAttempts: 1,
      assertLease: async () => { throw new Error("RelayerNonceLeaseLost"); },
    }), /LeaseLost/);
    assert.equal(broadcasts, 0);
  });
});

function fakeRpc({ disagreement = false, requestBlock = 64, status = 1, lateHead } = {}) {
  const iface = new Interface(operator.SERVICE_ABI);
  const storeIface = new Interface(operator.BLOCKHASH_STORE_ABI);
  const zero = `0x${"00".repeat(32)}`;
  const keyHash = `0x${"11".repeat(32)}`;
  const fields = iface.getFunction("getRequest").outputs[0].components;
  const request = Object.fromEntries(fields.map(f => [f.name, f.type === "address"
    ? "0x1111111111111111111111111111111111111111" : f.type === "bytes32" ? zero : f.type === "bool" ? false : 0n]));
  Object.assign(request, { requestBlock, status, keyHash, maxGasPriceWei: 100n });
  const encoded = iface.encodeEventLog(iface.getEvent("RandomWordsRequested"),
    [keyHash, 9, request.consumer, 1, 2, requestBlock, 7200, 100000, 1, 100, false]);
  let heights = 0;
  return {
    get provider() { return this; },
    getBlockNumber: async () => (++heights > 1 && lateHead !== undefined ? lateHead : 100),
    getBlock: async () => ({ hash: zero }),
    getLogs: async () => disagreement ? [] : [{ ...encoded, address: request.consumer,
      blockNumber: requestBlock, blockHash: zero, transactionHash: zero, index: 0, transactionIndex: 0 }],
    call: async tx => {
      if (tx.data.startsWith(storeIface.getFunction("blockhashes").selector)) return storeIface.encodeFunctionResult("blockhashes", [zero]);
      const decoded = iface.parseTransaction(tx);
      if (decoded.name === "contextBlockNumber") return iface.encodeFunctionResult(decoded.name, [98]);
      if (decoded.name === "getRequest") return iface.encodeFunctionResult(decoded.name, [request]);
      throw new Error(`unexpected fake call ${decoded.name}`);
    },
  };
}
describe("independent archival protection", () => {
  const zero = `0x${"00".repeat(32)}`;
  const manifest = { keyHash: `0x${"11".repeat(32)}`, contracts: {
    coordinator: { address: "0x1111111111111111111111111111111111111111", blockNumber: 0 },
    blockhashStore: { address: "0x2222222222222222222222222222222222222222" },
  } };
  it("handles the 256-block boundary and skips protected/finalized requests", () => {
    assert.equal(archive.archiveDecision({ status: 1, requestBlock: 100 }, zero, 131), "young");
    assert.equal(archive.archiveDecision({ status: 1, requestBlock: 100 }, zero, 132), "archive");
    assert.equal(archive.archiveDecision({ status: 1, requestBlock: 100 }, zero, 356), "archive");
    assert.equal(archive.archiveDecision({ status: 1, requestBlock: 100 }, zero, 357), "missed-window");
    assert.equal(archive.archiveDecision({ status: 1, requestBlock: 100 }, `0x${"ab".repeat(32)}`, 900), "protected");
    assert.equal(archive.archiveDecision({ status: 2, requestBlock: 100 }, zero, 200), "finalized");
  });
  it("archives without a prover or an Operator scan/request lease", async () => {
    const calls = [];
    const result = await archive.archiveCycle({ providers: [fakeRpc(), fakeRpc()], manifest,
      budget: { checkpoint: x => calls.push(["checkpoint", x]) },
      sendArchive: async x => calls.push(["archive", x.requestId]) });
    assert.equal(result.archived, 1);
    assert.equal(result.errors.length, 0);
    assert.deepEqual(calls[0], ["archive", "9"]);
  });
  it("refuses archival when independent event sets disagree", async () => {
    let sends = 0;
    await assert.rejects(archive.archiveCycle({ providers: [fakeRpc(), fakeRpc({ disagreement: true })], manifest,
      budget: { checkpoint() {} }, sendArchive: async () => sends++ }), /Disagreement/);
    assert.equal(sends, 0);
  });
  it("refreshes height after slow RPC reads and flags a missed window", async () => {
    let sends = 0;
    const result = await archive.archiveCycle({ providers: [fakeRpc({ lateHead: 321 }), fakeRpc({ lateHead: 321 })], manifest,
      budget: { checkpoint() {} }, sendArchive: async () => sends++ });
    assert.equal(result.missedWindow, 1);
    assert.equal(sends, 0);
  });
  it("persists its spending ceiling and flags gaps across restart", () => {
    const path = join(mkdtempSync(join(tmpdir(), "vrf-archive-budget-")), "state.json");
    const identity = { chainId: "46630", coordinator: "test" };
    const budget = new archive.ArchiveBudget(path, identity, 100n);
    budget.reserve({ gasLimit: 10n, gasPriceWei: 3n, transactionHash: "hash" });
    budget.checkpoint(100);
    const restarted = new archive.ArchiveBudget(path, identity, 100n);
    assert.equal(restarted.remaining, 70n);
    assert.throws(() => restarted.reserve({ gasLimit: 10n, gasPriceWei: 8n }), /Exhausted/);
    restarted.checkpoint(400);
    assert.deepEqual(restarted.state.coverageGap, { afterBlock: 100, resumedBlock: 400 });
    assert.throws(() => new archive.ArchiveBudget(path, identity, 200n), /differs/);
  });
});

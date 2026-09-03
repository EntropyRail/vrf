const assert = require("node:assert/strict");
const { describe, it } = require("node:test");
const { mkdtempSync, readFileSync, statSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

describe("V3 testnet release journal", () => {
  async function setup(maximumWei = 1_000_000_000_000_000n) {
    const { ReleaseSender } = await import("../scripts/deploy-compact-testnet.mjs");
    const { Wallet, keccak256 } = await import("ethers");
    const wallet = Wallet.createRandom(); let sent = 0, receipt = null, timeout = true;
    const directory = mkdtempSync(join(tmpdir(), "vrf-release-journal-")), journalPath = join(directory, "journal.json");
    const p = () => ({ send: async (m) => ({ eth_chainId: "0xb626", eth_gasPrice: "0x989680", eth_getTransactionCount: "0x0",
      eth_getTransactionReceipt: receipt ? { blockHash: receipt.blockHash, status: "0x1", gasUsed: "0x5208" } : null })[m],
      estimateGas: async () => 21000n, getBalance: async () => maximumWei,
      getTransactionReceipt: async () => receipt,
      broadcastTransaction: async raw => { sent++; const hash = keccak256(raw);
        return { wait: async () => { if (timeout) throw new Error("timeout"); receipt = { hash, status: 1, blockHash: "0x" + "ab".repeat(32), blockNumber: 1, gasUsed: 21000n, fee: 210000000000n }; return receipt; } }; } });
    const options = { wallet, providers: [p(), p()], journalPath, maximumWei, identity: { test: true, signer: wallet.address } };
    return { ReleaseSender, options, sender: new ReleaseSender(options), sent: () => sent, resume: () => { timeout = false; }, journalPath };
  }
  it("journals before broadcast and reuses identical signed bytes after a timeout/restart", async () => {
    const f = await setup(), request = { to: f.options.wallet.address, value: 0n };
    await assert.rejects(f.sender.send("step", request), /timeout/);
    const first = JSON.parse(readFileSync(f.journalPath, "utf8"));
    assert.equal(first.transactions.step.status, "signed");
    assert.equal(statSync(f.journalPath).mode & 0o077, 0);
    f.resume();
    const next = new f.ReleaseSender(f.options);
    const receipt = await next.send("step", request);
    assert.equal(receipt.hash, first.transactions.step.hash);
    assert.equal(next.journal.reservedWei, first.reservedWei);
    await next.send("step", request);
    assert.equal(f.sent(), 2);
    await assert.rejects(next.send("step", { ...request, value: 1n }), /differs/);
  });
  it("does not broadcast above the total budget or on chain/nonce disagreement", async () => {
    const f = await setup(1n);
    await assert.rejects(f.sender.send("step", { to: f.options.wallet.address }), /budget/);
    assert.equal(f.sent(), 0);
    const g = await setup();
    g.options.providers[1].send = async () => "0x123";
    await assert.rejects(g.sender.send("step", { to: g.options.wallet.address }), /46630/);
    assert.equal(g.sent(), 0);
  });
});

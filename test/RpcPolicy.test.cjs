const assert = require("node:assert/strict");
const { before, describe, it } = require("node:test");

let normalizeRpcUrls;

before(async function () {
  ({ normalizeRpcUrls } = await import("../operator/rpc-policy.mjs"));
});

describe("RPC endpoint policy", function () {
  it("accepts HTTPS endpoints on independent origins", function () {
    assert.deepEqual(normalizeRpcUrls([
      "https://rpc-a.example/token-a",
      "https://rpc-b.example/token-b",
    ], { minimum: 2 }), [
      "https://rpc-a.example/token-a",
      "https://rpc-b.example/token-b",
    ]);
  });

  it("rejects multiple tokens behind the same provider origin", function () {
    assert.throws(() => normalizeRpcUrls([
      "https://rpc.example/token-a",
      "https://rpc.example/token-b",
    ], { minimum: 2 }), /distinct origins/);
  });

  it("permits an explicitly marked shared-origin testnet input", function () {
    assert.equal(normalizeRpcUrls([
      "https://rpc.example/token-a",
      "https://rpc.example/token-b",
    ], { minimum: 2, allowSharedOrigin: true }).length, 2);
  });

  it("rejects plaintext non-loopback RPC transport", function () {
    assert.throws(
      () => normalizeRpcUrls(["http://rpc.example"], { minimum: 1 }),
      /must use HTTPS/,
    );
  });
});

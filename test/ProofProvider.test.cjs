const assert = require("node:assert/strict");
const http = require("node:http");
const { after, before, describe, it } = require("node:test");
const { keccak256 } = require("ethers");

const VRF_PRIVATE_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";

let proofProviderTools;
let proofTools;
let server;
let baseUrl;
let publicKey;
let keyHash;

function serializableProof(proof) {
  return Object.fromEntries(Object.entries(proof).map(([name, value]) => [
    name,
    Array.isArray(value) ? value.map(String) : typeof value === "bigint" ? value.toString() : value,
  ]));
}

before(async function () {
  proofProviderTools = await import("../operator/proof-provider.mjs");
  proofTools = await import("../operator/proof.mjs");
  publicKey = proofTools.publicKeyFor(VRF_PRIVATE_KEY);
  keyHash = proofTools.serviceKeyHash(publicKey);
  server = http.createServer(async (request, response) => {
    response.setHeader("content-type", "application/json");
    if (request.method === "GET" && request.url === "/v1/status") {
      response.end(JSON.stringify({ publicKey: publicKey.map(String), serviceKeyHash: keyHash }));
      return;
    }
    if (request.method === "POST" && request.url === "/v1/proofs") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      const result = proofTools.generateProof({
        privateKey: VRF_PRIVATE_KEY,
        actualSeed: 123n,
        preSeed: 456n,
      });
      response.end(JSON.stringify({
        serviceKeyHash: keyHash,
        actualSeed: "123",
        preSeed: "456",
        proof: serializableProof(result.proof),
      }));
      return;
    }
    response.statusCode = 404;
    response.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async function () {
  if (server) await new Promise((resolve) => server.close(resolve));
});

describe("RemoteProofProvider", function () {
  it("loads an authenticated key identity and normalizes a remote proof", async function () {
    const provider = await new proofProviderTools.RemoteProofProvider({
      baseUrl,
      bearerToken: "test-only-token",
      timeoutMs: 2_000,
    }).initialize(keyHash);
    const result = await provider.prove({
      actualSeed: 123n,
      preSeed: 456n,
      requestId: 7n,
      coordinator: "0x0000000000000000000000000000000000000001",
      chainId: 46630n,
    });
    assert.equal(provider.keyHash, keyHash);
    assert.equal(result.proof.seed, 456n);
    assert.equal(result.output, proofTools.outputForProof(result.proof));
  });

  it("rejects plaintext remote endpoints outside loopback", function () {
    assert.throws(
      () => new proofProviderTools.RemoteProofProvider({
        baseUrl: "http://prover.example",
        timeoutMs: 2_000,
      }),
      /must use HTTPS/,
    );
  });

  it("rejects a status key that differs from the configured commitment", async function () {
    const provider = new proofProviderTools.RemoteProofProvider({
      baseUrl,
      timeoutMs: 2_000,
    });
    await assert.rejects(
      provider.initialize(`0x${"00".repeat(32)}`),
      /does not match --proof-key-hash/,
    );
  });
});

describe("ECVRF proof properties", function () {
  it("is deterministic and produces distinct outputs for boundary seeds", function () {
    const seeds = [0n, 1n, 2n, 255n, 256n, 2n ** 128n, (2n ** 256n) - 1n];
    const outputs = new Set();
    for (const actualSeed of seeds) {
      const first = proofTools.generateProof({
        privateKey: VRF_PRIVATE_KEY,
        actualSeed,
        preSeed: actualSeed,
      });
      const second = proofTools.generateProof({
        privateKey: VRF_PRIVATE_KEY,
        actualSeed,
        preSeed: actualSeed,
      });
      assert.deepEqual(first, second);
      outputs.add(first.output.toString());
    }
    assert.equal(outputs.size, seeds.length);
  });
});

describe("PostgresOperatorStore helpers", function () {
  it("rejects unsafe block numbers before they reach SQL", async function () {
    const { internals } = await import("../operator/postgres-store.mjs");
    assert.throws(
      () => internals.safeBlockNumber("9007199254740992", "block"),
      /safe integer range/,
    );
  });
});

describe("operator transaction durability", function () {
  it("journals a signed transaction before broadcasting it", async function () {
    const { internals } = await import("../operator/cli.mjs");
    const order = [];
    const signedTransaction = "0x1234";
    const transactionHash = keccak256(signedTransaction);
    const provider = {
      estimateGas: async () => 100_000n,
      getFeeData: async () => ({ gasPrice: 10n }),
      broadcastTransaction: async (raw) => {
        assert.equal(raw, signedTransaction);
        order.push("broadcast");
        return {
          hash: transactionHash,
          wait: async () => ({ hash: transactionHash, blockNumber: 1 }),
        };
      },
    };
    const wallet = {
      address: "0x1111111111111111111111111111111111111111",
      getNonce: async () => 7,
      populateTransaction: async (request) => request,
      signTransaction: async () => signedTransaction,
    };
    const receipt = await internals.sendWithReplacement({
      wallet,
      provider,
      transactionRequest: { to: wallet.address, data: "0x" },
      maxGasPrice: 100n,
      timeoutMs: 1_000,
      maximumAttempts: 1,
      onBroadcast: async ({ transactionHash: recordedHash, nonce }) => {
        assert.equal(recordedHash, transactionHash);
        assert.equal(nonce, 7);
        order.push("journal");
      },
    });
    assert.equal(receipt.hash, transactionHash);
    assert.deepEqual(order, ["journal", "broadcast"]);
  });

  it("constructs a quorum-one fallback provider over every configured RPC", async function () {
    const { internals } = await import("../operator/cli.mjs");
    const provider = internals.createProvider([
      "http://127.0.0.1:18545",
      "http://127.0.0.1:28545",
    ]);
    assert.equal(provider.constructor.name, "FallbackProvider");
    assert.equal(provider.quorum, 1);
    assert.equal(provider.providerConfigs.length, 2);
  });
});

describe("secret file policy", function () {
  it("rejects symlinks and group-readable credential files", async function () {
    const { internals } = await import("../operator/secrets.mjs");
    assert.throws(() => internals.validateSecretFileMetadata({
      isFile: () => true,
      isSymbolicLink: () => true,
      mode: 0o100600,
      size: 32,
    }, "VRF_TEST_SECRET"), /not a symlink/);
    assert.throws(() => internals.validateSecretFileMetadata({
      isFile: () => true,
      isSymbolicLink: () => false,
      mode: 0o100640,
      size: 32,
    }, "VRF_TEST_SECRET"), /group\/other/);
  });
});

describe("server readiness policy", function () {
  it("requires encrypted remote transports", async function () {
    const { internals } = await import("../operator/readiness.mjs");
    assert.equal(internals.minimumRelayerBalance(), 2_000_000_000_000_000n);
    assert.equal(internals.minimumRelayerBalance("0.005"), 5_000_000_000_000_000n);
    assert.throws(() => internals.safeUrl("http://rpc.example", "RPC"), /HTTPS/);
    assert.throws(
      () => internals.safeUrl("postgresql://user:pass@db.example/vrf", "PostgreSQL"),
      /sslmode/,
    );
    assert.doesNotThrow(() => internals.safeUrl(
      "postgresql://user:pass@db.example/vrf?sslmode=verify-full",
      "PostgreSQL",
    ));
  });

  it("rejects stale or structurally invalid health records", async function () {
    const { validateHealth } = await import("../operator/healthcheck.mjs");
    const now = Date.now();
    const healthy = {
      status: "healthy",
      coordinator: "0x1111111111111111111111111111111111111111",
      keyHash: `0x${"22".repeat(32)}`,
      head: 100,
      cursor: 99,
      pending: 0,
      updatedAt: new Date(now - 5_000).toISOString(),
    };
    assert.equal(validateHealth(healthy, { maximumAgeSeconds: 30, now }).status, "healthy");
    assert.throws(
      () => validateHealth({ ...healthy, updatedAt: new Date(now - 60_000).toISOString() }, {
        maximumAgeSeconds: 30,
        now,
      }),
      /stale/,
    );
  });
});

describe("soak report block context", function () {
  it("uses coordinator context height instead of the RPC event height for expiry", async function () {
    const { internals } = await import("../operator/soak-report.mjs");
    const requests = new Map([["1", { expiresAtBlock: 1_010 }]]);
    assert.equal(internals.countOverdueRequests(requests, new Map(), new Set(), 1_005), 0);
    assert.equal(internals.countOverdueRequests(requests, new Map(), new Set(), 1_011), 1);
    assert.equal(internals.countOverdueRequests(requests, new Map([["1", {}]]), new Set(), 1_011), 0);
  });
});

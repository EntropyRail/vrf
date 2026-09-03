const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { randomBytes } = require("node:crypto");
const { once } = require("node:events");
const path = require("node:path");
const { after, before, describe, it } = require("node:test");

const databaseUrl = process.env.VRF_TEST_DATABASE_URL;

describe("PostgreSQL operator coordination", { skip: !databaseUrl }, function () {
  let PostgresOperatorStore;
  let first;
  let second;
  let identity;
  const relayer = "0x1111111111111111111111111111111111111111";

  before(async function () {
    ({ PostgresOperatorStore } = await import("../operator/postgres-store.mjs"));
    identity = {
      chainId: String(BigInt(`0x${randomBytes(6).toString("hex")}`)),
      coordinator: "0x2222222222222222222222222222222222222222",
      keyHash: `0x${randomBytes(32).toString("hex")}`,
      deploymentBlock: 1,
    };
    first = await PostgresOperatorStore.connect({ databaseUrl, identity });
    second = await PostgresOperatorStore.connect({ databaseUrl, identity });
  });

  after(async function () {
    if (first) await first.close();
    if (second) {
      await second.pool.query("DELETE FROM vrf_operator_transactions WHERE chain_id = $1", [identity.chainId]);
      await second.pool.query("DELETE FROM vrf_operator_requests WHERE chain_id = $1", [identity.chainId]);
      await second.pool.query("DELETE FROM vrf_operator_scan_state WHERE chain_id = $1", [identity.chainId]);
      await second.close();
    }
  });

  it("serializes a relayer nonce and recovers the advisory lock after SIGKILL", async function () {
    let release;
    const held = first.withRelayerNonceLock(relayer, async () => {
      await new Promise((resolve) => { release = resolve; });
    });
    while (!release) await new Promise((resolve) => setImmediate(resolve));
    await assert.rejects(
      second.withRelayerNonceLock(relayer, async () => {}),
      /RelayerNonceLeaseBusy/,
    );
    release();
    await held;

    const child = spawn(process.execPath, [path.join(__dirname, "fixtures/hold-pg-lock.mjs")], {
      env: {
        ...process.env,
        VRF_TEST_STORE_IDENTITY: JSON.stringify(identity),
        VRF_TEST_RELAYER: relayer,
      },
      stdio: ["ignore", "pipe", "inherit"],
    });
    let output = "";
    for await (const chunk of child.stdout) {
      output += chunk.toString();
      if (output.includes("LOCKED")) break;
    }
    child.kill("SIGKILL");
    await once(child, "exit");
    await second.withRelayerNonceLock(relayer, async () => {});
  });

  it("persists unresolved broadcasts and resolves every replacement sharing a nonce", async function () {
    const firstHash = `0x31${randomBytes(31).toString("hex")}`;
    const secondHash = `0x32${randomBytes(31).toString("hex")}`;
    for (const transactionHash of [firstHash, secondHash]) {
      await first.recordBroadcast({
        transactionHash,
        relayer,
        nonce: 7,
        requestId: "9",
        transactionKind: "fulfillment",
        gasPriceWei: "10000000",
        instanceId: "test-instance",
      });
    }
    assert.equal((await first.listUnresolvedTransactions(relayer)).length, 2);
    await first.resolveNonce({
      relayer,
      nonce: 7,
      status: "replaced",
      minedTransactionHash: secondHash,
      blockNumber: 100,
    });
    assert.equal((await first.listUnresolvedTransactions(relayer)).length, 0);
    const rows = await first.pool.query(
      "SELECT transaction_hash, status FROM vrf_operator_transactions WHERE chain_id = $1 ORDER BY transaction_hash",
      [identity.chainId],
    );
    assert.deepEqual(rows.rows.map((row) => row.status), ["replaced", "mined"]);
  });

  it("fails closed when only the test lock connection is terminated and permits reacquisition", async function () {
    await first.withRelayerNonceLock(relayer, async ({ assertHeld, backendPid }) => {
      assert.ok(Number.isInteger(backendPid) && backendPid > 0);
      await assertHeld();
      const result = await second.pool.query("SELECT pg_terminate_backend($1) AS terminated", [backendPid]);
      assert.equal(result.rows[0].terminated, true);
      await assert.rejects(assertHeld(), /RelayerNonceLeaseLost/);
    });
    await second.withRelayerNonceLock(relayer, async ({ assertHeld }) => { await assertHeld(); });
  });
});

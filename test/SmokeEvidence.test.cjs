const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

describe("smoke event consensus", () => {
  const event = { blockNumber: 100, blockHash: "block-a", transactionHash: "tx-a", index: 0,
    topics: ["topic-a"], data: "0x1234" };
  it("accepts identical event evidence from independent RPCs", async () => {
    const { assertEventConsensus } = await import("../operator/smoke-report.mjs");
    assert.doesNotThrow(() => assertEventConsensus([[event], [structuredClone(event)]]));
  });
  it("rejects missing, extra, reorged, and payload-conflicting events", async () => {
    const { assertEventConsensus } = await import("../operator/smoke-report.mjs");
    for (const other of [[], [event, event], [{ ...event, blockHash: "block-b" }],
      [{ ...event, data: "0x9999" }], [{ ...event, transactionHash: "tx-b" }]]) {
      assert.throws(() => assertEventConsensus([[event], other]), /disagree/);
    }
    assert.throws(() => assertEventConsensus([]), /disagree/);
  });
});

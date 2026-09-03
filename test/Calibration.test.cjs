const assert = require("node:assert/strict");
const { before, describe, it } = require("node:test");
let tools;
before(async () => { ({ internals: tools } = await import("../operator/calibrate.mjs")); });

describe("calibration receipt evidence", () => {
  it("derives Nitro parent-chain fees without double counting them in total gas", () => {
    const fees = tools.receiptFees({ status: "0x1", gasUsed: "0x4c9c3",
      effectiveGasPrice: "0x989680", gasUsedForL1: "0x5330" });
    assert.equal(fees.l1Fee, 212960000000n);
    assert.equal(fees.transactionFee, 3137950000000n);
    assert.equal(fees.l1FeeSource, "gasUsedForL1*effectiveGasPrice");
  });
  it("preserves zero fees and distinguishes missing data from zero", () => {
    const receipt = { status: "0x1", gasUsed: "100", effectiveGasPrice: "10" };
    assert.equal(tools.receiptFees(receipt).l1Fee, null);
    assert.equal(tools.receiptFees({ ...receipt, gasUsedForL1: "0x0" }).l1Fee, 0n);
    assert.equal(tools.receiptFees({ ...receipt, l1Fee: "42" }).l1Fee, 42n);
    assert.equal(tools.bigintFromRpc("-1"), null);
  });
  it("rejects missing, reverted, and malformed receipts", () => {
    assert.throws(() => tools.receiptFees(null), /missing/);
    assert.throws(() => tools.receiptFees({ status: "0x0" }), /unsuccessful/);
    assert.throws(() => tools.receiptFees({ status: "0x1" }), /unavailable/);
    assert.throws(() => tools.receiptFees({ status: "0x1", gasUsed: "1",
      effectiveGasPrice: "10", gasUsedForL1: "2" }), /exceeds/);
  });
  it("fails closed on conflicting independent RPC receipts or logs", () => {
    assert.doesNotThrow(() => tools.assertConsensus([{ fee: 1n }, { fee: 1n }], "fee"));
    assert.throws(() => tools.assertConsensus([{ fee: 1n }, { fee: 2n }], "fee"), /disagree/);
    assert.throws(() => tools.assertConsensus([["tx1"], []], "logs"), /disagree/);
  });
  it("keeps sparse samples visible and computes nearest-rank percentiles", () => {
    assert.equal(tools.distribution([]).p99, null);
    assert.deepEqual(tools.distribution([3n]), { samples: 1, p50: "3", p95: "3", p99: "3", max: "3" });
    assert.equal(tools.percentile([3n, 1n, 2n], 50), 2n);
  });
  it("converts manual USD inputs with integer rounding, not floating point", () => {
    assert.equal(tools.minimumFeeFromUsd(undefined, undefined), null);
    assert.equal(tools.minimumFeeFromUsd("0.01", "3000"), "3333333333334");
    assert.equal(tools.minimumFeeFromUsd("0.000000000000000001", "3000"), "1");
    for (const input of ["Infinity", "NaN", "-1", "0", "1e-3", undefined]) {
      assert.throws(() => tools.minimumFeeFromUsd(input, "3000"), /positive/);
    }
  });
});

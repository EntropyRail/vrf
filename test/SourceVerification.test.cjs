const assert = require("node:assert/strict");
const { before, describe, it } = require("node:test");

let internals;

before(async function () {
  ({ internals } = await import("../operator/source-verification.mjs"));
});

describe("source verification evidence", function () {
  const address = "0x1111111111111111111111111111111111111111";

  it("requires the API URL to be bound to the exact contract address", function () {
    assert.equal(internals.addressBoundUrl(
      new URL(`https://explorer.example/api?module=contract&action=getsourcecode&address=${address}`),
      address,
    ), true);
    assert.equal(internals.addressBoundUrl(
      new URL(`https://explorer.example/api/v2/smart-contracts/${address}`),
      address,
    ), true);
    assert.equal(internals.addressBoundUrl(
      new URL("https://explorer.example/address/0x2222222222222222222222222222222222222222"),
      address,
    ), false);
  });

  it("accepts only structured Blockscout source-verification evidence", function () {
    assert.equal(internals.parseEvidence({
      status: "1",
      message: "OK",
      result: [{ SourceCode: "contract A {}", ContractName: "A", CompilerVersion: "v0.8.24" }],
    }).verified, true);
    assert.equal(internals.parseEvidence({
      is_verified: true,
      is_fully_verified: true,
      source_code: "contract A {}",
      compiler_version: "v0.8.24",
    }).verified, true);
    assert.equal(internals.parseEvidence({
      is_verified: true,
      is_fully_verified: false,
      source_code: "contract A {}",
      compiler_version: "v0.8.24",
    }).verified, false);
    assert.equal(internals.parseEvidence({ html: "verified source" }).verified, false);
  });
});

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { readFileSync, readdirSync, existsSync } = require("node:fs");
const { join, dirname, resolve } = require("node:path");
const { describe, it } = require("node:test");

const root = resolve(__dirname, "..");
const read = file => readFileSync(join(root, file), "utf8");

describe("standalone public release", () => {
  it("preserves the exported contract and operator source hashes", () => {
    const provenance = JSON.parse(read("source-provenance.json"));
    assert.match(provenance.exportedFromOriginalCommit, /^[a-f0-9]{40}$/);
    assert.ok(Object.keys(provenance.sha256).length >= 60);
    for (const [file, hash] of Object.entries(provenance.sha256)) {
      assert.match(file, /^(contracts|operator)\//);
      assert.equal(createHash("sha256").update(read(file)).digest("hex"), hash, file);
    }
  });

  it("uses a standalone lockfile and prevents accidental npm publication", () => {
    const pkg = JSON.parse(read("package.json"));
    const lock = JSON.parse(read("package-lock.json"));
    assert.equal(pkg.name, "@entropyrail/vrf");
    assert.equal(pkg.private, true);
    assert.equal(lock.packages[""].name, pkg.name);
    assert.equal(lock.packages[""].workspaces, undefined);
    assert.equal(pkg.license, "MIT");
    assert.match(read("NOTICE"), /Copyright \(c\) 2025 Randamu/);
  });

  it("keeps local Markdown links resolvable", () => {
    function walk(dir) {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const file = join(dir, entry.name);
        if (entry.isDirectory()) walk(file);
        else if (entry.name.endsWith(".md")) check(file);
      }
    }
    function check(file) {
      for (const match of readFileSync(file, "utf8").matchAll(/\]\(([^)\s]+)\)/g)) {
        const target = match[1].split("#")[0];
        if (!target || /^[a-z]+:/i.test(target)) continue;
        assert.ok(existsSync(resolve(dirname(file), target)), `${file}: ${target}`);
      }
    }
    check(join(root, "README.md"));
    check(join(root, "SECURITY.md"));
    walk(join(root, "docs"));
    walk(join(root, "deploy"));
  });

  it("labels public deployment metadata as testnet-only evidence", () => {
    const deployment = JSON.parse(read("docs/deployments/robinhood-testnet-v3.json"));
    assert.equal(deployment.chainId, 46630);
    assert.match(deployment.scope, /not a runtime operator manifest/);
    assert.match(deployment.keyHash, /^0x[a-f0-9]{64}$/i);
    for (const contract of Object.values(deployment.contracts)) {
      assert.match(contract.address, /^0x[a-f0-9]{40}$/i);
      assert.match(contract.runtimeCodeHash, /^0x[a-f0-9]{64}$/i);
    }
    assert.match(read("SECURITY.md"), /pre-audit, testnet software/);
    assert.match(read("README.md"), /not an active V3 threshold network/);
  });
});

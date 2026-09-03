const assert = require("node:assert/strict");
const { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { spawnSync } = require("node:child_process");
const { after, before, describe, it } = require("node:test");

let directory;

before(function () {
  directory = mkdtempSync(join(tmpdir(), "proof-vrf-entrypoint-"));
});

after(function () {
  if (directory) rmSync(directory, { recursive: true, force: true });
});

describe("ESM command entrypoints", function () {
  it("runs keygen when invoked through the current-release symlink", function () {
    const cliLink = join(directory, "cli.mjs");
    const output = join(directory, "proof-key.json");
    symlinkSync(resolve(__dirname, "..", "operator", "cli.mjs"), cliLink);
    const child = spawnSync(process.execPath, [cliLink, "keygen", "--out", output], {
      encoding: "utf8",
      env: { ...process.env, VRF_KEY_PASSWORD: "entrypoint-regression-test-only" },
      timeout: 20_000,
    });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(existsSync(output), true);
    const payload = JSON.parse(readFileSync(output, "utf8"));
    assert.equal(payload.format, "proof-vrf-keystore-v1");
    assert.match(payload.serviceKeyHash, /^0x[0-9a-f]{64}$/i);
  });
});

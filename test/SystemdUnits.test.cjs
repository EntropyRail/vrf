const assert = require("node:assert/strict");
const { readFileSync, readdirSync } = require("node:fs");
const { join } = require("node:path");
const { describe, it } = require("node:test");

const SYSTEMD_DIR = join(__dirname, "..", "deploy", "systemd");

function unit(name) {
  return readFileSync(join(SYSTEMD_DIR, name), "utf8");
}

describe("systemd deployment units", function () {
  it("targets the immutable current release and systemd 249 credentials", function () {
    const services = readdirSync(SYSTEMD_DIR).filter((name) => name.endsWith(".service"));
    for (const name of services) {
      const contents = unit(name);
      assert.match(contents, name.startsWith("proof-vrf-v3-")
        ? /WorkingDirectory=\/opt\/proof-vrf-v3\/current/ : /WorkingDirectory=\/opt\/proof-vrf\/current/);
      assert.doesNotMatch(contents, /\/opt\/proof-vrf\/vrf\//);
      assert.doesNotMatch(contents, /LoadCredentialEncrypted=/);
      assert.doesNotMatch(contents, /%d\//);
    }

    for (const name of [
      "proof-vrf-operator.service",
      "proof-vrf-archiver.service",
      "proof-vrf-prover.service",
      "proof-vrf-threshold-aggregator.service",
      "proof-vrf-threshold-node.service",
    ]) {
      const contents = unit(name);
      assert.match(contents, /LoadCredential=/);
      assert.match(contents, /LoadCredential=rpc-urls:/);
      assert.match(contents, /VRF_RPC_URLS_FILE=\$\{CREDENTIALS_DIRECTORY\}\/rpc-urls/);
      assert.match(contents, /\$\{CREDENTIALS_DIRECTORY\}/);
    }
  });

  it("keeps the isolated prover on WireGuard with mutual TLS", function () {
    const contents = unit("proof-vrf-prover.service");
    assert.match(contents, /Requires=wg-quick@wg0\.service/);
    assert.match(contents, /--tls-key \/etc\/proof-vrf\/tls\/prover-server\.key/);
    assert.match(contents, /--tls-cert \/etc\/proof-vrf\/tls\/prover-server\.crt/);
    assert.match(contents, /--tls-ca \/etc\/proof-vrf\/tls\/prover-ca\.crt/);
  });

  it("keeps proof-key material out of the operator service", function () {
    const contents = unit("proof-vrf-operator.service");
    assert.doesNotMatch(contents, /^ExecStartPre=/m);
    assert.doesNotMatch(contents, /--keystore/);
    assert.doesNotMatch(contents, /proof-key-password/);
    assert.match(contents, /cli\.mjs run-v2 --readiness true/);
    assert.match(contents, /--expected-chain-id 46630 --minimum-rpc-count 2/);
    assert.match(contents, /--minimum-relayer-balance-eth 0\.002/);
    assert.match(contents, /--prover-url \$\{VRF_PROVER_URL\}/);
    assert.match(contents, /--proof-key-hash \$\{VRF_PROOF_KEY_HASH\}/);
    assert.match(contents, /--prover-client-key \/etc\/proof-vrf\/tls\/prover-client\.key/);
    assert.match(contents, /LoadCredential=prover-bearer-token:/);
  });
  it("runs an independent, testnet-only, budget-capped archiver without proof credentials", function () {
    const contents = unit("proof-vrf-archiver.service");
    assert.match(contents, /operator\/archiver\.mjs/);
    assert.match(contents, /--archive-after-blocks 32/);
    assert.match(contents, /--maximum-total-fee-wei 10000000000000/);
    assert.doesNotMatch(contents, /prover-bearer-token|proof-key-password|--keystore|Requires=proof-vrf-operator/);
  });
  it("isolates V3 services, new relayer credentials and state while reusing only the existing proof key", function () {
    for (const mode of ["operator", "archiver", "prover"]) {
      const contents = unit(`proof-vrf-v3-${mode}.service`);
      assert.match(contents, /StateDirectory=proof-vrf-v3/);
      assert.match(contents, /ReadWritePaths=\/var\/lib\/proof-vrf-v3/);
      assert.doesNotMatch(contents, /run-v2|LoadCredentialEncrypted=/);
      if (mode !== "prover") {
        assert.match(contents, /LoadCredential=tx-private-key:\/etc\/proof-vrf-v3\/credentials/);
        assert.doesNotMatch(contents, /proof-key-password|--keystore/);
        assert.match(contents, /--maximum-total-fee-wei/);
      } else {
        assert.match(contents, /--host 10\.200\.0\.12 --port 9445/);
        assert.match(contents, /--keystore \/var\/lib\/proof-vrf\/proof-key\.json/);
      }
    }
    assert.doesNotMatch(unit("proof-vrf-v3-archiver.service"), /prover-bearer-token|--prover-url/);
  });
});

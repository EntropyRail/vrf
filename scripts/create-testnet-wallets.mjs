#!/usr/bin/env node
// Offline provisioning only. It never imports a provider, signs a transaction,
// changes an existing credential, or prints private keys/passwords.
import { randomBytes } from "node:crypto";
import { constants, lstatSync, mkdirSync, mkdtempSync, openSync, closeSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { Wallet, hexlify, verifyMessage } from "ethers";
import { isMain } from "../operator/entrypoint.mjs";

export const TESTNET_WALLET_ROLES = Object.freeze([
  { role: "deployer", purpose: "Deploy contracts and relay fully signed governance transactions", gas: "required-for-deployment-and-execution" },
  { role: "fulfiller", purpose: "Operator transaction relayer; never a proof key", gas: "required-for-fulfillments", currentReadinessBalanceFloorWei: "2000000000000000" },
  { role: "archiver", purpose: "Separate permissionless blockhash archive transaction relayer", gas: "required-when-archiver-enabled", currentArchiverBalanceFloorWei: "2000000000000000" },
  { role: "canary-subscription", purpose: "Test consumer owner and test/Sponsor subscription funder", gas: "required-plus-subscription-funding" },
  { role: "guardian", purpose: "Emergency request pause; not the Coordinator owner", gas: "keep-emergency-gas-reserve" },
  { role: "payee", purpose: "Operator credit beneficiary and withdrawal caller", gas: "needed-only-when-withdrawing" },
  { role: "safe-signer-1", purpose: "Proposed governance Safe signer 1 of 3", gas: "not-for-offchain-signatures; needed-if-broadcasting" },
  { role: "safe-signer-2", purpose: "Proposed governance Safe signer 2 of 3", gas: "not-for-offchain-signatures; needed-if-broadcasting" },
  { role: "safe-signer-3", purpose: "Proposed governance Safe signer 3 of 3", gas: "not-for-offchain-signatures; needed-if-broadcasting" },
].map(Object.freeze));

function protectedFile(path, contents) {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, contents); } finally { closeSync(fd); }
}
function assertPrivate(path, directory) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())
      || (stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) {
    throw new Error("unsafe wallet artifact ownership or permissions");
  }
}
function freshWallet() {
  for (let attempt = 0; attempt < 8; attempt++) {
    const entropy = randomBytes(32);
    try { return new Wallet(hexlify(entropy)); }
    catch { /* Re-sample the negligible out-of-range secp256k1 scalar case. */ }
    finally { entropy.fill(0); }
  }
  throw new Error("wallet entropy validation failed");
}

export async function createTestnetWallets(root) {
  if (!isAbsolute(root) || resolve(root) !== root) throw new Error("use a canonical absolute output root");
  const repository = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
  const canonicalParent = realpathSync(dirname(root));
  if (canonicalParent !== dirname(root)) throw new Error("output parent must not use a symlink");
  const candidate = join(canonicalParent, root.slice(dirname(root).length + 1));
  const repoRelative = relative(repository, candidate);
  if (repoRelative === "" || (!repoRelative.startsWith("..") && !isAbsolute(repoRelative))) {
    throw new Error("wallet material must be outside the repository");
  }
  try { mkdirSync(root, { mode: 0o700 }); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  assertPrivate(root, true);
  const batch = mkdtempSync(join(root, `${new Date().toISOString().slice(0, 10)}-`));
  assertPrivate(batch, true);
  const keystores = join(batch, "keystores"), passwords = join(batch, "passwords");
  mkdirSync(keystores, { mode: 0o700 });
  mkdirSync(passwords, { mode: 0o700 });
  const addresses = new Set();
  const accounts = [];
  for (const definition of TESTNET_WALLET_ROLES) {
    const wallet = freshWallet();
    if (addresses.has(wallet.address)) throw new Error("duplicate wallet; refusing to publish batch");
    addresses.add(wallet.address);
    const password = randomBytes(32).toString("base64url");
    const encrypted = await wallet.encrypt(password);
    const keyPath = join(keystores, `${definition.role}.json`);
    const passwordPath = join(passwords, `${definition.role}.password`);
    protectedFile(passwordPath, `${password}\n`);
    protectedFile(keyPath, `${encrypted}\n`);
    assertPrivate(keyPath, false); assertPrivate(passwordPath, false);
    const restored = await Wallet.fromEncryptedJson(readFileSync(keyPath, "utf8"), readFileSync(passwordPath, "utf8").trim());
    const challenge = `VRF_TESTNET_WALLET_BACKUP_CHECK_V1:46630:${definition.role}:${wallet.address}`;
    if (restored.address !== wallet.address
        || verifyMessage(challenge, await restored.signMessage(challenge)) !== wallet.address) {
      throw new Error("wallet backup verification failed; refusing to publish batch");
    }
    // Only public data is allowed in the manifest and stdout.
    accounts.push({ ...definition, address: wallet.address, encryptedKeystore: `keystores/${definition.role}.json`,
      passwordFile: `passwords/${definition.role}.password`, decryptAndSignVerified: true });
  }
  const manifest = {
    format: "proof-vrf-testnet-wallet-addresses/v1", generatedAt: new Date().toISOString(),
    chainId: 46630, network: "Robinhood Chain Testnet", intendedUse: "TESTNET_ONLY_DO_NOT_FUND_ON_MAINNET",
    status: "generated-offline-not-deployed-not-funded-by-this-script", batchDirectory: batch,
    storage: { encryption: "Ethereum JSON keystore (ethers default scrypt)", directories: "0700", files: "0600",
      warning: "Passwords and encrypted keys are on the same host. This is not HSM custody or independent multisig custody. No off-device backup was created." },
    governance: { plannedSafeThreshold: 2, plannedSafeSignerCount: 3, safeAddress: null, timelockAddress: null,
      signerCustody: "same-local-host-testnet-only", defaultGasExecutorRole: "deployer" },
    proofKeyChanged: false, thresholdSharesChanged: false, accounts,
  };
  protectedFile(join(batch, "addresses.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

if (isMain(import.meta.url)) {
  const { values } = parseArgs({ options: { "output-root": { type: "string" } }, strict: true });
  if (!values["output-root"]) throw new Error("--output-root is required");
  createTestnetWallets(values["output-root"]).then(manifest => {
    process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
  }).catch(() => {
    // Do not dump crypto-library errors or any potentially secret-bearing inputs.
    process.stderr.write("Wallet generation failed; no complete address manifest was published. Preserve any partial batch for inspection; do not fund it.\n");
    process.exitCode = 1;
  });
}

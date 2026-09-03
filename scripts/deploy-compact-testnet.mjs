#!/usr/bin/env node
// Dedicated testnet release. No mainnet switch, no secret logging, no implicit funding.
import { execFileSync } from "node:child_process";
import { readFileSync, existsSync, openSync, closeSync, writeFileSync, fsyncSync, renameSync, lstatSync } from "node:fs";
import { dirname, join } from "node:path";
import { createHash } from "node:crypto";
import { parseArgs } from "node:util";
import { Wallet, Contract, ContractFactory, Interface, AbiCoder, ZeroAddress, getAddress, getCreateAddress, keccak256, toQuantity } from "ethers";
import { readSecret } from "../operator/secrets.mjs";
import { rpcProvider } from "../operator/rpc.mjs";
import { normalizeRpcUrls } from "../operator/rpc-policy.mjs";
import { errorDetails } from "../operator/errors.mjs";
import { isMain } from "../operator/entrypoint.mjs";

export const SAFE = Object.freeze({
  singleton: "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
  singletonHash: "0xb1f926978a0f44a2c0ec8fe822418ae969bd8c3f18d61e5103100339894f81ff",
  factory: "0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67",
  factoryHash: "0x50c3cdc4074750a7a974204a716c999edd37482f907608d960b2b025ee0b3317",
  proxyHash: "0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c",
});
export const TESTNET_PRICING = Object.freeze({ minimumRequestFeeWei: "10000000000000", l1FeeReserveWei: "500000000000",
  fulfillmentOverheadGas: "150000", perWordGas: "500", publicPremiumBps: "2000", operatorPremiumShareBps: "5000", requestTimeoutBlocks: "7200" });
export const SAFE_ABI = [
  "function setup(address[] owners,uint256 threshold,address to,bytes data,address fallbackHandler,address paymentToken,uint256 payment,address paymentReceiver)",
  "function getOwners() view returns(address[])", "function getThreshold() view returns(uint256)",
  "function getModulesPaginated(address start,uint256 pageSize) view returns(address[],address)",
];
const FACTORY_ABI = ["function createProxyWithNonce(address singleton,bytes initializer,uint256 saltNonce) returns(address proxy)",
  "event ProxyCreation(address indexed proxy,address singleton)"];
const json = v => JSON.stringify(v, (_, x) => typeof x === "bigint" ? String(x) : x, 2);
export function durableJson(path, value) {
  if (existsSync(path) && (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink() || (lstatSync(path).mode & 0o077))) throw new Error("unsafe release journal path");
  const temp = `${path}.tmp`;
  const fd = openSync(temp, "wx", 0o600);
  try { writeFileSync(fd, json(value) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
  renameSync(temp, path);
  const dir = openSync(dirname(path), "r"); try { fsyncSync(dir); } finally { closeSync(dir); }
}
export async function loadRoleWallet(directory, role, provider) {
  const manifest = JSON.parse(readFileSync(join(directory, "addresses.json"), "utf8"));
  if (manifest.chainId !== 46630) throw new Error("wallet batch is not testnet scoped");
  const account = manifest.accounts.find(a => a.role === role);
  if (!account) throw new Error("missing wallet role");
  // Fixed filenames; do not follow paths embedded in an arbitrary manifest.
  const keyPath = join(directory, "keystores", `${role}.json`), passwordPath = join(directory, "passwords", `${role}.password`);
  for (const p of [keyPath, passwordPath]) {
    const s = lstatSync(p);
    if (!s.isFile() || s.isSymbolicLink() || (s.mode & 0o077)) throw new Error("unsafe wallet permissions");
  }
  const wallet = await Wallet.fromEncryptedJson(readFileSync(keyPath, "utf8"), readFileSync(passwordPath, "utf8").trim());
  if (getAddress(wallet.address) !== getAddress(account.address)) throw new Error("wallet role address mismatch");
  return wallet.connect(provider);
}

// One signer, single writer, fixed gas cap. Journal the EXACT signed bytes before
// broadcast; retries reuse those bytes/nonce, never create another spend implicitly.
export class ReleaseSender {
  constructor({ wallet, providers, journalPath, maximumWei, identity }) {
    Object.assign(this, { wallet, providers, journalPath, maximumWei, identity });
    if (existsSync(journalPath)) {
      const s = lstatSync(journalPath);
      if (!s.isFile() || s.isSymbolicLink() || (s.mode & 0o077)) throw new Error("unsafe release journal permissions");
    }
    this.journal = existsSync(journalPath) ? JSON.parse(readFileSync(journalPath, "utf8")) :
      { identity, maximumWei: String(maximumWei), reservedWei: "0", transactions: {} };
    if (json(this.journal.identity) !== json(identity) || this.journal.maximumWei !== String(maximumWei)) throw new Error("release journal identity mismatch");
  }
  async send(name, request) {
    const fingerprint = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "bytes", "uint256"],
      [request.to ?? ZeroAddress, request.data ?? "0x", request.value ?? 0]));
    let item = this.journal.transactions[name];
    if (item && item.fingerprint !== fingerprint) throw new Error("release step differs from signed journal");
    if (!item) {
      const networks = await Promise.all(this.providers.map(p => p.send("eth_chainId", [])));
      if (networks.some(n => BigInt(n) !== 46630n)) throw new Error("release restricted to chain 46630");
      const nonces = await Promise.all(this.providers.map(p => p.send("eth_getTransactionCount", [this.wallet.address, "pending"])));
      if (nonces.some(n => n !== nonces[0])) throw new Error("release nonce disagreement");
      const prices = await Promise.all(this.providers.map(p => p.send("eth_gasPrice", []).then(BigInt)));
      const gasPrice = prices.reduce((a, b) => a > b ? a : b);
      if (gasPrice <= 0n || gasPrice > 15_000_000n) throw new Error("release gas price cap exceeded");
      const estimates = await Promise.all(this.providers.map(p => p.estimateGas({ ...request, from: this.wallet.address, gasPrice })));
      const gasLimit = estimates.reduce((a, b) => a > b ? a : b) * 125n / 100n;
      const maximumCost = gasLimit * gasPrice + BigInt(request.value ?? 0);
      if (BigInt(this.journal.reservedWei) + maximumCost > this.maximumWei) throw new Error("release total budget exceeded");
      const balances = await Promise.all(this.providers.map(p => p.getBalance(this.wallet.address, "pending")));
      if (balances.some(b => b < maximumCost)) throw new Error("release wallet balance insufficient");
      const nonce = Number(BigInt(nonces[0]));
      const raw = await this.wallet.signTransaction({ ...request, nonce, gasLimit, gasPrice, chainId: 46630, type: 0 });
      item = { fingerprint, nonce, raw, hash: keccak256(raw), maximumCostWei: String(maximumCost), status: "signed" };
      this.journal.transactions[name] = item;
      this.journal.reservedWei = String(BigInt(this.journal.reservedWei) + maximumCost);
      durableJson(this.journalPath, this.journal);
    }
    let receipt = await this.providers[0].getTransactionReceipt(item.hash);
    if (!receipt) {
      // Unknown/timeout is safe to replay only with these exact journaled bytes.
      const response = await this.providers[0].broadcastTransaction(item.raw);
      receipt = await response.wait(2, 45_000);
    }
    if (!receipt || receipt.status !== 1) throw new Error("release receipt absent or reverted; inspect journal before continuing");
    const evidence = await Promise.all(this.providers.map(p => p.send("eth_getTransactionReceipt", [item.hash])));
    if (evidence.some(r => !r || r.blockHash !== receipt.blockHash || BigInt(r.status) !== 1n
        || BigInt(r.gasUsed) !== receipt.gasUsed)) throw new Error("release receipt disagreement");
    Object.assign(item, { status: "mined", blockNumber: receipt.blockNumber, blockHash: receipt.blockHash,
      gasUsed: String(receipt.gasUsed), feeWei: String(receipt.fee) });
    durableJson(this.journalPath, this.journal);
    return receipt;
  }
}

export async function deployCompactSuite({ artifacts, sender, roles, publicKey, gitCommit, out }) {
  const providers = sender.providers;
  for (const p of providers) {
    if (keccak256(await p.getCode(SAFE.singleton)) !== SAFE.singletonHash
        || keccak256(await p.getCode(SAFE.factory)) !== SAFE.factoryHash) throw new Error("Safe official runtime pin mismatch");
  }
  const all = Object.values(roles).map(a => getAddress(a));
  if (all.length !== 9 || new Set(all).size !== 9 || all.includes(ZeroAddress)) throw new Error("nine distinct testnet roles required");
  const manifest = { format: "robinhood-proof-vrf-deployment/v3", status: "deploying", chainId: 46630, gitCommit,
    generatedAt: new Date().toISOString(), deployer: roles.deployer, fulfiller: roles.fulfiller, archiver: roles.archiver,
    guardian: roles.guardian, payee: roles.payee, canary: roles["canary-subscription"], contracts: {},
    pricing: TESTNET_PRICING, publicKey: publicKey.map(String), keyConfig: { maxGasPriceWei: "50000000", verificationGasLimit: "2100000", proofDataLength: 416 },
    sourceVerification: { status: "pending" }, threshold: { status: "verifiers-only-not-registered-not-network-active" },
    build: { node: process.version, solc: "0.8.24", viaIR: true, optimizerRuns: 500 },
    governance: { owners: [roles["safe-signer-1"], roles["safe-signer-2"], roles["safe-signer-3"]], threshold: 2,
      custody: "same-local-host-testnet-only", delaySeconds: 43200, singleton: SAFE.singleton, factory: SAFE.factory } };
  const capture = async (name, address, receipt, contractName, args = []) => {
    const codes = await Promise.all(providers.map(p => p.getCode(address)));
    if (codes.some(c => c === "0x" || c !== codes[0])) throw new Error("deployment runtime disagreement");
    manifest.contracts[name] = { address, contractName, constructorArguments: args,
      runtimeCodeHash: keccak256(codes[0]), blockNumber: receipt.blockNumber, transactionHash: receipt.hash,
      gasUsed: String(receipt.gasUsed), feeWei: String(receipt.fee) };
    durableJson(out, manifest);
  };
  const safeInitializer = new Interface(SAFE_ABI).encodeFunctionData("setup", [manifest.governance.owners, 2,
    ZeroAddress, "0x", ZeroAddress, ZeroAddress, 0, ZeroAddress]);
  const factory = new Contract(SAFE.factory, FACTORY_ABI, providers[0]);
  const salt = BigInt(roles.deployer);
  const safeReceipt = await sender.send("safe", await factory.createProxyWithNonce.populateTransaction(SAFE.singleton, safeInitializer, salt));
  const created = safeReceipt.logs.filter(l => l.address.toLowerCase() === SAFE.factory.toLowerCase())
    .map(l => { try { return factory.interface.parseLog(l); } catch { return null; } }).find(l => l?.name === "ProxyCreation");
  if (!created || getAddress(created.args.singleton) !== getAddress(SAFE.singleton)) throw new Error("Safe creation event missing");
  const safe = created.args.proxy;
  await capture("safe", safe, safeReceipt, "SafeProxy", [SAFE.singleton]);
  if (manifest.contracts.safe.runtimeCodeHash !== SAFE.proxyHash) throw new Error("Safe proxy runtime mismatch");
  for (const p of providers) {
    const s = new Contract(safe, SAFE_ABI, p);
    if (json((await s.getOwners()).map(getAddress).sort()) !== json(manifest.governance.owners.map(getAddress).sort())
        || await s.getThreshold() !== 2n || (await s.getModulesPaginated("0x0000000000000000000000000000000000000001", 10))[0].length) throw new Error("Safe ownership or modules mismatch");
  }
  async function deploy(name, contractName, args = []) {
    const artifact = await artifacts.readArtifact(contractName);
    const f = new ContractFactory(artifact.abi, artifact.bytecode);
    const request = await f.getDeployTransaction(...args);
    const receipt = await sender.send(name, request);
    const address = getCreateAddress({ from: sender.wallet.address, nonce: sender.journal.transactions[name].nonce });
    if (getAddress(receipt.contractAddress) !== address) throw new Error("CREATE address mismatch");
    await capture(name, address, receipt, contractName, args);
    manifest.contracts[name].artifactBytecodeSha256 = createHash("sha256").update(artifact.bytecode).digest("hex");
    return new Contract(address, artifact.abi, providers[0]);
  }
  const timelock = await deploy("timelock", "VRFAdminTimelock", [safe, 43200]);
  const context = await deploy("blockContext", "ArbitrumBlockContext");
  const store = await deploy("blockhashStore", "BlockhashStore", [context.target]);
  const fee = await deploy("l1FeeCalculator", "ArbitrumL1FeeCalculator");
  const verifier = await deploy("verifier", "Secp256k1ECVRFVerifier");
  const keyHash = await verifier.keyHash(publicKey);
  manifest.keyHash = keyHash;
  const coordinator = await deploy("coordinator", "VRFServiceCoordinatorV3", [timelock.target, roles.guardian, store.target, fee.target,
    TESTNET_PRICING, { keyHash, verifier: verifier.target, keyData: AbiCoder.defaultAbiCoder().encode(["uint256[2]"], [publicKey]),
      fulfiller: roles.fulfiller, payee: roles.payee, maxGasPriceWei: "50000000", verificationGasLimit: "2100000" }]);
  const backend = await deploy("blsBackend", "BLS12381Backend");
  const adapter = await deploy("thresholdVerifier", "ThresholdBLSVerifierAdapter", [backend.target]);
  for (const p of providers) {
    const c = coordinator.connect(p), t = timelock.connect(p), key = await c.getKey(keyHash);
    const block = await p.send("eth_blockNumber", []);
    if (await c.owner() !== timelock.target || await c.pendingOwner() !== ZeroAddress || await c.guardian() !== roles.guardian
        || await t.owner() !== safe || await t.delay() !== 43200n || !key.active
        || key.fulfiller !== roles.fulfiller || key.payee !== roles.payee || key.proofDataLength !== 416n
        || await c.contextBlockNumber({ blockTag: block }) !== BigInt(block)) throw new Error("deployed config verification failed");
    const { bls12_381: bls } = await import("@noble/curves/bls12-381");
    const message = Uint8Array.from({ length: 32 }, () => 0xa5);
    const pk = bls.G2.ProjectivePoint.BASE.multiply(42n).toRawBytes(false);
    const sig = bls.G1.hashToCurve(message, { DST: "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_" }).multiply(42n).toRawBytes(false);
    if (!await backend.connect(p).verify(pk, message, sig) || !await adapter.connect(p).validateKey(await adapter.keyHash(pk), pk)) throw new Error("BLS precompile probe failed");
  }
  Object.assign(manifest, { status: "deployed", ownershipStatus: "timelock-owner-from-constructor", keyRegistrationMode: "constructor-atomic",
    precompileInterop: "pass", updatedAt: new Date().toISOString(), totalDeploymentFeeWei:
      String(Object.values(manifest.contracts).reduce((sum, c) => sum + BigInt(c.feeWei), 0n)) });
  durableJson(out, manifest);
  return manifest;
}

export async function deployCompactTestnet({ walletDirectory, referenceManifest, out, rpcUrls }) {
  if (!process.version.startsWith("v22.")) throw new Error("Node 22 required");
  const gitCommit = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  if (execFileSync("git", ["status", "--porcelain"], { encoding: "utf8" }).trim()) throw new Error("clean committed release worktree required");
  const providers = normalizeRpcUrls(rpcUrls, { minimum: 2, label: "V3 deployment" }).map(u => rpcProvider(u, 15_000));
  try {
    const { artifacts } = await import("hardhat");
    const wallets = JSON.parse(readFileSync(join(walletDirectory, "addresses.json"), "utf8"));
    const roles = Object.fromEntries(wallets.accounts.map(a => [a.role, getAddress(a.address)]));
    const reference = JSON.parse(readFileSync(referenceManifest, "utf8"));
    if (Number(reference.chainId) !== 46630) throw new Error("proof reference is not testnet");
    const wallet = await loadRoleWallet(walletDirectory, "deployer", providers[0]);
    const sender = new ReleaseSender({ wallet, providers, journalPath: `${out}.transactions.private.json`, maximumWei: 500_000_000_000_000n,
      identity: { gitCommit, chainId: 46630, deployer: wallet.address, out } });
    return await deployCompactSuite({ artifacts, sender, roles, publicKey: reference.publicKey.map(BigInt), gitCommit, out });
  } finally { providers.forEach(p => p.destroy()); }
}
if (isMain(import.meta.url)) {
  const { values } = parseArgs({ options: { "wallet-directory": { type: "string" }, "reference-manifest": { type: "string" }, out: { type: "string" } }, strict: true });
  deployCompactTestnet({ walletDirectory: values["wallet-directory"], referenceManifest: values["reference-manifest"], out: values.out,
    rpcUrls: readSecret("VRF_RPC_URLS", { required: true }) }).then(m => console.log(json({ status: m.status, coordinator: m.contracts.coordinator, totalDeploymentFeeWei: m.totalDeploymentFeeWei })))
    .catch(e => { console.error(json(errorDetails(e))); process.exitCode = 1; });
}

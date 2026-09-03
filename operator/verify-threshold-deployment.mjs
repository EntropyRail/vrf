#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { Contract, JsonRpcProvider, getAddress, hexlify, keccak256 } from "ethers";
import { BLS_DST } from "./threshold-crypto.mjs";
import { verifySources } from "./source-verification.mjs";

const BACKEND_ABI = [
  "function validatePublicKey(bytes groupPublicKey) view returns (bool)",
  "function verify(bytes groupPublicKey,bytes message,bytes signature) view returns (bool)",
];
const ADAPTER_ABI = [
  "function backend() view returns (address)",
  "function backendCodeHash() view returns (bytes32)",
  "function proofLength() view returns (uint32)",
  "function keyHash(bytes groupPublicKey) view returns (bytes32)",
  "function validateKey(bytes32 expectedKeyHash,bytes keyData) view returns (bool)",
];

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      "rpc-url": { type: "string" },
      manifest: { type: "string" },
      out: { type: "string" },
      "source-verification-file": { type: "string" },
      overwrite: { type: "boolean", default: false },
    },
    strict: true,
  });
  const manifest = readJson(values.manifest);
  if (manifest.format !== "robinhood-proof-vrf-threshold-verifier-deployment/v1") {
    throw new Error("unsupported threshold verifier deployment manifest");
  }
  const provider = new JsonRpcProvider(values["rpc-url"]);
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(manifest.chainId)) throw new Error("manifest chainId mismatch");

  const backendAddress = getAddress(manifest.contracts.backend.address);
  const adapterAddress = getAddress(manifest.contracts.adapter.address);
  const [backendCode, adapterCode] = await Promise.all([
    provider.getCode(backendAddress),
    provider.getCode(adapterAddress),
  ]);
  const backend = new Contract(backendAddress, BACKEND_ABI, provider);
  const adapter = new Contract(adapterAddress, ADAPTER_ABI, provider);

  const secret = 42n;
  const message = new Uint8Array(32).fill(0xa5);
  const groupPublicKey = hexlify(bls.G2.ProjectivePoint.BASE.multiply(secret).toRawBytes(false));
  const signature = hexlify(bls.G1.hashToCurve(message, { DST: BLS_DST })
    .multiply(secret).toRawBytes(false));
  const expectedKeyHash = await adapter.keyHash(groupPublicKey);
  const [
    pinnedBackend,
    pinnedBackendCodeHash,
    proofLength,
    publicKeyValid,
    signatureValid,
    adapterKeyValid,
    sourceVerification,
  ] = await Promise.all([
    adapter.backend(),
    adapter.backendCodeHash(),
    adapter.proofLength(),
    backend.validatePublicKey(groupPublicKey),
    backend.verify(groupPublicKey, message, signature),
    adapter.validateKey(expectedKeyHash, groupPublicKey),
    verifySources(
      values["source-verification-file"],
      manifest.contracts,
      readJson,
      {
        allowedHosts: [Number(manifest.chainId) === 4663
          ? "robinhoodchain.blockscout.com"
          : "explorer.testnet.chain.robinhood.com"],
        expectedCompiler: "0.8.24",
      },
    ),
  ]);
  const codeChecks = {
    backend: backendCode !== "0x"
      && keccak256(backendCode).toLowerCase()
        === manifest.contracts.backend.runtimeCodeHash.toLowerCase(),
    adapter: adapterCode !== "0x"
      && keccak256(adapterCode).toLowerCase()
        === manifest.contracts.adapter.runtimeCodeHash.toLowerCase(),
  };
  const checks = {
    runtimeCodeHashes: Object.values(codeChecks).every(Boolean),
    backendBinding: pinnedBackend.toLowerCase() === backendAddress.toLowerCase()
      && pinnedBackendCodeHash.toLowerCase() === keccak256(backendCode).toLowerCase(),
    proofDataLength: Number(proofLength) === 416 && Number(manifest.proofDataLength) === 416,
    publicKeyValidation: publicKeyValid === true,
    rfc9380HashToCurveAndPairing: signatureValid === true,
    adapterKeyValidation: adapterKeyValid === true,
    sourceVerified: sourceVerification.pass,
  };
  const pass = Object.values(checks).every(Boolean);
  const report = {
    format: "robinhood-proof-vrf-threshold-verifier-verification/v1",
    generatedAt: new Date().toISOString(),
    chainId: network.chainId.toString(),
    gitCommit: manifest.gitCommit,
    backend: backendAddress,
    adapter: adapterAddress,
    codeChecks,
    checks,
    sourceVerification,
    status: pass ? "pass" : "fail",
  };
  if (values.out) {
    if (existsSync(values.out) && !values.overwrite) throw new Error("output report exists");
    writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`, {
      flag: values.overwrite ? "w" : "wx",
      mode: 0o600,
    });
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!pass) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error.shortMessage || error.message || String(error)}\n`);
  process.exitCode = 1;
});

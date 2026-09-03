#!/usr/bin/env node
import process from "node:process";
import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { Interface, JsonRpcProvider } from "ethers";
import { BLS_DST } from "./threshold-crypto.mjs";

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    if (!argv[index]?.startsWith("--") || argv[index + 1] === undefined) {
      throw new Error(`invalid argument near ${argv[index] || "end of command"}`);
    }
    options[argv[index].slice(2)] = argv[index + 1];
  }
  return options;
}

function fieldElement(value) {
  return value.toString(16).padStart(128, "0");
}

function g1(point) {
  const affine = point.toAffine();
  return `${fieldElement(affine.x)}${fieldElement(affine.y)}`;
}

function g2(point) {
  const affine = point.toAffine();
  return [affine.x.c0, affine.x.c1, affine.y.c0, affine.y.c1]
    .map(fieldElement)
    .join("");
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options["rpc-url"]) throw new Error("--rpc-url is required");
  const provider = new JsonRpcProvider(options["rpc-url"]);
  const network = await provider.getNetwork();
  const arbSys = new Interface(["function arbOSVersion() view returns (uint256)"]);
  const rawVersion = await provider.call({
    to: "0x0000000000000000000000000000000000000064",
    data: arbSys.encodeFunctionData("arbOSVersion"),
  });
  const arbOSVersionRaw = arbSys.decodeFunctionResult("arbOSVersion", rawVersion)[0];
  const bn254Pairing = await provider.call({
    to: "0x0000000000000000000000000000000000000008",
    data: "0x",
  });
  const bls12381G1Add = await provider.call({
    to: "0x000000000000000000000000000000000000000b",
    data: `0x${"00".repeat(256)}`,
  });
  const pairingMessage = new Uint8Array(32).fill(0x42);
  const messagePoint = bls.G1.hashToCurve(pairingMessage, { DST: BLS_DST });
  const pairingSecret = 123456789n;
  const pairingSignature = messagePoint.multiply(pairingSecret);
  const pairingPublicKey = bls.G2.ProjectivePoint.BASE.multiply(pairingSecret);
  const bls12381Pairing = await provider.call({
    to: "0x000000000000000000000000000000000000000f",
    data: `0x${g1(pairingSignature)}${g2(bls.G2.ProjectivePoint.BASE.negate())}${g1(messagePoint)}${g2(pairingPublicKey)}`,
  });
  const report = {
    format: "proof-vrf-precompile-probe-v1",
    checkedAt: new Date().toISOString(),
    chainId: network.chainId.toString(),
    arbOSVersionRaw: arbOSVersionRaw.toString(),
    arbOSVersion: arbOSVersionRaw >= 55n ? (arbOSVersionRaw - 55n).toString() : null,
    precompiles: {
      bn254Pairing: {
        address: "0x0000000000000000000000000000000000000008",
        supported: bn254Pairing.length === 66 && BigInt(bn254Pairing) === 1n,
        outputBytes: (bn254Pairing.length - 2) / 2,
      },
      bls12381G1Add: {
        address: "0x000000000000000000000000000000000000000b",
        supported: bls12381G1Add.length === 258 && BigInt(bls12381G1Add) === 0n,
        outputBytes: (bls12381G1Add.length - 2) / 2,
      },
      bls12381Pairing: {
        address: "0x000000000000000000000000000000000000000f",
        supported: bls12381Pairing.length === 66 && BigInt(bls12381Pairing) === 1n,
        outputBytes: (bls12381Pairing.length - 2) / 2,
        vector: "deterministic-rfc9380-g1-signature",
      },
    },
  };
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!report.precompiles.bls12381G1Add.supported
      || !report.precompiles.bls12381Pairing.supported) process.exitCode = 2;
}

main().catch((error) => {
  process.stderr.write(`${error.message || String(error)}\n`);
  process.exitCode = 1;
});

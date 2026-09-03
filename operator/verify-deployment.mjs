#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { Contract, JsonRpcProvider, getAddress, keccak256 } from "ethers";
import { verifySources } from "./source-verification.mjs";

const COORDINATOR_ABI = [
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function guardian() view returns (address)",
  "function blockhashStore() view returns (address)",
  "function l1FeeCalculator() view returns (address)",
  "function l1FeeCalculatorCodeHash() view returns (bytes32)",
  "function contextBlockNumber() view returns (uint256)",
  "function pricing() view returns (uint96 minimumRequestFeeWei,uint96 l1FeeReserveWei,uint32 fulfillmentOverheadGas,uint32 perWordGas,uint16 publicPremiumBps,uint16 operatorPremiumShareBps,uint32 requestTimeoutBlocks)",
  "function getKey(bytes32 keyHash) view returns ((address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,bool exists,bool active) config)",
];
const STORE_ABI = [
  "function blockContext() view returns (address)",
  "function blockContextCodeHash() view returns (bytes32)",
];
const TIMELOCK_ABI = [
  "function owner() view returns (address)",
  "function delay() view returns (uint64)",
  "function MIN_DELAY() view returns (uint64)",
];

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
  const manifest = JSON.parse(readFileSync(values.manifest, "utf8"));
  if (manifest.format !== "robinhood-proof-vrf-deployment/v1") {
    throw new Error("unsupported deployment manifest");
  }
  const provider = new JsonRpcProvider(values["rpc-url"]);
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(manifest.chainId)) throw new Error("manifest chainId mismatch");
  const codeChecks = {};
  for (const [name, deployed] of Object.entries(manifest.contracts)) {
    const code = await provider.getCode(getAddress(deployed.address));
    const runtimeCodeHash = keccak256(code);
    codeChecks[name] = {
      address: deployed.address,
      runtimeCodeHash,
      matchesManifest: code !== "0x" && runtimeCodeHash === deployed.runtimeCodeHash,
    };
  }
  const coordinatorAddress = manifest.contracts.coordinator.address;
  const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
  const [
    owner,
    pendingOwner,
    guardian,
    blockhashStore,
    l1FeeCalculator,
    pinnedL1CodeHash,
    contextBlock,
    key,
    pricing,
  ] =
    await Promise.all([
      coordinator.owner(),
      coordinator.pendingOwner(),
      coordinator.guardian(),
      coordinator.blockhashStore(),
      coordinator.l1FeeCalculator(),
      coordinator.l1FeeCalculatorCodeHash(),
      coordinator.contextBlockNumber(),
      coordinator.getKey(manifest.keyHash),
      coordinator.pricing(),
    ]);
  const store = new Contract(blockhashStore, STORE_ABI, provider);
  const timelock = new Contract(owner, TIMELOCK_ABI, provider);
  const rpcHead = await provider.getBlockNumber();
  const [
    blockContext,
    pinnedBlockContextCodeHash,
    governanceSafe,
    timelockDelay,
    minimumTimelockDelay,
    sourceVerification,
  ] = await Promise.all([
    store.blockContext(),
    store.blockContextCodeHash(),
    timelock.owner(),
    timelock.delay(),
    timelock.MIN_DELAY(),
    verifySources(
      values["source-verification-file"],
      manifest.contracts,
      (path) => JSON.parse(readFileSync(path, "utf8")),
      {
        allowedHosts: [Number(manifest.chainId) === 4663
          ? "robinhoodchain.blockscout.com"
          : "explorer.testnet.chain.robinhood.com"],
        expectedCompiler: "0.8.24",
      },
    ),
  ]);
  const [ownerCode, safeCode, contextCode, l1Code] = await Promise.all([
    provider.getCode(owner),
    provider.getCode(governanceSafe),
    provider.getCode(blockContext),
    provider.getCode(l1FeeCalculator),
  ]);
  const checks = {
    runtimeCodeHashes: Object.values(codeChecks).every((item) => item.matchesManifest),
    ownershipAccepted: owner.toLowerCase() === manifest.configuredOwner.toLowerCase()
      && pendingOwner === "0x0000000000000000000000000000000000000000",
    ownerIsTimelock: ownerCode !== "0x"
      && timelockDelay >= minimumTimelockDelay
      && timelockDelay >= 43_200n
      && keccak256(ownerCode).toLowerCase()
        === manifest.configuredOwnerRuntimeCodeHash?.toLowerCase()
      && timelockDelay.toString() === String(manifest.timelockDelaySeconds),
    timelockOwnedBySafe: safeCode !== "0x"
      && governanceSafe.toLowerCase() === manifest.governanceSafe?.toLowerCase(),
    guardian: guardian.toLowerCase() === manifest.guardian.toLowerCase(),
    blockhashStore: blockhashStore.toLowerCase()
      === manifest.contracts.blockhashStore.address.toLowerCase(),
    blockContext: blockContext.toLowerCase()
      === manifest.contracts.blockContext.address.toLowerCase(),
    blockContextCodeHash: contextCode !== "0x"
      && keccak256(contextCode) === pinnedBlockContextCodeHash,
    l1FeeCalculator: l1FeeCalculator.toLowerCase()
      === manifest.contracts.l1FeeCalculator.address.toLowerCase(),
    l1FeeCalculatorCodeHash: l1Code !== "0x" && keccak256(l1Code) === pinnedL1CodeHash,
    keyActive: key.exists && key.active,
    keyVerifier: key.verifier.toLowerCase() === manifest.contracts.verifier.address.toLowerCase(),
    keyFulfiller: key.fulfiller.toLowerCase() === manifest.fulfiller.toLowerCase(),
    keyPayee: key.payee.toLowerCase() === manifest.payee.toLowerCase(),
    keyGasLane: key.maxGasPriceWei.toString() === manifest.keyConfig?.maxGasPriceWei
      && key.verificationGasLimit.toString() === manifest.keyConfig?.verificationGasLimit,
    proofDataLength: Number(key.proofDataLength) === 416
      && Number(key.proofDataLength) === Number(manifest.keyConfig?.proofDataLength),
    pricing: [
      "minimumRequestFeeWei",
      "l1FeeReserveWei",
      "fulfillmentOverheadGas",
      "perWordGas",
      "publicPremiumBps",
      "operatorPremiumShareBps",
      "requestTimeoutBlocks",
    ].every((field) => pricing[field].toString() === manifest.pricing?.[field]),
    rolesSeparated: new Set([owner, guardian, key.fulfiller, key.payee]
      .map((item) => item.toLowerCase())).size === 4,
    l2ContextNearRpcHead: Math.abs(Number(contextBlock) - rpcHead) <= 8,
    sourceVerified: sourceVerification.pass,
  };
  const pass = Object.values(checks).every(Boolean);
  const report = {
    format: "robinhood-proof-vrf-deployment-verification/v1",
    generatedAt: new Date().toISOString(),
    chainId: network.chainId.toString(),
    coordinator: coordinatorAddress,
    gitCommit: manifest.gitCommit,
    rpcHead,
    contextBlock: contextBlock.toString(),
    governanceSafe,
    timelockDelaySeconds: timelockDelay.toString(),
    codeChecks,
    checks,
    sourceVerification,
    status: pass ? "pass" : "fail",
  };
  if (values.out) {
    if (existsSync(values.out) && !values.overwrite) throw new Error("output report exists");
    writeFileSync(values.out, `${JSON.stringify(report, null, 2)}\n`, {
      flag: values.overwrite ? "w" : "wx",
    });
  }
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (!pass) process.exitCode = 1;
}

main().catch((error) => {
  process.stderr.write(`${error.message || String(error)}\n`);
  process.exitCode = 1;
});

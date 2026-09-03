#!/usr/bin/env node
import process from "node:process";
import { parseArgs } from "node:util";
import { Contract, Interface, JsonRpcProvider, getAddress } from "ethers";

const TIMELOCK_ABI = [
  "function owner() view returns (address)",
  "function delay() view returns (uint64)",
  "function MIN_DELAY() view returns (uint64)",
  "function nonce() view returns (uint256)",
  "function hashOperation(uint256 operationNonce,address target,uint256 value,bytes data) view returns (bytes32)",
  "function schedule(address target,uint256 value,bytes data) returns (bytes32 operationId)",
  "function execute(uint256 operationNonce,address target,uint256 value,bytes data) returns (bytes result)",
];
const COORDINATOR_ABI = [
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
];

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      "rpc-url": { type: "string" },
      timelock: { type: "string" },
      coordinator: { type: "string" },
    },
    strict: true,
  });
  const provider = new JsonRpcProvider(values["rpc-url"]);
  const timelockAddress = getAddress(values.timelock);
  const coordinatorAddress = getAddress(values.coordinator);
  const timelock = new Contract(timelockAddress, TIMELOCK_ABI, provider);
  const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
  const coordinatorInterface = new Interface(["function acceptOwnership()"]);
  const acceptData = coordinatorInterface.encodeFunctionData("acceptOwnership");
  const [
    governanceSafe,
    delay,
    minimumDelay,
    currentNonce,
    currentOwner,
    pendingOwner,
  ] = await Promise.all([
    timelock.owner(),
    timelock.delay(),
    timelock.MIN_DELAY(),
    timelock.nonce(),
    coordinator.owner(),
    coordinator.pendingOwner(),
  ]);
  const [timelockCode, safeCode, coordinatorCode] = await Promise.all([
    provider.getCode(timelockAddress),
    provider.getCode(governanceSafe),
    provider.getCode(coordinatorAddress),
  ]);
  if (timelockCode === "0x" || safeCode === "0x" || coordinatorCode === "0x") {
    throw new Error("timelock, governance Safe, and coordinator must all be deployed contracts");
  }
  if (delay < minimumDelay || delay < 43_200n) {
    throw new Error("timelock delay is below the required 12 hours");
  }
  if (currentOwner.toLowerCase() === timelockAddress.toLowerCase()) {
    throw new Error("coordinator ownership is already accepted by the timelock");
  }
  if (pendingOwner.toLowerCase() !== timelockAddress.toLowerCase()) {
    throw new Error("coordinator pendingOwner is not the supplied timelock");
  }
  const operationNonce = currentNonce + 1n;
  const operationId = await timelock.hashOperation(
    operationNonce,
    coordinatorAddress,
    0,
    acceptData,
  );
  const timelockInterface = new Interface(TIMELOCK_ABI);
  process.stdout.write(`${JSON.stringify({
    governanceSafe,
    scheduleSafeTransaction: {
      to: timelockAddress,
      value: "0",
      data: timelockInterface.encodeFunctionData(
        "schedule",
        [coordinatorAddress, 0, acceptData],
      ),
    },
    operationNonce: operationNonce.toString(),
    operationId,
    minimumDelaySeconds: delay.toString(),
    permissionlessExecuteTransactionAfterDelay: {
      to: timelockAddress,
      value: "0",
      data: timelockInterface.encodeFunctionData(
        "execute",
        [operationNonce, coordinatorAddress, 0, acceptData],
      ),
    },
  }, null, 2)}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message || String(error)}\n`);
  process.exitCode = 1;
});

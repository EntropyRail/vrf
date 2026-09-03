#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import process from "node:process";
import { Contract, JsonRpcProvider } from "ethers";
import { isMain } from "./entrypoint.mjs";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";

const ABI = [
  "event RequestSettled(uint256 indexed requestId,uint256 networkCost,uint256 totalCharge,uint256 operatorPayment,uint256 treasuryPayment)",
  "function getRequest(uint256 requestId) view returns ((address consumer,address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,bytes32 keyHash,uint256 subscriptionId,uint256 preSeed,uint256 reservedPayment,uint256 randomness,uint96 minimumFeeWei,uint64 requestBlock,uint64 expiresAtBlock,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,uint32 callbackGasLimit,uint32 numWords,uint32 callbackAttempts,uint32 fulfillmentOverheadGas,uint16 confirmations,uint16 premiumBps,uint16 operatorPremiumShareBps,uint8 status,bool sponsored,bool waiveMinimumFee,bool callbackSucceeded) request)",
];

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined) {
      throw new Error(`invalid argument near ${name || "end of command"}`);
    }
    options[name.slice(2)] = value;
  }
  return options;
}

function integer(value, name, fallback, minimum = 0) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) throw new Error(`invalid --${name}`);
  return parsed;
}

function bigintFromRpc(value) {
  if (value === undefined || value === null) return null;
  try {
    const parsed = BigInt(value);
    return parsed >= 0n ? parsed : null;
  } catch {
    return null;
  }
}

function receiptFees(receipt) {
  if (!receipt || bigintFromRpc(receipt.status) !== 1n) {
    throw new Error("settlement receipt is missing or unsuccessful");
  }
  const gasPrice = bigintFromRpc(receipt.effectiveGasPrice ?? receipt.gasPrice);
  const gasUsed = bigintFromRpc(receipt.gasUsed);
  if (gasPrice === null || gasUsed === null) throw new Error("receipt gas fields are unavailable");
  const directL1Fee = bigintFromRpc(receipt.l1Fee ?? receipt.l1FeeWei);
  const gasUsedForL1 = bigintFromRpc(receipt.gasUsedForL1);
  if (gasUsedForL1 !== null && gasUsedForL1 > gasUsed) {
    throw new Error("receipt gasUsedForL1 exceeds total gasUsed");
  }
  // Nitro reports parent-chain gas in child-chain gas units. It is ALREADY included
  // in gasUsed; do not add the derived parent fee to the total transaction fee.
  // https://docs.arbitrum.io/how-arbitrum-works/deep-dives/gas-and-fees
  const l1Fee = directL1Fee ?? (gasUsedForL1 === null ? null : gasUsedForL1 * gasPrice);
  return {
    gasPrice, gasUsed, l1Fee,
    transactionFee: gasUsed * gasPrice,
    l1FeeSource: directL1Fee !== null ? "receipt.l1Fee"
      : gasUsedForL1 !== null ? "gasUsedForL1*effectiveGasPrice" : "unavailable",
  };
}

function fingerprint(value) {
  return JSON.stringify(value, (_, item) => typeof item === "bigint" ? item.toString() : item);
}

function assertConsensus(values, label) {
  if (values.some((value) => fingerprint(value) !== fingerprint(values[0]))) {
    throw new Error(`independent RPC endpoints disagree on ${label}`);
  }
}

function percentile(values, percent) {
  if (values.length === 0) return null;
  const sorted = [...values].sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  return sorted[Math.max(0, Math.ceil((percent / 100) * sorted.length) - 1)];
}

function distribution(values) {
  return {
    samples: values.length,
    p50: percentile(values, 50)?.toString() ?? null,
    p95: percentile(values, 95)?.toString() ?? null,
    p99: percentile(values, 99)?.toString() ?? null,
    max: percentile(values, 100)?.toString() ?? null,
  };
}

async function queryInRanges(contract, filter, fromBlock, toBlock, blockRange) {
  const events = [];
  for (let start = fromBlock; start <= toBlock; start += blockRange) {
    events.push(...await contract.queryFilter(filter, start, Math.min(toBlock, start + blockRange - 1)));
  }
  return events;
}

function recommendation(value, multiplierBps) {
  return value === null ? null : ((value * BigInt(multiplierBps) + 9_999n) / 10_000n).toString();
}

function minimumFeeFromUsd(target, price) {
  if (target === undefined && price === undefined) return null;
  function decimal(value) {
    const text = String(value);
    if (!/^\d+(?:\.\d{1,18})?$/.test(text)) throw new Error("USD inputs must be positive decimal values (up to 18 decimals)");
    const [whole, fraction = ""] = text.split(".");
    const numerator = BigInt(whole + fraction);
    if (numerator === 0n) throw new Error("USD inputs must both be positive");
    return { numerator, scale: 10n ** BigInt(fraction.length) };
  }
  const usd = decimal(target);
  const eth = decimal(price);
  const numerator = usd.numerator * eth.scale * 10n ** 18n;
  const denominator = usd.scale * eth.numerator;
  return ((numerator + denominator - 1n) / denominator).toString();
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.coordinator || options["from-block"] === undefined) {
    throw new Error("--coordinator and --from-block are required");
  }
  const rpcUrls = normalizeRpcUrls([
    ...(readSecret("VRF_RPC_URLS") || "").split(","),
    options["rpc-url"], options["rpc-url-secondary"],
  ], { minimum: 2, label: "fee calibration" });
  const providers = rpcUrls.map((url) => new JsonRpcProvider(url));
  try {
    await collectReport(options, providers, rpcUrls);
  } finally {
    providers.forEach((provider) => provider.destroy());
  }
}

async function collectReport(options, providers, rpcUrls) {
  const networks = await Promise.all(providers.map((provider) => provider.getNetwork()));
  assertConsensus(networks.map((network) => network.chainId.toString()), "chain ID");
  const network = networks[0];
  const fromBlock = integer(options["from-block"], "from-block", undefined);
  const heads = await Promise.all(providers.map((provider) => provider.getBlockNumber()));
  const confirmations = integer(options.confirmations, "confirmations", 12, 1);
  const toBlock = options["to-block"] === undefined
    ? Math.min(...heads) - confirmations
    : integer(options["to-block"], "to-block", undefined);
  if (heads.some((head) => toBlock > head - confirmations)) {
    throw new Error("--to-block has insufficient confirmations on an RPC");
  }
  const blockRange = integer(options["block-range"], "block-range", 2_000, 1);
  const minimumSamples = integer(options["minimum-samples"], "minimum-samples", 100, 1);
  if (toBlock < fromBlock) throw new Error("--to-block must not be below --from-block");

  const coordinators = providers.map((provider) => new Contract(options.coordinator, ABI, provider));
  const boundaryBlocks = await Promise.all(providers.map((provider) => provider.getBlock(toBlock)));
  if (boundaryBlocks.some((block) => !block)) throw new Error("calibration boundary block is missing");
  assertConsensus(boundaryBlocks.map((block) => block.hash), "boundary block");
  const eventSets = await Promise.all(coordinators.map((coordinator) => queryInRanges(
    coordinator,
    coordinator.filters.RequestSettled(),
    fromBlock,
    toBlock,
    blockRange,
  )));
  assertConsensus(eventSets.map((events) => events.map((event) => ({
    hash: event.transactionHash, blockHash: event.blockHash, index: event.index,
    topics: event.topics, data: event.data,
  }))), "settlements");
  const events = eventSets[0];
  const networkCosts = [];
  const totalCharges = [];
  const reservedPayments = [];
  const effectiveGasPrices = [];
  const receiptGasUsed = [];
  const l1Fees = [];
  const transactionFees = [];
  const l1FeeSources = {};
  const samples = [];
  let reserveViolations = 0;
  let networkCostBelowReceiptFee = 0;
  let operatorPaymentBelowReceiptFee = 0;

  for (const event of events) {
    const measurements = await Promise.all(providers.map(async (provider, index) => {
      const [request, rawReceipt] = await Promise.all([
        coordinators[index].getRequest(event.args.requestId, { blockTag: toBlock }),
        provider.send("eth_getTransactionReceipt", [event.transactionHash]),
      ]);
      const fees = receiptFees(rawReceipt);
      if (rawReceipt.blockHash?.toLowerCase() !== event.blockHash.toLowerCase()
          || rawReceipt.transactionHash?.toLowerCase() !== event.transactionHash.toLowerCase()) {
        throw new Error("receipt does not match the settlement event");
      }
      return { reservedPayment: BigInt(request.reservedPayment), ...fees };
    }));
    assertConsensus(measurements, "receipt fees and request reserve");
    const networkCost = BigInt(event.args.networkCost);
    const totalCharge = BigInt(event.args.totalCharge);
    const { reservedPayment, gasPrice, gasUsed, l1Fee, transactionFee, l1FeeSource } = measurements[0];
    networkCosts.push(networkCost);
    totalCharges.push(totalCharge);
    reservedPayments.push(reservedPayment);
    if (gasPrice !== null) effectiveGasPrices.push(gasPrice);
    if (gasUsed !== null) receiptGasUsed.push(gasUsed);
    if (l1Fee !== null) l1Fees.push(l1Fee);
    transactionFees.push(transactionFee);
    l1FeeSources[l1FeeSource] = (l1FeeSources[l1FeeSource] || 0) + 1;
    if (totalCharge > reservedPayment) reserveViolations += 1;
    if (networkCost < transactionFee) networkCostBelowReceiptFee += 1;
    if (BigInt(event.args.operatorPayment) < transactionFee) operatorPaymentBelowReceiptFee += 1;
    samples.push({ requestId: event.args.requestId.toString(), transactionHash: event.transactionHash,
      blockNumber: event.blockNumber, gasUsed: gasUsed.toString(), gasPriceWei: gasPrice.toString(),
      transactionFeeWei: transactionFee.toString(), l1FeeWei: l1Fee?.toString() ?? null,
      l1FeeSource, networkCostWei: networkCost.toString(), totalChargeWei: totalCharge.toString() });
  }

  const gasP99 = percentile(effectiveGasPrices, 99);
  const l1P99 = percentile(l1Fees, 99);
  const targetMinimumUsd = options["target-minimum-usd"];
  const ethUsd = options["eth-usd"];
  const minimumRequestFeeWei = minimumFeeFromUsd(targetMinimumUsd, ethUsd);
  const finalBoundaries = await Promise.all(providers.map((provider) => provider.getBlock(toBlock)));
  if (finalBoundaries.some((block) => block?.hash !== boundaryBlocks[0].hash)) {
    throw new Error("calibration boundary changed during collection; rerun after the reorg");
  }

  const report = {
    format: "proof-vrf-gas-calibration-v1",
    generatedAt: new Date().toISOString(),
    chainId: network.chainId.toString(),
    coordinator: options.coordinator.toLowerCase(),
    rpcCount: rpcUrls.length,
    rpcConsensus: true,
    range: { fromBlock, toBlock, endBlockHash: boundaryBlocks[0].hash, confirmations },
    sufficientSample: events.length >= minimumSamples,
    minimumSamples,
    distributionsWei: {
      networkCost: distribution(networkCosts),
      totalCharge: distribution(totalCharges),
      reservedPayment: distribution(reservedPayments),
      effectiveGasPrice: distribution(effectiveGasPrices),
      l1Fee: distribution(l1Fees),
      transactionFee: distribution(transactionFees),
    },
    distributionsGas: { receiptGasUsed: distribution(receiptGasUsed) },
    reserveViolations,
    networkCostBelowReceiptFee,
    operatorPaymentBelowReceiptFee,
    l1FeeSources,
    samples,
    readyForGovernanceReview: events.length >= Math.max(100, minimumSamples) && reserveViolations === 0
      && l1Fees.length === events.length && operatorPaymentBelowReceiptFee === 0,
    recommendations: {
      maxGasPriceWei: recommendation(gasP99, 12_500),
      l1FeeReserveWei: recommendation(l1P99, 15_000),
      minimumRequestFeeWei,
      basis: {
        maxGasPriceWei: "125% of observed p99 effective gas price",
        l1FeeReserveWei: l1P99 === null
          ? "unavailable: RPC receipts did not expose parent-chain fee fields"
          : "150% of observed p99 L1 fee",
        minimumRequestFeeWei: targetMinimumUsd === undefined
          ? "unavailable: provide --target-minimum-usd and --eth-usd"
          : `manual ETH/USD input ${ethUsd}; target USD ${targetMinimumUsd}`,
      },
      warning: events.length < Math.max(100, minimumSamples)
        ? "sample is below the requested minimum; do not apply these values"
        : "apply only through timelocked governance after human review",
    },
  };
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (options.out) {
    if (existsSync(options.out) && options.overwrite !== "true") {
      throw new Error("output exists; pass --overwrite true to replace it");
    }
    writeFileSync(options.out, output, { flag: options.overwrite === "true" ? "w" : "wx", mode: 0o600 });
  }
  process.stdout.write(output);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${String(error.message || error).replace(/https?:\/\/[^\s"'<>]+/g, "[redacted-url]")}\n`);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({ percentile, distribution, bigintFromRpc, receiptFees, assertConsensus, minimumFeeFromUsd });

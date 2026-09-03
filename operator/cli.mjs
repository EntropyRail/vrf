#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import process from "node:process";
import {
  AbiCoder,
  Contract,
  FallbackProvider,
  JsonRpcProvider,
  Wallet,
  keccak256,
} from "ethers";
import {
  generateProof,
  publicKeyFor,
  publicKeyHash,
  serviceKeyHash,
} from "./proof.mjs";
import { PostgresOperatorStore } from "./postgres-store.mjs";
import { createProofProvider } from "./proof-provider.mjs";
import { checkReadiness } from "./readiness.mjs";
import { isMain } from "./entrypoint.mjs";
import { normalizeRpcUrls, rpcOriginCount } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";
import { errorDetails, errorMessage } from "./errors.mjs";
import { pendingNonceConsensus, rpcProvider } from "./rpc.mjs";

const ABI = [
  "event RandomWordsRequested(bytes32 indexed keyHash,uint256 indexed requestId,address indexed consumer,uint256 preSeed,uint256 requestBlock,uint16 confirmations,uint32 callbackGasLimit,uint32 numWords,uint256 fee)",
  "function requests(uint256 requestId) view returns (address consumer,address operator,bytes32 keyHash,uint64 requestBlock,uint16 confirmations,uint32 callbackGasLimit,uint32 numWords,uint96 feePaid,uint32 callbackAttempts,bool fulfilled,bool refunded,bool callbackSucceeded,uint256 preSeed,uint256 randomness)",
  "function requestSeed(uint256 requestId) view returns (uint256)",
  "function fulfillRandomWords(uint256 requestId,(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv) proof) returns (uint256 randomness,bool callbackSuccess)",
];

const SERVICE_ABI = [
  "event RandomWordsRequested(bytes32 indexed keyHash,uint256 indexed requestId,address indexed consumer,uint256 subscriptionId,uint256 preSeed,uint256 requestBlock,uint256 expiresAtBlock,uint32 callbackGasLimit,uint32 numWords,uint256 reservedPayment,bool sponsored)",
  "event ProofVerified(uint256 indexed requestId,bytes32 indexed keyHash,uint256 randomness)",
  "event RequestExpiredAndReleased(uint256 indexed requestId,uint256 releasedPayment)",
  "function getKey(bytes32 keyHash) view returns ((address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,bool exists,bool active) config)",
  "function getRequest(uint256 requestId) view returns ((address consumer,address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,bytes32 keyHash,uint256 subscriptionId,uint256 preSeed,uint256 reservedPayment,uint256 randomness,uint96 minimumFeeWei,uint64 requestBlock,uint64 expiresAtBlock,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,uint32 callbackGasLimit,uint32 numWords,uint32 callbackAttempts,uint32 fulfillmentOverheadGas,uint16 confirmations,uint16 premiumBps,uint16 operatorPremiumShareBps,uint8 status,bool sponsored,bool waiveMinimumFee,bool callbackSucceeded) request)",
  "function blockhashStore() view returns (address)",
  "function contextBlockNumber() view returns (uint256)",
  "function requestSeed(uint256 requestId) view returns (uint256)",
  "function fulfillRandomWords(uint256 requestId,bytes proofData) returns (uint256 randomness,bool callbackSuccess,uint256 charge)",
];

const BLOCKHASH_STORE_ABI = [
  "function blockhashes(uint256 blockNumber) view returns (bytes32)",
  "function getBlockHash(uint256 blockNumber) view returns (bytes32)",
  "function store(uint256 blockNumber) returns (bytes32 blockHash)",
];

const PROOF_TYPE =
  "tuple(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv)";
const abiCoder = AbiCoder.defaultAbiCoder();

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let i = 0; i < rest.length; i += 1) {
    const item = rest[i];
    if (!item.startsWith("--")) throw new Error(`unexpected argument: ${item}`);
    const value = rest[i + 1];
    if (value === undefined || value.startsWith("--")) throw new Error(`missing value for ${item}`);
    options[item.slice(2)] = value;
    i += 1;
  }
  return { command, options };
}

function password() {
  return readSecret("VRF_KEY_PASSWORD", { required: true });
}

async function createKey(outputPath) {
  if (!outputPath) throw new Error("--out is required");
  if (existsSync(outputPath)) throw new Error(`refusing to overwrite existing key: ${outputPath}`);

  const wallet = Wallet.createRandom();
  const publicKey = publicKeyFor(wallet.privateKey);
  const encryptedKey = JSON.parse(await wallet.encrypt(password()));
  const payload = {
    format: "proof-vrf-keystore-v1",
    purpose: "VRF_PROOF_KEY_DO_NOT_USE_FOR_TRANSACTIONS",
    publicKey: publicKey.map(String),
    keyHash: publicKeyHash(publicKey),
    serviceKeyHash: serviceKeyHash(publicKey),
    encryptedKey,
  };
  writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    publicKey: payload.publicKey,
    keyHash: payload.keyHash,
    serviceKeyHash: payload.serviceKeyHash,
  })}\n`);
}

async function loadProofWallet(keyPath) {
  if (!keyPath) throw new Error("--keystore is required");
  const payload = JSON.parse(readFileSync(keyPath, "utf8"));
  if (payload.format !== "proof-vrf-keystore-v1") throw new Error("unsupported VRF keystore format");
  return Wallet.fromEncryptedJson(JSON.stringify(payload.encryptedKey), password());
}

function jsonProof(result) {
  return JSON.stringify({
    ...result,
    proof: Object.fromEntries(
      Object.entries(result.proof).map(([key, value]) => [
        key,
        Array.isArray(value) ? value.map(String) : typeof value === "bigint" ? value.toString() : value,
      ]),
    ),
    output: result.output.toString(),
    publicKey: result.publicKey.map(String),
  });
}

async function prove(options) {
  const wallet = await loadProofWallet(options.keystore);
  if (!options["actual-seed"] || !options["pre-seed"]) {
    throw new Error("--actual-seed and --pre-seed are required");
  }
  const result = generateProof({
    privateKey: wallet.privateKey,
    actualSeed: options["actual-seed"],
    preSeed: options["pre-seed"],
  });
  process.stdout.write(`${jsonProof(result)}\n`);
}

async function run(options) {
  if (!options["rpc-url"] || !options.coordinator || !options.keystore) {
    throw new Error("--rpc-url, --coordinator, and --keystore are required");
  }
  if (!options["from-block"]) throw new Error("--from-block is required for restart-safe scanning");
  const relayerPrivateKey = readSecret("VRF_TX_PRIVATE_KEY", { required: true });

  const proofWallet = await loadProofWallet(options.keystore);
  const proofPublicKey = publicKeyFor(proofWallet.privateKey);
  const proofKeyHash = publicKeyHash(proofPublicKey);
  const provider = new JsonRpcProvider(options["rpc-url"]);
  const relayer = new Wallet(relayerPrivateKey, provider);
  if (relayer.address.toLowerCase() === proofWallet.address.toLowerCase()) {
    throw new Error("proof key and relayer transaction key must be different");
  }
  const coordinator = new Contract(options.coordinator, ABI, relayer);
  const pollMs = Number(options["poll-ms"] || 4_000);
  const blockRange = Number(options["block-range"] || 2_000);
  let cursor = Number(options["from-block"]);
  if (!Number.isSafeInteger(cursor) || cursor < 0) throw new Error("invalid --from-block");
  if (!Number.isSafeInteger(blockRange) || blockRange <= 0) throw new Error("invalid --block-range");
  if (!Number.isSafeInteger(pollMs) || pollMs < 250) throw new Error("invalid --poll-ms");
  const pending = new Map();

  process.stdout.write(`${JSON.stringify({
    status: "started",
    coordinator: options.coordinator,
    keyHash: proofKeyHash,
    relayer: relayer.address,
    fromBlock: cursor,
  })}\n`);

  for (;;) {
    const latest = await provider.getBlockNumber();
    if (cursor <= latest) {
      const rangeEnd = Math.min(latest, cursor + blockRange - 1);
      const events = await coordinator.queryFilter(
        coordinator.filters.RandomWordsRequested(proofKeyHash), cursor, rangeEnd,
      );
      for (const event of events) {
        pending.set(event.args.requestId.toString(), {
          requestId: event.args.requestId,
          preSeed: event.args.preSeed,
        });
      }
      cursor = rangeEnd + 1;
    }

    for (const [id, request] of pending) {
      try {
        const actualSeed = await coordinator.requestSeed(request.requestId);
        const { proof, output } = generateProof({
          privateKey: proofWallet.privateKey,
          actualSeed,
          preSeed: request.preSeed,
        });
        const transaction = await coordinator.fulfillRandomWords(request.requestId, proof);
        const receipt = await transaction.wait();
        process.stdout.write(`${JSON.stringify({
          status: "fulfilled",
          requestId: id,
          output: output.toString(),
          transactionHash: receipt.hash,
        })}\n`);
        pending.delete(id);
      } catch (error) {
        const message = errorMessage(error);
        if (/ConfirmationsPending|BlockhashUnavailable/.test(message)) continue;
        if (/RequestAlreadyFinalized|RequestNotFulfilled|execution reverted/.test(message)) {
          // Some RPC providers omit custom-error data. Read durable request state before deciding
          // whether a generic revert means "still waiting" or "already handled by another relayer".
          try {
            const state = await coordinator.requests(request.requestId);
            if (state.fulfilled || state.refunded) pending.delete(id);
          } catch {
            // Preserve the request for the next polling cycle when state cannot be read.
          }
          continue;
        }
        process.stderr.write(`${JSON.stringify({ status: "error", requestId: id, message })}\n`);
      }
    }

    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

function positiveInteger(value, name, fallback, minimum = 1) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) throw new Error(`invalid --${name}`);
  return parsed;
}

function createProvider(rpcUrls) {
  return new FallbackProvider(rpcUrls.map((url, index) => ({
    provider: rpcProvider(url),
    priority: index + 1,
    stallTimeout: 2_000,
    weight: 1,
  })), undefined, { quorum: 1 });
}

function requestFingerprint(request, actualSeed) {
  return JSON.stringify({
    consumer: request.consumer.toLowerCase(),
    verifier: request.verifier.toLowerCase(),
    verifierCodeHash: request.verifierCodeHash.toLowerCase(),
    fulfiller: request.fulfiller.toLowerCase(),
    payee: request.payee.toLowerCase(),
    keyHash: request.keyHash.toLowerCase(),
    subscriptionId: request.subscriptionId.toString(),
    preSeed: request.preSeed.toString(),
    reservedPayment: request.reservedPayment.toString(),
    randomness: request.randomness.toString(),
    minimumFeeWei: request.minimumFeeWei.toString(),
    requestBlock: request.requestBlock.toString(),
    expiresAtBlock: request.expiresAtBlock.toString(),
    maxGasPriceWei: request.maxGasPriceWei.toString(),
    verificationGasLimit: Number(request.verificationGasLimit),
    proofDataLength: Number(request.proofDataLength),
    callbackGasLimit: Number(request.callbackGasLimit),
    numWords: Number(request.numWords),
    callbackAttempts: Number(request.callbackAttempts),
    fulfillmentOverheadGas: Number(request.fulfillmentOverheadGas),
    confirmations: Number(request.confirmations),
    premiumBps: Number(request.premiumBps),
    operatorPremiumShareBps: Number(request.operatorPremiumShareBps),
    status: Number(request.status),
    sponsored: request.sponsored,
    waiveMinimumFee: request.waiveMinimumFee,
    callbackSucceeded: request.callbackSucceeded,
    actualSeed: actualSeed.toString(),
  });
}

async function readRequestConsensus({ rpcProviders, coordinatorAddress, requestId, keyHash }) {
  const states = await Promise.all(rpcProviders.map(async (rpcProvider) => {
    const contract = new Contract(coordinatorAddress, SERVICE_ABI, rpcProvider);
    const [request, actualSeed] = await Promise.all([
      contract.getRequest(requestId),
      contract.requestSeed(requestId),
    ]);
    if (Number(request.status) !== 1 || request.keyHash.toLowerCase() !== keyHash.toLowerCase()) {
      throw new Error("RPC returned a non-pending request or the wrong keyHash");
    }
    return { request, actualSeed, fingerprint: requestFingerprint(request, actualSeed) };
  }));
  if (states.some((state) => state.fingerprint !== states[0].fingerprint)) {
    throw new Error("independent RPC endpoints disagree on the canonical request");
  }
  return states[0];
}

function writeJsonAtomic(path, value) {
  const temporaryPath = `${path}.tmp`;
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporaryPath, path);
}

function loadServiceState(path, expected) {
  if (!existsSync(path)) {
    return {
      format: "proof-vrf-service-operator-state-v1",
      ...expected,
      cursor: expected.deploymentBlock,
      requests: {},
      updatedAt: new Date().toISOString(),
    };
  }
  const state = JSON.parse(readFileSync(path, "utf8"));
  for (const field of ["format", "chainId", "coordinator", "keyHash", "deploymentBlock"]) {
    if (String(state[field]).toLowerCase() !== String(expected[field]).toLowerCase()) {
      throw new Error(`state file ${field} does not match this operator`);
    }
  }
  if (!state.requests || !Number.isSafeInteger(state.cursor)) {
    throw new Error("invalid operator state file");
  }
  return state;
}

async function waitForReceipt(transaction, timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      transaction.wait(),
      new Promise((resolve) => { timer = setTimeout(() => resolve(null), timeoutMs); }),
    ]);
  } finally { clearTimeout(timer); }
}

async function sendWithReplacement({
  wallet,
  provider,
  transactionRequest,
  maxGasPrice,
  timeoutMs,
  maximumAttempts,
  nonce: suppliedNonce,
  onBroadcast,
  beforeBroadcast,
  assertLease,
}) {
  const estimated = await provider.estimateGas({
    ...transactionRequest,
    from: wallet.address,
  });
  const gasLimit = (estimated * 120n) / 100n;
  const feeData = await provider.getFeeData();
  let gasPrice = feeData.gasPrice ?? feeData.maxFeePerGas;
  if (gasPrice === null) throw new Error("RPC did not return a gas price");
  if (gasPrice > maxGasPrice) {
    throw new Error(`GasPriceAboveLane:${gasPrice}:${maxGasPrice}`);
  }
  const nonce = suppliedNonce ?? await wallet.getNonce("pending");
  let lastHash;

  for (let attempt = 1; attempt <= maximumAttempts; attempt += 1) {
    const populated = await wallet.populateTransaction({
      ...transactionRequest,
      nonce,
      gasLimit,
      gasPrice,
    });
    const signedTransaction = await wallet.signTransaction(populated);
    lastHash = keccak256(signedTransaction);
    if (assertLease) await assertLease();
    if (beforeBroadcast) await beforeBroadcast({ gasLimit, gasPriceWei: gasPrice, transactionHash: lastHash, attempt });
    if (onBroadcast) {
      await onBroadcast({
        transactionHash: lastHash,
        nonce,
        gasPriceWei: gasPrice,
        attempt,
      });
    }
    if (assertLease) await assertLease();
    const transaction = await provider.broadcastTransaction(signedTransaction);
    if (transaction.hash.toLowerCase() !== lastHash.toLowerCase()) {
      throw new Error("RPC returned a transaction hash that differs from the signed transaction");
    }
    try {
      const receipt = await waitForReceipt(transaction, timeoutMs);
      if (receipt) return receipt;
    } catch (error) {
      if (error.code === "TRANSACTION_REPLACED" && error.receipt) return error.receipt;
      throw error;
    }

    const bumped = (gasPrice * 9n) / 8n + 1n;
    if (bumped > maxGasPrice || attempt === maximumAttempts) break;
    gasPrice = bumped;
  }
  throw new Error(`transaction not confirmed before replacement limit: ${lastHash}`);
}

async function scanServiceEvents({
  coordinator,
  state,
  latest,
  rangeSize,
  reorgLookback,
  keyHash,
  statePath,
}) {
  if (state.cursor > latest) return;
  const fromBlock = Math.max(
    state.deploymentBlock,
    Math.min(state.cursor, latest) - reorgLookback,
  );
  const toBlock = Math.min(latest, fromBlock + rangeSize - 1);

  for (const [requestId, request] of Object.entries(state.requests)) {
    if (request.eventBlockNumber >= fromBlock) delete state.requests[requestId];
  }

  const [requested, fulfilled, expired] = await Promise.all([
    coordinator.queryFilter(coordinator.filters.RandomWordsRequested(keyHash), fromBlock, toBlock),
    coordinator.queryFilter(coordinator.filters.ProofVerified(null, keyHash), fromBlock, toBlock),
    coordinator.queryFilter(coordinator.filters.RequestExpiredAndReleased(), fromBlock, toBlock),
  ]);
  for (const event of requested) {
    state.requests[event.args.requestId.toString()] = {
      requestId: event.args.requestId.toString(),
      preSeed: event.args.preSeed.toString(),
      requestBlock: event.args.requestBlock.toString(),
      expiresAtBlock: event.args.expiresAtBlock.toString(),
      eventBlockNumber: event.blockNumber,
      eventBlockHash: event.blockHash,
      transactionHash: event.transactionHash,
    };
  }
  for (const event of [...fulfilled, ...expired]) {
    delete state.requests[event.args.requestId.toString()];
  }
  state.cursor = Math.max(state.cursor, toBlock + 1);
  state.updatedAt = new Date().toISOString();
  writeJsonAtomic(statePath, state);
}

async function scanServiceEventsPostgres({
  coordinator,
  store,
  instanceId,
  fromBlock,
  toBlock,
  keyHash,
}) {
  const [requested, fulfilled, expired] = await Promise.all([
    coordinator.queryFilter(
      coordinator.filters.RandomWordsRequested(keyHash),
      fromBlock,
      toBlock,
    ),
    coordinator.queryFilter(
      coordinator.filters.ProofVerified(null, keyHash),
      fromBlock,
      toBlock,
    ),
    coordinator.queryFilter(
      coordinator.filters.RequestExpiredAndReleased(),
      fromBlock,
      toBlock,
    ),
  ]);
  await store.commitScan({
    instanceId,
    fromBlock,
    toBlock,
    requested: requested.map((event) => ({
      requestId: event.args.requestId.toString(),
      preSeed: event.args.preSeed.toString(),
      requestBlock: event.args.requestBlock.toString(),
      expiresAtBlock: event.args.expiresAtBlock.toString(),
      eventBlockNumber: event.blockNumber,
      eventBlockHash: event.blockHash,
      transactionHash: event.transactionHash,
    })),
    finalizedRequestIds: [...fulfilled, ...expired]
      .map((event) => event.args.requestId.toString()),
  });
}

async function sendPostgresTransaction({
  store,
  instanceId,
  wallet,
  provider,
  transactionRequest,
  maxGasPrice,
  timeoutMs,
  maximumAttempts,
  requestId,
  transactionKind,
  rpcProviders = [provider],
  beforeBroadcast,
}) {
  const receipt = await store.withRelayerNonceLock(wallet.address, async (lease) => {
    await reconcileRelayerTransactions({ store, rpcProviders, relayer: wallet.address });
    const nonce = await pendingNonceConsensus(rpcProviders, wallet.address);
    return sendWithReplacement({
      wallet,
      provider,
      transactionRequest,
      maxGasPrice,
      timeoutMs,
      maximumAttempts,
      nonce,
      beforeBroadcast,
      assertLease: lease?.assertHeld,
      onBroadcast: async ({ transactionHash, nonce, gasPriceWei }) => {
        await store.recordBroadcast({
          transactionHash,
          relayer: wallet.address,
          nonce,
          requestId,
          transactionKind,
          gasPriceWei,
          instanceId,
        });
      },
    });
  });
  try {
    await store.markMined(receipt.hash, receipt.blockNumber);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({
      status: "transaction-journal-error",
      transactionHash: receipt.hash,
      message: errorMessage(error),
      error: errorDetails(error),
    })}\n`);
  }
  return receipt;
}

async function reconcileRelayerTransactions({ store, rpcProviders, relayer }) {
  const unresolved = await store.listUnresolvedTransactions(relayer);
  const byNonce = new Map();
  for (const transaction of unresolved) {
    const transactions = byNonce.get(transaction.nonce) || [];
    transactions.push(transaction);
    byNonce.set(transaction.nonce, transactions);
  }
  for (const [nonce, transactions] of byNonce) {
    let mined = null;
    for (const transaction of transactions) {
      const receipts = await Promise.all(rpcProviders.map(
        (provider) => provider.getTransactionReceipt(transaction.transactionHash),
      ));
      const observed = receipts.filter(Boolean);
      if (observed.length > 0 && observed.length !== receipts.length) {
        throw new Error(`RpcReceiptDisagreement:${nonce}`);
      }
      if (observed.length === receipts.length && observed.some((receipt) => (
        receipt.blockHash.toLowerCase() !== observed[0].blockHash.toLowerCase()
        || receipt.status !== observed[0].status
      ))) {
        throw new Error(`RpcReceiptDisagreement:${nonce}`);
      }
      if (observed.length === receipts.length) {
        mined = { transactionHash: transaction.transactionHash, receipt: observed[0] };
        break;
      }
    }
    if (mined) {
      await store.resolveNonce({
        relayer,
        nonce,
        status: "replaced",
        minedTransactionHash: mined.transactionHash,
        blockNumber: mined.receipt.blockNumber,
      });
      continue;
    }
    const pending = (await Promise.all(transactions.flatMap((transaction) => (
      rpcProviders.map((provider) => provider.getTransaction(transaction.transactionHash))
    )))).some(Boolean);
    if (pending) throw new Error(`RelayerTransactionPending:${nonce}`);

    const latestNonces = await Promise.all(rpcProviders.map(
      (provider) => provider.getTransactionCount(relayer, "latest"),
    ));
    const allConsumed = latestNonces.every((latestNonce) => latestNonce > nonce);
    const allReusable = latestNonces.every((latestNonce) => latestNonce <= nonce);
    if (!allConsumed && !allReusable) throw new Error(`RpcNonceDisagreement:${nonce}`);
    await store.resolveNonce({
      relayer,
      nonce,
      status: allConsumed ? "consumed" : "dropped",
    });
  }
}

function retryDelaySeconds(message, attempts) {
  if (/RelayerNonceLeaseBusy|RpcNonceDisagreement/.test(message)) return 1;
  if (/RelayerTransactionPending/.test(message)) return 10;
  if (/ConfirmationsPending|BlockhashUnavailable/.test(message)) return 5;
  if (/GasPriceAboveLane/.test(message)) return 30;
  return Math.min(300, 2 ** Math.min(Number(attempts) + 1, 8));
}

async function runServicePostgres({
  options,
  provider,
  network,
  relayer,
  coordinator,
  blockhashStore,
  proofProvider,
  keyHash,
  coordinatorAddress,
  deploymentBlock,
  pollMs,
  blockRange,
  reorgLookback,
  eventConfirmations,
  replacementMs,
  replacementAttempts,
  archiveAfterBlocks,
  rpcProviders,
}) {
  const instanceId = options["instance-id"] || `${hostname()}:${process.pid}:${randomUUID()}`;
  const scanLeaseSeconds = positiveInteger(
    options["scan-lease-seconds"], "scan-lease-seconds", 60,
  );
  const requestLeaseSeconds = positiveInteger(
    options["request-lease-seconds"], "request-lease-seconds", 360,
  );
  const minimumRequestLeaseSeconds = Math.ceil(
    (2 * replacementMs * replacementAttempts) / 1_000,
  ) + 60;
  if (requestLeaseSeconds < minimumRequestLeaseSeconds) {
    throw new Error(
      `--request-lease-seconds must be at least ${minimumRequestLeaseSeconds} for the replacement policy`,
    );
  }
  const workLimit = positiveInteger(options["work-limit"], "work-limit", 25);
  const store = await PostgresOperatorStore.connect({
    databaseUrl: options["database-url"],
    identity: {
      chainId: network.chainId.toString(),
      coordinator: coordinatorAddress,
      keyHash,
      deploymentBlock,
    },
    maximumConnections: positiveInteger(
      options["database-pool-size"], "database-pool-size", 10,
    ),
  });
  const healthPath = options["health-file"];

  try {
    const initial = await store.summary();
    process.stdout.write(`${JSON.stringify({
      status: "started",
      mode: "service-v2-postgres",
      instanceId,
      coordinator: coordinatorAddress,
      keyHash,
      proofProvider: proofProvider.mode,
      relayer: relayer.address,
      cursor: initial.cursor,
      pending: initial.pending,
    })}\n`);

    for (;;) {
      try {
        const head = await provider.getBlockNumber();
        const latest = Math.max(deploymentBlock, head - eventConfirmations);
        await store.heartbeat(instanceId, {
          chainId: network.chainId.toString(),
          coordinator: coordinatorAddress,
          keyHash,
          head,
        });

        const scan = await store.claimScan({
          instanceId,
          latest,
          rangeSize: blockRange,
          reorgLookback,
          leaseSeconds: scanLeaseSeconds,
        });
        if (scan) {
          try {
            await scanServiceEventsPostgres({
              coordinator,
              store,
              instanceId,
              keyHash,
              ...scan,
            });
          } catch (error) {
            await store.releaseScan(instanceId);
            throw error;
          }
        }

        const contextBlock = await coordinator.contextBlockNumber();
        for (let processed = 0; processed < workLimit; processed += 1) {
          const pending = await store.claimRequest({ instanceId, leaseSeconds: requestLeaseSeconds });
          if (!pending) break;
          const requestId = pending.requestId;
          try {
            const request = await coordinator.getRequest(requestId);
            if (Number(request.status) !== 1) {
              await store.completeRequest(requestId, instanceId);
              continue;
            }

            if (contextBlock >= BigInt(pending.requestBlock) + BigInt(archiveAfterBlocks)) {
              const storedHash = await blockhashStore.blockhashes(pending.requestBlock);
              if (storedHash === `0x${"00".repeat(32)}`) {
                const archiveTransaction = await blockhashStore.store.populateTransaction(
                  pending.requestBlock,
                );
                const archiveReceipt = await sendPostgresTransaction({
                  store,
                  instanceId,
                  wallet: relayer,
                  provider,
                  transactionRequest: archiveTransaction,
                  maxGasPrice: request.maxGasPriceWei,
                  timeoutMs: replacementMs,
                  maximumAttempts: replacementAttempts,
                  requestId,
                  transactionKind: "blockhash-archive",
                  rpcProviders,
                });
                process.stdout.write(`${JSON.stringify({
                  status: "blockhash-archived",
                  instanceId,
                  requestId,
                  requestBlock: pending.requestBlock,
                  transactionHash: archiveReceipt.hash,
                })}\n`);
              }
            }

            const { actualSeed } = await readRequestConsensus({
              rpcProviders,
              coordinatorAddress,
              requestId,
              keyHash,
            });
            const proofResult = await proofProvider.prove({
              actualSeed,
              preSeed: pending.preSeed,
              requestId,
              coordinator: coordinatorAddress,
              chainId: network.chainId,
            });
            const proofData = proofResult.proofData
              ?? abiCoder.encode([PROOF_TYPE], [proofResult.proof]);
            const fulfillmentTransaction =
              await coordinator.fulfillRandomWords.populateTransaction(requestId, proofData);
            const receipt = await sendPostgresTransaction({
              store,
              instanceId,
              wallet: relayer,
              provider,
              transactionRequest: fulfillmentTransaction,
              maxGasPrice: request.maxGasPriceWei,
              timeoutMs: replacementMs,
              maximumAttempts: replacementAttempts,
              requestId,
              transactionKind: "fulfillment",
              rpcProviders,
            });
            await store.completeRequest(requestId, instanceId);
            process.stdout.write(`${JSON.stringify({
              status: "fulfilled",
              instanceId,
              requestId,
              output: proofResult.output.toString(),
              transactionHash: receipt.hash,
              blockNumber: receipt.blockNumber,
            })}\n`);
          } catch (error) {
            const message = errorMessage(error);
            let finalized = false;
            try {
              finalized = Number((await coordinator.getRequest(requestId)).status) !== 1;
            } catch {}
            if (finalized) {
              await store.completeRequest(requestId, instanceId);
              continue;
            }
            const retrySeconds = retryDelaySeconds(message, pending.attempts);
            await store.retryRequest(requestId, instanceId, message, retrySeconds);
            if (!/ConfirmationsPending|BlockhashUnavailable|GasPriceAboveLane|RelayerNonceLeaseBusy|RelayerTransactionPending/.test(message)) {
              process.stderr.write(`${JSON.stringify({
                status: "request-error",
                instanceId,
                requestId,
                retrySeconds,
                message,
                error: errorDetails(error),
              })}\n`);
            }
          }
        }

        const summary = await store.summary();
        const health = {
          status: "healthy",
          mode: "service-v2-postgres",
          instanceId,
          chainId: network.chainId.toString(),
          coordinator: coordinatorAddress,
          keyHash,
          proofProvider: proofProvider.mode,
          head,
          ...summary,
          updatedAt: new Date().toISOString(),
        };
        if (healthPath) writeJsonAtomic(healthPath, health);
        if (options.once === "true") return;
      } catch (error) {
        const message = errorMessage(error);
        process.stderr.write(`${JSON.stringify({
          status: "loop-error",
          instanceId,
          message,
          error: errorDetails(error),
        })}\n`);
        if (healthPath) {
          writeJsonAtomic(healthPath, {
            status: "unhealthy",
            instanceId,
            message,
            updatedAt: new Date().toISOString(),
          });
        }
        if (options.once === "true") throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  } finally {
    await store.close();
  }
}

async function runService(options) {
  options["rpc-urls"] ||= readSecret("VRF_RPC_URLS");
  options["database-url"] ||= readSecret("VRF_DATABASE_URL");
  options["prover-url"] ||= process.env.VRF_PROVER_URL;
  if (options.readiness === "true") {
    const report = await checkReadiness(options);
    process.stdout.write(`${JSON.stringify({
      status: "readiness-passed",
      ...report,
    })}\n`);
  }
  if (!options["rpc-urls"] || !options.coordinator) {
    throw new Error("--rpc-urls and --coordinator are required");
  }
  const proofModeCount = [options.keystore, options["prover-url"], options["threshold-manifest"]]
    .filter(Boolean).length;
  if (proofModeCount !== 1) {
    throw new Error("configure exactly one of --keystore, --prover-url, or --threshold-manifest");
  }
  if (Boolean(options.state) === Boolean(options["database-url"])) {
    throw new Error("configure exactly one of --state or --database-url");
  }
  const relayerPrivateKey = readSecret("VRF_TX_PRIVATE_KEY", { required: true });

  const deploymentBlock = positiveInteger(
    options["from-block"], "from-block", undefined, 0,
  );
  const pollMs = positiveInteger(options["poll-ms"], "poll-ms", 4_000, 250);
  const blockRange = positiveInteger(options["block-range"], "block-range", 2_000);
  const reorgLookback = positiveInteger(options["reorg-lookback"], "reorg-lookback", 32);
  const eventConfirmations = positiveInteger(
    options["event-confirmations"], "event-confirmations", 2, 0,
  );
  const replacementMs = positiveInteger(
    options["replacement-ms"], "replacement-ms", 45_000, 5_000,
  );
  const replacementAttempts = positiveInteger(
    options["replacement-attempts"], "replacement-attempts", 3,
  );
  const archiveAfterBlocks = positiveInteger(
    options["archive-after-blocks"], "archive-after-blocks", 128,
  );
  if (archiveAfterBlocks >= 256) throw new Error("--archive-after-blocks must be below 256");
  const allowSharedRpcOrigin = process.env.VRF_ALLOW_SHARED_RPC_ORIGIN === "true"
    && !options["threshold-manifest"];
  const rpcUrls = normalizeRpcUrls(options["rpc-urls"], {
    label: "operator",
    allowSharedOrigin: allowSharedRpcOrigin,
  });

  const proofProvider = await createProofProvider({
    keyPath: options.keystore,
    password: readSecret("VRF_KEY_PASSWORD"),
    proverUrl: options["prover-url"],
    bearerToken: options["threshold-manifest"]
      ? readSecret("VRF_THRESHOLD_NODE_TOKEN")
      : readSecret("VRF_PROVER_BEARER_TOKEN"),
    timeoutMs: positiveInteger(options["prover-timeout-ms"], "prover-timeout-ms", 15_000, 100),
    expectedKeyHash: options["proof-key-hash"],
    proverClientCertificatePath: options["prover-client-cert"],
    proverClientKeyPath: options["prover-client-key"],
    proverCaCertificatePath: options["prover-ca"],
    thresholdManifestPath: options["threshold-manifest"],
    previousManifestPath: options["threshold-previous-manifest"],
    trustedPreviousManifestHash: options["threshold-trusted-previous-hash"],
    allowLoopback: options["threshold-allow-loopback"] === "true",
    clientCertificatePath: options["threshold-client-cert"],
    clientKeyPath: options["threshold-client-key"],
    caCertificatePath: options["threshold-ca"],
  });
  const keyHash = proofProvider.keyHash;
  const provider = createProvider(rpcUrls);
  const rpcProviders = rpcUrls.map((url) => rpcProvider(url));
  const network = await provider.getNetwork();
  if (allowSharedRpcOrigin && network.chainId !== 46630n) {
    throw new Error("shared RPC origin override is permitted only on Robinhood testnet");
  }
  if ((network.chainId === 46630n || network.chainId === 4663n) && rpcProviders.length < 2) {
    throw new Error("Robinhood service operation requires at least two independent RPC endpoints");
  }
  if ((network.chainId === 46630n || network.chainId === 4663n) && !options["database-url"]) {
    throw new Error("Robinhood service operation requires PostgreSQL persistence");
  }
  const relayer = new Wallet(relayerPrivateKey, provider);
  if (proofProvider.proofKeyAddress
      && relayer.address.toLowerCase() === proofProvider.proofKeyAddress.toLowerCase()) {
    throw new Error("proof key and relayer transaction key must be different");
  }
  const coordinatorAddress = options.coordinator.toLowerCase();
  const coordinator = new Contract(coordinatorAddress, SERVICE_ABI, relayer);
  const blockhashStore = new Contract(
    await coordinator.blockhashStore(),
    BLOCKHASH_STORE_ABI,
    relayer,
  );
  const key = await coordinator.getKey(keyHash);
  if (key.fulfiller.toLowerCase() !== relayer.address.toLowerCase()) {
    throw new Error(`relayer ${relayer.address} is not the configured fulfiller ${key.fulfiller}`);
  }

  if (options["database-url"]) {
    return runServicePostgres({
      options,
      provider,
      network,
      relayer,
      coordinator,
      blockhashStore,
      proofProvider,
      keyHash,
      coordinatorAddress,
      deploymentBlock,
      pollMs,
      blockRange,
      reorgLookback,
      eventConfirmations,
      replacementMs,
      replacementAttempts,
      archiveAfterBlocks,
      rpcProviders,
    });
  }

  const state = loadServiceState(options.state, {
    format: "proof-vrf-service-operator-state-v1",
    chainId: network.chainId.toString(),
    coordinator: coordinatorAddress,
    keyHash,
    deploymentBlock,
  });
  const healthPath = options["health-file"];

  process.stdout.write(`${JSON.stringify({
    status: "started",
    mode: "service-v2",
    coordinator: coordinatorAddress,
    keyHash,
    relayer: relayer.address,
    proofProvider: proofProvider.mode,
    rpcCount: rpcUrls.length,
    rpcOriginCount: rpcOriginCount(rpcUrls),
    rpcDiversity: rpcOriginCount(rpcUrls) === rpcUrls.length ? "independent-origins" : "shared-origin",
    cursor: state.cursor,
    pending: Object.keys(state.requests).length,
  })}\n`);

  for (;;) {
    try {
      const head = await provider.getBlockNumber();
      const latest = Math.max(deploymentBlock, head - eventConfirmations);
      await scanServiceEvents({
        coordinator,
        state,
        latest,
        rangeSize: blockRange,
        reorgLookback,
        keyHash,
        statePath: options.state,
      });

      const contextBlock = await coordinator.contextBlockNumber();

      for (const [requestId, pending] of Object.entries(state.requests)) {
        try {
          const request = await coordinator.getRequest(requestId);
          if (Number(request.status) !== 1) {
            delete state.requests[requestId];
            continue;
          }
          if (contextBlock >= BigInt(pending.requestBlock) + BigInt(archiveAfterBlocks)) {
            const storedHash = await blockhashStore.blockhashes(pending.requestBlock);
            if (storedHash === `0x${"00".repeat(32)}`) {
              const archiveTransaction = await blockhashStore.store.populateTransaction(
                pending.requestBlock,
              );
              const archiveReceipt = await sendWithReplacement({
                wallet: relayer,
                provider,
                transactionRequest: archiveTransaction,
                maxGasPrice: request.maxGasPriceWei,
                timeoutMs: replacementMs,
                maximumAttempts: replacementAttempts,
              });
              process.stdout.write(`${JSON.stringify({
                status: "blockhash-archived",
                requestId,
                requestBlock: pending.requestBlock,
                transactionHash: archiveReceipt.hash,
              })}\n`);
            }
          }
          const { actualSeed } = await readRequestConsensus({
            rpcProviders,
            coordinatorAddress,
            requestId,
            keyHash,
          });
          const proofResult = await proofProvider.prove({
            actualSeed,
            preSeed: pending.preSeed,
            requestId,
            coordinator: coordinatorAddress,
            chainId: network.chainId,
          });
          const proofData = proofResult.proofData
            ?? abiCoder.encode([PROOF_TYPE], [proofResult.proof]);
          const transactionRequest = await coordinator.fulfillRandomWords.populateTransaction(
            requestId,
            proofData,
          );
          const receipt = await sendWithReplacement({
            wallet: relayer,
            provider,
            transactionRequest,
            maxGasPrice: request.maxGasPriceWei,
            timeoutMs: replacementMs,
            maximumAttempts: replacementAttempts,
          });
          process.stdout.write(`${JSON.stringify({
            status: "fulfilled",
            requestId,
            output: proofResult.output.toString(),
            transactionHash: receipt.hash,
            blockNumber: receipt.blockNumber,
          })}\n`);
          delete state.requests[requestId];
          state.updatedAt = new Date().toISOString();
          writeJsonAtomic(options.state, state);
        } catch (error) {
          const message = errorMessage(error);
          if (/ConfirmationsPending|BlockhashUnavailable|GasPriceAboveLane/.test(message)) continue;
          try {
            const request = await coordinator.getRequest(requestId);
            if (Number(request.status) !== 1) {
              delete state.requests[requestId];
              state.updatedAt = new Date().toISOString();
              writeJsonAtomic(options.state, state);
              continue;
            }
          } catch {}
          process.stderr.write(`${JSON.stringify({ status: "error", requestId, message })}\n`);
        }
      }

      const health = {
        status: "healthy",
        mode: "service-v2",
        chainId: network.chainId.toString(),
        coordinator: coordinatorAddress,
        keyHash,
        head,
        cursor: state.cursor,
        pending: Object.keys(state.requests).length,
        updatedAt: new Date().toISOString(),
      };
      if (healthPath) writeJsonAtomic(healthPath, health);
      if (options.once === "true") return;
    } catch (error) {
      const message = errorMessage(error);
      process.stderr.write(`${JSON.stringify({ status: "loop-error", message })}\n`);
      if (healthPath) {
        writeJsonAtomic(healthPath, {
          status: "unhealthy",
          message,
          updatedAt: new Date().toISOString(),
        });
      }
      if (options.once === "true") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
}

function usage() {
  return [
    "Proof VRF operator",
    "",
    "  VRF_KEY_PASSWORD=... npm run operator -- keygen --out ./vrf-key.json",
    "  VRF_KEY_PASSWORD=... npm run operator -- prove --keystore ./vrf-key.json --actual-seed N --pre-seed N",
    "  VRF_KEY_PASSWORD=... VRF_TX_PRIVATE_KEY=... npm run operator -- run --keystore ./vrf-key.json --rpc-url URL --coordinator ADDRESS --from-block N",
    "  VRF_KEY_PASSWORD=... VRF_TX_PRIVATE_KEY=... npm run operator -- run-v2 --keystore ./vrf-key.json --rpc-urls URL[,URL] --coordinator ADDRESS --from-block N --state /data/operator-state.json",
    "  VRF_DATABASE_URL=... VRF_RPC_URLS=... VRF_TX_PRIVATE_KEY=... npm run operator -- run-v2 --prover-url https://prover.internal --proof-key-hash 0x... --coordinator ADDRESS --from-block N",
    "  VRF_DATABASE_URL=... VRF_RPC_URLS=... VRF_TX_PRIVATE_KEY=... npm run operator -- run-v2 --threshold-manifest group.json --threshold-client-cert client.crt --threshold-client-key client.key --threshold-ca ca.crt --coordinator ADDRESS --from-block N",
  ].join("\n");
}

if (isMain(import.meta.url)) {
  try {
    const { command, options } = parseArgs(process.argv.slice(2));
    if (command === "keygen") await createKey(options.out);
    else if (command === "prove") await prove(options);
    else if (command === "run") await run(options);
    else if (command === "run-v2") await runService(options);
    else process.stdout.write(`${usage()}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ status: "fatal-error", message: errorMessage(error), error: errorDetails(error) })}\n`);
    process.exitCode = 1;
  }
}

export const internals = Object.freeze({
  createProvider,
  requestFingerprint,
  sendWithReplacement,
  sendPostgresTransaction,
  reconcileRelayerTransactions,
  readRequestConsensus,
  SERVICE_ABI,
  BLOCKHASH_STORE_ABI,
});

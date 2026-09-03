#!/usr/bin/env node
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { Contract, Wallet } from "ethers";
import { isMain } from "./entrypoint.mjs";
import {
  generateProof,
  publicKeyFor,
  serviceKeyHash,
} from "./proof.mjs";
import { normalizeRpcUrls, rpcOriginCount } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";
import { errorDetails, errorMessage } from "./errors.mjs";
import { rpcProvider } from "./rpc.mjs";
import { verifyCompactWitnessConsensus } from "./compact-protocol.mjs";

const COORDINATOR_ABI = [
  "function getRequest(uint256 requestId) view returns ((address consumer,address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,bytes32 keyHash,uint256 subscriptionId,uint256 preSeed,uint256 reservedPayment,uint256 randomness,uint96 minimumFeeWei,uint64 requestBlock,uint64 expiresAtBlock,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,uint32 callbackGasLimit,uint32 numWords,uint32 callbackAttempts,uint32 fulfillmentOverheadGas,uint16 confirmations,uint16 premiumBps,uint16 operatorPremiumShareBps,uint8 status,bool sponsored,bool waiveMinimumFee,bool callbackSucceeded) request)",
  "function requestSeed(uint256 requestId) view returns (uint256)",
];

function serializableProof(proof) {
  return Object.fromEntries(Object.entries(proof).map(([name, value]) => [
    name,
    Array.isArray(value) ? value.map(String) : typeof value === "bigint" ? value.toString() : value,
  ]));
}

function normalizedRequest(request, actualSeed) {
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

export async function resolveProofRequest({
  rpcUrls,
  coordinatorAddress,
  chainId,
  keyHash,
  requestId,
  allowSharedOrigin = false,
  compactWitness,
}) {
  if (compactWitness !== undefined) {
    return verifyCompactWitnessConsensus({
      rpcUrls, coordinatorAddress, chainId, keyHash, requestId, allowSharedOrigin,
      witness: compactWitness, includeSeed: true,
    });
  }
  const endpoints = normalizeRpcUrls(rpcUrls, {
    minimum: 2,
    label: "remote prover",
    allowSharedOrigin,
  });
  const states = await Promise.all(endpoints.map(async (rpcUrl) => {
    const provider = rpcProvider(rpcUrl);
    try {
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(chainId)) throw new Error("RPC chainId mismatch");
    const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
    const request = await coordinator.getRequest(requestId);
    if (Number(request.status) !== 1) throw new Error("request is not pending");
    if (request.keyHash.toLowerCase() !== keyHash.toLowerCase()) {
      throw new Error("request keyHash does not match the prover key");
    }
    const actualSeed = await coordinator.requestSeed(requestId);
    return { request, actualSeed, normalized: normalizedRequest(request, actualSeed) };
    } finally { provider.destroy(); }
  }));
  if (states.some((state) => state.normalized !== states[0].normalized)) {
    throw new Error("independent RPC endpoints disagree on the canonical request");
  }
  return states[0];
}

async function readBody(request) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > 4_096) throw new Error("request body is too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

export async function startProverServer(options) {
  if (options.allowHttpLoopback
      && !["localhost", "127.0.0.1", "::1"].includes(options.host)) {
    throw new Error("plaintext prover mode may bind only to a loopback host");
  }
  const payload = JSON.parse(readFileSync(options.keystorePath, "utf8"));
  if (payload.format !== "proof-vrf-keystore-v1") throw new Error("unsupported VRF keystore");
  const wallet = await Wallet.fromEncryptedJson(
    JSON.stringify(payload.encryptedKey),
    options.password,
  );
  const publicKey = publicKeyFor(wallet.privateKey);
  const keyHash = serviceKeyHash(publicKey);
  if (payload.serviceKeyHash?.toLowerCase() !== keyHash.toLowerCase()) {
    throw new Error("VRF keystore key commitment mismatch");
  }

  const handler = async (request, response) => {
    response.setHeader("content-type", "application/json");
    try {
      if (options.bearerToken
          && request.headers.authorization !== `Bearer ${options.bearerToken}`) {
        response.statusCode = 401;
        response.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      if (request.method === "GET" && request.url === "/v1/status") {
        response.end(JSON.stringify({ publicKey: publicKey.map(String), serviceKeyHash: keyHash }));
        return;
      }
      if (request.method !== "POST" || request.url !== "/v1/proofs") {
        response.statusCode = 404;
        response.end(JSON.stringify({ error: "not found" }));
        return;
      }
      const body = await readBody(request);
      const exactKeys = ["scheme", "serviceKeyHash", "requestId", "coordinator", "chainId"];
      if (Object.hasOwn(body, "compactWitness")) exactKeys.push("compactWitness");
      if (Object.keys(body).sort().join(",") !== [...exactKeys].sort().join(",")
          || body.scheme !== "SECP256K1_ECVRF_V1"
          || body.serviceKeyHash.toLowerCase() !== keyHash.toLowerCase()
          || body.coordinator.toLowerCase() !== options.coordinator.toLowerCase()
          || BigInt(body.chainId) !== BigInt(options.chainId)
          || !/^\d+$/.test(String(body.requestId))) {
        throw new Error("proof request is not bound to this configured service");
      }
      const canonical = await resolveProofRequest({
        rpcUrls: options.rpcUrls,
        coordinatorAddress: options.coordinator,
        chainId: options.chainId,
        keyHash,
        requestId: body.requestId,
        allowSharedOrigin: options.allowSharedRpcOrigin,
        compactWitness: body.compactWitness,
      });
      const result = generateProof({
        privateKey: wallet.privateKey,
        actualSeed: canonical.actualSeed,
        preSeed: canonical.request.preSeed,
      });
      response.end(JSON.stringify({
        serviceKeyHash: keyHash,
        actualSeed: canonical.actualSeed.toString(),
        preSeed: canonical.request.preSeed.toString(),
        proof: serializableProof(result.proof),
      }));
    } catch (error) {
      const details = errorDetails(error);
      process.stderr.write(`${JSON.stringify({ status: "proof-request-error", error: details })}\n`);
      response.statusCode = 400;
      response.end(JSON.stringify({ error: errorMessage(error), details }));
    }
  };

  let server;
  if (options.allowHttpLoopback) {
    server = createHttpServer((request, response) => void handler(request, response));
  } else {
    if (!options.tlsKeyPath || !options.tlsCertPath || !options.tlsCaPath) {
      throw new Error("production prover requires TLS key, certificate, and client CA");
    }
    server = createHttpsServer({
      key: readFileSync(options.tlsKeyPath),
      cert: readFileSync(options.tlsCertPath),
      ca: readFileSync(options.tlsCaPath),
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
    }, (request, response) => void handler(request, response));
  }
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port, options.host, resolve);
  });
  return { server, keyHash, publicKey };
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      keystore: { type: "string" },
      coordinator: { type: "string" },
      "chain-id": { type: "string", default: "46630" },
      host: { type: "string", default: "127.0.0.1" },
      port: { type: "string", default: "9444" },
      "tls-key": { type: "string" },
      "tls-cert": { type: "string" },
      "tls-ca": { type: "string" },
      "allow-http-loopback": { type: "boolean", default: false },
    },
    strict: true,
  });
  const allowSharedRpcOrigin = process.env.VRF_ALLOW_SHARED_RPC_ORIGIN === "true"
    && BigInt(values["chain-id"]) === 46630n;
  const rpcUrls = normalizeRpcUrls(readSecret("VRF_RPC_URLS"), {
    minimum: 2,
    label: "remote prover",
    allowSharedOrigin: allowSharedRpcOrigin,
  });
  const started = await startProverServer({
    keystorePath: values.keystore,
    password: readSecret("VRF_KEY_PASSWORD", { required: true }),
    bearerToken: readSecret("VRF_PROVER_BEARER_TOKEN"),
    coordinator: values.coordinator,
    chainId: values["chain-id"],
    rpcUrls,
    allowSharedRpcOrigin,
    host: values.host,
    port: Number(values.port),
    tlsKeyPath: values["tls-key"],
    tlsCertPath: values["tls-cert"],
    tlsCaPath: values["tls-ca"],
    allowHttpLoopback: values["allow-http-loopback"],
  });
  process.stdout.write(`${JSON.stringify({
    status: "listening",
    keyHash: started.keyHash,
    rpcCount: rpcUrls.length,
    rpcOriginCount: rpcOriginCount(rpcUrls),
    rpcDiversity: rpcOriginCount(rpcUrls) === rpcUrls.length
      ? "independent-origins"
      : "shared-origin",
  })}\n`);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${JSON.stringify({ status: "fatal-error", error: errorDetails(error) })}\n`);
    process.exitCode = 1;
  });
}

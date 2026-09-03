#!/usr/bin/env node
import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import {
  appendFileSync,
  closeSync,
  existsSync,
  fdatasyncSync,
  lstatSync,
  openSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { Contract, JsonRpcProvider, getBytes, hexlify, keccak256, toUtf8Bytes } from "ethers";
import { isMain } from "./entrypoint.mjs";
import { canonicalJson, validateGroupManifest } from "./threshold-group.mjs";
import { internals as dkgInternals } from "./threshold-dkg.mjs";
import { publicKeyForShare, signPartial, verifyPartialSignature } from "./threshold-crypto.mjs";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { readSecret } from "./secrets.mjs";

export const PARTIAL_RESPONSE_FORMAT = "robinhood-proof-vrf-threshold-partial/v1";
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const ZERO_HASH = `0x${"00".repeat(32)}`;

const COORDINATOR_ABI = [
  "function getRequest(uint256 requestId) view returns ((address consumer,address verifier,bytes32 verifierCodeHash,address fulfiller,address payee,bytes32 keyHash,uint256 subscriptionId,uint256 preSeed,uint256 reservedPayment,uint256 randomness,uint96 minimumFeeWei,uint64 requestBlock,uint64 expiresAtBlock,uint64 maxGasPriceWei,uint32 verificationGasLimit,uint32 proofDataLength,uint32 callbackGasLimit,uint32 numWords,uint32 callbackAttempts,uint32 fulfillmentOverheadGas,uint16 confirmations,uint16 premiumBps,uint16 operatorPremiumShareBps,uint8 status,bool sponsored,bool waiveMinimumFee,bool callbackSucceeded) request)",
  "function requestSeed(uint256 requestId) view returns (uint256)",
];
const ADAPTER_ABI = [
  "function messageFor(bytes32 expectedKeyHash,uint256 actualSeed,uint256 expectedPreSeed) view returns (bytes32)",
];

function ed25519PublicKey(rawHex) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(getBytes(rawHex))]),
    format: "der",
    type: "spki",
  });
}

function responseHash(body) {
  return keccak256(toUtf8Bytes(canonicalJson(body)));
}

export function verifyPartialResponse(response, participant, expected) {
  const body = response?.body;
  if (body?.format !== PARTIAL_RESPONSE_FORMAT
      || body.participantId !== participant.id
      || body.index !== participant.index
      || body.manifestHash.toLowerCase() !== expected.manifestHash.toLowerCase()
      || body.keyHash.toLowerCase() !== expected.keyHash.toLowerCase()
      || String(body.requestId) !== String(expected.requestId)
      || body.message.toLowerCase() !== expected.message.toLowerCase()) {
    throw new Error(`partial response from ${participant.id} is bound to the wrong request`);
  }
  const signature = Buffer.from(getBytes(response.identitySignature));
  if (signature.length !== 64 || !verify(
    null,
    Buffer.from(getBytes(responseHash(body))),
    ed25519PublicKey(participant.identityPublicKey),
    signature,
  )) {
    throw new Error(`partial response from ${participant.id} has an invalid identity signature`);
  }
  if (!verifyPartialSignature({
    message: body.message,
    publicKey: participant.sharePublicKey,
    signature: body.signature,
  })) {
    throw new Error(`partial response from ${participant.id} has an invalid BLS share`);
  }
  return body;
}

export function buildPartialResponse({
  participant,
  manifestHash,
  keyHash,
  requestId,
  message,
  secretShare,
  identityPrivateKey,
}) {
  if (publicKeyForShare(secretShare).toLowerCase() !== participant.sharePublicKey.toLowerCase()) {
    throw new Error("secret share does not match the manifest share public key");
  }
  const body = {
    format: PARTIAL_RESPONSE_FORMAT,
    participantId: participant.id,
    index: participant.index,
    manifestHash,
    keyHash,
    requestId: String(requestId),
    message,
    signature: signPartial({ message, secretShare }),
  };
  return {
    body,
    identitySignature: hexlify(sign(
      null,
      Buffer.from(getBytes(responseHash(body))),
      identityPrivateKey,
    )),
  };
}

function normalizeCanonicalRequest(request, actualSeed, message) {
  return canonicalJson({
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
    message: message.toLowerCase(),
  });
}

export async function resolveCanonicalRequest({ rpcUrls, coordinatorAddress, group, requestId }) {
  const endpoints = normalizeRpcUrls(rpcUrls, { minimum: 2, label: "threshold signing" });
  const states = await Promise.all(endpoints.map(async (url) => {
    const provider = new JsonRpcProvider(url);
    const network = await provider.getNetwork();
    if (network.chainId !== BigInt(group.manifest.chainId)) {
      throw new Error(`RPC chain ${network.chainId} does not match the threshold manifest`);
    }
    const coordinator = new Contract(coordinatorAddress, COORDINATOR_ABI, provider);
    const request = await coordinator.getRequest(requestId);
    if (Number(request.status) !== 1) throw new Error("request is not pending");
    if (request.keyHash.toLowerCase() !== group.keyHash.toLowerCase()) {
      throw new Error("request keyHash does not match the threshold group");
    }
    if (request.verifier.toLowerCase() !== group.manifest.verifierAdapter.toLowerCase()) {
      throw new Error("request verifier does not match the threshold adapter");
    }
    const actualSeed = await coordinator.requestSeed(requestId);
    const adapter = new Contract(group.manifest.verifierAdapter, ADAPTER_ABI, provider);
    const message = await adapter.messageFor(group.keyHash, actualSeed, request.preSeed);
    return { request, actualSeed, message, normalized: normalizeCanonicalRequest(request, actualSeed, message) };
  }));
  if (states.some((state) => state.normalized !== states[0].normalized)) {
    throw new Error("independent RPC endpoints disagree on the canonical request");
  }
  return states[0];
}

function atomicWrite(path, value) {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(temporary, path);
}

function loadSigningState(path, manifestHash) {
  if (!existsSync(path)) {
    return {
      format: "robinhood-proof-vrf-threshold-signing-state/v1",
      manifestHash,
      signedRequests: {},
      auditedRequests: {},
      auditHead: ZERO_HASH,
    };
  }
  const state = JSON.parse(readFileSync(path, "utf8"));
  if (state.format !== "robinhood-proof-vrf-threshold-signing-state/v1"
      || state.manifestHash.toLowerCase() !== manifestHash.toLowerCase()
      || !state.signedRequests || typeof state.signedRequests !== "object") {
    throw new Error("threshold signing state does not match this manifest");
  }
  state.auditedRequests ??= {};
  state.auditHead ??= ZERO_HASH;
  return state;
}

function loadAuditLog(path, state, statePath, expected) {
  if (!existsSync(path)) return;
  const metadata = lstatSync(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
    throw new Error("threshold audit log must be a mode-0600 regular file");
  }
  let head = ZERO_HASH;
  const audited = {};
  const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
  for (const line of lines) {
    const record = JSON.parse(line);
    if (record.format !== "robinhood-proof-vrf-threshold-audit/v1"
        || !/^\d+$/.test(String(record.requestId))
        || !/^0x[0-9a-f]{64}$/i.test(record.message)
        || !/^0x[0-9a-f]{192}$/i.test(record.signature)
        || !/^0x[0-9a-f]{128}$/i.test(record.identitySignature)
        || audited[String(record.requestId)]) {
      throw new Error("threshold audit log contains an invalid or duplicate record");
    }
    if (record.previousHash?.toLowerCase() !== head.toLowerCase()) {
      throw new Error("threshold audit log hash chain is broken");
    }
    const body = { ...record };
    delete body.eventHash;
    const calculated = keccak256(toUtf8Bytes(canonicalJson(body)));
    if (calculated.toLowerCase() !== record.eventHash?.toLowerCase()) {
      throw new Error("threshold audit log event hash is invalid");
    }
    const signed = state.signedRequests[String(record.requestId)];
    if (!signed || signed.toLowerCase() !== record.message.toLowerCase()) {
      throw new Error("threshold audit log conflicts with anti-equivocation state");
    }
    if (expected) {
      verifyPartialResponse({
        body: {
          format: PARTIAL_RESPONSE_FORMAT,
          participantId: record.participantId,
          index: expected.participant.index,
          manifestHash: record.manifestHash,
          keyHash: record.keyHash,
          requestId: String(record.requestId),
          message: record.message,
          signature: record.signature,
        },
        identitySignature: record.identitySignature,
      }, expected.participant, {
        manifestHash: expected.manifestHash,
        keyHash: expected.keyHash,
        requestId: record.requestId,
        message: record.message,
      });
    }
    audited[String(record.requestId)] = record.eventHash;
    head = record.eventHash;
  }
  state.auditedRequests = audited;
  state.auditHead = head;
  atomicWrite(statePath, state);
}

function appendAuditRecord(path, state, body) {
  if (existsSync(path)) {
    const metadata = lstatSync(path);
    if (!metadata.isFile() || metadata.isSymbolicLink() || (metadata.mode & 0o077) !== 0) {
      throw new Error("threshold audit log must be a mode-0600 regular file");
    }
  }
  const record = { ...body, previousHash: state.auditHead };
  record.eventHash = keccak256(toUtf8Bytes(canonicalJson(record)));
  appendFileSync(path, `${JSON.stringify(record)}\n`, { mode: 0o600 });
  const descriptor = openSync(path, "r+");
  try {
    fdatasyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  state.auditHead = record.eventHash;
  state.auditedRequests[String(body.requestId)] = record.eventHash;
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

export async function startThresholdNode(options) {
  if (!options.statePath) throw new Error("threshold signing state path is required");
  if (!options.auditPath) throw new Error("threshold append-only audit log path is required");
  if (options.allowHttpLoopback
      && !["localhost", "127.0.0.1", "::1"].includes(options.host)) {
    throw new Error("plaintext threshold mode may bind only to a loopback host");
  }
  const group = validateGroupManifest(options.manifest, {
    allowLoopback: options.allowHttpLoopback,
    previousManifest: options.previousManifest,
    trustedPreviousManifestHash: options.trustedPreviousManifestHash,
  });
  const loaded = dkgInternals.loadKeystore(options.keystore, options.password);
  if (loaded.secret.thresholdManifestHash?.toLowerCase() !== group.manifestHash.toLowerCase()) {
    throw new Error("threshold share keystore is not bound to this manifest");
  }
  const participant = group.manifest.participants.find(
    (item) => item.id === options.keystore.participantId,
  );
  if (!participant) throw new Error("threshold share owner is not in the manifest");
  if (!loaded.secret.thresholdShare) throw new Error("threshold keystore has no secret share");
  if (participant.identityPublicKey.toLowerCase()
        !== options.keystore.identityPublicKey.toLowerCase()
      || participant.transportPublicKey.toLowerCase()
        !== options.keystore.transportPublicKey.toLowerCase()
      || publicKeyForShare(loaded.secret.thresholdShare).toLowerCase()
        !== participant.sharePublicKey.toLowerCase()) {
    throw new Error("threshold keystore identity or share does not match the manifest");
  }
  const signingState = loadSigningState(options.statePath, group.manifestHash);
  loadAuditLog(options.auditPath, signingState, options.statePath, {
    participant,
    manifestHash: group.manifestHash,
    keyHash: group.keyHash,
  });
  let queue = Promise.resolve();

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
        response.end(JSON.stringify({
          status: "ready",
          participantId: participant.id,
          index: participant.index,
          manifestHash: group.manifestHash,
          keyHash: group.keyHash,
          epoch: group.manifest.epoch,
        }));
        return;
      }
      if (request.method !== "POST" || request.url !== "/v1/partial") {
        response.statusCode = 404;
        response.end(JSON.stringify({ error: "not found" }));
        return;
      }
      const body = await readBody(request);
      if (!/^\d+$/.test(String(body.requestId))) throw new Error("requestId must be an integer");
      const canonical = await resolveCanonicalRequest({
        rpcUrls: options.rpcUrls,
        coordinatorAddress: options.coordinator,
        group,
        requestId: body.requestId,
      });
      const requestId = String(body.requestId);
      let partialResponse;
      queue = queue.catch(() => {}).then(async () => {
        const previous = signingState.signedRequests[requestId];
        if (previous && previous.toLowerCase() !== canonical.message.toLowerCase()) {
          throw new Error("refusing to sign a conflicting message for this requestId");
        }
        signingState.signedRequests[requestId] = canonical.message;
        atomicWrite(options.statePath, signingState);
        partialResponse = buildPartialResponse({
          participant,
          manifestHash: group.manifestHash,
          keyHash: group.keyHash,
          requestId,
          message: canonical.message,
          secretShare: loaded.secret.thresholdShare,
          identityPrivateKey: loaded.identityPrivateKey,
        });
        if (!signingState.auditedRequests[requestId]) {
          appendAuditRecord(options.auditPath, signingState, {
            format: "robinhood-proof-vrf-threshold-audit/v1",
            signedAt: new Date().toISOString(),
            participantId: participant.id,
            manifestHash: group.manifestHash,
            keyHash: group.keyHash,
            requestId,
            message: canonical.message,
            signature: partialResponse.body.signature,
            identitySignature: partialResponse.identitySignature,
          });
          atomicWrite(options.statePath, signingState);
        }
      });
      await queue;
      response.end(JSON.stringify(partialResponse));
    } catch (error) {
      response.statusCode = 400;
      response.end(JSON.stringify({ error: error.shortMessage || error.message || String(error) }));
    }
  };

  let server;
  if (options.allowHttpLoopback) {
    server = createHttpServer((request, response) => void handler(request, response));
  } else {
    if (!options.tlsKeyPath || !options.tlsCertPath || !options.tlsCaPath) {
      throw new Error("production threshold node requires TLS key, certificate, and client CA");
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
  return { server, group, participant };
}

async function main() {
  const { values } = parseArgs({
    args: process.argv.slice(2),
    options: {
      manifest: { type: "string" },
      previous: { type: "string" },
      "trusted-previous-hash": { type: "string" },
      keystore: { type: "string" },
      coordinator: { type: "string" },
      state: { type: "string" },
      "audit-log": { type: "string" },
      host: { type: "string", default: "127.0.0.1" },
      port: { type: "string", default: "9443" },
      "tls-key": { type: "string" },
      "tls-cert": { type: "string" },
      "tls-ca": { type: "string" },
      "allow-http-loopback": { type: "boolean", default: false },
    },
    strict: true,
  });
  const rpcUrls = normalizeRpcUrls(readSecret("VRF_RPC_URLS"), {
    minimum: 2,
    label: "threshold signing",
  });
  const { participant } = await startThresholdNode({
    manifest: JSON.parse(readFileSync(values.manifest, "utf8")),
    previousManifest: values.previous
      ? JSON.parse(readFileSync(values.previous, "utf8"))
      : undefined,
    trustedPreviousManifestHash: values["trusted-previous-hash"],
    keystore: JSON.parse(readFileSync(values.keystore, "utf8")),
    password: readSecret("VRF_THRESHOLD_KEY_PASSWORD", { required: true }),
    bearerToken: readSecret("VRF_THRESHOLD_NODE_TOKEN"),
    rpcUrls,
    coordinator: values.coordinator,
    statePath: values.state,
    auditPath: values["audit-log"],
    host: values.host,
    port: Number(values.port),
    tlsKeyPath: values["tls-key"],
    tlsCertPath: values["tls-cert"],
    tlsCaPath: values["tls-ca"],
    allowHttpLoopback: values["allow-http-loopback"],
  });
  process.stdout.write(`${JSON.stringify({ status: "listening", participantId: participant.id })}\n`);
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({
  appendAuditRecord,
  ed25519PublicKey,
  loadAuditLog,
  responseHash,
});

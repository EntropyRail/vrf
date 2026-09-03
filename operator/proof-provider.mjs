import { readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { AbiCoder, isAddress, keccak256, toUtf8Bytes, Wallet } from "ethers";
import {
  addressForPublicKey,
  generateProof,
  outputForProof,
  publicKeyFor,
  serviceKeyHash,
} from "./proof.mjs";
import { aggregateThresholdShares } from "./threshold-crypto.mjs";
import { validateGroupManifest } from "./threshold-group.mjs";
import { verifyPartialResponse } from "./threshold-node.mjs";
import { redactText } from "./errors.mjs";
import { serializeCompactWitness } from "./compact-protocol.mjs";

const THRESHOLD_MESSAGE_DOMAIN = keccak256(
  toUtf8Bytes("ROBINHOOD_PROOF_VRF_THRESHOLD_BLS_MESSAGE_V1"),
);
const THRESHOLD_OUTPUT_DOMAIN = keccak256(
  toUtf8Bytes("ROBINHOOD_PROOF_VRF_THRESHOLD_BLS_OUTPUT_V1"),
);
const abiCoder = AbiCoder.defaultAbiCoder();

function normalizePublicKey(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error("prover public key must contain two coordinates");
  }
  return value.map((coordinate) => BigInt(coordinate));
}

function normalizePair(value, name) {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${name} must contain two coordinates`);
  }
  return value.map((coordinate) => BigInt(coordinate));
}

function normalizeProof(value, expectedPreSeed) {
  if (!value || typeof value !== "object") throw new Error("remote prover returned no proof");
  const proof = {
    pk: normalizePair(value.pk, "proof.pk"),
    gamma: normalizePair(value.gamma, "proof.gamma"),
    c: BigInt(value.c),
    s: BigInt(value.s),
    seed: BigInt(value.seed),
    uWitness: String(value.uWitness),
    cGammaWitness: normalizePair(value.cGammaWitness, "proof.cGammaWitness"),
    sHashWitness: normalizePair(value.sHashWitness, "proof.sHashWitness"),
    zInv: BigInt(value.zInv),
  };
  if (!isAddress(proof.uWitness)) throw new Error("remote prover returned an invalid uWitness");
  if (proof.seed !== BigInt(expectedPreSeed)) {
    throw new Error("remote prover proof seed does not match the request pre-seed");
  }
  return proof;
}

function endpoint(baseUrl, path) {
  return `${baseUrl.replace(/\/$/, "")}${path}`;
}

function assertRemoteUrl(value) {
  const url = new URL(value);
  const local = ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  if (url.protocol !== "https:" && !(local && url.protocol === "http:")) {
    throw new Error("remote prover must use HTTPS (HTTP is allowed only for loopback testing)");
  }
  return url.toString().replace(/\/$/, "");
}

async function fetchJson(url, options, timeoutMs) {
  const response = await fetch(url, {
    ...options,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw remoteHttpError(response.status, body);
  }
  return response.json();
}

function remoteHttpError(status, body) {
  const error = new Error(`remote proof endpoint returned HTTP ${status}: ${redactText(body?.error || "request failed")}`);
  error.code = "REMOTE_PROOF_HTTP_ERROR";
  // Only the server's sanitized diagnostic message crosses the trust boundary.
  return error;
}

function requestThresholdJson(url, body, options) {
  const parsed = new URL(url);
  const transport = parsed.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    const request = transport(parsed, {
      method: options.method || "POST",
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(options.bearerToken
          ? { authorization: `Bearer ${options.bearerToken}` }
          : {}),
      },
      ...(parsed.protocol === "https:" ? {
        cert: options.clientCertificate,
        key: options.clientKey,
        ca: options.caCertificate,
        minVersion: "TLSv1.3",
        rejectUnauthorized: true,
      } : {}),
      timeout: options.timeoutMs,
    }, (response) => {
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        length += chunk.length;
        if (length > 1_000_000) {
          request.destroy(new Error("threshold node response is too large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          let body;
          try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch {}
          reject(remoteHttpError(response.statusCode, body));
          return;
        }
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          reject(new Error("threshold node returned invalid JSON"));
        }
      });
    });
    request.on("timeout", () => request.destroy(new Error("threshold node request timed out")));
    request.on("error", reject);
    request.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

export class LocalKeystoreProofProvider {
  constructor(wallet) {
    this.wallet = wallet;
    this.publicKey = publicKeyFor(wallet.privateKey);
    this.keyHash = serviceKeyHash(this.publicKey);
    this.proofKeyAddress = wallet.address;
    this.mode = "local-keystore";
  }

  static async load({ keyPath, password }) {
    if (!keyPath) throw new Error("--keystore is required for a local proof provider");
    if (!password) throw new Error("VRF_KEY_PASSWORD is required");
    const payload = JSON.parse(readFileSync(keyPath, "utf8"));
    if (payload.format !== "proof-vrf-keystore-v1") {
      throw new Error("unsupported VRF keystore format");
    }
    const wallet = await Wallet.fromEncryptedJson(
      JSON.stringify(payload.encryptedKey),
      password,
    );
    const provider = new LocalKeystoreProofProvider(wallet);
    if (payload.serviceKeyHash && payload.serviceKeyHash.toLowerCase() !== provider.keyHash) {
      throw new Error("keystore service key hash does not match its encrypted key");
    }
    return provider;
  }

  async prove({ actualSeed, preSeed }) {
    return generateProof({
      privateKey: this.wallet.privateKey,
      actualSeed,
      preSeed,
    });
  }
}

export class RemoteProofProvider {
  constructor({
    baseUrl,
    bearerToken,
    timeoutMs,
    clientCertificatePath,
    clientKeyPath,
    caCertificatePath,
  }) {
    this.baseUrl = assertRemoteUrl(baseUrl);
    this.bearerToken = bearerToken;
    this.timeoutMs = timeoutMs;
    this.mode = "remote-prover";
    this.clientCertificate = clientCertificatePath ? readFileSync(clientCertificatePath) : undefined;
    this.clientKey = clientKeyPath ? readFileSync(clientKeyPath) : undefined;
    this.caCertificate = caCertificatePath ? readFileSync(caCertificatePath) : undefined;
  }

  async request(path, body) {
    if (this.clientCertificate || this.clientKey || this.caCertificate) {
      if (!this.clientCertificate || !this.clientKey || !this.caCertificate) {
        throw new Error("remote prover mTLS requires client certificate, key, and CA");
      }
      return requestThresholdJson(endpoint(this.baseUrl, path), body, {
        method: body === undefined ? "GET" : "POST",
        timeoutMs: this.timeoutMs,
        bearerToken: this.bearerToken,
        clientCertificate: this.clientCertificate,
        clientKey: this.clientKey,
        caCertificate: this.caCertificate,
      });
    }
    return fetchJson(
      endpoint(this.baseUrl, path),
      body === undefined
        ? { headers: this.headers() }
        : {
          method: "POST",
          headers: this.headers({ "content-type": "application/json" }),
          body: JSON.stringify(body),
        },
      this.timeoutMs,
    );
  }

  headers(extra = {}) {
    return {
      accept: "application/json",
      ...(this.bearerToken ? { authorization: `Bearer ${this.bearerToken}` } : {}),
      ...extra,
    };
  }

  async initialize(expectedKeyHash) {
    const status = await this.request("/v1/status");
    this.publicKey = normalizePublicKey(status.publicKey);
    this.keyHash = serviceKeyHash(this.publicKey);
    this.proofKeyAddress = addressForPublicKey(this.publicKey);
    if (status.serviceKeyHash && status.serviceKeyHash.toLowerCase() !== this.keyHash) {
      throw new Error("remote prover status contains an inconsistent service key hash");
    }
    if (expectedKeyHash && expectedKeyHash.toLowerCase() !== this.keyHash) {
      throw new Error("remote prover key does not match --proof-key-hash");
    }
    return this;
  }

  async prove({ actualSeed, preSeed, requestId, coordinator, chainId, compactWitness }) {
    const payload = {
      scheme: "SECP256K1_ECVRF_V1",
      serviceKeyHash: this.keyHash,
      requestId: String(requestId),
      coordinator,
      chainId: String(chainId),
      ...(compactWitness === undefined ? {} : { compactWitness: serializeCompactWitness(compactWitness) }),
    };
    const result = await this.request("/v1/proofs", payload);
    if (result.serviceKeyHash?.toLowerCase() !== this.keyHash) {
      throw new Error("remote prover response key does not match the configured key");
    }
    if (BigInt(result.actualSeed) !== BigInt(actualSeed)
        || BigInt(result.preSeed) !== BigInt(preSeed)) {
      throw new Error("remote prover resolved a different canonical request seed");
    }
    const proof = normalizeProof(result.proof, preSeed);
    if (serviceKeyHash(proof.pk) !== this.keyHash) {
      throw new Error("remote prover proof public key does not match the configured key");
    }
    return {
      proof,
      output: outputForProof(proof),
      publicKey: this.publicKey,
      serviceKeyHash: this.keyHash,
    };
  }
}

export class ThresholdProofProvider {
  constructor(options) {
    const manifest = JSON.parse(readFileSync(options.manifestPath, "utf8"));
    const previousManifest = options.previousManifestPath
      ? JSON.parse(readFileSync(options.previousManifestPath, "utf8"))
      : undefined;
    this.group = validateGroupManifest(manifest, {
      allowLoopback: options.allowLoopback,
      previousManifest,
      trustedPreviousManifestHash: options.trustedPreviousManifestHash,
    });
    this.keyHash = this.group.keyHash;
    this.publicKey = this.group.manifest.groupPublicKey;
    this.proofKeyAddress = null;
    this.mode = "threshold-bls";
    this.timeoutMs = options.timeoutMs;
    this.bearerToken = options.bearerToken;
    this.clientCertificate = options.clientCertificatePath
      ? readFileSync(options.clientCertificatePath)
      : undefined;
    this.clientKey = options.clientKeyPath ? readFileSync(options.clientKeyPath) : undefined;
    this.caCertificate = options.caCertificatePath
      ? readFileSync(options.caCertificatePath)
      : undefined;
    if (!options.allowLoopback
        && (!this.clientCertificate || !this.clientKey || !this.caCertificate)) {
      throw new Error("threshold aggregation requires a client certificate, key, and CA");
    }
  }

  async prove({ actualSeed, preSeed, requestId, coordinator, chainId }) {
    if (BigInt(chainId) !== BigInt(this.group.manifest.chainId)) {
      throw new Error("operator chain does not match the threshold manifest");
    }
    const message = keccak256(abiCoder.encode(
      ["bytes32", "uint256", "address", "bytes32", "uint256", "uint256"],
      [
        THRESHOLD_MESSAGE_DOMAIN,
        chainId,
        this.group.manifest.verifierAdapter,
        this.keyHash,
        actualSeed,
        preSeed,
      ],
    ));
    const results = await Promise.allSettled(this.group.manifest.participants.map(
      async (participant) => {
        const response = await requestThresholdJson(
          `${participant.endpoint}/v1/partial`,
          { requestId: String(requestId) },
          {
            timeoutMs: this.timeoutMs,
            bearerToken: this.bearerToken,
            clientCertificate: this.clientCertificate,
            clientKey: this.clientKey,
            caCertificate: this.caCertificate,
          },
        );
        const body = verifyPartialResponse(response, participant, {
          manifestHash: this.group.manifestHash,
          keyHash: this.keyHash,
          requestId,
          message,
        });
        return {
          participantId: participant.id,
          index: participant.index,
          publicKey: participant.sharePublicKey,
          signature: body.signature,
        };
      },
    ));
    const valid = results.filter((result) => result.status === "fulfilled")
      .map((result) => result.value)
      .sort((left, right) => left.index - right.index);
    if (valid.length < this.group.manifest.threshold) {
      const reasons = results.filter((result) => result.status === "rejected")
        .map((result) => result.reason?.message || String(result.reason));
      throw new Error(`received ${valid.length}/${this.group.manifest.threshold} valid shares: ${reasons.join("; ")}`);
    }
    const aggregate = aggregateThresholdShares({
      message,
      groupPublicKey: this.group.manifest.groupPublicKey,
      threshold: this.group.manifest.threshold,
      shares: valid.slice(0, this.group.manifest.threshold),
    });
    const proofData = abiCoder.encode(
      ["bytes", "bytes"],
      [this.group.manifest.groupPublicKey, aggregate.signature],
    );
    const output = BigInt(keccak256(abiCoder.encode(
      ["bytes32", "bytes32", "bytes32"],
      [THRESHOLD_OUTPUT_DOMAIN, message, keccak256(aggregate.signature)],
    )));
    return {
      proofData,
      output,
      signature: aggregate.signature,
      message,
      shareIndexes: aggregate.indexes,
      manifestHash: this.group.manifestHash,
    };
  }
}

export async function createProofProvider(options) {
  const hasLocal = Boolean(options.keyPath);
  const hasRemote = Boolean(options.proverUrl);
  const hasThreshold = Boolean(options.thresholdManifestPath);
  if (Number(hasLocal) + Number(hasRemote) + Number(hasThreshold) !== 1) {
    throw new Error("configure exactly one of --keystore, --prover-url, or --threshold-manifest");
  }
  if (hasLocal) {
    return LocalKeystoreProofProvider.load({
      keyPath: options.keyPath,
      password: options.password,
    });
  }
  if (hasThreshold) return new ThresholdProofProvider(options);
  const remote = new RemoteProofProvider({
    baseUrl: options.proverUrl,
    bearerToken: options.bearerToken,
    timeoutMs: options.timeoutMs,
    clientCertificatePath: options.proverClientCertificatePath,
    clientKeyPath: options.proverClientKeyPath,
    caCertificatePath: options.proverCaCertificatePath,
  });
  return remote.initialize(options.expectedKeyHash);
}

export const internals = Object.freeze({
  normalizeProof,
  normalizePublicKey,
  assertRemoteUrl,
  requestThresholdJson,
});

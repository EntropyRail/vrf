import {
  createPublicKey,
  verify as verifyIdentitySignature,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import {
  AbiCoder,
  getAddress,
  getBytes,
  isHexString,
  keccak256,
  toUtf8Bytes,
} from "ethers";
import {
  aggregateThresholdShares,
  internals as thresholdInternals,
  verifyPublicShareCommitment,
} from "./threshold-crypto.mjs";
import { isMain } from "./entrypoint.mjs";

export const GROUP_FORMAT = "robinhood-proof-vrf-threshold-group/v1";
export const BLS_SCHEME = "THRESHOLD_BLS_UNIQUE_SIGNATURE_V1";
export const BLS_SCHEME_ID = keccak256(toUtf8Bytes(BLS_SCHEME));

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const TOP_LEVEL_KEYS = new Set([
  "format",
  "scheme",
  "network",
  "chainId",
  "verifierAdapter",
  "ceremony",
  "previousManifestHash",
  "epoch",
  "threshold",
  "groupPublicKey",
  "publicCoefficients",
  "keyHash",
  "dkgTranscriptHash",
  "softwareCommit",
  "containerDigest",
  "participants",
  "attestations",
  "handoffAttestations",
]);
const PARTICIPANT_KEYS = new Set([
  "id",
  "index",
  "identityPublicKey",
  "transportPublicKey",
  "sharePublicKey",
  "endpoint",
]);
const ATTESTATION_KEYS = new Set(["participantId", "signature"]);

function exactKeys(value, allowed, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${name} contains unsupported field ${key}`);
  }
  for (const key of allowed) {
    if (!(key in value)) throw new Error(`${name} is missing ${key}`);
  }
}

function integer(value, name, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${name} must be an integer of at least ${minimum}`);
  }
  return value;
}

function fixedHex(value, bytes, name) {
  if (typeof value !== "string" || !isHexString(value, bytes)) {
    throw new Error(`${name} must be ${bytes} hex bytes`);
  }
  return value.toLowerCase();
}

function fixedNonzeroHex(value, bytes, name) {
  const normalized = fixedHex(value, bytes, name);
  if (/^0x0+$/.test(normalized)) throw new Error(`${name} cannot be zero`);
  return normalized;
}

function endpoint(value, allowLoopback) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("participant endpoint must be a valid URL");
  }
  const loopback = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(allowLoopback && loopback && parsed.protocol === "http:")) {
    throw new Error("participant endpoint must use HTTPS");
  }
  if (parsed.username || parsed.password || parsed.hash) {
    throw new Error("participant endpoint cannot contain credentials or a fragment");
  }
  return parsed.toString().replace(/\/$/, "");
}

export function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`
    )).join(",")}}`;
  }
  throw new Error("manifest contains a non-canonical JSON value");
}

export function adapterKeyHash(groupPublicKey) {
  const normalizedKey = fixedHex(groupPublicKey, 192, "groupPublicKey");
  thresholdInternals.g2Point(normalizedKey, "group public key");
  return keccak256(AbiCoder.defaultAbiCoder().encode(
    ["bytes32", "bytes32"],
    [BLS_SCHEME_ID, keccak256(normalizedKey)],
  ));
}

function normalizeBody(manifest, { allowLoopback = false } = {}) {
  exactKeys(manifest, TOP_LEVEL_KEYS, "manifest");
  if (manifest.format !== GROUP_FORMAT) throw new Error("unsupported group manifest format");
  if (manifest.scheme !== BLS_SCHEME) throw new Error("unsupported threshold signature scheme");
  if (typeof manifest.network !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(manifest.network)) {
    throw new Error("network must be a stable lowercase identifier");
  }
  const chainId = integer(manifest.chainId, "chainId");
  const epoch = integer(manifest.epoch, "epoch");
  const threshold = integer(manifest.threshold, "threshold", 2);
  if (manifest.ceremony !== "dkg" && manifest.ceremony !== "reshare") {
    throw new Error("ceremony must be dkg or reshare");
  }
  let previousManifestHash = null;
  if (manifest.ceremony === "dkg") {
    if (epoch !== 1 || manifest.previousManifestHash !== null) {
      throw new Error("initial DKG must use epoch 1 and a null previousManifestHash");
    }
  } else {
    if (epoch < 2) throw new Error("resharing must start at epoch 2 or later");
    previousManifestHash = fixedHex(
      manifest.previousManifestHash,
      32,
      "previousManifestHash",
    );
  }
  let verifierAdapter;
  try {
    verifierAdapter = getAddress(manifest.verifierAdapter);
  } catch {
    throw new Error("verifierAdapter must be a nonzero address");
  }
  if (/^0x0{40}$/i.test(verifierAdapter)) throw new Error("verifierAdapter must be a nonzero address");
  const groupPublicKey = fixedHex(manifest.groupPublicKey, 192, "groupPublicKey");
  thresholdInternals.g2Point(groupPublicKey, "group public key");
  if (!Array.isArray(manifest.publicCoefficients)
      || manifest.publicCoefficients.length !== threshold) {
    throw new Error("publicCoefficients must contain exactly threshold G2 commitments");
  }
  const publicCoefficients = manifest.publicCoefficients.map((value, position) => {
    const commitment = fixedHex(value, 192, `publicCoefficients[${position}]`);
    thresholdInternals.g2CommitmentPoint(commitment, `publicCoefficients[${position}]`);
    return commitment;
  });
  if (publicCoefficients[0] !== groupPublicKey) {
    throw new Error("publicCoefficients[0] must equal the group public key");
  }
  if (thresholdInternals.g2CommitmentPoint(
    publicCoefficients.at(-1),
    "highest public coefficient",
  ).equals(thresholdInternals.g2CommitmentPoint(
    `0x40${"00".repeat(191)}`,
    "point at infinity",
  ))) {
    throw new Error("highest public coefficient cannot be zero");
  }
  const keyHash = fixedHex(manifest.keyHash, 32, "keyHash");
  if (keyHash !== adapterKeyHash(groupPublicKey)) {
    throw new Error("keyHash does not match the group public key and scheme");
  }
  const dkgTranscriptHash = fixedNonzeroHex(
    manifest.dkgTranscriptHash,
    32,
    "dkgTranscriptHash",
  );
  if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(manifest.softwareCommit)) {
    throw new Error("softwareCommit must be a lowercase 40- or 64-character hex commit");
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(manifest.containerDigest)) {
    throw new Error("containerDigest must be a pinned sha256 digest");
  }
  if (!Array.isArray(manifest.participants)
      || manifest.participants.length < 3
      || manifest.participants.length > 31) {
    throw new Error("participants must contain between 3 and 31 operators");
  }
  if (threshold > manifest.participants.length || threshold * 2 <= manifest.participants.length) {
    throw new Error("threshold must be a strict majority and cannot exceed the roster size");
  }

  const participants = manifest.participants.map((participant, position) => {
    exactKeys(participant, PARTICIPANT_KEYS, `participants[${position}]`);
    if (typeof participant.id !== "string" || !/^[a-z0-9][a-z0-9._-]{1,62}$/.test(participant.id)) {
      throw new Error(`participants[${position}].id is invalid`);
    }
    const index = integer(participant.index, `participants[${position}].index`);
    const identityPublicKey = fixedNonzeroHex(
      participant.identityPublicKey,
      32,
      `participants[${position}].identityPublicKey`,
    );
    const transportPublicKey = fixedNonzeroHex(
      participant.transportPublicKey,
      32,
      `participants[${position}].transportPublicKey`,
    );
    const sharePublicKey = fixedHex(
      participant.sharePublicKey,
      192,
      `participants[${position}].sharePublicKey`,
    );
    thresholdInternals.g2Point(sharePublicKey, `participants[${position}].sharePublicKey`);
    return {
      id: participant.id,
      index,
      identityPublicKey,
      transportPublicKey,
      sharePublicKey,
      endpoint: endpoint(participant.endpoint, allowLoopback),
    };
  });
  for (let position = 0; position < participants.length; position += 1) {
    if (participants[position].index !== position + 1) {
      throw new Error("participants must be sorted and use contiguous indexes starting at 1");
    }
  }
  for (const [field, values] of Object.entries({
    "participant IDs": participants.map((item) => item.id),
    "identity public keys": participants.map((item) => item.identityPublicKey),
    "transport public keys": participants.map((item) => item.transportPublicKey),
    "share public keys": participants.map((item) => item.sharePublicKey),
    endpoints: participants.map((item) => item.endpoint),
  })) {
    if (new Set(values).size !== values.length) throw new Error(`${field} must be unique`);
  }
  for (const participant of participants) {
    if (!verifyPublicShareCommitment({
      index: participant.index,
      sharePublicKey: participant.sharePublicKey,
      publicCoefficients,
    })) {
      throw new Error(`share public key for ${participant.id} does not match publicCoefficients`);
    }
  }

  return {
    format: GROUP_FORMAT,
    scheme: BLS_SCHEME,
    network: manifest.network,
    chainId,
    verifierAdapter,
    ceremony: manifest.ceremony,
    previousManifestHash,
    epoch,
    threshold,
    groupPublicKey,
    publicCoefficients,
    keyHash,
    dkgTranscriptHash,
    softwareCommit: manifest.softwareCommit,
    containerDigest: manifest.containerDigest,
    participants,
  };
}

export function prepareGroupManifest(manifest, options) {
  const body = normalizeBody(manifest, options);
  const manifestHash = keccak256(toUtf8Bytes(canonicalJson(body)));
  return { body, manifestHash };
}

function ed25519PublicKey(rawHex) {
  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(getBytes(rawHex))]),
    format: "der",
    type: "spki",
  });
}

function validateAttestations(attestations, participants, required, manifestHash, label) {
  if (!Array.isArray(attestations)) throw new Error(`${label} must be an array`);
  const attesters = new Set();
  for (let position = 0; position < attestations.length; position += 1) {
    const attestation = attestations[position];
    exactKeys(attestation, ATTESTATION_KEYS, `${label}[${position}]`);
    const participant = participants.get(attestation.participantId);
    if (!participant) {
      throw new Error(`${label} references unknown participant ${attestation.participantId}`);
    }
    if (attesters.has(participant.id)) throw new Error(`duplicate ${label} from ${participant.id}`);
    const signature = fixedHex(attestation.signature, 64, `${label} signature`);
    if (!verifyIdentitySignature(
      null,
      Buffer.from(getBytes(manifestHash)),
      ed25519PublicKey(participant.identityPublicKey),
      Buffer.from(getBytes(signature)),
    )) {
      throw new Error(`invalid ${label} from ${participant.id}`);
    }
    attesters.add(participant.id);
  }
  if (attesters.size < required) {
    throw new Error(`at least ${required} valid ${label} are required`);
  }
  return [...attesters].sort();
}

export function validateGroupManifest(manifest, options = {}) {
  const { body, manifestHash } = prepareGroupManifest(manifest, options);
  const participants = new Map(body.participants.map((participant) => [participant.id, participant]));
  const validAttesters = validateAttestations(
    manifest.attestations,
    participants,
    body.threshold,
    manifestHash,
    "identity attestations",
  );
  let validHandoffAttesters = [];
  if (body.ceremony === "dkg") {
    if (!Array.isArray(manifest.handoffAttestations)
        || manifest.handoffAttestations.length !== 0) {
      throw new Error("initial DKG cannot contain handoff attestations");
    }
  } else {
    if (!options.previousManifest || !options.trustedPreviousManifestHash) {
      throw new Error("resharing requires the previous manifest and its separately trusted hash");
    }
    const previous = prepareGroupManifest(options.previousManifest, options);
    const trustedPreviousManifestHash = fixedHex(
      options.trustedPreviousManifestHash,
      32,
      "trustedPreviousManifestHash",
    );
    if (previous.manifestHash !== trustedPreviousManifestHash
        || body.previousManifestHash !== previous.manifestHash) {
      throw new Error("resharing previous manifest does not match the trusted hash");
    }
    for (const field of ["scheme", "network", "chainId", "verifierAdapter", "groupPublicKey", "keyHash"]) {
      if (body[field] !== previous.body[field]) {
        throw new Error(`resharing cannot change ${field}`);
      }
    }
    if (body.epoch !== previous.body.epoch + 1) {
      throw new Error("resharing epoch must immediately follow the previous epoch");
    }
    const previousParticipants = new Map(
      previous.body.participants.map((participant) => [participant.id, participant]),
    );
    validHandoffAttesters = validateAttestations(
      manifest.handoffAttestations,
      previousParticipants,
      previous.body.threshold,
      manifestHash,
      "handoff attestations",
    );
  }
  return {
    manifest: {
      ...body,
      attestations: manifest.attestations,
      handoffAttestations: manifest.handoffAttestations,
    },
    manifestHash,
    keyHash: body.keyHash,
    validAttesters,
    validHandoffAttesters,
  };
}

function loadJson(path, name) {
  if (!path) throw new Error(`${name} path is required`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function aggregateFromFiles(manifestPath, sharesPath, options) {
  const group = validateGroupManifest(loadJson(manifestPath, "manifest"), options);
  const shareSet = loadJson(sharesPath, "shares");
  exactKeys(shareSet, new Set(["manifestHash", "message", "shares"]), "share set");
  if (fixedHex(shareSet.manifestHash, 32, "share set manifestHash") !== group.manifestHash) {
    throw new Error("share set belongs to a different group manifest");
  }
  const message = fixedHex(shareSet.message, 32, "share set message");
  if (!Array.isArray(shareSet.shares)) throw new Error("share set shares must be an array");
  const participants = new Map(group.manifest.participants.map((item) => [item.id, item]));
  const shares = shareSet.shares.map((share, position) => {
    exactKeys(share, new Set(["participantId", "index", "signature"]), `shares[${position}]`);
    const participant = participants.get(share.participantId);
    if (!participant || participant.index !== share.index) {
      throw new Error(`share ${position} does not match a manifest participant`);
    }
    return {
      index: share.index,
      publicKey: participant.sharePublicKey,
      signature: fixedHex(share.signature, 96, `shares[${position}].signature`),
    };
  });
  const aggregate = aggregateThresholdShares({
    message,
    groupPublicKey: group.manifest.groupPublicKey,
    threshold: group.manifest.threshold,
    shares,
  });
  return {
    manifestHash: group.manifestHash,
    keyHash: group.keyHash,
    message,
    signature: aggregate.signature,
    proofData: AbiCoder.defaultAbiCoder().encode(
      ["bytes", "bytes"],
      [group.manifest.groupPublicKey, aggregate.signature],
    ),
    shareIndexes: aggregate.indexes,
  };
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  const { values } = parseArgs({
    args,
    options: {
      file: { type: "string" },
      manifest: { type: "string" },
      shares: { type: "string" },
      previous: { type: "string" },
      "trusted-previous-hash": { type: "string" },
      "allow-loopback": { type: "boolean", default: false },
    },
    strict: true,
  });
  if (command === "validate") {
    const result = validateGroupManifest(loadJson(values.file, "manifest"), {
      allowLoopback: values["allow-loopback"],
      previousManifest: values.previous ? loadJson(values.previous, "previous manifest") : undefined,
      trustedPreviousManifestHash: values["trusted-previous-hash"],
    });
    process.stdout.write(`${JSON.stringify({
      manifestHash: result.manifestHash,
      keyHash: result.keyHash,
      threshold: result.manifest.threshold,
      participants: result.manifest.participants.length,
      validAttesters: result.validAttesters,
      validHandoffAttesters: result.validHandoffAttesters,
    }, null, 2)}\n`);
    return;
  }
  if (command === "aggregate") {
    process.stdout.write(`${JSON.stringify(aggregateFromFiles(
      values.manifest,
      values.shares,
      {
        allowLoopback: values["allow-loopback"],
        previousManifest: values.previous
          ? loadJson(values.previous, "previous manifest")
          : undefined,
        trustedPreviousManifestHash: values["trusted-previous-hash"],
      },
    ), null, 2)}\n`);
    return;
  }
  throw new Error("usage: threshold-group.mjs validate --file <group.json> [--previous <group.json> --trusted-previous-hash 0x...] | aggregate --manifest <group.json> --shares <shares.json>");
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({
  aggregateFromFiles,
  exactKeys,
  fixedHex,
  fixedNonzeroHex,
  normalizeBody,
});

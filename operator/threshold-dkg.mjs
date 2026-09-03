#!/usr/bin/env node
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  scryptSync,
  sign,
  verify,
} from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import process from "node:process";
import { parseArgs } from "node:util";
import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { getBytes, hexlify, isHexString, keccak256, toUtf8Bytes } from "ethers";
import { canonicalJson, adapterKeyHash, prepareGroupManifest } from "./threshold-group.mjs";
import { isMain } from "./entrypoint.mjs";
import {
  BLS_SCALAR_ORDER,
  internals as thresholdInternals,
  lagrangeCoefficientAtZero,
  publicKeyForShare,
} from "./threshold-crypto.mjs";
import { readSecret } from "./secrets.mjs";

export const DKG_PACKET_FORMAT = "robinhood-proof-vrf-dkg-packet/v1";
export const DKG_KEYSTORE_FORMAT = "robinhood-proof-vrf-threshold-keystore/v1";
export const DKG_FINALIZATION_FORMAT = "robinhood-proof-vrf-dkg-finalization/v1";

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

function fixedHex(value, bytes, name) {
  if (typeof value !== "string" || !isHexString(value, bytes)) {
    throw new Error(`${name} must be ${bytes} hex bytes`);
  }
  return value.toLowerCase();
}

function scalar(value, name = "scalar", allowZero = false) {
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= BLS_SCALAR_ORDER || (!allowZero && parsed === 0n)) {
    throw new Error(`${name} is outside the BLS scalar field`);
  }
  return parsed;
}

function scalarHex(value) {
  return `0x${scalar(value, "scalar", true).toString(16).padStart(64, "0")}`;
}

function randomScalar(allowZero = false) {
  for (;;) {
    const value = BigInt(hexlify(randomBytes(64))) % BLS_SCALAR_ORDER;
    if (allowZero || value !== 0n) return value;
  }
}

function rawPublicKey(publicKey) {
  return hexlify(publicKey.export({ format: "der", type: "spki" }).subarray(-32));
}

function publicKeyFromRaw(raw, type) {
  const prefix = type === "ed25519" ? ED25519_SPKI_PREFIX : X25519_SPKI_PREFIX;
  return createPublicKey({
    key: Buffer.concat([prefix, Buffer.from(getBytes(fixedHex(raw, 32, `${type} public key`)))]),
    format: "der",
    type: "spki",
  });
}

function encryptPayload(payload, password, workFactor = 32_768) {
  if (!password) throw new Error("threshold keystore password is required");
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(password, salt, 32, { N: workFactor, r: 8, p: 1 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(canonicalJson(payload))),
    cipher.final(),
  ]);
  return {
    cipher: "aes-256-gcm",
    ciphertext: hexlify(ciphertext),
    iv: hexlify(iv),
    tag: hexlify(cipher.getAuthTag()),
    kdf: "scrypt",
    kdfparams: { N: workFactor, r: 8, p: 1, salt: hexlify(salt) },
  };
}

function decryptPayload(crypto, password) {
  if (!password) throw new Error("threshold keystore password is required");
  if (crypto?.cipher !== "aes-256-gcm" || crypto?.kdf !== "scrypt") {
    throw new Error("unsupported threshold keystore encryption");
  }
  const { N, r, p, salt } = crypto.kdfparams || {};
  if (!Number.isSafeInteger(N) || N < 1_024 || !Number.isSafeInteger(r)
      || r < 1 || !Number.isSafeInteger(p) || p < 1) {
    throw new Error("invalid threshold keystore KDF parameters");
  }
  const key = scryptSync(password, getBytes(fixedHex(salt, 16, "KDF salt")), 32, { N, r, p });
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    getBytes(fixedHex(crypto.iv, 12, "cipher IV")),
  );
  decipher.setAuthTag(Buffer.from(getBytes(fixedHex(crypto.tag, 16, "cipher tag"))));
  const cleartext = Buffer.concat([
    decipher.update(Buffer.from(getBytes(crypto.ciphertext))),
    decipher.final(),
  ]);
  return JSON.parse(cleartext.toString("utf8"));
}

function validateParticipant(participant, expectedIndex) {
  if (!participant || typeof participant !== "object") throw new Error("invalid participant");
  if (participant.index !== expectedIndex) throw new Error("participant indexes must be contiguous");
  if (!/^[a-z0-9][a-z0-9._-]{1,62}$/.test(participant.id)) {
    throw new Error(`invalid participant id ${participant.id}`);
  }
  fixedHex(participant.identityPublicKey, 32, `${participant.id} identity public key`);
  fixedHex(participant.transportPublicKey, 32, `${participant.id} transport public key`);
  return participant;
}

function validateRoster(roster, threshold) {
  if (!Array.isArray(roster) || roster.length < 3 || roster.length > 31) {
    throw new Error("roster must contain between 3 and 31 participants");
  }
  if (!Number.isSafeInteger(threshold) || threshold < 2 || threshold > roster.length
      || threshold * 2 <= roster.length) {
    throw new Error("threshold must be a strict majority of the roster");
  }
  const normalized = roster.map((participant, position) => (
    validateParticipant(participant, position + 1)
  ));
  for (const field of ["id", "identityPublicKey", "transportPublicKey", "endpoint"]) {
    if (new Set(normalized.map((item) => item[field])).size !== normalized.length) {
      throw new Error(`roster ${field} values must be unique`);
    }
  }
  return normalized;
}

export function generateParticipant({ id, endpoint, password, workFactor }) {
  const { publicKey: identityPublic, privateKey: identityPrivate } =
    generateKeyPairSync("ed25519");
  const { publicKey: transportPublic, privateKey: transportPrivate } =
    generateKeyPairSync("x25519");
  const participant = {
    id,
    index: 1,
    identityPublicKey: rawPublicKey(identityPublic),
    transportPublicKey: rawPublicKey(transportPublic),
    endpoint,
  };
  validateParticipant(participant, 1);
  const secret = {
    identityPrivateKey: identityPrivate.export({ format: "der", type: "pkcs8" }).toString("base64"),
    transportPrivateKey: transportPrivate.export({ format: "der", type: "pkcs8" }).toString("base64"),
    thresholdShare: null,
    thresholdEpoch: null,
    thresholdManifestHash: null,
  };
  return {
    participant,
    keystore: {
      format: DKG_KEYSTORE_FORMAT,
      participantId: id,
      identityPublicKey: participant.identityPublicKey,
      transportPublicKey: participant.transportPublicKey,
      crypto: encryptPayload(secret, password, workFactor),
    },
  };
}

function loadKeystore(keystore, password) {
  if (keystore?.format !== DKG_KEYSTORE_FORMAT) throw new Error("invalid threshold keystore format");
  const secret = decryptPayload(keystore.crypto, password);
  const identityPrivateKey = createPrivateKey({
    key: Buffer.from(secret.identityPrivateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const transportPrivateKey = createPrivateKey({
    key: Buffer.from(secret.transportPrivateKey, "base64"),
    format: "der",
    type: "pkcs8",
  });
  if (rawPublicKey(createPublicKey(identityPrivateKey)).toLowerCase()
      !== fixedHex(keystore.identityPublicKey, 32, "keystore identity key")) {
    throw new Error("threshold keystore identity key mismatch");
  }
  if (rawPublicKey(createPublicKey(transportPrivateKey)).toLowerCase()
      !== fixedHex(keystore.transportPublicKey, 32, "keystore transport key")) {
    throw new Error("threshold keystore transport key mismatch");
  }
  return { keystore, secret, identityPrivateKey, transportPrivateKey };
}

function polynomialAt(coefficients, index) {
  return coefficients.reduceRight(
    (value, coefficient) => (
      (value * BigInt(index) + coefficient) % BLS_SCALAR_ORDER
    ),
    0n,
  );
}

function pointHex(point) {
  return hexlify(point.toRawBytes(false));
}

function commitmentsFor(coefficients) {
  return coefficients.map((coefficient) => pointHex(
    bls.G2.ProjectivePoint.BASE.multiply(coefficient),
  ));
}

function expectedSharePoint(commitments, index) {
  let expected = bls.G2.ProjectivePoint.ZERO;
  let power = 1n;
  for (let position = 0; position < commitments.length; position += 1) {
    expected = expected.add(
      thresholdInternals.g2CommitmentPoint(
        commitments[position],
        `commitments[${position}]`,
      ).multiply(power),
    );
    power = (power * BigInt(index)) % BLS_SCALAR_ORDER;
  }
  return expected;
}

function shareMatchesCommitments(share, commitments, index) {
  return bls.G2.ProjectivePoint.BASE.multiply(scalar(share, "share", true))
    .equals(expectedSharePoint(commitments, index));
}

function packetHash(body) {
  return keccak256(toUtf8Bytes(canonicalJson(body)));
}

function signPacket(body, privateKey) {
  return hexlify(sign(null, Buffer.from(getBytes(packetHash(body))), privateKey));
}

function verifyPacket(packet, participant) {
  if (!packet?.body || typeof packet.signature !== "string") return false;
  return verify(
    null,
    Buffer.from(getBytes(packetHash(packet.body))),
    publicKeyFromRaw(participant.identityPublicKey, "ed25519"),
    Buffer.from(getBytes(fixedHex(packet.signature, 64, "packet signature"))),
  );
}

function shareAssociatedData(body, recipientId) {
  return Buffer.from(canonicalJson({
    format: body.format,
    type: body.type,
    ceremony: body.ceremony,
    sessionId: body.sessionId,
    epoch: body.epoch,
    threshold: body.threshold,
    dealerId: body.dealerId,
    dealerIndex: body.dealerIndex,
    previousManifestHash: body.previousManifestHash,
    selectedDealerIds: body.selectedDealerIds,
    commitments: body.commitments,
    recipientId,
  }));
}

function encryptShare(share, recipient, associatedData) {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  const shared = diffieHellman({
    privateKey,
    publicKey: publicKeyFromRaw(recipient.transportPublicKey, "x25519"),
  });
  const info = createHash("sha256").update(associatedData).digest();
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), info, 32));
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(associatedData);
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(getBytes(scalarHex(share)))),
    cipher.final(),
  ]);
  return {
    ephemeralPublicKey: rawPublicKey(publicKey),
    iv: hexlify(iv),
    ciphertext: hexlify(ciphertext),
    tag: hexlify(cipher.getAuthTag()),
  };
}

function decryptShare(envelope, transportPrivateKey, associatedData) {
  const shared = diffieHellman({
    privateKey: transportPrivateKey,
    publicKey: publicKeyFromRaw(envelope.ephemeralPublicKey, "x25519"),
  });
  const info = createHash("sha256").update(associatedData).digest();
  const key = Buffer.from(hkdfSync("sha256", shared, Buffer.alloc(0), info, 32));
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    getBytes(fixedHex(envelope.iv, 12, "share IV")),
  );
  decipher.setAAD(associatedData);
  decipher.setAuthTag(Buffer.from(getBytes(fixedHex(envelope.tag, 16, "share tag"))));
  return BigInt(hexlify(Buffer.concat([
    decipher.update(Buffer.from(getBytes(fixedHex(envelope.ciphertext, 32, "encrypted share")))),
    decipher.final(),
  ])));
}

function selectedDealerIndexes(previousManifest, selectedDealerIds) {
  if (!previousManifest) throw new Error("resharing requires the previous manifest");
  const byId = new Map(previousManifest.participants.map((item) => [item.id, item]));
  const indexes = selectedDealerIds.map((id) => {
    const participant = byId.get(id);
    if (!participant) throw new Error(`selected dealer ${id} is not in the previous manifest`);
    return BigInt(participant.index);
  });
  if (new Set(indexes.map(String)).size !== indexes.length) {
    throw new Error("selected resharing dealer indexes must be unique");
  }
  if (indexes.length < previousManifest.threshold) {
    throw new Error("resharing requires at least the old threshold of selected dealers");
  }
  const selected = new Set(selectedDealerIds);
  const canonicalIds = previousManifest.participants
    .filter((participant) => selected.has(participant.id))
    .map((participant) => participant.id);
  if (canonicalJson(canonicalIds) !== canonicalJson(selectedDealerIds)) {
    throw new Error("selected resharing dealers must follow previous-manifest roster order");
  }
  return indexes;
}

export function createDealBundle({
  ceremony = "dkg",
  sessionId,
  epoch,
  threshold,
  roster,
  dealerKeystore,
  password,
  previousManifest,
  previousManifestHash = null,
  selectedDealerIds = [],
  workFactor,
}) {
  const participants = validateRoster(roster, threshold);
  const loaded = loadKeystore(dealerKeystore, password);
  const dealer = (ceremony === "reshare" ? previousManifest?.participants : participants)
    ?.find((item) => item.id === dealerKeystore.participantId);
  if (!dealer) throw new Error("dealer is not in the applicable roster");

  let constant = randomScalar();
  if (ceremony === "reshare") {
    const preparedPrevious = prepareGroupManifest(previousManifest, { allowLoopback: true });
    const trustedPreviousHash = fixedHex(
      previousManifestHash,
      32,
      "previousManifestHash",
    );
    if (preparedPrevious.manifestHash !== trustedPreviousHash) {
      throw new Error("previous manifest does not match its separately trusted hash");
    }
    if (epoch !== previousManifest.epoch + 1) {
      throw new Error("resharing epoch must immediately follow the previous epoch");
    }
    if (!selectedDealerIds.includes(dealer.id)) throw new Error("dealer was not selected for resharing");
    if (!loaded.secret.thresholdShare) throw new Error("old dealer keystore has no threshold share");
    if (loaded.secret.thresholdManifestHash?.toLowerCase() !== previousManifestHash?.toLowerCase()) {
      throw new Error("old dealer share is not bound to the trusted previous manifest");
    }
    const indexes = selectedDealerIndexes(previousManifest, selectedDealerIds);
    const lambda = lagrangeCoefficientAtZero(dealer.index, indexes);
    constant = thresholdInternals.mod(scalar(loaded.secret.thresholdShare) * lambda);
  } else if (ceremony !== "dkg") {
    throw new Error("ceremony must be dkg or reshare");
  }

  const coefficients = [constant];
  while (coefficients.length < threshold) coefficients.push(randomScalar(true));
  if (coefficients.at(-1) === 0n) coefficients[coefficients.length - 1] = randomScalar();
  const commitments = commitmentsFor(coefficients);
  const body = {
    format: DKG_PACKET_FORMAT,
    type: "deal",
    ceremony,
    sessionId: fixedHex(sessionId, 32, "sessionId"),
    epoch,
    threshold,
    dealerId: dealer.id,
    dealerIndex: dealer.index,
    previousManifestHash: ceremony === "dkg" ? null : fixedHex(
      previousManifestHash,
      32,
      "previousManifestHash",
    ),
    selectedDealerIds: ceremony === "dkg" ? [] : [...selectedDealerIds],
    commitments,
    encryptedShares: [],
  };
  for (const recipient of participants) {
    body.encryptedShares.push({
      recipientId: recipient.id,
      envelope: encryptShare(
        polynomialAt(coefficients, recipient.index),
        recipient,
        shareAssociatedData(body, recipient.id),
      ),
    });
  }
  const packet = { body, signature: signPacket(body, loaded.identityPrivateKey) };
  const state = {
    format: DKG_PACKET_FORMAT,
    type: "dealer-state",
    sessionId: body.sessionId,
    dealerId: dealer.id,
    crypto: encryptPayload({
      coefficients: coefficients.map(scalarHex),
      dealHash: packetHash(body),
    }, password, workFactor),
  };
  return { packet, state };
}

function validateDealPacket(packet, roster, dealerRoster, expected) {
  const body = packet?.body;
  if (body?.format !== DKG_PACKET_FORMAT || body.type !== "deal") {
    throw new Error("invalid deal packet format");
  }
  for (const field of ["ceremony", "sessionId", "epoch", "threshold"]) {
    if (body[field] !== expected[field]) throw new Error(`deal has the wrong ${field}`);
  }
  for (const field of ["previousManifestHash", "selectedDealerIds"]) {
    if (canonicalJson(body[field]) !== canonicalJson(expected[field])) {
      throw new Error(`deal has the wrong ${field}`);
    }
  }
  const dealer = dealerRoster.find((item) => item.id === body.dealerId);
  if (!dealer || dealer.index !== body.dealerIndex || !verifyPacket(packet, dealer)) {
    throw new Error(`invalid deal identity signature from ${body.dealerId}`);
  }
  if (!Array.isArray(body.commitments) || body.commitments.length !== expected.threshold) {
    throw new Error(`invalid commitments from ${body.dealerId}`);
  }
  body.commitments.forEach((commitment, position) => (
    thresholdInternals.g2CommitmentPoint(commitment, `commitment ${position}`)
  ));
  if (thresholdInternals.g2CommitmentPoint(body.commitments.at(-1), "highest commitment")
    .equals(bls.G2.ProjectivePoint.ZERO)) {
    throw new Error(`zero highest commitment from ${body.dealerId}`);
  }
  if (!Array.isArray(body.encryptedShares) || body.encryptedShares.length !== roster.length
      || new Set(body.encryptedShares.map((item) => item.recipientId)).size !== roster.length) {
    throw new Error(`deal from ${body.dealerId} does not cover the roster exactly once`);
  }
  const recipientIds = body.encryptedShares.map((item) => item.recipientId).sort();
  const rosterIds = roster.map((item) => item.id).sort();
  if (canonicalJson(recipientIds) !== canonicalJson(rosterIds)) {
    throw new Error(`deal from ${body.dealerId} targets the wrong roster`);
  }
  return { body, dealer };
}

export function createResponseBundle({
  ceremony = "dkg",
  sessionId,
  epoch,
  threshold,
  roster,
  dealerRoster = roster,
  previousManifestHash = null,
  selectedDealerIds = [],
  recipientKeystore,
  password,
  deals,
}) {
  const participants = validateRoster(roster, threshold);
  const dealers = dealerRoster.map((item, position) => validateParticipant(item, position + 1));
  const loaded = loadKeystore(recipientKeystore, password);
  const recipient = participants.find((item) => item.id === recipientKeystore.participantId);
  if (!recipient) throw new Error("response signer is not in the new roster");
  const expected = {
    ceremony,
    sessionId: fixedHex(sessionId, 32, "sessionId"),
    epoch,
    threshold,
    previousManifestHash: ceremony === "dkg"
      ? null
      : fixedHex(previousManifestHash, 32, "previousManifestHash"),
    selectedDealerIds: ceremony === "dkg" ? [] : [...selectedDealerIds],
  };
  const statuses = [];
  for (const packet of deals) {
    let status = true;
    let reason = "accepted";
    try {
      const { body } = validateDealPacket(packet, participants, dealers, expected);
      const item = body.encryptedShares.find((candidate) => candidate.recipientId === recipient.id);
      const share = decryptShare(
        item.envelope,
        loaded.transportPrivateKey,
        shareAssociatedData(body, recipient.id),
      );
      if (!shareMatchesCommitments(share, body.commitments, recipient.index)) {
        throw new Error("share does not match the public commitments");
      }
    } catch (error) {
      status = false;
      reason = String(error.message || error).slice(0, 160);
    }
    statuses.push({ dealerId: packet?.body?.dealerId || "unknown", status, reason });
  }
  statuses.sort((left, right) => left.dealerId.localeCompare(right.dealerId));
  const body = {
    format: DKG_PACKET_FORMAT,
    type: "response",
    ceremony,
    sessionId: expected.sessionId,
    epoch,
    threshold,
    recipientId: recipient.id,
    recipientIndex: recipient.index,
    statuses,
  };
  return { body, signature: signPacket(body, loaded.identityPrivateKey) };
}

export function createResolutionBundle({
  dealerKeystore,
  dealerState,
  password,
  deal,
  responses,
  roster,
  dealerRoster = roster,
}) {
  const participants = validateRoster(roster, deal?.body?.threshold);
  const dealers = dealerRoster.map((item, position) => validateParticipant(item, position + 1));
  const loaded = loadKeystore(dealerKeystore, password);
  if (dealerState?.type !== "dealer-state" || dealerState.dealerId !== dealerKeystore.participantId
      || dealerState.sessionId !== deal?.body?.sessionId) {
    throw new Error("dealer state does not match the deal");
  }
  const secret = decryptPayload(dealerState.crypto, password);
  if (secret.dealHash !== packetHash(deal.body)) throw new Error("dealer state deal hash mismatch");
  const expected = {
    ceremony: deal.body.ceremony,
    sessionId: fixedHex(deal.body.sessionId, 32, "sessionId"),
    epoch: deal.body.epoch,
    threshold: deal.body.threshold,
    previousManifestHash: deal.body.previousManifestHash,
    selectedDealerIds: deal.body.selectedDealerIds,
  };
  const validatedDeal = validateDealPacket(deal, participants, dealers, expected);
  if (validatedDeal.dealer.id !== dealerKeystore.participantId) {
    throw new Error("dealer keystore does not own the signed deal");
  }
  const coefficients = secret.coefficients.map((value) => scalar(value, "dealer coefficient", true));
  const complaints = [];
  const responders = new Set();
  for (const response of responses) {
    const responseBody = validateResponsePacket(response, participants, expected);
    if (responders.has(responseBody.recipientId)) throw new Error("duplicate response packet");
    responders.add(responseBody.recipientId);
    const complaint = responseBody.statuses?.find(
      (item) => item.dealerId === dealerKeystore.participantId && !item.status,
    );
    if (complaint) {
      complaints.push({
        recipientId: responseBody.recipientId,
        recipientIndex: responseBody.recipientIndex,
        share: scalarHex(polynomialAt(coefficients, responseBody.recipientIndex)),
      });
    }
  }
  if (new Set(complaints.map((item) => item.recipientId)).size !== complaints.length) {
    throw new Error("duplicate complaint response");
  }
  if (complaints.length >= deal.body.threshold) {
    throw new Error("refusing to reveal threshold shares; disqualify the dealer and restart");
  }
  complaints.sort((left, right) => left.recipientIndex - right.recipientIndex);
  const body = {
    format: DKG_PACKET_FORMAT,
    type: "resolution",
    ceremony: deal.body.ceremony,
    sessionId: deal.body.sessionId,
    epoch: deal.body.epoch,
    threshold: deal.body.threshold,
    dealerId: dealerKeystore.participantId,
    complaints,
  };
  return { body, signature: signPacket(body, loaded.identityPrivateKey) };
}

function validateResponsePacket(packet, roster, expected) {
  const body = packet?.body;
  const recipient = roster.find((item) => item.id === body?.recipientId);
  if (body?.format !== DKG_PACKET_FORMAT || body.type !== "response" || !recipient
      || recipient.index !== body.recipientIndex || !verifyPacket(packet, recipient)) {
    throw new Error("invalid response packet");
  }
  for (const field of ["ceremony", "sessionId", "epoch", "threshold"]) {
    if (body[field] !== expected[field]) throw new Error(`response has the wrong ${field}`);
  }
  if (!Array.isArray(body.statuses)) throw new Error("response statuses must be an array");
  const seenDealers = new Set();
  for (const status of body.statuses) {
    if (!status || typeof status.dealerId !== "string" || typeof status.status !== "boolean"
        || typeof status.reason !== "string" || status.reason.length > 160
        || seenDealers.has(status.dealerId)) {
      throw new Error("invalid response status");
    }
    seenDealers.add(status.dealerId);
  }
  return body;
}

function validateResolution(packet, dealer, deal, expected, roster, responsesByRecipient) {
  const body = packet?.body;
  if (body?.format !== DKG_PACKET_FORMAT || body.type !== "resolution"
      || body.dealerId !== dealer.id || !verifyPacket(packet, dealer)) {
    throw new Error(`invalid resolution from ${dealer.id}`);
  }
  for (const field of ["ceremony", "sessionId", "epoch", "threshold"]) {
    if (body[field] !== expected[field]) throw new Error(`resolution has the wrong ${field}`);
  }
  if (!Array.isArray(body.complaints)) throw new Error("resolution complaints must be an array");
  const complainedRecipientIds = [...responsesByRecipient.values()]
    .filter((response) => response.statuses.some(
      (status) => status.dealerId === dealer.id && !status.status,
    ))
    .map((response) => response.recipientId)
    .sort();
  if (complainedRecipientIds.length >= expected.threshold) {
    throw new Error(`resolution from ${dealer.id} would reveal threshold shares`);
  }
  const resolvedRecipientIds = body.complaints.map((item) => item.recipientId).sort();
  if (canonicalJson(resolvedRecipientIds) !== canonicalJson(complainedRecipientIds)) {
    throw new Error(`resolution from ${dealer.id} does not exactly match signed complaints`);
  }
  const seen = new Set();
  for (const item of body.complaints) {
    const recipient = roster.find((candidate) => candidate.id === item.recipientId);
    if (!recipient || recipient.index !== item.recipientIndex || seen.has(item.recipientId)) {
      throw new Error(`invalid resolution recipient from ${dealer.id}`);
    }
    seen.add(item.recipientId);
    if (!shareMatchesCommitments(item.share, deal.body.commitments, item.recipientIndex)) {
      throw new Error(`invalid resolved share from ${dealer.id}`);
    }
  }
  return body;
}

function aggregateCommitments(deals, threshold) {
  return Array.from({ length: threshold }, (_, position) => pointHex(
    deals.reduce(
      (sum, deal) => sum.add(thresholdInternals.g2CommitmentPoint(
        deal.body.commitments[position],
        `commitment ${position}`,
      )),
      bls.G2.ProjectivePoint.ZERO,
    ),
  ));
}

export function finalizeCeremony({
  ceremony = "dkg",
  sessionId,
  epoch,
  threshold,
  roster,
  dealerRoster = roster,
  participantKeystore,
  password,
  deals,
  responses,
  resolutions = [],
  previousManifest,
  previousManifestHash = null,
  selectedDealerIds = [],
  workFactor,
}) {
  const participants = validateRoster(roster, threshold);
  const dealers = dealerRoster.map((item, position) => validateParticipant(item, position + 1));
  const loaded = loadKeystore(participantKeystore, password);
  const participant = participants.find((item) => item.id === participantKeystore.participantId);
  if (!participant) throw new Error("finalizing participant is not in the new roster");
  const expected = {
    ceremony,
    sessionId: fixedHex(sessionId, 32, "sessionId"),
    epoch,
    threshold,
    previousManifestHash: ceremony === "dkg"
      ? null
      : fixedHex(previousManifestHash, 32, "previousManifestHash"),
    selectedDealerIds: ceremony === "dkg" ? [] : [...selectedDealerIds],
  };
  const validResponses = new Map();
  for (const response of responses) {
    const body = validateResponsePacket(response, participants, expected);
    if (validResponses.has(body.recipientId)) throw new Error("duplicate response packet");
    validResponses.set(body.recipientId, body);
  }

  const resolutionsByDealer = new Map();
  const resolutionPackets = new Map();
  for (const resolution of resolutions) {
    const dealerId = resolution?.body?.dealerId;
    if (typeof dealerId !== "string" || resolutionPackets.has(dealerId)) {
      throw new Error("invalid or duplicate resolution packet");
    }
    resolutionPackets.set(dealerId, resolution);
  }
  const validDeals = [];
  for (const packet of deals) {
    const { body, dealer } = validateDealPacket(packet, participants, dealers, expected);
    if (validDeals.some((item) => item.body.dealerId === dealer.id)) {
      throw new Error(`duplicate deal from ${dealer.id}`);
    }
    const resolutionPacket = resolutionPackets.get(dealer.id);
    if (resolutionPacket) {
      resolutionsByDealer.set(
        dealer.id,
        validateResolution(
          resolutionPacket,
          dealer,
          packet,
          expected,
          participants,
          validResponses,
        ),
      );
    }
    if (ceremony === "reshare") {
      const indexes = selectedDealerIndexes(previousManifest, selectedDealerIds);
      const lambda = lagrangeCoefficientAtZero(dealer.index, indexes);
      const oldShare = previousManifest.participants.find((item) => item.id === dealer.id);
      const expectedConstant = thresholdInternals.g2Point(
        oldShare.sharePublicKey,
        `${dealer.id} old share public key`,
      ).multiply(lambda);
      if (!thresholdInternals.g2CommitmentPoint(
        body.commitments[0],
        `${dealer.id} resharing constant commitment`,
      ).equals(expectedConstant)) {
        throw new Error(`resharing constant commitment from ${dealer.id} is invalid`);
      }
    }
    validDeals.push(packet);
  }
  const validDealerIds = validDeals.map((item) => item.body.dealerId).sort();
  if ([...resolutionPackets.keys()].some((dealerId) => !validDealerIds.includes(dealerId))) {
    throw new Error("resolution references a dealer without a valid deal");
  }
  for (const response of validResponses.values()) {
    const responseDealerIds = response.statuses.map((status) => status.dealerId).sort();
    if (canonicalJson(responseDealerIds) !== canonicalJson(validDealerIds)) {
      throw new Error(`response from ${response.recipientId} does not cover every valid deal`);
    }
  }

  const qualified = [];
  for (const deal of validDeals) {
    const evaluations = [...validResponses.values()].map((response) => ({
      recipientId: response.recipientId,
      status: response.statuses.find((item) => item.dealerId === deal.body.dealerId),
    })).filter((evaluation) => evaluation.status);
    const complaints = evaluations.filter((evaluation) => !evaluation.status.status);
    const resolution = resolutionsByDealer.get(deal.body.dealerId);
    const resolvedIds = new Set(resolution?.complaints.map((item) => item.recipientId) || []);
    const accepted = evaluations.filter((evaluation) => evaluation.status.status).length
      + complaints.filter((evaluation) => resolvedIds.has(evaluation.recipientId)).length;
    const allComplaintsResolved = complaints.every(
      (evaluation) => resolvedIds.has(evaluation.recipientId),
    );
    if (complaints.length < threshold && allComplaintsResolved && accepted >= threshold) {
      qualified.push(deal);
    }
  }
  if (ceremony === "dkg" && qualified.length < threshold) {
    throw new Error("fewer than threshold dealers qualified");
  }
  if (ceremony === "reshare") {
    selectedDealerIndexes(previousManifest, selectedDealerIds);
    const qualifiedIds = new Set(qualified.map((item) => item.body.dealerId));
    if (qualified.length !== selectedDealerIds.length
        || selectedDealerIds.some((id) => !qualifiedIds.has(id))) {
      throw new Error("resharing aborts unless every preselected old dealer qualifies");
    }
  }

  let privateShare = 0n;
  for (const deal of qualified) {
    const item = deal.body.encryptedShares.find(
      (candidate) => candidate.recipientId === participant.id,
    );
    let contribution;
    try {
      contribution = decryptShare(
        item.envelope,
        loaded.transportPrivateKey,
        shareAssociatedData(deal.body, participant.id),
      );
      if (!shareMatchesCommitments(contribution, deal.body.commitments, participant.index)) {
        throw new Error("invalid local share");
      }
    } catch {
      const resolved = resolutionsByDealer.get(deal.body.dealerId)?.complaints.find(
        (candidate) => candidate.recipientId === participant.id,
      );
      if (!resolved) throw new Error(`no valid share from ${deal.body.dealerId}`);
      contribution = scalar(resolved.share, "resolved share", true);
    }
    privateShare = (privateShare + contribution) % BLS_SCALAR_ORDER;
  }
  if (privateShare === 0n) throw new Error("final threshold share is zero");
  const publicCoefficients = aggregateCommitments(qualified, threshold);
  const groupPublicKey = publicCoefficients[0];
  if (ceremony === "reshare"
      && groupPublicKey.toLowerCase() !== previousManifest.groupPublicKey.toLowerCase()) {
    throw new Error("resharing changed the group public key");
  }
  const transcript = {
    format: DKG_PACKET_FORMAT,
    ceremony,
    sessionId: expected.sessionId,
    epoch,
    threshold,
    qualifiedDealerIds: qualified.map((item) => item.body.dealerId).sort(),
    deals: [...deals].sort((a, b) => a.body.dealerId.localeCompare(b.body.dealerId)),
    responses: [...responses].sort((a, b) => a.body.recipientId.localeCompare(b.body.recipientId)),
    resolutions: [...resolutions].sort((a, b) => a.body.dealerId.localeCompare(b.body.dealerId)),
  };
  const transcriptHash = keccak256(toUtf8Bytes(canonicalJson(transcript)));
  const secret = {
    ...loaded.secret,
    thresholdShare: scalarHex(privateShare),
    thresholdEpoch: epoch,
    thresholdManifestHash: null,
    thresholdTranscriptHash: transcriptHash,
  };
  const sharePublicKey = pointHex(bls.G2.ProjectivePoint.BASE.multiply(privateShare));
  return {
    finalization: {
      format: DKG_FINALIZATION_FORMAT,
      ceremony,
      sessionId: expected.sessionId,
      epoch,
      threshold,
      participantId: participant.id,
      participantIndex: participant.index,
      groupPublicKey,
      publicCoefficients,
      sharePublicKey,
      transcriptHash,
      qualifiedDealerIds: transcript.qualifiedDealerIds,
      previousManifestHash: ceremony === "dkg" ? null : fixedHex(
        previousManifestHash,
        32,
        "previousManifestHash",
      ),
    },
    keystore: {
      ...participantKeystore,
      crypto: encryptPayload(secret, password, workFactor),
    },
    transcript,
  };
}

export function assembleManifest({
  finalizations,
  roster,
  network,
  chainId,
  verifierAdapter,
  softwareCommit,
  containerDigest,
  previousManifestHash = null,
}) {
  if (!Array.isArray(finalizations) || finalizations.length !== roster.length) {
    throw new Error("one finalization is required for every new participant");
  }
  const first = finalizations[0];
  const fields = [
    "ceremony", "sessionId", "epoch", "threshold", "groupPublicKey",
    "transcriptHash", "previousManifestHash",
  ];
  for (const finalization of finalizations) {
    if (finalization.format !== DKG_FINALIZATION_FORMAT) throw new Error("invalid finalization");
    for (const field of fields) {
      if (canonicalJson(finalization[field]) !== canonicalJson(first[field])) {
        throw new Error(`finalizations disagree on ${field}`);
      }
    }
    if (canonicalJson(finalization.publicCoefficients)
        !== canonicalJson(first.publicCoefficients)) {
      throw new Error("finalizations disagree on public coefficients");
    }
  }
  const byId = new Map(finalizations.map((item) => [item.participantId, item]));
  if (byId.size !== roster.length || roster.some((participant) => {
    const finalization = byId.get(participant.id);
    return !finalization || finalization.participantIndex !== participant.index;
  })) {
    throw new Error("finalizations must cover the roster exactly once");
  }
  const manifest = {
    format: "robinhood-proof-vrf-threshold-group/v1",
    scheme: "THRESHOLD_BLS_UNIQUE_SIGNATURE_V1",
    network,
    chainId,
    verifierAdapter,
    ceremony: first.ceremony,
    previousManifestHash,
    epoch: first.epoch,
    threshold: first.threshold,
    groupPublicKey: first.groupPublicKey,
    publicCoefficients: first.publicCoefficients,
    keyHash: adapterKeyHash(first.groupPublicKey),
    dkgTranscriptHash: first.transcriptHash,
    softwareCommit,
    containerDigest,
    participants: roster.map((participant) => ({
      ...participant,
      sharePublicKey: byId.get(participant.id)?.sharePublicKey,
    })),
    attestations: [],
    handoffAttestations: [],
  };
  prepareGroupManifest(manifest, { allowLoopback: true });
  return manifest;
}

export function attestManifest({ manifest, participantKeystore, password }) {
  const loaded = loadKeystore(participantKeystore, password);
  const { manifestHash } = prepareGroupManifest(manifest, { allowLoopback: true });
  return {
    participantId: participantKeystore.participantId,
    signature: hexlify(sign(
      null,
      Buffer.from(getBytes(manifestHash)),
      loaded.identityPrivateKey,
    )),
  };
}

export function bindKeystoreToManifest({ keystore, password, manifest, manifestHash, workFactor }) {
  const loaded = loadKeystore(keystore, password);
  if (!loaded.secret.thresholdShare) throw new Error("keystore has no finalized threshold share");
  const prepared = prepareGroupManifest(manifest, { allowLoopback: true });
  const trustedHash = fixedHex(manifestHash, 32, "manifestHash");
  if (prepared.manifestHash !== trustedHash) {
    throw new Error("manifest does not match its separately trusted hash");
  }
  const participant = prepared.body.participants.find(
    (item) => item.id === keystore.participantId,
  );
  if (!participant
      || participant.identityPublicKey.toLowerCase() !== keystore.identityPublicKey.toLowerCase()
      || participant.transportPublicKey.toLowerCase() !== keystore.transportPublicKey.toLowerCase()
      || publicKeyForShare(loaded.secret.thresholdShare).toLowerCase()
        !== participant.sharePublicKey.toLowerCase()) {
    throw new Error("threshold keystore does not match the manifest participant and share");
  }
  return {
    ...keystore,
    crypto: encryptPayload({
      ...loaded.secret,
      thresholdManifestHash: trustedHash,
    }, password, workFactor),
  };
}

function readJson(path, name) {
  if (!path) throw new Error(`${name} path is required`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
  if (!path) throw new Error("--out is required");
  if (existsSync(path)) throw new Error(`refusing to overwrite ${path}`);
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
}

async function main() {
  const [command, ...argv] = process.argv.slice(2);
  const { values } = parseArgs({
    args: argv,
    options: {
      id: { type: "string" },
      endpoint: { type: "string" },
      out: { type: "string" },
      descriptor: { type: "string" },
      manifest: { type: "string" },
      keystore: { type: "string" },
      "manifest-hash": { type: "string" },
      ceremony: { type: "string", default: "dkg" },
      session: { type: "string" },
      epoch: { type: "string" },
      threshold: { type: "string" },
      roster: { type: "string" },
      previous: { type: "string" },
      "previous-manifest-hash": { type: "string" },
      "selected-dealers": { type: "string", default: "" },
      deals: { type: "string" },
      responses: { type: "string" },
      resolutions: { type: "string" },
      deal: { type: "string" },
      state: { type: "string" },
      "state-out": { type: "string" },
      "keystore-out": { type: "string" },
      "transcript-out": { type: "string" },
      finalizations: { type: "string" },
      network: { type: "string" },
      "chain-id": { type: "string" },
      "verifier-adapter": { type: "string" },
      "software-commit": { type: "string" },
      "container-digest": { type: "string" },
    },
    strict: true,
  });
  let password;
  const keyPassword = () => {
    password ??= readSecret("VRF_THRESHOLD_KEY_PASSWORD", { required: true });
    return password;
  };
  const ceremonyOptions = () => ({
    ceremony: values.ceremony,
    sessionId: values.session,
    epoch: Number(values.epoch),
    threshold: Number(values.threshold),
    roster: readJson(values.roster, "roster"),
    previousManifest: values.previous ? readJson(values.previous, "previous manifest") : undefined,
    previousManifestHash: values["previous-manifest-hash"] || null,
    selectedDealerIds: values["selected-dealers"].split(",").filter(Boolean),
  });
  if (command === "identity") {
    const generated = generateParticipant({
      id: values.id,
      endpoint: values.endpoint,
      password: keyPassword(),
    });
    writeJson(values.out, generated.keystore);
    writeJson(values.descriptor, generated.participant);
    return;
  }
  if (command === "attest") {
    const manifest = readJson(values.manifest, "manifest");
    process.stdout.write(`${JSON.stringify(attestManifest({
      manifest,
      participantKeystore: readJson(values.keystore, "keystore"),
      password: keyPassword(),
    }), null, 2)}\n`);
    return;
  }
  if (command === "bind") {
    const manifest = readJson(values.manifest, "manifest");
    writeJson(values.out, bindKeystoreToManifest({
      keystore: readJson(values.keystore, "keystore"),
      password: keyPassword(),
      manifest,
      manifestHash: values["manifest-hash"],
    }));
    return;
  }
  if (command === "deal") {
    const result = createDealBundle({
      ...ceremonyOptions(),
      dealerKeystore: readJson(values.keystore, "keystore"),
      password: keyPassword(),
    });
    writeJson(values.out, result.packet);
    writeJson(values["state-out"], result.state);
    return;
  }
  if (command === "respond") {
    writeJson(values.out, createResponseBundle({
      ...ceremonyOptions(),
      dealerRoster: values.ceremony === "reshare"
        ? readJson(values.previous, "previous manifest").participants
        : undefined,
      recipientKeystore: readJson(values.keystore, "keystore"),
      password: keyPassword(),
      deals: readJson(values.deals, "deals"),
    }));
    return;
  }
  if (command === "resolve") {
    writeJson(values.out, createResolutionBundle({
      dealerKeystore: readJson(values.keystore, "keystore"),
      dealerState: readJson(values.state, "dealer state"),
      password: keyPassword(),
      deal: readJson(values.deal, "deal"),
      responses: readJson(values.responses, "responses"),
      roster: readJson(values.roster, "roster"),
      dealerRoster: values.ceremony === "reshare"
        ? readJson(values.previous, "previous manifest").participants
        : undefined,
    }));
    return;
  }
  if (command === "finalize") {
    const result = finalizeCeremony({
      ...ceremonyOptions(),
      dealerRoster: values.ceremony === "reshare"
        ? readJson(values.previous, "previous manifest").participants
        : undefined,
      participantKeystore: readJson(values.keystore, "keystore"),
      password: keyPassword(),
      deals: readJson(values.deals, "deals"),
      responses: readJson(values.responses, "responses"),
      resolutions: values.resolutions ? readJson(values.resolutions, "resolutions") : [],
    });
    writeJson(values.out, result.finalization);
    writeJson(values["keystore-out"], result.keystore);
    if (values["transcript-out"]) writeJson(values["transcript-out"], result.transcript);
    return;
  }
  if (command === "assemble") {
    writeJson(values.out, assembleManifest({
      finalizations: readJson(values.finalizations, "finalizations"),
      roster: readJson(values.roster, "roster"),
      network: values.network,
      chainId: Number(values["chain-id"]),
      verifierAdapter: values["verifier-adapter"],
      softwareCommit: values["software-commit"],
      containerDigest: values["container-digest"],
      previousManifestHash: values["previous-manifest-hash"] || null,
    }));
    return;
  }
  throw new Error("usage: threshold-dkg.mjs identity|deal|respond|resolve|finalize|assemble|attest|bind");
}

if (isMain(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error.message || String(error)}\n`);
    process.exitCode = 1;
  });
}

export const internals = Object.freeze({
  commitmentsFor,
  decryptPayload,
  decryptShare,
  encryptPayload,
  expectedSharePoint,
  loadKeystore,
  packetHash,
  polynomialAt,
  scalar,
  scalarHex,
  shareMatchesCommitments,
  signPacket,
  validateRoster,
  verifyPacket,
});

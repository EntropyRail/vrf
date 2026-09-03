import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { getBytes, hexlify } from "ethers";

export const BLS_DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
export const BLS_SCALAR_ORDER = bls.params.r;

function bytesFor(value, name) {
  if (value instanceof Uint8Array) return value;
  try {
    return getBytes(value);
  } catch {
    throw new Error(`${name} must be hex bytes`);
  }
}

function pointFor(value, group, expectedLength, name, allowInfinity = false) {
  const bytes = bytesFor(value, name);
  if (bytes.length !== expectedLength) {
    throw new Error(`${name} must be ${expectedLength} uncompressed bytes`);
  }
  try {
    const point = group.ProjectivePoint.fromHex(bytes);
    point.assertValidity();
    if (hexlify(point.toRawBytes(false)).toLowerCase() !== hexlify(bytes).toLowerCase()) {
      throw new Error(`${name} must use canonical uncompressed encoding`);
    }
    if (!allowInfinity && point.equals(group.ProjectivePoint.ZERO)) {
      throw new Error(`${name} cannot be the point at infinity`);
    }
    return point;
  } catch (error) {
    if (error.message?.startsWith(`${name} cannot`)) throw error;
    throw new Error(`${name} is not a valid subgroup point`);
  }
}

function g1Point(value, name = "signature") {
  return pointFor(value, bls.G1, 96, name);
}

function g2Point(value, name = "public key") {
  return pointFor(value, bls.G2, 192, name);
}

function g2CommitmentPoint(value, name = "public coefficient commitment") {
  return pointFor(value, bls.G2, 192, name, true);
}

function wireHex(point) {
  return hexlify(point.toRawBytes(false));
}

function scalarIndex(value, name = "share index") {
  const index = typeof value === "bigint" ? value : BigInt(value);
  if (index <= 0n || index >= BLS_SCALAR_ORDER) {
    throw new Error(`${name} must be in [1, scalar order)`);
  }
  return index;
}

function mod(value) {
  const reduced = value % BLS_SCALAR_ORDER;
  return reduced >= 0n ? reduced : reduced + BLS_SCALAR_ORDER;
}

function invert(value) {
  let low = mod(value);
  if (low === 0n) throw new Error("cannot invert zero scalar");
  let high = BLS_SCALAR_ORDER;
  let lm = 1n;
  let hm = 0n;
  while (low > 1n) {
    const ratio = high / low;
    [lm, hm] = [hm - lm * ratio, lm];
    [low, high] = [high - low * ratio, low];
  }
  return mod(lm);
}

export function lagrangeCoefficientAtZero(indexValue, allIndexValues) {
  const index = scalarIndex(indexValue);
  const indexes = allIndexValues.map((value) => scalarIndex(value));
  if (new Set(indexes.map(String)).size !== indexes.length) {
    throw new Error("share indexes must be unique");
  }
  if (!indexes.some((candidate) => candidate === index)) {
    throw new Error("share index is not in the interpolation set");
  }
  let numerator = 1n;
  let denominator = 1n;
  for (const other of indexes) {
    if (other === index) continue;
    numerator = mod(numerator * other);
    denominator = mod(denominator * (other - index));
  }
  return mod(numerator * invert(denominator));
}

export function verifyPartialSignature({ message, publicKey, signature }) {
  try {
    const messagePoint = bls.G1.hashToCurve(bytesFor(message, "message"), { DST: BLS_DST });
    const signaturePoint = g1Point(signature, "partial signature");
    const publicKeyPoint = g2Point(publicKey, "share public key");
    const left = bls.pairing(signaturePoint, bls.G2.ProjectivePoint.BASE);
    const right = bls.pairing(messagePoint, publicKeyPoint);
    return bls.fields.Fp12.eql(left, right);
  } catch {
    return false;
  }
}

export function publicKeyForShare(secretShare) {
  const scalar = mod(BigInt(secretShare));
  if (scalar === 0n) throw new Error("secret share cannot be zero");
  return wireHex(bls.G2.ProjectivePoint.BASE.multiply(scalar));
}

export function signPartial({ message, secretShare }) {
  const scalar = mod(BigInt(secretShare));
  if (scalar === 0n) throw new Error("secret share cannot be zero");
  const messagePoint = bls.G1.hashToCurve(bytesFor(message, "message"), { DST: BLS_DST });
  return wireHex(messagePoint.multiply(scalar));
}

export function verifyAggregateSignature({ message, groupPublicKey, signature }) {
  try {
    const messagePoint = bls.G1.hashToCurve(bytesFor(message, "message"), { DST: BLS_DST });
    const signaturePoint = g1Point(signature, "aggregate signature");
    const publicKeyPoint = g2Point(groupPublicKey, "group public key");
    const left = bls.pairing(signaturePoint, bls.G2.ProjectivePoint.BASE);
    const right = bls.pairing(messagePoint, publicKeyPoint);
    return bls.fields.Fp12.eql(left, right);
  } catch {
    return false;
  }
}

export function verifyPublicShareCommitment({ index, sharePublicKey, publicCoefficients }) {
  if (!Array.isArray(publicCoefficients) || publicCoefficients.length < 2) {
    throw new Error("publicCoefficients must contain at least two G2 commitments");
  }
  const scalar = scalarIndex(index);
  let expected = bls.G2.ProjectivePoint.ZERO;
  let power = 1n;
  for (let position = 0; position < publicCoefficients.length; position += 1) {
    expected = expected.add(
      g2CommitmentPoint(
        publicCoefficients[position],
        `publicCoefficients[${position}]`,
      ).multiply(power),
    );
    power = mod(power * scalar);
  }
  return expected.equals(g2Point(sharePublicKey, "share public key"));
}

export function aggregateThresholdShares({ message, groupPublicKey, threshold, shares }) {
  if (!Number.isSafeInteger(threshold) || threshold < 2) {
    throw new Error("threshold must be an integer of at least 2");
  }
  if (!Array.isArray(shares) || shares.length < threshold) {
    throw new Error(`at least ${threshold} shares are required`);
  }
  const indexes = shares.map((share) => scalarIndex(share.index));
  if (new Set(indexes.map(String)).size !== indexes.length) {
    throw new Error("share indexes must be unique");
  }
  for (const share of shares) {
    if (!verifyPartialSignature({
      message,
      publicKey: share.publicKey,
      signature: share.signature,
    })) {
      throw new Error(`partial signature ${share.index} failed verification`);
    }
  }

  let aggregate = bls.G1.ProjectivePoint.ZERO;
  for (let position = 0; position < shares.length; position += 1) {
    const coefficient = lagrangeCoefficientAtZero(indexes[position], indexes);
    aggregate = aggregate.add(
      g1Point(shares[position].signature, "partial signature").multiply(coefficient),
    );
  }
  if (aggregate.equals(bls.G1.ProjectivePoint.ZERO)) {
    throw new Error("aggregate signature is the point at infinity");
  }
  const signature = wireHex(aggregate);
  if (!verifyAggregateSignature({ message, groupPublicKey, signature })) {
    throw new Error("aggregate signature does not match the group public key");
  }
  return {
    signature,
    indexes: indexes.map((value) => value.toString()),
  };
}

export const internals = Object.freeze({
  bytesFor,
  g1Point,
  g2CommitmentPoint,
  g2Point,
  mod,
  scalarIndex,
  wireHex,
});

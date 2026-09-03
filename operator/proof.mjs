// Adapted from the MIT-licensed Chainlink ECVRF proof construction so the output matches
// @chainlink/contracts/src/v0.8/vrf/VRF.sol. Elliptic-curve arithmetic is provided by noble-curves.
import { createHmac } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1";
import {
  AbiCoder,
  concat,
  getBytes,
  keccak256,
  toBeHex,
  toUtf8Bytes,
  zeroPadValue,
} from "ethers";

const FIELD_SIZE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const GROUP_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Point = secp256k1.ProjectivePoint;
const abiCoder = AbiCoder.defaultAbiCoder();
const SERVICE_SCHEME_ID = keccak256(toUtf8Bytes("SECP256K1_ECVRF_V1"));
const NONCE_DOMAIN = Buffer.from("ROBINHOOD_ECVRF_PROOF_NONCE_V1", "utf8");

function mod(value, modulus) {
  const result = value % modulus;
  return result >= 0n ? result : result + modulus;
}

function modPow(base, exponent, modulus) {
  let result = 1n;
  let x = mod(base, modulus);
  let power = exponent;
  while (power > 0n) {
    if (power & 1n) result = (result * x) % modulus;
    x = (x * x) % modulus;
    power >>= 1n;
  }
  return result;
}

function modInverse(value, modulus) {
  let oldR = mod(value, modulus);
  let r = modulus;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  if (oldR !== 1n) throw new Error("value has no modular inverse");
  return mod(oldS, modulus);
}

function word(value) {
  return getBytes(zeroPadValue(toBeHex(value), 32));
}

function pointCoordinates(point) {
  const { x, y } = point.toAffine();
  return [x, y];
}

function pointBytes(point) {
  const [x, y] = pointCoordinates(point);
  return getBytes(concat([word(x), word(y)]));
}

function hashBig(bytes) {
  return BigInt(keccak256(bytes));
}

function fieldHash(bytes) {
  let value = hashBig(bytes);
  while (value >= FIELD_SIZE) value = hashBig(word(value));
  return value;
}

function ySquared(x) {
  return mod(x * x * x + 7n, FIELD_SIZE);
}

function isSquare(value) {
  if (value === 0n) return true;
  return modPow(value, (FIELD_SIZE - 1n) / 2n, FIELD_SIZE) === 1n;
}

function hashToCurve(publicKey, seed) {
  let x = fieldHash(concat([word(1n), pointBytes(publicKey), word(seed)]));
  while (!isSquare(ySquared(x))) x = fieldHash(word(x));

  let y = modPow(ySquared(x), (FIELD_SIZE + 1n) / 4n, FIELD_SIZE);
  if (y & 1n) y = FIELD_SIZE - y;
  return Point.fromAffine({ x, y });
}

function ethereumAddress(point) {
  const digest = keccak256(pointBytes(point));
  return `0x${digest.slice(-40)}`;
}

function scalarFromCurvePoints(hash, publicKey, gamma, uWitness, v) {
  return hashBig(concat([
    word(2n),
    pointBytes(hash),
    pointBytes(publicKey),
    pointBytes(gamma),
    pointBytes(v),
    getBytes(uWitness),
  ]));
}

function projectiveSub(x1, z1, x2, z2) {
  const numerator1 = mod(z2 * x1, FIELD_SIZE);
  const numerator2 = mod((FIELD_SIZE - x2) * z1, FIELD_SIZE);
  return [mod(numerator1 + numerator2, FIELD_SIZE), mod(z1 * z2, FIELD_SIZE)];
}

function projectiveMul(x1, z1, x2, z2) {
  return [mod(x1 * x2, FIELD_SIZE), mod(z1 * z2, FIELD_SIZE)];
}

function projectiveECAdd(first, second) {
  const [px, py] = pointCoordinates(first);
  const [qx, qy] = pointCoordinates(second);
  const lx = mod(qy - py, FIELD_SIZE);
  const lz = mod(qx - px, FIELD_SIZE);

  let [sx, dx] = projectiveMul(lx, lz, lx, lz);
  [sx, dx] = projectiveSub(sx, dx, px, 1n);
  [sx, dx] = projectiveSub(sx, dx, qx, 1n);

  let [sy, dy] = projectiveSub(px, 1n, sx, dx);
  [sy, dy] = projectiveMul(sy, dy, lx, lz);
  [sy, dy] = projectiveSub(sy, dy, py, 1n);

  let z;
  if (dx !== dy) {
    sx = mod(sx * dy, FIELD_SIZE);
    sy = mod(sy * dx, FIELD_SIZE);
    z = mod(dx * dy, FIELD_SIZE);
  } else {
    z = dx;
  }
  return [sx, sy, z];
}

function deterministicScalar(privateKey, seed, attempt) {
  const key = Buffer.from(getBytes(zeroPadValue(toBeHex(privateKey), 32)));
  const input = Buffer.concat([
    NONCE_DOMAIN,
    Buffer.from(word(seed)),
    Buffer.from(word(attempt)),
  ]);
  return BigInt(`0x${createHmac("sha256", key).update(input).digest("hex")}`);
}

export function publicKeyFor(privateKey) {
  const secret = BigInt(privateKey);
  if (secret <= 0n || secret >= GROUP_ORDER) throw new Error("invalid VRF private key");
  return pointCoordinates(Point.BASE.multiply(secret));
}

export function publicKeyHash(publicKey) {
  return keccak256(abiCoder.encode(["uint256[2]"], [publicKey]));
}

export function serviceKeyHash(publicKey) {
  return keccak256(
    abiCoder.encode(["bytes32", "uint256[2]"], [SERVICE_SCHEME_ID, publicKey]),
  );
}

export function addressForPublicKey(publicKey) {
  if (!Array.isArray(publicKey) || publicKey.length !== 2) {
    throw new Error("public key must contain x and y coordinates");
  }
  return ethereumAddress(Point.fromAffine({
    x: BigInt(publicKey[0]),
    y: BigInt(publicKey[1]),
  }));
}

export function outputForProof(proof) {
  if (!proof || !Array.isArray(proof.gamma) || proof.gamma.length !== 2) {
    throw new Error("proof gamma must contain x and y coordinates");
  }
  const gamma = Point.fromAffine({ x: BigInt(proof.gamma[0]), y: BigInt(proof.gamma[1]) });
  return hashBig(concat([word(3n), pointBytes(gamma)]));
}

export function generateProof({ privateKey, actualSeed, preSeed, nonce }) {
  const secret = BigInt(privateKey);
  const seed = BigInt(actualSeed);
  const wireSeed = BigInt(preSeed);
  if (secret <= 0n || secret >= GROUP_ORDER) throw new Error("invalid VRF private key");
  if (seed < 0n || seed >= 1n << 256n) throw new Error("actual seed is not uint256");
  if (wireSeed < 0n || wireSeed >= 1n << 256n) throw new Error("pre-seed is not uint256");

  const publicKeyPoint = Point.BASE.multiply(secret);
  const hash = hashToCurve(publicKeyPoint, seed);
  const gamma = hash.multiply(secret);

  for (let attempt = 0n; ; attempt += 1n) {
    const proofNonce = nonce === undefined
      ? deterministicScalar(secret, seed, attempt)
      : BigInt(nonce);
    if (proofNonce <= 0n || proofNonce >= GROUP_ORDER) {
      if (nonce !== undefined) throw new Error("invalid proof nonce");
      continue;
    }

    const u = Point.BASE.multiply(proofNonce);
    const uWitness = ethereumAddress(u);
    const v = hash.multiply(proofNonce);
    const c = scalarFromCurvePoints(hash, publicKeyPoint, gamma, uWitness, v);
    const s = mod(proofNonce - mod(c * secret, GROUP_ORDER), GROUP_ORDER);
    if (c === 0n || s === 0n) {
      if (nonce !== undefined) throw new Error("deterministic nonce produced a zero proof scalar");
      continue;
    }

    const cGammaWitness = gamma.multiply(mod(c, GROUP_ORDER));
    const sHashWitness = hash.multiply(s);
    const [cGammaX] = pointCoordinates(cGammaWitness);
    const [sHashX] = pointCoordinates(sHashWitness);
    if (cGammaX === sHashX) {
      if (nonce !== undefined) throw new Error("deterministic nonce produced equal witnesses");
      continue;
    }
    const [, , z] = projectiveECAdd(cGammaWitness, sHashWitness);
    const zInv = modInverse(z, FIELD_SIZE);
    const output = hashBig(concat([word(3n), pointBytes(gamma)]));

    return {
      proof: {
        pk: pointCoordinates(publicKeyPoint),
        gamma: pointCoordinates(gamma),
        c,
        s,
        seed: wireSeed,
        uWitness,
        cGammaWitness: pointCoordinates(cGammaWitness),
        sHashWitness: pointCoordinates(sHashWitness),
        zInv,
      },
      output,
      publicKey: pointCoordinates(publicKeyPoint),
      keyHash: publicKeyHash(pointCoordinates(publicKeyPoint)),
      serviceKeyHash: serviceKeyHash(pointCoordinates(publicKeyPoint)),
    };
  }
}

export const internals = Object.freeze({
  FIELD_SIZE,
  GROUP_ORDER,
  SERVICE_SCHEME_ID,
  hashToCurve,
  projectiveECAdd,
});

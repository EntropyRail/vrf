import { AbiCoder, Interface, getAddress, id, keccak256, toBeHex, toQuantity } from "ethers";
import { normalizeRpcUrls } from "./rpc-policy.mjs";
import { rpcProvider } from "./rpc.mjs";

export const COMPACT_FIELDS = Object.freeze([
  ["address", "consumer"], ["address", "verifier"], ["bytes32", "verifierCodeHash"],
  ["address", "fulfiller"], ["address", "payee"], ["bytes32", "keyHash"],
  ["uint256", "subscriptionId"], ["uint256", "preSeed"], ["uint256", "reservedPayment"],
  ["uint256", "randomness"], ["uint96", "minimumFeeWei"], ["uint64", "requestBlock"],
  ["uint64", "expiresAtBlock"], ["uint64", "maxGasPriceWei"], ["uint32", "verificationGasLimit"],
  ["uint32", "proofDataLength"], ["uint32", "callbackGasLimit"], ["uint32", "numWords"],
  ["uint32", "callbackAttempts"], ["uint32", "fulfillmentOverheadGas"], ["uint16", "confirmations"],
  ["uint16", "premiumBps"], ["uint16", "operatorPremiumShareBps"], ["uint8", "status"],
  ["bool", "sponsored"], ["bool", "waiveMinimumFee"], ["bool", "callbackSucceeded"],
].map(Object.freeze));
export const COMPACT_REQUEST_TYPE = `tuple(${COMPACT_FIELDS.map(f => f.join(" ")).join(",")})`;
export const COMPACT_ABI = [
  `event CompactRequestState(bytes32 indexed keyHash,uint256 indexed requestId,address indexed consumer,${COMPACT_REQUEST_TYPE} request)`,
  "function commitments(uint256 requestId) view returns(bytes32)",
  `function getRequest(${COMPACT_REQUEST_TYPE} witness) view returns(${COMPACT_REQUEST_TYPE})`,
  `function requestSeed(${COMPACT_REQUEST_TYPE} witness) view returns(uint256)`,
  `function fulfillRandomWords(${COMPACT_REQUEST_TYPE} witness,bytes proofData) returns(uint256,bool,uint256)`,
  `function retryCallback(${COMPACT_REQUEST_TYPE} witness) returns(bool)`,
  `function expireRequest(${COMPACT_REQUEST_TYPE} witness)`,
  `function pruneRequest(${COMPACT_REQUEST_TYPE} witness)`,
];
const iface = new Interface(COMPACT_ABI);
const coder = AbiCoder.defaultAbiCoder();
const DOMAIN = id("ROBINHOOD_VRF_COMPACT_REQUEST_V3");
const mutable = new Set(["status", "randomness", "callbackAttempts", "callbackSucceeded"]);
const PROOF_TYPE = "tuple(uint256[2] pk,uint256[2] gamma,uint256 c,uint256 s,uint256 seed,address uWitness,uint256[2] cGammaWitness,uint256[2] sHashWitness,uint256 zInv)";

export function normalizeCompactWitness(value) {
  if (typeof value?.toObject === "function") value = value.toObject();
  if (!value || Array.isArray(value) || typeof value !== "object"
      || Object.keys(value).sort().join(",") !== COMPACT_FIELDS.map(f => f[1]).sort().join(",")) {
    throw new Error("compact witness must contain exactly 27 named fields");
  }
  return Object.fromEntries(COMPACT_FIELDS.map(([type, name]) => {
    const input = value[name];
    if (type === "address") return [name, getAddress(input).toLowerCase()];
    if (type === "bytes32") {
      if (typeof input !== "string" || !/^0x[0-9a-f]{64}$/i.test(input)) throw new Error(`invalid ${name}`);
      return [name, input.toLowerCase()];
    }
    if (type === "bool") {
      if (typeof input !== "boolean") throw new Error(`invalid ${name}`);
      return [name, input];
    }
    if ((typeof input !== "bigint" && typeof input !== "number" && typeof input !== "string")
        || (typeof input === "number" && !Number.isSafeInteger(input))
        || !/^(0|[1-9][0-9]*)$/.test(String(input))) throw new Error(`invalid ${name}`);
    const result = BigInt(input);
    if (result >= 1n << BigInt(type.slice(4))) throw new Error(`out of range ${name}`);
    return [name, result];
  }));
}

export function serializeCompactWitness(value) {
  return Object.fromEntries(Object.entries(normalizeCompactWitness(value)).map(([k, v]) => [k, typeof v === "bigint" ? String(v) : v]));
}
export function compactRequestId(value) {
  return BigInt(keccak256(coder.encode(["uint256"], [normalizeCompactWitness(value).preSeed])));
}
export function compactCommitment(value, chainId, coordinatorAddress) {
  return keccak256(coder.encode(["bytes32", "uint256", "address", COMPACT_REQUEST_TYPE],
    [DOMAIN, chainId, coordinatorAddress, normalizeCompactWitness(value)]));
}
const fingerprint = value => JSON.stringify(serializeCompactWitness(value));

export function validateCompactTransitions(values) {
  if (!values.length) throw new Error("missing compact request creation event");
  const states = values.map(normalizeCompactWitness);
  const first = states[0];
  if (first.status !== 1n || first.randomness !== 0n || first.callbackAttempts !== 0n || first.callbackSucceeded) {
    throw new Error("missing or invalid compact request creation event");
  }
  for (let i = 1; i < states.length; i++) {
    const previous = states[i - 1], next = states[i];
    if (COMPACT_FIELDS.some(([, name]) => !mutable.has(name) && next[name] !== first[name])) {
      throw new Error("compact transition changed immutable fields");
    }
    const fulfilled = previous.status === 1n && next.status === 2n && next.callbackAttempts === 1n;
    const expired = previous.status === 1n && next.status === 3n && next.callbackAttempts === 0n
      && next.randomness === 0n && !next.callbackSucceeded;
    const retried = previous.status === 2n && !previous.callbackSucceeded && next.status === 2n
      && next.randomness === previous.randomness && next.callbackAttempts === previous.callbackAttempts + 1n;
    if (!fulfilled && !expired && !retried) throw new Error("missing or invalid compact state transition");
  }
  return states.at(-1);
}

async function withProviders(options, run) {
  if (options.providers && options.rpcUrls) throw new Error("supply providers OR rpcUrls");
  // Injected providers are for integrations/tests; the caller must independently
  // establish their origins. URL-based production callers enforce distinct origins.
  const owned = !options.providers;
  const providers = options.providers ?? normalizeRpcUrls(options.rpcUrls, {
    minimum: 2, label: "compact protocol", allowSharedOrigin: options.allowSharedOrigin ?? false,
  }).map(url => rpcProvider(url));
  if (providers.length < 2 || new Set(providers).size !== providers.length) throw new Error("compact protocol requires two distinct providers");
  try { return await run(providers); }
  finally { if (owned) providers.forEach(p => p.destroy()); }
}

async function anchorFor(providers, chainId) {
  const heads = await Promise.all(providers.map(async p => {
    if (BigInt(await p.send("eth_chainId", [])) !== BigInt(chainId)) throw new Error("compact RPC chainId mismatch");
    const height = Number(BigInt(await p.send("eth_blockNumber", [])));
    if (!Number.isSafeInteger(height) || height < 0) throw new Error("invalid compact RPC height");
    return height;
  }));
  const number = Math.min(...heads), tag = toQuantity(number);
  const blocks = await Promise.all(providers.map(p => p.send("eth_getBlockByNumber", [tag, false])));
  const hash = blocks[0]?.hash;
  if (!/^0x[0-9a-f]{64}$/i.test(hash ?? "") || blocks.some(b => b?.hash !== hash || Number(BigInt(b.number)) !== number)) {
    throw new Error("compact RPC anchor disagreement");
  }
  return { number, tag, hash };
}
async function assertAnchor(providers, anchor) {
  const blocks = await Promise.all(providers.map(p => p.send("eth_getBlockByNumber", [anchor.tag, false])));
  if (blocks.some(b => b?.hash !== anchor.hash)) throw new Error("compact anchor changed during read; retry after reorg");
}
async function view(provider, address, anchor, method, args) {
  const raw = await provider.send("eth_call", [{ to: address, data: iface.encodeFunctionData(method, args) }, anchor.tag]);
  return iface.decodeFunctionResult(method, raw)[0];
}
async function authenticatedState(providers, options, anchor, witness) {
  const request = normalizeCompactWitness(witness);
  const requestId = compactRequestId(request);
  if (requestId !== BigInt(options.requestId)) throw new Error("compact requestId mismatch");
  if (options.keyHash && request.keyHash !== options.keyHash.toLowerCase()) throw new Error("compact prover key mismatch");
  const commitment = compactCommitment(request, options.chainId, options.coordinatorAddress);
  const committed = await Promise.all(providers.map(p => view(p, options.coordinatorAddress, anchor, "commitments", [requestId])));
  if (committed.some(v => v !== commitment)) throw new Error("compact commitment mismatch: stale/missing witness, pruned request or RPC disagreement");
  let actualSeed;
  if (options.includeSeed) {
    if (request.status !== 1n) throw new Error("compact request is not pending");
    const seeds = await Promise.all(providers.map(p => view(p, options.coordinatorAddress, anchor, "requestSeed", [request])));
    if (seeds.some(v => v !== seeds[0])) throw new Error("compact canonical seed disagreement");
    actualSeed = seeds[0];
  }
  return { request, requestId, commitment, actualSeed, anchor };
}

// For an isolated prover: independently authenticate the supplied witness on at
// least two RPCs at one block/hash, and derive the seed ONLY via the coordinator.
export async function verifyCompactWitnessConsensus(options) {
  return withProviders(options, async providers => {
    const anchor = await anchorFor(providers, options.chainId);
    const result = await authenticatedState(providers, options, anchor, options.witness);
    await assertAnchor(providers, anchor);
    return result;
  });
}

// Stateless recovery from a trusted deployment block. No missing-history fallback.
// This is a bounded-request SDK, not a production all-requests indexer/daemon.
export async function recoverCompactRequest(options) {
  return withProviders(options, async providers => {
    const anchor = await anchorFor(providers, options.chainId);
    const start = options.fromBlock;
    if (!Number.isSafeInteger(start) || start < 0 || start > anchor.number) throw new Error("invalid compact deployment/fromBlock");
    const histories = await Promise.all(providers.map(async p => {
      const events = [];
      const topic = iface.getEvent("CompactRequestState").topicHash;
      for (let from = start; from <= anchor.number; from += 2_000) {
        const logs = await p.send("eth_getLogs", [{ address: options.coordinatorAddress,
          fromBlock: toQuantity(from), toBlock: toQuantity(Math.min(from + 1_999, anchor.number)),
          topics: [topic, null, toBeHex(options.requestId, 32)],
        }]);
        for (const log of logs) {
          const block = Number(BigInt(log.blockNumber));
          const index = Number(BigInt(log.logIndex));
          if (log.removed || log.address.toLowerCase() !== getAddress(options.coordinatorAddress).toLowerCase()
              || block < from || block > Math.min(from + 1_999, anchor.number)
              || !Number.isSafeInteger(block) || !Number.isSafeInteger(index) || index < 0) throw new Error("invalid compact event location");
          const parsed = iface.parseLog(log).args;
          const witness = normalizeCompactWitness(parsed.request);
          if (BigInt(parsed.requestId) !== BigInt(options.requestId) || compactRequestId(witness) !== BigInt(options.requestId)
              || parsed.consumer.toLowerCase() !== witness.consumer || parsed.keyHash.toLowerCase() !== witness.keyHash) {
            throw new Error("compact event identity mismatch");
          }
          const canonical = iface.encodeEventLog(iface.getEvent("CompactRequestState"), [parsed.keyHash, parsed.requestId, parsed.consumer, witness]);
          if (canonical.data !== log.data || JSON.stringify(canonical.topics) !== JSON.stringify(log.topics)) throw new Error("noncanonical compact event");
          events.push({ block, index, blockHash: log.blockHash, transactionHash: log.transactionHash, witness });
        }
      }
      events.sort((a, b) => a.block - b.block || a.index - b.index);
      if (events.some((e, i) => i > 0 && e.block === events[i - 1].block && e.index === events[i - 1].index)) throw new Error("duplicate compact event");
      validateCompactTransitions(events.map(e => e.witness));
      return events;
    }));
    const describe = events => JSON.stringify(events.map(e => ({ ...e, witness: fingerprint(e.witness) })));
    if (histories.some(h => describe(h) !== describe(histories[0]))) throw new Error("compact event history disagreement");
    const result = await authenticatedState(providers, options, anchor, histories[0].at(-1).witness);
    await assertAnchor(providers, anchor);
    return { ...result, transitionCount: histories[0].length };
  });
}

// Read-only preparation and simulation. The caller MUST use the existing durable
// nonce journal/lease and spending limits to sign/broadcast, then recover fresh
// state from the receipt/history. No keys or nonce state are managed here.
export async function prepareCompactTransaction(options) {
  const action = options.action ?? "fulfillRandomWords";
  if (!["fulfillRandomWords", "retryCallback", "expireRequest", "pruneRequest"].includes(action)) throw new Error("unsupported compact action");
  return withProviders(options, async providers => {
    const scoped = { ...options, rpcUrls: undefined, providers, includeSeed: action === "fulfillRandomWords" };
    const recovered = await recoverCompactRequest(scoped);
    let proofData;
    if (action === "fulfillRandomWords") {
      if (options.proofProvider?.mode === "threshold-bls") throw new Error("compact remote threshold nodes require a witness-aware resolver; not integrated");
      if (getAddress(options.from).toLowerCase() !== recovered.request.fulfiller) throw new Error("compact sender is not the pinned fulfiller");
      const result = await options.proofProvider.prove({ actualSeed: recovered.actualSeed, preSeed: recovered.request.preSeed,
        requestId: recovered.requestId, coordinator: options.coordinatorAddress, chainId: options.chainId,
        compactWitness: serializeCompactWitness(recovered.request),
      });
      proofData = result.proofData ?? coder.encode([PROOF_TYPE], [result.proof]);
    }
    const gasPrice = BigInt(options.gasPriceWei), gasLimit = BigInt(options.gasLimit ?? 3_000_000);
    if (gasPrice <= 0n || gasLimit <= 0n || (action === "fulfillRandomWords" && gasPrice > recovered.request.maxGasPriceWei)) throw new Error("invalid compact transaction gas bounds");
    const fresh = await verifyCompactWitnessConsensus({ ...scoped, witness: recovered.request });
    const data = iface.encodeFunctionData(action, action === "fulfillRandomWords" ? [fresh.request, proofData] : [fresh.request]);
    const transaction = { to: getAddress(options.coordinatorAddress), from: getAddress(options.from), data,
      gasPrice, gasLimit, chainId: BigInt(options.chainId) };
    const simulations = await Promise.all(providers.map(p => p.send("eth_call", [{ to: transaction.to, from: transaction.from,
      data, gasPrice: toQuantity(gasPrice), gas: toQuantity(gasLimit) }, fresh.anchor.tag])));
    if (simulations.some(value => value !== simulations[0])) throw new Error("compact simulation disagreement");
    await assertAnchor(providers, fresh.anchor);
    return { transaction, snapshot: fresh, simulation: simulations[0] };
  });
}

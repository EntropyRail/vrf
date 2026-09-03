// V3-only confirmed event ingestion. Never interpret V2 events as V3 witnesses.
import { Contract, Interface, toQuantity } from "ethers";
import { COMPACT_ABI, normalizeCompactWitness, serializeCompactWitness, compactRequestId,
  compactCommitment, recoverCompactRequest, prepareCompactTransaction } from "./compact-protocol.mjs";
import { archiveDecision } from "./archiver.mjs";
import { internals as operator } from "./cli.mjs";

const iface = new Interface(COMPACT_ABI);
const json = v => JSON.stringify(v, (_, x) => typeof x === "bigint" ? String(x) : x);
function equal(values, label) {
  if (!values.length || values.some(v => json(v) !== json(values[0]))) throw new Error(`CompactRpcDisagreement:${label}`);
  return values[0];
}
export async function compactHead(providers, chainId) {
  if (providers.length < 2 || new Set(providers).size !== providers.length) throw new Error("two distinct RPCs required");
  const heads = await Promise.all(providers.map(async p => {
    if (BigInt(await p.send("eth_chainId", [])) !== BigInt(chainId)) throw new Error("compact chain mismatch");
    return Number(BigInt(await p.send("eth_blockNumber", [])));
  }));
  if (heads.some(h => !Number.isSafeInteger(h)) || Math.max(...heads) - Math.min(...heads) > 32) throw new Error("compact RPC head skew");
  return Math.min(...heads) - 2;
}
export async function compactEvents({ providers, manifest, fromBlock, toBlock }) {
  if (providers.length < 2 || new Set(providers).size !== providers.length) throw new Error("two distinct RPCs required");
  if (!Number.isSafeInteger(fromBlock) || !Number.isSafeInteger(toBlock) || fromBlock < 0
      || toBlock < fromBlock || toBlock - fromBlock >= 2000) throw new Error("invalid compact scan range");
  const address = manifest.contracts.coordinator.address.toLowerCase();
  const tag = toQuantity(toBlock);
  const observations = await Promise.all(providers.map(async p => {
    const boundary = await p.send("eth_getBlockByNumber", [tag, false]);
    if (!boundary?.hash || Number(BigInt(boundary.number)) !== toBlock) throw new Error("missing compact scan anchor");
    const context = new Contract(address, ["function contextBlockNumber() view returns(uint256)"], p);
    if (await context.contextBlockNumber({ blockTag: toBlock }) !== BigInt(toBlock)) throw new Error("compact L2 context mismatch");
    const logs = await p.send("eth_getLogs", [{ address, fromBlock: toQuantity(fromBlock), toBlock: tag,
      topics: [iface.getEvent("CompactRequestState").topicHash, manifest.keyHash] }]);
    const events = logs.map(log => {
      const block = Number(BigInt(log.blockNumber)), index = Number(BigInt(log.logIndex));
      if (log.removed || log.address.toLowerCase() !== address || block < fromBlock || block > toBlock
          || !Number.isSafeInteger(block) || !Number.isSafeInteger(index) || index < 0) throw new Error("invalid compact scan log");
      const args = iface.parseLog(log).args, request = normalizeCompactWitness(args.request);
      const canonical = iface.encodeEventLog(iface.getEvent("CompactRequestState"), [args.keyHash, args.requestId, args.consumer, request]);
      if (request.keyHash !== manifest.keyHash.toLowerCase() || args.keyHash.toLowerCase() !== request.keyHash
          || args.consumer.toLowerCase() !== request.consumer || compactRequestId(request) !== args.requestId
          || json(canonical.topics) !== json(log.topics) || canonical.data !== log.data) throw new Error("invalid compact scan witness");
      return { requestId: String(args.requestId), preSeed: String(request.preSeed), requestBlock: String(request.requestBlock),
        expiresAtBlock: String(request.expiresAtBlock), eventBlockNumber: block, index, eventBlockHash: log.blockHash,
        transactionHash: log.transactionHash, witness: serializeCompactWitness(request) };
    }).sort((a, b) => a.eventBlockNumber - b.eventBlockNumber || a.index - b.index);
    if (events.some((e, i) => i && e.eventBlockNumber === events[i - 1].eventBlockNumber && e.index === events[i - 1].index)) throw new Error("duplicate compact scan log");
    const after = await p.send("eth_getBlockByNumber", [tag, false]);
    if (after?.hash !== boundary.hash) throw new Error("compact scan reorg");
    return { boundary: boundary.hash, events };
  }));
  return equal(observations, "scan events and boundary").events;
}

// Append-only evidence, keyed by fork identity. A cached witness is NEVER used as
// proof authority: recoverCompactRequest still checks full RPC history + commitment.
export async function initializeWitnessStore(store) {
  await store.pool.query(`CREATE TABLE IF NOT EXISTS vrf_compact_witness_events (
    chain_id numeric(78,0) NOT NULL, coordinator varchar(42) NOT NULL,
    block_hash varchar(66) NOT NULL, log_index bigint NOT NULL,
    request_id numeric(78,0) NOT NULL, event_block bigint NOT NULL,
    transaction_hash varchar(66) NOT NULL, commitment varchar(66) NOT NULL,
    witness jsonb NOT NULL, observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(chain_id, coordinator, block_hash, log_index))`);
}
export async function saveWitnessEvents(store, manifest, events) {
  for (const e of events) await store.pool.query(`INSERT INTO vrf_compact_witness_events
    (chain_id,coordinator,block_hash,log_index,request_id,event_block,transaction_hash,commitment,witness)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT DO NOTHING`,
  [String(manifest.chainId), manifest.contracts.coordinator.address.toLowerCase(), e.eventBlockHash, e.index,
    e.requestId, e.eventBlockNumber, e.transactionHash,
    compactCommitment(e.witness, manifest.chainId, manifest.contracts.coordinator.address), json(e.witness)]);
}
export async function compactScan({ providers, manifest, store, instanceId }) {
  const head = await compactHead(providers, manifest.chainId);
  const range = await store.claimScan({ instanceId, latest: head, rangeSize: 2000, reorgLookback: 32, leaseSeconds: 60 });
  if (!range) return { head, events: 0 };
  try {
    const events = await compactEvents({ providers, manifest, ...range });
    await saveWitnessEvents(store, manifest, events);
    await store.commitScan({ instanceId, ...range,
      requested: events.filter(e => e.witness.status === "1"),
      finalizedRequestIds: events.filter(e => e.witness.status !== "1").map(e => e.requestId) });
    return { head, events: events.length, reviewRequestIds: events.filter(e =>
      e.witness.status !== "1" && !e.witness.callbackSucceeded).map(e => e.requestId) };
  } catch (error) { await store.releaseScan(instanceId); throw error; }
}
export async function fulfillCompactClaim({ providers, manifest, pending, from, proofProvider, gasPriceWei, send }) {
  const options = { providers, chainId: manifest.chainId, coordinatorAddress: manifest.contracts.coordinator.address,
    keyHash: manifest.keyHash, requestId: pending.requestId, fromBlock: pending.eventBlockNumber };
  const recovered = await recoverCompactRequest(options);
  if (recovered.request.status !== 1n) return { finalized: true, callbackSucceeded: recovered.request.callbackSucceeded };
  const context = new Contract(options.coordinatorAddress, ["function contextBlockNumber() view returns(uint256)"], providers[0]);
  const height = await context.contextBlockNumber({ blockTag: recovered.anchor.number });
  const action = height > recovered.request.expiresAtBlock ? "expireRequest" : "fulfillRandomWords";
  const prepared = await prepareCompactTransaction({ ...options, action, from, proofProvider, gasPriceWei });
  const receipt = await send({ transaction: prepared.transaction, requestId: pending.requestId,
    maxGasPriceWei: recovered.request.maxGasPriceWei, kind: `compact-${action}` });
  if (receipt.status !== 1) throw new Error("compact transaction reverted");
  const final = await recoverCompactRequest(options);
  if (final.request.status === 1n) throw new Error("compact transaction not finalized across RPCs");
  return { finalized: true, callbackSucceeded: final.request.callbackSucceeded, transactionHash: receipt.hash };
}

export async function compactArchiveCycle({ providers, manifest, budget, send, saveEvents = async () => {} }) {
  const head = await compactHead(providers, manifest.chainId);
  const fromBlock = Math.max(manifest.contracts.coordinator.blockNumber, head - 511);
  if (head < fromBlock) return { head, pending: 0, archived: 0, missedWindow: 0 };
  const events = await compactEvents({ providers, manifest, fromBlock, toBlock: head });
  await saveEvents(events);
  const stats = { head, pending: 0, archived: 0, missedWindow: 0 };
  for (const event of events.filter(e => e.witness.status === "1")) {
    const recovered = await recoverCompactRequest({ providers, chainId: manifest.chainId,
      coordinatorAddress: manifest.contracts.coordinator.address, keyHash: manifest.keyHash,
      requestId: event.requestId, fromBlock: event.eventBlockNumber });
    if (recovered.request.status !== 1n) continue;
    stats.pending++;
    const hashes = await Promise.all(providers.map(p => new Contract(manifest.contracts.blockhashStore.address,
      operator.BLOCKHASH_STORE_ABI, p).blockhashes(recovered.request.requestBlock)));
    const freshHead = await compactHead(providers, manifest.chainId) + 2;
    const action = archiveDecision(recovered.request, equal(hashes, "archive hash"), freshHead, 32);
    if (action === "missed-window") { budget.recordMissed(event.requestId); stats.missedWindow++; }
    if (action === "archive") {
      const archive = new Contract(manifest.contracts.blockhashStore.address, operator.BLOCKHASH_STORE_ABI);
      const receipt = await send({ transaction: await archive.store.populateTransaction(recovered.request.requestBlock),
        requestId: event.requestId, maxGasPriceWei: recovered.request.maxGasPriceWei, kind: "compact-archive" });
      if (receipt.status !== 1) throw new Error("compact archive reverted");
      stats.archived++;
    }
  }
  budget.checkpoint(head);
  return stats;
}

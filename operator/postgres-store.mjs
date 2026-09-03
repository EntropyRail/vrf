import pg from "pg";
import { errorDetails } from "./errors.mjs";

const { Pool } = pg;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS vrf_operator_instances (
  instance_id text PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  heartbeat_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS vrf_operator_scan_state (
  chain_id numeric(78, 0) NOT NULL,
  coordinator varchar(42) NOT NULL,
  key_hash varchar(66) NOT NULL,
  deployment_block bigint NOT NULL,
  next_block bigint NOT NULL,
  lease_owner text,
  lease_expires_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, coordinator, key_hash)
);

CREATE TABLE IF NOT EXISTS vrf_operator_requests (
  chain_id numeric(78, 0) NOT NULL,
  coordinator varchar(42) NOT NULL,
  key_hash varchar(66) NOT NULL,
  request_id numeric(78, 0) NOT NULL,
  pre_seed numeric(78, 0) NOT NULL,
  request_block bigint NOT NULL,
  expires_at_block bigint NOT NULL,
  event_block_number bigint NOT NULL,
  event_block_hash varchar(66) NOT NULL,
  request_tx_hash varchar(66) NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_owner text,
  lease_expires_at timestamptz,
  last_error text,
  orphaned boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (chain_id, coordinator, key_hash, request_id)
);

CREATE INDEX IF NOT EXISTS vrf_operator_requests_claim_idx
  ON vrf_operator_requests (
    chain_id, coordinator, key_hash, next_attempt_at, request_block
  );

CREATE TABLE IF NOT EXISTS vrf_operator_transactions (
  transaction_hash varchar(66) PRIMARY KEY,
  chain_id numeric(78, 0) NOT NULL,
  relayer varchar(42) NOT NULL,
  nonce bigint NOT NULL,
  request_id numeric(78, 0),
  transaction_kind text NOT NULL,
  gas_price_wei numeric(78, 0) NOT NULL,
  instance_id text NOT NULL,
  status text NOT NULL DEFAULT 'broadcast',
  block_number bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS vrf_operator_transactions_nonce_idx
  ON vrf_operator_transactions (chain_id, relayer, nonce);

ALTER TABLE vrf_operator_requests
  ADD COLUMN IF NOT EXISTS orphaned boolean NOT NULL DEFAULT false;
`;

function safeBlockNumber(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} is outside the JavaScript safe integer range`);
  }
  return parsed;
}

function normalizeIdentity(identity) {
  return {
    chainId: String(identity.chainId),
    coordinator: String(identity.coordinator).toLowerCase(),
    keyHash: String(identity.keyHash).toLowerCase(),
    deploymentBlock: safeBlockNumber(identity.deploymentBlock, "deploymentBlock"),
  };
}

export class PostgresOperatorStore {
  constructor(pool, identity) {
    this.pool = pool;
    this.identity = normalizeIdentity(identity);
  }

  static async connect({ databaseUrl, identity, maximumConnections = 10 }) {
    if (!databaseUrl) throw new Error("databaseUrl is required");
    const pool = new Pool({
      connectionString: databaseUrl,
      max: maximumConnections,
      application_name: "proof-vrf-operator",
      connectionTimeoutMillis: 5_000,
    });
    pool.on("error", (error) => {
      process.stderr.write(`${JSON.stringify({ status: "postgres-idle-connection-error", error: errorDetails(error) })}\n`);
    });
    const store = new PostgresOperatorStore(pool, identity);
    try {
      await store.migrate();
      await store.initialize();
    } catch (error) {
      await pool.end();
      throw error;
    }
    return store;
  }

  async migrate() {
    await this.pool.query(SCHEMA);
  }

  async initialize() {
    const { chainId, coordinator, keyHash, deploymentBlock } = this.identity;
    await this.pool.query(
      `INSERT INTO vrf_operator_scan_state
         (chain_id, coordinator, key_hash, deployment_block, next_block)
       VALUES ($1, $2, $3, $4, $4)
       ON CONFLICT (chain_id, coordinator, key_hash) DO NOTHING`,
      [chainId, coordinator, keyHash, deploymentBlock],
    );
    const result = await this.pool.query(
      `SELECT deployment_block
         FROM vrf_operator_scan_state
        WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3`,
      [chainId, coordinator, keyHash],
    );
    if (result.rowCount !== 1) throw new Error("failed to initialize PostgreSQL scan state");
    if (safeBlockNumber(result.rows[0].deployment_block, "stored deployment block") !== deploymentBlock) {
      throw new Error("PostgreSQL deployment block does not match this operator");
    }
  }

  async heartbeat(instanceId, metadata) {
    await this.pool.query(
      `INSERT INTO vrf_operator_instances (instance_id, heartbeat_at, metadata)
       VALUES ($1, now(), $2::jsonb)
       ON CONFLICT (instance_id) DO UPDATE
         SET heartbeat_at = now(), metadata = EXCLUDED.metadata`,
      [instanceId, JSON.stringify(metadata)],
    );
  }

  async claimScan({ instanceId, latest, rangeSize, reorgLookback, leaseSeconds }) {
    const { chainId, coordinator, keyHash, deploymentBlock } = this.identity;
    const result = await this.pool.query(
      `UPDATE vrf_operator_scan_state
          SET lease_owner = $4,
              lease_expires_at = now() + make_interval(secs => $6::int),
              updated_at = now()
        WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
          AND next_block <= $5::bigint
          AND (lease_owner IS NULL OR lease_expires_at < now() OR lease_owner = $4)
      RETURNING next_block`,
      [chainId, coordinator, keyHash, instanceId, latest, leaseSeconds],
    );
    if (result.rowCount === 0) return null;
    const cursor = safeBlockNumber(result.rows[0].next_block, "scan cursor");
    const fromBlock = Math.max(
      deploymentBlock,
      Math.min(cursor, latest) - reorgLookback,
    );
    return {
      fromBlock,
      toBlock: Math.min(latest, fromBlock + rangeSize - 1),
    };
  }

  async commitScan({ instanceId, fromBlock, toBlock, requested, finalizedRequestIds }) {
    const { chainId, coordinator, keyHash } = this.identity;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const state = await client.query(
        `SELECT next_block, lease_owner
           FROM vrf_operator_scan_state
          WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
          FOR UPDATE`,
        [chainId, coordinator, keyHash],
      );
      if (state.rowCount !== 1 || state.rows[0].lease_owner !== instanceId) {
        throw new Error("scan lease was lost before commit");
      }

      await client.query(
        `UPDATE vrf_operator_requests
            SET orphaned = true, updated_at = now()
          WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
            AND event_block_number >= $4`,
        [chainId, coordinator, keyHash, fromBlock],
      );

      for (const event of requested) {
        await client.query(
          `INSERT INTO vrf_operator_requests (
             chain_id, coordinator, key_hash, request_id, pre_seed,
             request_block, expires_at_block, event_block_number,
             event_block_hash, request_tx_hash
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           ON CONFLICT (chain_id, coordinator, key_hash, request_id) DO UPDATE SET
             pre_seed = EXCLUDED.pre_seed,
             request_block = EXCLUDED.request_block,
             expires_at_block = EXCLUDED.expires_at_block,
             event_block_number = EXCLUDED.event_block_number,
             event_block_hash = EXCLUDED.event_block_hash,
             request_tx_hash = EXCLUDED.request_tx_hash,
             orphaned = false,
             updated_at = now()`,
          [
            chainId,
            coordinator,
            keyHash,
            event.requestId,
            event.preSeed,
            event.requestBlock,
            event.expiresAtBlock,
            event.eventBlockNumber,
            event.eventBlockHash,
            event.transactionHash,
          ],
        );
      }

      if (finalizedRequestIds.length > 0) {
        await client.query(
          `DELETE FROM vrf_operator_requests
            WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
              AND request_id = ANY($4::numeric[])`,
          [chainId, coordinator, keyHash, finalizedRequestIds],
        );
      }


      await client.query(
        `DELETE FROM vrf_operator_requests
          WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
            AND orphaned = true
            AND (lease_owner IS NULL OR lease_expires_at < now())`,
        [chainId, coordinator, keyHash],
      );

      const storedCursor = safeBlockNumber(state.rows[0].next_block, "scan cursor");
      await client.query(
        `UPDATE vrf_operator_scan_state
            SET next_block = $4,
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = now()
          WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3`,
        [chainId, coordinator, keyHash, Math.max(storedCursor, toBlock + 1)],
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async releaseScan(instanceId) {
    const { chainId, coordinator, keyHash } = this.identity;
    await this.pool.query(
      `UPDATE vrf_operator_scan_state
          SET lease_owner = NULL, lease_expires_at = NULL, updated_at = now()
        WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
          AND lease_owner = $4`,
      [chainId, coordinator, keyHash, instanceId],
    );
  }

  async claimRequest({ instanceId, leaseSeconds }) {
    const { chainId, coordinator, keyHash } = this.identity;
    const result = await this.pool.query(
      `WITH candidate AS (
         SELECT request_id
           FROM vrf_operator_requests
          WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
            AND next_attempt_at <= now()
            AND orphaned = false
            AND (lease_owner IS NULL OR lease_expires_at < now())
          ORDER BY request_block, request_id
          LIMIT 1
          FOR UPDATE SKIP LOCKED
       )
       UPDATE vrf_operator_requests AS request
          SET lease_owner = $4,
              lease_expires_at = now() + make_interval(secs => $5::int),
              updated_at = now()
         FROM candidate
        WHERE request.chain_id = $1
          AND request.coordinator = $2
          AND request.key_hash = $3
          AND request.request_id = candidate.request_id
      RETURNING request.request_id, request.pre_seed, request.request_block,
                request.expires_at_block, request.event_block_number,
                request.event_block_hash, request.request_tx_hash, request.attempts`,
      [chainId, coordinator, keyHash, instanceId, leaseSeconds],
    );
    if (result.rowCount === 0) return null;
    const row = result.rows[0];
    return {
      requestId: row.request_id,
      preSeed: row.pre_seed,
      requestBlock: row.request_block,
      expiresAtBlock: row.expires_at_block,
      eventBlockNumber: safeBlockNumber(row.event_block_number, "event block"),
      eventBlockHash: row.event_block_hash,
      transactionHash: row.request_tx_hash,
      attempts: row.attempts,
    };
  }

  async completeRequest(requestId, instanceId) {
    const { chainId, coordinator, keyHash } = this.identity;
    await this.pool.query(
      `DELETE FROM vrf_operator_requests
        WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
          AND request_id = $4 AND lease_owner = $5`,
      [chainId, coordinator, keyHash, requestId, instanceId],
    );
  }

  async retryRequest(requestId, instanceId, error, retrySeconds) {
    const { chainId, coordinator, keyHash } = this.identity;
    await this.pool.query(
      `UPDATE vrf_operator_requests
          SET attempts = attempts + 1,
              next_attempt_at = now() + make_interval(secs => $6::int),
              lease_owner = NULL,
              lease_expires_at = NULL,
              last_error = left($5, 4000),
              updated_at = now()
        WHERE chain_id = $1 AND coordinator = $2 AND key_hash = $3
          AND request_id = $4 AND lease_owner = $7`,
      [chainId, coordinator, keyHash, requestId, String(error), retrySeconds, instanceId],
    );
  }

  async summary() {
    const { chainId, coordinator, keyHash } = this.identity;
    const result = await this.pool.query(
      `SELECT scan.next_block,
              count(request.request_id)::integer AS pending,
              min(request.request_block) AS oldest_request_block
         FROM vrf_operator_scan_state AS scan
         LEFT JOIN vrf_operator_requests AS request
           ON request.chain_id = scan.chain_id
          AND request.coordinator = scan.coordinator
          AND request.key_hash = scan.key_hash
        WHERE scan.chain_id = $1 AND scan.coordinator = $2 AND scan.key_hash = $3
        GROUP BY scan.next_block`,
      [chainId, coordinator, keyHash],
    );
    const row = result.rows[0];
    return {
      cursor: safeBlockNumber(row.next_block, "scan cursor"),
      pending: row.pending,
      oldestRequestBlock: row.oldest_request_block === null
        ? null
        : safeBlockNumber(row.oldest_request_block, "oldest request block"),
    };
  }

  async withRelayerNonceLock(relayer, operation) {
    const client = await this.pool.connect();
    const lockName = `proof-vrf:${this.identity.chainId}:${String(relayer).toLowerCase()}`;
    let locked = false;
    let lost = null;
    const onError = (error) => { lost = error; };
    client.on("error", onError);
    const assertHeld = async () => {
      if (lost) throw new Error("RelayerNonceLeaseLost", { cause: lost });
      try { await client.query("SELECT 1"); }
      catch (error) { lost = error; throw new Error("RelayerNonceLeaseLost", { cause: error }); }
      if (lost) throw new Error("RelayerNonceLeaseLost", { cause: lost });
    };
    try {
      const result = await client.query(
        "SELECT pg_try_advisory_lock(hashtextextended($1, 0)) AS locked",
        [lockName],
      );
      locked = result.rows[0].locked === true;
      if (!locked) throw new Error("RelayerNonceLeaseBusy");
      return await operation({ assertHeld, backendPid: client.processID });
    } finally {
      try {
        if (locked && !lost) {
          await client.query(
            "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
            [lockName],
          );
        }
      } catch (error) {
        lost = error;
      } finally {
        client.removeListener("error", onError);
        client.release(lost || undefined);
      }
    }
  }

  async recordBroadcast({
    transactionHash,
    relayer,
    nonce,
    requestId,
    transactionKind,
    gasPriceWei,
    instanceId,
  }) {
    await this.pool.query(
      `INSERT INTO vrf_operator_transactions (
         transaction_hash, chain_id, relayer, nonce, request_id,
         transaction_kind, gas_price_wei, instance_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (transaction_hash) DO NOTHING`,
      [
        transactionHash,
        this.identity.chainId,
        String(relayer).toLowerCase(),
        nonce,
        requestId,
        transactionKind,
        gasPriceWei,
        instanceId,
      ],
    );
  }

  async markMined(transactionHash, blockNumber) {
    await this.pool.query(
      `UPDATE vrf_operator_transactions
          SET status = 'mined', block_number = $2, updated_at = now()
        WHERE transaction_hash = $1`,
      [transactionHash, blockNumber],
    );
  }

  async listUnresolvedTransactions(relayer) {
    const result = await this.pool.query(
      `SELECT transaction_hash, nonce, request_id, transaction_kind, gas_price_wei
         FROM vrf_operator_transactions
        WHERE chain_id = $1 AND relayer = $2 AND status = 'broadcast'
        ORDER BY nonce, created_at`,
      [this.identity.chainId, String(relayer).toLowerCase()],
    );
    return result.rows.map((row) => ({
      transactionHash: row.transaction_hash,
      nonce: safeBlockNumber(row.nonce, "transaction nonce"),
      requestId: row.request_id,
      transactionKind: row.transaction_kind,
      gasPriceWei: row.gas_price_wei,
    }));
  }

  async resolveNonce({ relayer, nonce, status, minedTransactionHash, blockNumber }) {
    if (!["dropped", "consumed", "replaced"].includes(status)) {
      throw new Error("invalid transaction journal resolution status");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `UPDATE vrf_operator_transactions
            SET status = $4, updated_at = now()
          WHERE chain_id = $1 AND relayer = $2 AND nonce = $3 AND status = 'broadcast'`,
        [this.identity.chainId, String(relayer).toLowerCase(), nonce, status],
      );
      if (minedTransactionHash) {
        await client.query(
          `UPDATE vrf_operator_transactions
              SET status = 'mined', block_number = $2, updated_at = now()
            WHERE transaction_hash = $1`,
          [minedTransactionHash, blockNumber],
        );
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async close() {
    await this.pool.end();
  }
}

export const internals = Object.freeze({ SCHEMA, safeBlockNumber, normalizeIdentity });

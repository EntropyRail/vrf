# EntropyRail VRF

Independent, proof-based verifiable randomness infrastructure for Robinhood Chain.

[Website](https://entropyrail.com) · [Quickstart](docs/QUICKSTART.md) · [Testnet deployment](docs/DEPLOYMENTS.md) · [Security](SECURITY.md) · [X](https://x.com/EntropyRail)

> **Testnet / pre-audit software.** V3 has a recorded Robinhood testnet deployment and one successful end-to-end canary. The live V3 path uses a single ECVRF prover. Threshold DKG, resharing, and share signing are experimental; they are not an active V3 threshold network. No independent audit or completed 30-day soak is claimed. Do not use for production value.

## What it does

- **Verify results onchain:** secp256k1 ECVRF proofs bind a fixed public key and seed to a unique valid output. A prover can still withhold a result.
- **Reduce request storage:** V3 stores a full 256-bit commitment to the complete request witness. Fulfillment and lifecycle operations authenticate that witness before using it.
- **Recover callback failures:** store the verified result before callback delivery; permissionless retries reuse the same result without another service fee. Retry transaction gas still applies.
- **Make billing explicit:** prepaid subscriptions, consumer authorization, maximum-cost reservation, measured-gas settlement with configured overhead/fees, and sponsor-funded allowlists.
- **Recover operationally:** independent RPC checks, PostgreSQL request leases and nonce coordination, isolated mTLS proof generation, and timely block-hash archival.
- **Explore distributed operation:** executable 3-of-5 BLS DKG, encrypted shares, signed complaints, partial-signature validation, aggregation, and group-key-preserving resharing.

The cryptography builds on established constructions. This is not a new cryptographic primitive, a Chainlink service, or an official Robinhood product.

## Run locally

Use Node **22.13+ in the Node 22 LTS line** (see `.nvmrc`). No wallet or paid RPC is needed for the default local suite.

```bash
git clone https://github.com/EntropyRail/vrf.git
cd vrf
nvm use
npm ci
npm run compile
npm test
```

PostgreSQL and Robinhood-fork integration tests are opt-in and skip without their explicit configuration. See [testing](docs/TESTING.md). Running the local suite does not deploy contracts or start a live operator.

## Versions and integration

| Version | Role | Important boundary |
| --- | --- | --- |
| V1 | Legacy direct-funded prototype/router | Retained for reference and tests |
| V2 | Subscription and sponsorship coordinator | Stores expanded request state |
| V3 | Compact coordinator used by the recorded testnet canary | Requires authenticated event witnesses for lifecycle operations |

V3 preserves the consumer request and callback interface, but **is not a drop-in V2 replacement or an in-place upgrade**. It has a separate deployment and subscription balances. V2-style request queries, fulfillment, retry, expiry, and pruning must not be used against V3; see [the integration guide](docs/QUICKSTART.md).

The source includes `operator/compact-protocol.mjs` integration helpers. It is not a separately published npm SDK. The package remains `private: true` to prevent accidental npm publication; the repository source is MIT-licensed.

## Measured storage optimization

In the controlled local steady-state, single-word benchmark, request + fulfillment used **293,148 gas** in V3 versus **558,439** in the initial implementation and **376,218** in the preceding V2 optimization: reductions of **47.5%** and **22.1%**, respectively.

These measurements exclude L1 data fees. V3 increases calldata and makes callback retries and expiration more expensive. This is not a live fee quote, competitor comparison, or production SLA. See [methodology and tradeoffs](docs/GAS_OPTIMIZATION_ROUND3_2026-09-03.md) and [raw benchmark data](docs/evidence/gas-compact-v3-2026-09-03.json).

## Source map

- `contracts/`: coordinators, consumer interfaces, billing, block context, archival, governance, and verifiers.
- `operator/`: proof construction, compact witnesses, RPC policies, persistence, monitoring, and threshold protocols.
- `test/`: contract, cryptography, accounting, recovery, and integration tests.
- `scripts/`: explicit deployment and rehearsal tooling; never point these at a valuable network without review.
- `deploy/`: example service configuration, not the live infrastructure configuration.
- `docs/`: integration, protocol specifications, threat model, threshold runbook, and historical benchmark reports.

Start with [current status](docs/STATUS.md), [threat model](docs/THREAT_MODEL.md), and [threshold protocol](docs/THRESHOLD_PROTOCOL.md). Older Chinese design documents are retained as technical background; their historical deployment status is superseded by `docs/STATUS.md`.

## Security and license

Use [private vulnerability reporting](https://github.com/EntropyRail/vrf/security/advisories/new), not public issues, for exploitable findings. See [SECURITY.md](SECURITY.md). No response-time guarantee or bounty is promised.

MIT; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Vendored Chainlink and Randamu code retains its attribution and license notices. Source publication and explorer verification are not independent security audits.

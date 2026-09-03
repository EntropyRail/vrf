# Testing

Use Node 22 LTS (22.13 or newer), then `npm ci`, `npm run compile`, and `npm test` from the repository root. The active configuration is `hardhat.config.js` (Hardhat 3). There is no parent npm workspace requirement.

The default suite covers ECVRF verification, rejected forged proofs, request witnesses, accounting invariants, authorization, callback retries, threshold DKG/resharing, partial aggregation, RPC disagreement, and transaction-journal recovery. Test keys and repeated-byte vectors are synthetic: never fund or reuse them.

## Opt-in integration tests

Read `test/PostgresIntegration.test.cjs` before enabling database tests with `VRF_TEST_DATABASE_URL`. Use a dedicated disposable PostgreSQL database, not a shared production database. Process interruption and lock recovery tests may terminate their own child processes.

Robinhood fork tests require `VRF_RUN_ROBINHOOD_FORK=true` and optionally `ROBINHOOD_TESTNET_RPC_URL`; run `npm run test:robinhood-fork`. Transactions in the Hardhat fork remain local. RPC execution and fee behavior are not a substitute for a live Nitro-node test. Never place authenticated RPC URLs in reports or commits.

Gas benchmark tests use controlled local inputs and zero L1 data fees. Reproducing their execution gas does not reproduce a real user's live total bill.

Passing tests and skipped optional integration tests must be reported separately. This public snapshot does not add an automated CI/CD workflow; releases remain manual.

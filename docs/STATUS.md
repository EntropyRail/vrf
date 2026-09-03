# Current status — 2026-09-04

This page supersedes deployment-status statements in the historical design and gas reports.

| Component | Evidence / implemented scope | Not established |
| --- | --- | --- |
| V3 ECVRF coordinator | Recorded Robinhood testnet deployment, source verification, one successful end-to-end canary | Mainnet readiness, load/latency SLA, independent audit |
| Compact state | Full-domain-separated request commitment and checked event witnesses | Lower live total fees in every workload |
| Callback recovery | One stored result, permissionless retry, no second service fee | Free retry transaction gas |
| Operator recovery | Local tests for journals, leases, nonce recovery and RPC disagreement | Continuous active-active HA or arbitrary outage tolerance |
| Proof isolation | Separate relayer and mTLS prover | Actual HSM/enclave custody |
| Threshold | Executable 3-of-5 DKG/resharing/share-signing and BLS tests | Live V3 threshold resolver, five independent operators, specialist audit |
| Governance | Recorded 2-of-3 Safe and 12-hour timelock in testnet evidence | Independent key custody; recorded Safe keys were held on one local host |

Before external production use: independent contract/cryptography review, a completed 30-day soak, real fee calibration, independent governance/key custody, and broader recovery testing remain required. Source publication is not an approval to enable those paths.

## Public source provenance

This standalone repository was exported from the VRF subtree of local source revision `47d573d`. The full source revision is recorded in `source-provenance.json`. The recorded V3 deployment was made from source revision `35ba2cf0641487f45eb999a68879d439a25239bb` in the original private development repository.

The original monorepo history is intentionally not published. It includes unrelated applications and operational records. This initial public history contains only the reviewed standalone snapshot. Contract and operator source hashes are recorded in `source-provenance.json`; documentation, packaging, and example infrastructure configuration were adapted for standalone use. No claim is made that the new repository commit is the original deployment commit.

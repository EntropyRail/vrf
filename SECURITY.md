# Security policy

## Status

This is pre-audit, testnet software, not a production-approved service. A public repository, passing tests, explorer source verification, or one canary does not establish cryptographic security or operational availability.

The recorded V3 deployment uses one ECVRF prover. It can delay or withhold fulfillment. Threshold DKG, resharing, BLS verification, and multi-node share signing remain experimental. Hardware-backed proof-key custody, independent operator ceremonies, independent specialist audits, and a completed 30-day soak are not claimed.

Do not use this release for real-value gambling, lotteries, liquidations, settlement, or irreversible asset allocation. There is no supported mainnet release or security SLA.

## Report a vulnerability privately

Use GitHub's [Report a vulnerability](https://github.com/EntropyRail/vrf/security/advisories/new) form. If the private form is unavailable, do not post exploit details in public issues; use a non-sensitive issue to request a private reporting channel.

Include the affected commit, contract/version, reproduction, expected and actual behavior, impact, required privileges, and whether deployed funds or keys may be at risk. Never attach real private keys, wallet exports, authenticated RPC URLs, database credentials, or signing shares.

No bounty or response deadline is promised. Coordinate disclosure with maintainers where practical; do not test exploits against third-party contracts or infrastructure without permission.

## Priority areas

- Forged accepted proofs, biased accepted randomness, cross-request replay, or witness substitution.
- Unauthorized withdrawals, insolvency, sponsor quota bypass, or governance bypass.
- Nonce journal corruption, lost transaction ownership, and unrecoverable valid requests.
- Threshold share leakage, equivocation, invalid DKG/resharing transcripts, or group-key changes during resharing.

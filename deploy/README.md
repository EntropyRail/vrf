# Example service configuration

These are configuration templates, not live infrastructure settings. The original host inventory, SSH installer, credential files, certificates, wallets, and operational database are intentionally excluded.

For the standalone checkout, V3 templates expect `/opt/proof-vrf-v3/current` to point to a release whose root contains `operator/`, `contracts/`, and `package.json`. Legacy V2 templates use `/opt/proof-vrf/current`. Install runtime dependencies in that release with the pinned lockfile before using a template.

Addresses in the example private subnet `10.200.0.0/24` are illustrative. Replace them with an explicitly approved private-network configuration. Never expose the prover or database directly to the Internet. Mutual TLS and a separate proof-key custody boundary remain required; mTLS alone is not an HSM.

The templates reference systemd `LoadCredential` source paths. Provision those files separately with restricted permissions. Never commit real RPC URLs, relayer private keys, bearer tokens, proof-key passwords, or TLS private keys. Retain state/journals across service restarts; do not erase spending or transaction state to clear a health check.

A runtime manifest must be produced and verified by the deployment tooling. `docs/deployments/robinhood-testnet-v3.json` is a public evidence subset and deliberately cannot replace an operator manifest.

Review users, directories, permissions, credentials, firewall rules, independent RPC sources, and database availability before enabling any unit. No public template is an instruction to modify the existing testnet fleet. There is no automatic CI/CD or server installer in this public snapshot.

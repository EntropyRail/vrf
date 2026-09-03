# Recorded Robinhood testnet deployment

**Chain ID: 46630. Testnet only.** This is a public reference to the recorded V3 deployment and single end-to-end canary, not a live health dashboard or production integration approval.

| Contract | Address |
| --- | --- |
| V3 coordinator | [`0xA44D9b1058Baa07e053eB3B717dBb878E51B5f31`](https://explorer.testnet.chain.robinhood.com/address/0xA44D9b1058Baa07e053eB3B717dBb878E51B5f31) |
| Governance Safe | [`0x1071abAE78f87E419358AAC2699F99c640aA4362`](https://explorer.testnet.chain.robinhood.com/address/0x1071abAE78f87E419358AAC2699F99c640aA4362) |
| 12-hour timelock | [`0x32Bd74DF2D3d6BCe6D42d02B58A0d3F3F1FB1C61`](https://explorer.testnet.chain.robinhood.com/address/0x32Bd74DF2D3d6BCe6D42d02B58A0d3F3F1FB1C61) |
| Canary example consumer | [`0xA80f6Ba88c842D7C642E2AF63Eb2C81EFD291525`](https://explorer.testnet.chain.robinhood.com/address/0xA80f6Ba88c842D7C642E2AF63Eb2C81EFD291525) |

- [Canary request transaction](https://explorer.testnet.chain.robinhood.com/tx/0x9aabbf0b74fee53362575700332b80e3d3b79e22ee053642982900d5fb9712cc)
- [Canary fulfillment transaction](https://explorer.testnet.chain.robinhood.com/tx/0x4b567876e5c0d7cd08f6403f37f88f195488836e48f927c4f4d1f520ff2e3678)
- [Public deployment metadata](deployments/robinhood-testnet-v3.json): deployment block numbers, runtime code hashes, key hash, and verification links selected from the original deployment record. This public subset is not a runtime operator manifest.

The recorded canary verified one proof, settled once, completed its callback, and left no pending request or reserved balance for that request. Source verification was recorded for the suite and example consumer; it is not an independent audit.

The original deployment source revision is `35ba2cf0641487f45eb999a68879d439a25239bb`. It belongs to the private development history, not this new standalone repository. Public source hashes are available in `source-provenance.json` at the repository root.

The service currently uses one ECVRF prover. A deployed experimental BLS verifier is not evidence of a live threshold network. The recorded 2-of-3 Safe signers were held on one local host, so independent governance custody is not claimed. No mainnet address, completed 30-day soak, fixed price, or availability SLA is announced here.

Check current onchain configuration and coordinate a low-limit test before integration. Do not send mainnet assets to these addresses.

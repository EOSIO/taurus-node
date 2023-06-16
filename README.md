# EOSIO-Taurus - The Most Powerful Infrastructure for Decentralized Applications

Welcome to the EOSIO-Taurus source code repository! This software enables businesses to rapidly build and deploy high-performance and high-security blockchain-based applications. EOSIO-Taurus is a fork of the EOSIO codebase and builds on top of it.

Some of the groundbreaking features of EOSIO-Taurus include:

1. Free Rate Limited Transactions
2. Low Latency Block confirmation (0.5 seconds)
3. Low-overhead Byzantine Fault Tolerant Finality
4. Designed for optional high-overhead, low-latency BFT finality
5. Smart contract platform powered by WebAssembly
6. Designed for Sparse Header Light Client Validation
7. Hierarchical Role Based Permissions
8. Support for Biometric Hardware Secured Keys (e.g. Apple Secure Enclave)
9. Designed for Parallel Execution of Context Free Validation Logic
10. Designed for Inter Blockchain Communication
11. [Support for producer high availability](docs/01_nodeos/03_plugins/producer_ha_plugin/index.md) \*
12. [Support for preserving the input order of transactions for special use cases](docs/01_nodeos/03_plugins/amqp_trx_plugin/index.md) \*
13. [Support for streaming from smart contract to external systems](docs/01_nodeos/03_plugins/event_streamer_plugin/index.md) \*
14. [High performance multithreaded queries of the blockchain state](docs/01_nodeos/03_plugins/rodeos_plugin/index.md) \*
15. [Ability to debug and single step through smart contract execution](docs/01_nodeos/10_enterprise_app_integration/native-tester.md) \*
16. [Protocol Buffers support for contract action and blockchain data](docs/01_nodeos/10_enterprise_app_integration/protobuf.md) \*
17. [TPM support for signatures providing higher security](./docs/01_nodeos/03_plugins/signature_provider_plugin/index.md) \*
18. [Standard ECDSA keys support in contracts for enterprise application integration](docs/01_nodeos/10_enterprise_app_integration/ecdsa.md) \*\#
19. [RSA signature support in contracts for enterprise application integration](docs/01_nodeos/10_enterprise_app_integration/rsa.md) \*
20. [Ability to use snapshots for state persistence for stability and reliability](docs/01_nodeos/03_plugins/chain_plugin/snapshot-state.md) \*
21. [Support for long running time transactions for large scale contracts](./docs/01_nodeos/03_plugins/producer_plugin/index.md#long-running-time-transaction) \*
22. [Asynchronous block signing for improving block production performance](docs/01_nodeos/03_plugins/producer_plugin/async-block-signing.md) \*

(\* features added or extensively improved in EOSIO-Taurus for enterprise applications) \
(\# the ECDSA public key follows the [Standards for Efficient Cryptography 1](https://www.secg.org/sec1-v2.pdf))

## Disclaimer

This release refers only to version 1.0 of our open source software. We caution those who wish to use blockchains built on EOSIO-Taurus to carefully vet the companies and organizations launching blockchains based on EOSIO-Taurus before disclosing any private keys to their derivative software.

## Building the Project and Supported Operating Systems

The project is a cmake project and it can be built following the [building procedure](docs/00_install/01_build-from-source/index.md).

## Documentation
1. [Nodeos](docs/01_nodeos/index.md)
2. [Cleos](docs/02_cleos/index.md)
3. [More docs](docs/index.md)

## Getting Started
Instructions detailing the process of getting the software, building it, running a simple test network that produces blocks, account creation and uploading a sample contract to the blockchain can be found in the docs.

## License

EOSIO-Taurus is released under the open source [MIT](./LICENSE) license and is offered "AS IS" without warranty of any kind, express or implied. Any security provided by the EOSIO-Taurus software depends in part on how it is used, configured, and deployed. EOSIO-Taurus is built upon many third-party libraries such as WABT (Apache License) and WAVM (BSD 3-clause) which are also provided "AS IS" without warranty of any kind. You are responsible for reviewing and complying with the license terms included with any third party software that may be provided. Without limiting the generality of the foregoing, Bullish Global and its affiliates makes no representation or guarantee that EOSIO-Taurus or any third-party libraries will perform as intended or will be free of errors, bugs or faulty code. Both may fail in large or small ways that could completely or partially limit functionality or compromise computer systems. If you use or implement EOSIO-Taurus, you do so at your own risk. In no event will Bullish Global or its affiliates be liable to any party for any damages whatsoever, even if previously advised of the possibility of damage.

## Important

See [LICENSE](./LICENSE) for copyright and license terms.

All repositories and other materials are provided subject to the terms of this [IMPORTANT](./IMPORTANT.md) notice and you must familiarize yourself with its terms.  The notice contains important information, limitations and restrictions relating to our software, publications, trademarks, third-party resources, and forward-looking statements.  By accessing any of our repositories and other materials, you accept and agree to the terms of the notice.

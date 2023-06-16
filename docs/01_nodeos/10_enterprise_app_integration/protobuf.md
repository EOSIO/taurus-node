## Description

EOSIO-Taurus supports using Protocol Buffers as the data structure encoding format for transactions, including the action data, table data, return values, and etc. With the Protocol Buffers support, the same message format can be used among micro services and blockchain, making the integration easier and improving the on-chain data stability as long as smart contract development efficiency.

Protocol Buffers has certain advantages
- ID based field encoding. The field IDs ensure on-chain data and interface stability. Because the on-chain data history is immutable, we must make sure the formats are strictly controlled with the enforced ID based encoding/decoding.
- Language neutral message format, and extensive high quality libraries for various languages. With such library support, there will be less code to write and maintain, and it will be faster to evolve the systems. Micro services don't have to struggle with the sometimes hardcoded serialization.
- Backwards compatibility support. It makes it easy to upgrade the message data structure, like removing/adding fields. It's not needed to rely heavily on manual code review to avoid corrupting on-chain data for on-chain data upgrading.
- Fast serialization/deserialization and binary compact message encoding. The generated native smart contract native code from the proto definition files do the serialization/deserialization within smart contracts, and the code can be optimized by the compiler for optimizing the contracts.

## How this is supported

The ABIEOS library, `cleos` and `nodeos` as long as CDT are extended to support Protocol Buffers in the ABI definitions and tools.

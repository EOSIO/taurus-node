## Description

Use Protocol Buffer as transaction data: action data structure, table data structure, return value data structure, and etc. The same message format can be shared for microservices and blockchain for action data structure, table data structure, return value data structure, and etc.

Protocol Buffer has certain advantages
- ID based field encoding to ensure on-chain data and interface stability. On-chain data history is immutable and we must make sure the formats are strictly controlled with the enforce ID based encoding/decoding.
- Language neutral message format, and extensive high quality libraries for various languages. Less code to write, easier to maintain, faster to evolve. Microservices don’t have to struggle with the sometimes hardcoded serialization.
- Backwards compatibility. Easy to upgrade the message data structure, like removing/adding fields. No need to rely heavily on manual code review for on-chain data upgrading compatibility, to avoid “corrupted” on-chain data.
- Fast. Generated native code from .proto to do serialization/deserialization; compact serialization format. As convenience to use as JSON, without the high deserialization performance cost.

## How this is supported

The ABIEOS library, `cleos` and `nodeos` as long as CDT are extended to support protobuf in the ABI definitions and tools.

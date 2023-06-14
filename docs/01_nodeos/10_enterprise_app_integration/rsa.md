## Description

EOSIO-Taurus adds support to the RSA signature verification for easier integrations for enterprise applications using the RSA algorithm.

## How to use it

A new intrinsic function `verify_rsa_sha256_sig()` is added.

When it is used in a smart contract, the declaration (see for example `unittests/test-contracts/verify_rsa/verify_rsa.cpp`) should be

```cpp
extern "C" {
   __attribute__((eosio_wasm_import))
   int verify_rsa_sha256_sig(const char* message, uint32_t message_len,
                             const char* signature, uint32_t signature_len,
                             const char* exponent, uint32_t exponent_len,
                             const char* modulus, uint32_t modulus_len);
}
```

while the function signature in `libraries/chain/apply_context.cpp` is

```cpp
bool verify_rsa_sha256_sig(const char* message, size_t message_len,
                           const char* signature, size_t signature_len,
                           const char* exponent, size_t exponent_len,
                           const char* modulus, size_t modulus_len);
```

For an example of using the `verify_rsa_sha256_sig()` function in a smart contract, please check `unittests/test-contracts/verify_rsa/verify_rsa.cpp`.

A protocol feature `builtin_protocol_feature_t::verify_rsa_sha256_sig` is added to enable the new intrinsic.


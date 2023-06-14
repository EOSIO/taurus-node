## Description

Standard ECDSA formats are more widely used by enterprise applications. EOSIO-Taurus adds support to the standard ECDSA key formats for easier integrations. \*

*\* The ECDSA public key follows the [Standards for Efficient Cryptography 1](https://www.secg.org/sec1-v2.pdf).*

## How to use it

The following intrinsic functions are added for the Taurus VM for contracts and queries, as well as native tester support:

- `verify_ecdsa_sig(legacy_span<const char> message, legacy_span<const char> signature, legacy_span<const char> pubkey)`: return true if verification succeeds, otherwise return false
  - message: raw message string (e.g. string `message to sign`)
  - signature: ECDSA signature in ASN.1 DER format, base64 encoded string (e.g. string `MEYCIQCi5byy/JAvLvFWjMP8ls7z0ttP8E9UApmw69OBzFWJ3gIhANFE2l3jO3L8c/kwEfuWMnh8q1BcrjYx3m368Xc/7QJU`)
  - pubkey: ECDSA public key in X.509 SubjectPublicKeyInfo format, PEM encoded string (note: newline char `\n` is needed for the input string, e.g. string
      ```
      -----BEGIN PUBLIC KEY-----\n
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEzjca5ANoUF+XT+4gIZj2/X3V2UuT\n
      E9MTw3sQVcJzjyC/p7KeaXommTC/7n501p4Gd1TiTiH+YM6fw/YYJUPSPg==\n
      -----END PUBLIC KEY-----
      ```
- `is_supported_ecdsa_pubkey(legacy_span<const char> pubkey)`: return true if `pubkey` is in X.509 SubjectPublicKeyInfo format and PEM encoded

A protocol feature `builtin_protocol_feature_t::verify_ecdsa_sig` to control whether the feature is enabled or not.


#include <eosio/chain/apply_context.hpp>
#include <eosio/chain/protocol_state_object.hpp>
#include <eosio/chain/transaction_context.hpp>
#include <eosio/chain/webassembly/interface.hpp>

#include <fc/crypto/sha256.hpp>
#include <fc/crypto/base64.hpp>
#include <fc/crypto/hex.hpp>

#include <boost/multiprecision/cpp_int.hpp>

#include <stdexcept>
#include <string>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

namespace eosio { namespace chain { namespace webassembly {

   void interface::assert_recover_key( legacy_ptr<const fc::sha256> digest,
                                       legacy_span<const char> sig,
                                       legacy_span<const char> pub ) const {
      fc::crypto::signature s;
      fc::crypto::public_key p;
      datastream<const char*> ds( sig.data(), sig.size() );
      datastream<const char*> pubds ( pub.data(), pub.size() );

      fc::raw::unpack( ds, s );
      fc::raw::unpack( pubds, p );

      EOS_ASSERT(static_cast<unsigned>(s.which()) < context.db.get<protocol_state_object>().num_supported_key_types, unactivated_signature_type,
        "Unactivated signature type used during assert_recover_key");
      EOS_ASSERT(static_cast<unsigned>(p.which()) < context.db.get<protocol_state_object>().num_supported_key_types, unactivated_key_type,
        "Unactivated key type used when creating assert_recover_key");

      if(context.control.is_producing_block())
         EOS_ASSERT(s.variable_size() <= context.control.configured_subjective_signature_length_limit(),
                    sig_variable_size_limit_exception, "signature variable length component size greater than subjective maximum");

      auto check = fc::crypto::public_key( s, *digest, false );
      EOS_ASSERT( check == p, crypto_api_exception, "Error expected key different than recovered key" );
   }

   int32_t interface::recover_key( legacy_ptr<const fc::sha256> digest,
                                   legacy_span<const char> sig,
                                   legacy_span<char> pub ) const {
      fc::crypto::signature s;
      datastream<const char*> ds( sig.data(), sig.size() );
      fc::raw::unpack(ds, s);

      EOS_ASSERT(static_cast<unsigned>(s.which()) < context.db.get<protocol_state_object>().num_supported_key_types, unactivated_signature_type,
                 "Unactivated signature type used during recover_key");

      if(context.control.is_producing_block())
         EOS_ASSERT(s.variable_size() <= context.control.configured_subjective_signature_length_limit(),
                    sig_variable_size_limit_exception, "signature variable length component size greater than subjective maximum");


      auto recovered = fc::crypto::public_key(s, *digest, false);

      // the key types newer than the first 2 may be varible in length
      if (static_cast<unsigned>(s.which()) >= config::genesis_num_supported_key_types ) {
         EOS_ASSERT(pub.size() >= 33, wasm_execution_error,
                    "destination buffer must at least be able to hold an ECC public key");
         auto packed_pubkey = fc::raw::pack(recovered);
         auto copy_size = std::min<size_t>(pub.size(), packed_pubkey.size());
         std::memcpy(pub.data(), packed_pubkey.data(), copy_size);
         return packed_pubkey.size();
      } else {
         // legacy behavior, key types 0 and 1 always pack to 33 bytes.
         // this will do one less copy for those keys while maintaining the rules of
         //    [0..33) dest sizes: assert (asserts in fc::raw::pack)
         //    [33..inf) dest sizes: return packed size (always 33)
         datastream<char*> out_ds( pub.data(), pub.size() );
         fc::raw::pack(out_ds, recovered);
         return out_ds.tellp();
      }
   }

   void interface::assert_sha256(legacy_span<const char> data, legacy_ptr<const fc::sha256> hash_val) const {
      auto result = context.trx_context.hash_with_checktime<fc::sha256>( data.data(), data.size() );
      EOS_ASSERT( result == *hash_val, crypto_api_exception, "hash mismatch" );
   }

   void interface::assert_sha1(legacy_span<const char> data, legacy_ptr<const fc::sha1> hash_val) const {
      auto result = context.trx_context.hash_with_checktime<fc::sha1>( data.data(), data.size() );
      EOS_ASSERT( result == *hash_val, crypto_api_exception, "hash mismatch" );
   }

   void interface::assert_sha512(legacy_span<const char> data, legacy_ptr<const fc::sha512> hash_val) const {
      auto result = context.trx_context.hash_with_checktime<fc::sha512>( data.data(), data.size() );
      EOS_ASSERT( result == *hash_val, crypto_api_exception, "hash mismatch" );
   }

   void interface::assert_ripemd160(legacy_span<const char> data, legacy_ptr<const fc::ripemd160> hash_val) const {
      auto result = context.trx_context.hash_with_checktime<fc::ripemd160>( data.data(), data.size() );
      EOS_ASSERT( result == *hash_val, crypto_api_exception, "hash mismatch" );
   }

   void interface::sha1(legacy_span<const char> data, legacy_ptr<fc::sha1> hash_val) const {
      *hash_val = context.trx_context.hash_with_checktime<fc::sha1>( data.data(), data.size() );
   }

   void interface::sha256(legacy_span<const char> data, legacy_ptr<fc::sha256> hash_val) const {
      *hash_val = context.trx_context.hash_with_checktime<fc::sha256>( data.data(), data.size() );
   }

   void interface::sha512(legacy_span<const char> data, legacy_ptr<fc::sha512> hash_val) const {
      *hash_val = context.trx_context.hash_with_checktime<fc::sha512>( data.data(), data.size() );
   }

   void interface::ripemd160(legacy_span<const char> data, legacy_ptr<fc::ripemd160> hash_val) const {
      *hash_val = context.trx_context.hash_with_checktime<fc::ripemd160>( data.data(), data.size() );
   }

   /* This implementation is adapted from wax-hapi, which is under MIT license.
      See https://github.com/worldwide-asset-exchange/wax-hapi for details. */
   bool interface::verify_rsa_sha256_sig_impl(const char* message, size_t message_len,
                                              const char* signature, size_t signature_len,
                                              const char* exponent, size_t exponent_len,
                                              const char* modulus, size_t modulus_len) {
      using namespace std::string_literals;
      using boost::multiprecision::cpp_int;

      const std::string prefix = "verify_rsa_sha256_sig(): ";
      try {
         if (!message_len) {
            elog(prefix + "empty message string");
         } else if (!signature_len) {
            elog(prefix + "empty signature string");
         } else if (!exponent_len) {
            elog(prefix + "empty exponent string");
         } else if (modulus_len != signature_len) {
            const std::string sig_len_s = std::to_string(signature_len);
            const std::string mod_len_s = std::to_string(modulus_len);
            elog(prefix + "different lengths for "
                           "signature string (len=" + sig_len_s + ") and "
                           "modulus string (len=" + mod_len_s + ")");
         } else if (modulus_len % 2 == 1) {
            const std::string mod_len_s = std::to_string(modulus_len);
            elog(prefix + "odd length for modulus string "
                           "(len=" + mod_len_s + ")");
         } else {
            fc::sha256 msg_sha256 = fc::sha256::hash(message, message_len);
            std::string pkcs1_encoding =
               "3031300d060960864801650304020105000420"s +
               fc::to_hex(msg_sha256.data(), msg_sha256.data_size());
            size_t emLen = modulus_len / 2;
            size_t tLen = pkcs1_encoding.size() / 2;
            if (emLen < tLen + 11) {
               const std::string emLen_s = std::to_string(emLen);
               const std::string tLen_s = std::to_string(tLen);
               elog(prefix + "intended encoding message length is too short "
                              "(emLen=" + emLen_s + ", tLen=" + tLen_s + ")");
            } else {
               pkcs1_encoding = "0001"s + std::string(2 * (emLen - tLen - 3), 'f') + "00"s + pkcs1_encoding;
               const cpp_int from_message {"0x"s + pkcs1_encoding};
               const cpp_int signature_int {"0x"s + std::string(signature, signature_len)};
               const cpp_int exponent_int {"0x"s + std::string(exponent, exponent_len)};
               const cpp_int modulus_int {"0x"s + std::string(modulus, modulus_len)};
               const cpp_int from_signature = boost::multiprecision::powm(signature_int, exponent_int, modulus_int);
               return from_message == from_signature;
            }
         }
      } catch (const std::exception& e) {
         elog(prefix + e.what());
      } catch (...) {
         elog(prefix + "unknown exception");
      }
      return false;
   }

   bool interface::verify_rsa_sha256_sig(legacy_span<const char> message,
                                         legacy_span<const char> signature,
                                         legacy_span<const char> exponent,
                                         legacy_span<const char> modulus) const {
      return verify_rsa_sha256_sig_impl(message.data(), message.size(),
                                        signature.data(), signature.size(),
                                        exponent.data(), exponent.size(),
                                        modulus.data(), modulus.size());
   }

   EC_KEY* get_pubkey_from_pem(const char* pem, size_t pem_len) {
      EC_KEY* ec_key = NULL;
      BIO* bio = BIO_new_mem_buf(pem, pem_len);
      if (bio) {
         ec_key = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
      }
      BIO_free(bio);
      return ec_key;
   }

   inline void elog_openssl_err(const std::string& msg) {
      std::string log = msg;
      if (const char* openssl_err = ERR_error_string(ERR_get_error(), NULL)) {
         log += std::string(": ") + openssl_err;
      }
      elog(log + "\n");
   }

   bool interface::verify_ecdsa_sig_impl(const char* message, size_t message_len,
                                         const char* signature, size_t signature_len,
                                         const char* pubkey, size_t pubkey_len) {
      const std::string prefix = "verify_ecdsa_sig(): ";
      if (message_len <= 0 || signature_len <= 0 || pubkey_len <= 0) {
         elog(prefix + "Message, signature, and public key cannot be empty\n");
         return false;
      }

      EC_KEY* ec_key = NULL;
      ECDSA_SIG* sig = NULL;
      try {
         ec_key = get_pubkey_from_pem(pubkey, pubkey_len);
         if (!ec_key) {
            elog_openssl_err(prefix + "Error decoding public key");
            return false;
         }

         const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
         if (!ec_group) {
            elog_openssl_err(prefix + "Error getting EC_GROUP");
            EC_KEY_free(ec_key);
            return false;
         }

         if (EC_GROUP_get_curve_name(ec_group) != NID_X9_62_prime256v1) {
            elog_openssl_err(prefix + "Error validating secp256r1 curve");
            EC_KEY_free(ec_key);
            return false;
         }

         unsigned char digest[SHA256_DIGEST_LENGTH];
         auto* res = SHA256(reinterpret_cast<const unsigned char*>(message), message_len, digest);
         if (!res) {
            elog_openssl_err(prefix + "Error getting SHA-256 hash");
            EC_KEY_free(ec_key);
            return false;
         }

         const std::string sig_decoded = base64_decode(std::string(signature, signature_len));
         auto* sig_data = reinterpret_cast<const unsigned char*>(sig_decoded.data());
         sig = d2i_ECDSA_SIG(NULL, &sig_data, sig_decoded.size());
         if (!sig) {
            elog_openssl_err(prefix + "Error decoding signature");
            EC_KEY_free(ec_key);
            return false;
         }

         bool result = (ECDSA_do_verify(digest, sizeof(digest), sig, ec_key) == 1);
         if (!result) {
            elog_openssl_err(prefix + "Error verifying signature");
         }

         EC_KEY_free(ec_key);
         ECDSA_SIG_free(sig);

         return result;
      } catch (const std::exception& e) {
         elog(prefix + e.what());
      } catch (...) {
         elog(prefix + "unknown exception");
      }

      EC_KEY_free(ec_key);
      ECDSA_SIG_free(sig);
      return false;
   }


   bool interface::verify_ecdsa_sig(legacy_span<const char> message,
                                    legacy_span<const char> signature,
                                    legacy_span<const char> pubkey) {
      return verify_ecdsa_sig_impl(message.data(), message.size(),
                                   signature.data(), signature.size(),
                                   pubkey.data(), pubkey.size());
   }
   bool interface::is_supported_ecdsa_pubkey_impl(const char* pubkey, size_t pubkey_len) {
      bool result = false;
      EC_KEY* ec_key = get_pubkey_from_pem(pubkey, pubkey_len);
      if (ec_key) {
         const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
         if (ec_group && EC_GROUP_get_curve_name(ec_group) == NID_X9_62_prime256v1) {
            result = true;
         }
      }
      EC_KEY_free(ec_key);
      return result;
   }

   bool interface::is_supported_ecdsa_pubkey(legacy_span<const char> pubkey) {
      return is_supported_ecdsa_pubkey_impl(pubkey.data(), pubkey.size());
   }
}}} // ns eosio::chain::webassembly

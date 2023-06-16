#pragma once

#include <cstddef>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include <fc/crypto/sha256.hpp>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

namespace taurus {
   class ecdsa_signer {
   public:
      ecdsa_signer(const std::string& privkey) {
         BIO* bio = BIO_new_mem_buf(privkey.data(), privkey.size());
         if (bio) {
            ec_key = PEM_read_bio_ECPrivateKey(bio, NULL, NULL, NULL);
         }
         BIO_free(bio);
      }

      ~ecdsa_signer() {
         if (ec_key) {
            EC_KEY_free(ec_key);
         }
      }

      std::string sign(const std::string& message) const {
         const std::string prefix = "ecdsa_signer sign(): ";

         if (!ec_key) {
            std::cerr << prefix << "Error signing with NULL ec_key\n";
            return "";
         }

         const EC_GROUP* ec_group = EC_KEY_get0_group(ec_key);
         if (!ec_group) {
            log_openssl_err(prefix, "Error getting EC_GROUP");
            EC_KEY_free(ec_key);
            return "";
         }

         if(EC_GROUP_get_curve_name(ec_group) != NID_X9_62_prime256v1) {
            log_openssl_err(prefix, "Error validating secp256r1 curve");
            EC_KEY_free(ec_key);
            return "";
         }

         unsigned char digest[SHA256_DIGEST_LENGTH];
         auto* res = SHA256(reinterpret_cast<const unsigned char*>(message.data()), message.size(), digest);
         if (!res) {
            log_openssl_err(prefix, "Error getting SHA-256 hash");
            EC_KEY_free(ec_key);
            return "";
         }

         std::vector<unsigned char> sig(ECDSA_size(ec_key));
         unsigned int sig_len = 0;
         int result = ECDSA_sign(0, digest, sizeof(digest), sig.data(), &sig_len, ec_key);
         if (result != 1) {
            log_openssl_err(prefix, "Error creating signature");
            EC_KEY_free(ec_key);
            return "";
         }
         std::string sig_base64 = fc::base64_encode(std::string(reinterpret_cast<const char *>(sig.data()), sig_len));

         return sig_base64;
      }

   private:
      EC_KEY* ec_key = NULL;

      inline void log_openssl_err(const std::string& prefix, const std::string& msg) const {
         std::cerr << prefix << msg;
         if (char* openssl_err = ERR_error_string(ERR_get_error(), NULL)) {
            std::cerr << ": " << openssl_err;
         }
         std::cerr << "\n";
      }
   }; // class ecdsa_signer
} // namespace taurus

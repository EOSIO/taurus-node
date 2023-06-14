#include <eosio/eosio.hpp>

#include <cstring>
#include <string>
#include <string_view>

extern "C" {
   __attribute__((eosio_wasm_import))
   int verify_rsa_sha256_sig(const char* message, uint32_t message_len,
                             const char* signature, uint32_t signature_len,
                             const char* exponent, uint32_t exponent_len,
                             const char* modulus, uint32_t modulus_len);
}

class [[eosio::contract]] verify_rsa: public eosio::contract {
public:
   using eosio::contract::contract;

   [[eosio::action]]
   void verrsasig(const std::string& message,
                  const std::string& signature,
                  const std::string& exponent,
                  const std::string& modulus) {
      bool res = verify_rsa_sha256_sig(message.data(), message.size(),
                                       signature.data(), signature.size(),
                                       exponent.data(), exponent.size(),
                                       modulus.data(), modulus.size());
      eosio::check(res, "verify_rsa_sha256_sig() failed for std::string input");

      char *message_dat = nullptr;
      char *signature_dat = nullptr;
      char *exponent_dat = nullptr;
      char *modulus_dat = nullptr;
      if (message.size()) {
         message_dat = new char[message.size()];
         std::memcpy(message_dat, message.data(), message.size());
      }
      if (signature.size()) {
         signature_dat = new char[signature.size()];
         std::memcpy(signature_dat, signature.data(), signature.size());
      }
      if (exponent.size()) {
         exponent_dat = new char[exponent.size()];
         std::memcpy(exponent_dat, exponent.data(), exponent.size());
      }
      if (modulus.size()) {
         modulus_dat = new char[modulus.size()];
         std::memcpy(modulus_dat, modulus.data(), modulus.size());
      }
      res = verify_rsa_sha256_sig(message_dat, message.size(),
                                  signature_dat, signature.size(),
                                  exponent_dat, exponent.size(),
                                  modulus_dat, modulus.size());
      if (message.size()) {
         delete[] message_dat;
      }
      if (signature.size()) {
         delete[] signature_dat;
      }
      if (exponent.size()) {
         delete[] exponent_dat;
      }
      if (modulus.size()) {
         delete[] modulus_dat;
      }
      eosio::check(res, "verify_rsa_sha256_sig() failed for char array input");
   }
};

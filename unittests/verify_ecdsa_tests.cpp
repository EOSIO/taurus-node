#include <iterator>
#include <string>
#include <random>

#include <boost/test/unit_test.hpp>    // BOOST_AUTO_TEST_SUITE

#include <contracts.hpp>               // test contracts
#include <eosio/testing/tester.hpp>    // eosio tester

#include "ecdsa_signer.hpp"

const eosio::chain::name account_name = eosio::chain::name("alice");

const std::string pubkey = 
   "-----BEGIN PUBLIC KEY-----\n"
   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
   "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw==\n"
   "-----END PUBLIC KEY-----";

const std::string privkey = 
   "-----BEGIN EC PRIVATE KEY-----\n"
   "MHcCAQEEIE0rjBF0RxMx39OhkO9oMKO0+ComOgQNtxMCmLPpi9U8oAoGCCqGSM49\n"
   "AwEHoUQDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjIG3GG4plUH4r9c4de0b2Aevh3\n"
   "dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw==\n"
   "-----END EC PRIVATE KEY-----";

template<const std::string& privkey>
struct verify_fixture: public eosio::testing::tester {
   taurus::ecdsa_signer signer;

   verify_fixture() :
      tester(eosio::testing::setup_policy::preactivate_feature_and_new_bios),
      signer(privkey) {
         try {
            const auto& pfm = control->get_protocol_feature_manager();
            const auto& d = pfm.get_builtin_digest(eosio::chain::builtin_protocol_feature_t::verify_ecdsa_sig);
            BOOST_REQUIRE(d);
            preactivate_protocol_features({*d});
            produce_block();
            create_accounts({account_name});
            set_code(account_name, eosio::testing::contracts::verify_ecdsa_wasm());
            set_abi(account_name, eosio::testing::contracts::verify_ecdsa_abi().data());
            produce_block();
         }
         FC_LOG_AND_RETHROW();
   }

    void verify(const std::string& message,
                const std::string& signature,
                const std::string& pubkey) {
         try {
            produce_block();
            push_action(
               account_name,
               eosio::chain::name("verify"),
               account_name,
               fc::mutable_variant_object()
                  ("msg", message)
                  ("sig", signature)
                  ("pubkey", pubkey)
            );
         }
         FC_LOG_AND_RETHROW();
    }

    void validkey(const std::string& pubkey) {
      push_action(
         account_name,
         eosio::chain::name("validkey"),
         account_name,
         fc::mutable_variant_object()
            ("pubkey", pubkey)
      );
    }
};

std::string corrupt_ec_sig(const std::string& sig) {
   std::string sig_decoded = fc::base64_decode(sig);
   ++sig_decoded.back();
   return fc::base64_encode(sig_decoded);
}

inline std::string get_random_string(size_t len) {
   std::mt19937 rng(std::random_device{}());
   std::uniform_int_distribution<int> dis(32, 126);
   std::string res;
   res.reserve(len);
   for (size_t i = 0; i < len; ++i) {
      res += dis(rng);
   }
   return res;
}

inline int get_random_num(int max) {
   std::mt19937 rng(std::random_device{}());
   std::uniform_int_distribution<> dis(1, max);
   return dis(rng);
}

using verify_fixture_with_privkey = verify_fixture<privkey>;

BOOST_AUTO_TEST_SUITE(verify_ecdsa_sig_tests)

// --- Tests Expected To Pass ----------------------------------------------------------------------

BOOST_FIXTURE_TEST_CASE(verify_happy_path, verify_fixture_with_privkey) {
   const std::string message = "message to sign";
   std::string signature = signer.sign(message);
   BOOST_REQUIRE_NO_THROW(validkey(pubkey));
   BOOST_REQUIRE_NO_THROW(verify(message, signature, pubkey));
}

BOOST_FIXTURE_TEST_CASE(verify_min_message, verify_fixture_with_privkey) {
   const std::string message = "1";
   std::string signature = signer.sign(message);
   BOOST_REQUIRE_NO_THROW(verify(message, signature, pubkey));
}

BOOST_FIXTURE_TEST_CASE(verify_random_message, verify_fixture_with_privkey) {
   for (int len = 1; len <= 100; ++len) {
      std::string message = get_random_string(len);
      std::string signature = signer.sign(message);
      BOOST_REQUIRE_NO_THROW(verify(message, signature, pubkey));
   }
}

// --- Tests Expected To Fail ----------------------------------------------------------------------
using e = eosio::chain::eosio_assert_message_exception;

BOOST_FIXTURE_TEST_CASE(verify_empty_message, verify_fixture_with_privkey) {
   const std::string message = "";
   std::string signature = signer.sign(message);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey), e);
}

BOOST_FIXTURE_TEST_CASE(verify_empty_signature, verify_fixture_with_privkey) {
   const std::string message = "message to sign";
   std::string signature = "";
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey), e);
}

BOOST_FIXTURE_TEST_CASE(verify_empty_pubkey, verify_fixture_with_privkey) {
   const std::string message = "message to sign";
   std::string signature = signer.sign(message);
   BOOST_REQUIRE_THROW(verify(message, signature, ""), e);
}

BOOST_FIXTURE_TEST_CASE(invalid_pubkey, verify_fixture_with_privkey) {
   const std::string message = "message to sign";
   std::string signature = signer.sign(message);

   const std::string pubkey_k1 = 
      "-----BEGIN PUBLIC KEY-----\n"
      "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEbmhQwC/AWLtHKs7S7mecwMw2z0Q7EKll\n"
      "5wASKTK4NI1BNFcud0kdSKyck5RSxjhbriEyy0jdS17iUbaBolbtiA==\n"
      "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_k1), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_k1), e);

   const std::string empty_str = "";
   BOOST_REQUIRE_THROW(validkey(empty_str), e);

   const std::string random_str_as_key = get_random_string(get_random_num(100));
   BOOST_REQUIRE_THROW(validkey(random_str_as_key), e);
   BOOST_REQUIRE_THROW(verify(message, signature, random_str_as_key), e);

   const std::string pubkey_no_header = 
      // "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
      "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw==\n"
      "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_no_header), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_no_header), e);

   const std::string pubkey_no_trailer = 
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
      "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw==\n";
      // "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_no_trailer), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_no_trailer), e);

   std::string pubkey_wrong_format = 
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
      "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw=f\n" // replace ending '=' with 'f'
      "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_wrong_format), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_wrong_format), e);

   pubkey_wrong_format = 
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
      "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaMw=\n" // remove ending '='
      "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_wrong_format), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_wrong_format), e);

   pubkey_wrong_format = 
      "-----BEGIN PUBLIC KEY-----\n"
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8+Wkyp8/imL8XQPOPY8kAzpl4fjI\n"
      "G3GG4plUH4r9c4de0b2Aevh3dEvRyy3Ap4wsW+v7aV9aETVz8KjcVAYaM==\n" // remove ending 'w' befofe `==`
      "-----END PUBLIC KEY-----";
   BOOST_REQUIRE_THROW(validkey(pubkey_wrong_format), e);
   BOOST_REQUIRE_THROW(verify(message, signature, pubkey_wrong_format), e);
}

BOOST_FIXTURE_TEST_CASE(wrong_sginature, verify_fixture_with_privkey) {
   std::string bad_sig, message;

   for (int len = 1; len <= 100; ++len) {
      message = get_random_string(len);
      std::string sig = signer.sign(message);
      bad_sig = corrupt_ec_sig(sig);
      BOOST_REQUIRE_THROW(verify(message, bad_sig, pubkey), e);
   }

   message = "message to sign";
   bad_sig = get_random_string(get_random_num(100));
   BOOST_REQUIRE_THROW(verify(message, bad_sig, pubkey), e);
}

BOOST_AUTO_TEST_SUITE_END()

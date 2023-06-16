#pragma once

/**
C++ client supporting args following a command line interface

Args following a format: [OPTIONS] SUBCOMMAND

Options:
  -h,--help                   Print this help message and exit
  -u,--url TEXT=http://localhost:8888/
                              the http/https URL where nodeos is running
  --wallet-url TEXT=http://localhost:8888/
                              the http/https URL where keosd is running
  -r,--header                 pass specific HTTP header, repeat this option to pass multiple headers
  -n,--no-verify              don't verify peer certificate when using HTTPS
  -v,--verbose                output verbose errors and action output
  -c, --config                a json file is expected to after this option, eg: config.json which contain alias url pairs
  -a, --alias                 a server alias in the config json file is expected after this option, cleos will use the server url replace the server alias
                              when use -a, don't use -u, just make sure default config.json has the alias and url, or using -c to using a different config file has the alias/url

Subcommands:
  version                     Retrieve version information
  create                      Create various items, on and off the blockchain
  get                         Retrieve various items and information from the blockchain
  set                         Set or update blockchain state
  transfer                    Transfer tokens from account to account
  net                         Interact with local p2p network connections
  wallet                      Interact with local wallet
  sign                        Sign a transaction
  push                        Push arbitrary transactions to the blockchain
  multisig                    Multisig contract commands

```
*/

#include <pwd.h>
#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <chrono>
#include <thread>

#include <fc/crypto/hex.hpp>
#include <fc/variant.hpp>
#include <fc/io/datastream.hpp>
#include <fc/io/json.hpp>
#include <fc/io/console.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant_object.hpp>
#include <fc/static_variant.hpp>

#include <eosio/chain/name.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/contract_types.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/to_string.hpp>

#include <eosio/signature_provider_plugin/signature_provider_plugin.hpp>

#include <eosio/amqp_trx_plugin/amqp_trx_plugin.hpp>
#include <eosio/amqp_trx_plugin/amqp_trace_types.hpp>
#include <eosio/amqp/amqp_handler.hpp>

#include <eosio/version/version.hpp>

#pragma push_macro("N")
#undef N

#include <boost/asio.hpp>
#include <boost/format.hpp>
#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/filesystem.hpp>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
#ifdef __clang__
#pragma clang diagnostic ignored "-Wc++11-narrowing"
#endif
#include <boost/process/child.hpp>
#pragma GCC diagnostic pop
#include <boost/process.hpp>
#include <boost/process/spawn.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/range/algorithm/copy.hpp>

#pragma pop_macro("N")

#include <fc/io/fstream.hpp>
#include <eosio/chain/to_string.hpp>

#define CLI11_HAS_FILESYSTEM 0
#include "CLI11.hpp"
#include "help_text.hpp"
#include "config.hpp"
#include "httpc.hpp"
#include <eosio/abi.hpp>

using namespace std;
using namespace eosio;
using namespace eosio::client::help;
using namespace eosio::client::http;
using namespace eosio::client::config;
using namespace boost::filesystem;


FC_DECLARE_EXCEPTION( explained_exception, 9000000, "explained exception, see error log" );
FC_DECLARE_EXCEPTION( localized_exception, 10000000, "an error occured" );
#define EOSC_ASSERT( OSTREAM, TEST, FORMAT, ... ) \
  FC_EXPAND_MACRO( \
    FC_MULTILINE_MACRO_BEGIN \
      if( UNLIKELY(!(TEST)) ) \
      {                                                   \
        OSTREAM << FC_FMT( FORMAT, __VA_ARGS__ ) << std::endl; \
        FC_THROW_EXCEPTION( explained_exception, #TEST ); \
      }                                                   \
    FC_MULTILINE_MACRO_END \
  )

inline namespace literals {
chain::name operator "" _n( const char* input, std::size_t ) {
   return chain::name( input );
}
}


bfs::path determine_home_directory()
{
   bfs::path home;
   struct passwd* pwd = getpwuid(getuid());
   if(pwd) {
      home = pwd->pw_dir;
   }
   else {
      home = getenv("HOME");
   }
   if(home.empty())
      home = "./";
   return home;
}

std::string clean_output(std::string str) {
   const bool escape_control_chars = false;
   return fc::escape_string(str, nullptr, escape_control_chars);
}

bool is_public_key_str(const std::string &potential_key_str) {
   return boost::istarts_with(potential_key_str, "EOS") || boost::istarts_with(potential_key_str, "PUB_R1") ||
          boost::istarts_with(potential_key_str, "PUB_K1") || boost::istarts_with(potential_key_str, "PUB_WA");
}


// types and helper functions
enum class tx_compression_type {
   none,
   zlib,
   default_compression
};

chain::packed_transaction::compression_type to_compression_type( tx_compression_type t ) {
   switch( t ) {
      case tx_compression_type::none: return chain::packed_transaction::compression_type::none;
      case tx_compression_type::zlib: return chain::packed_transaction::compression_type::zlib;
      case tx_compression_type::default_compression: return chain::packed_transaction::compression_type::none;
   }
   __builtin_unreachable();
}

struct alias_url_pair{
   std::string alias;
   std::string url;
};

struct config_json_data{
   std::string default_url;
   std::vector<alias_url_pair> aups;  // alias url pairs
};

class signing_keys_option {
public:
   signing_keys_option() {}
   void add_option(CLI::App* cmd) {
      cmd->add_option("--sign-with", public_key_json, "The public key or json array of public keys to sign with");
   }

   std::vector<chain::public_key_type> get_keys() {
      std::vector<chain::public_key_type> signing_keys;
      if (!public_key_json.empty()) {
         if (is_public_key_str(public_key_json)) {
            try {
               signing_keys.push_back(chain::public_key_type(public_key_json));
            } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid public key: {public_key}", ("public_key", public_key_json))
         } else {
            fc::variant json_keys;
            try {
               json_keys = fc::json::from_string(public_key_json, fc::json::parse_type::relaxed_parser);
            } EOS_RETHROW_EXCEPTIONS(chain::json_parse_exception, "Fail to parse JSON from string: {string}", ("string", public_key_json));
            try {
               std::vector<chain::public_key_type> keys = json_keys.template as<std::vector<chain::public_key_type>>();
               signing_keys = std::move(keys);
            } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid public key array format '{data}'",
                                     ("data", fc::json::to_string(json_keys, fc::time_point::maximum())))
         }
      }
      return signing_keys;
   }
private:
   string public_key_json;
};

struct cleos_client;

template<typename T>
fc::variant call(cleos_client* client,
                 const std::string &url,
                 const std::string &path,
                 const T &v);

template<typename T>
fc::variant call(cleos_client* client,
                 const std::string &path,
                 const T &v);

template<>
fc::variant call(cleos_client* client,
                 const std::string &url,
                 const std::string &path);

struct cleos_client {
   string default_url = "http://127.0.0.1:8888/";
   string default_wallet_url = "unix://" + (determine_home_directory() / "eosio-wallet" /
                                            (string(key_store_executable_name) + ".sock")).string();
   string default_config_file = "config.json";
   string server_alias;
   string wallet_url; //to be set to default_wallet_url in main
   string amqp_address;
   string amqp_reply_to;
   string amqp_queue_name = "trx";
   std::map<chain::name, std::string> abi_files_override;

   std::ostream& my_out = std::cout;
   std::ostream& my_err = std::cerr;

   bool no_verify = false;
   vector<string> headers;

   fc::microseconds tx_expiration = fc::seconds(30);
   const fc::microseconds abi_serializer_max_time = fc::seconds(10); // No risk to client side serialization taking a long time
   string tx_ref_block_num_or_id;
   bool tx_force_unique = false;
   bool tx_dont_broadcast = false;
   bool tx_return_packed = false;
   bool tx_skip_sign = false;
   bool tx_print_json = false;
   bool tx_rtn_failure_trace = true;
   bool tx_read_only = false;
   bool tx_use_old_rpc = false;
   bool tx_use_old_send_rpc = false;
   string tx_json_save_file;
   bool print_request = false;
   bool print_response = false;
   bool no_auto_keosd = false;
   bool verbose = false;

   unordered_map<chain::account_name, eosio::abi> abi_resolver_cache;
   unordered_map<chain::account_name, std::optional<chain::abi_serializer> > abi_serializer_cache;
   map<pair<chain::account_name, chain::symbol_code>, chain::symbol> to_asset_cache;

   std::map<std::string, tx_compression_type> compression_type_map{
      {"none", tx_compression_type::none },
      {"zlib", tx_compression_type::zlib }
   };

   uint8_t tx_max_cpu_usage = 0;
   uint32_t tx_max_net_usage = 0;

   vector<string> tx_permission;

   eosio::client::http::http_context context;

   tx_compression_type tx_compression = tx_compression_type::default_compression;

   signing_keys_option signing_keys_opt;

   cleos_client() {}

   cleos_client(std::ostream& out, std::ostream& err) :
         my_out(out), my_err(err) {}

   bool parse_expiration(CLI::results_t res) {
      double value_s;
      if (res.size() == 0 || !CLI::detail::lexical_cast(res[0], value_s)) {
         return false;
      }

      tx_expiration = fc::seconds(static_cast<uint64_t>(value_s));
      return true;
   };

   void add_standard_transaction_options(CLI::App *cmd, string default_permission = "") {
      cmd->add_option("-x,--expiration", [this](auto res){return this->parse_expiration(res);},
                      "Set the time in seconds before a transaction expires, defaults to 30s");
      cmd->add_flag("-f,--force-unique", tx_force_unique,
                    "Force the transaction to be unique. this will consume extra bandwidth and remove any protections against accidently issuing the same transaction multiple times");
      cmd->add_flag("-s,--skip-sign", tx_skip_sign,
                    "Specify if unlocked wallet keys should be used to sign transaction");
      cmd->add_flag("-j,--json", tx_print_json, "Print result as JSON");
      cmd->add_option("--json-file", tx_json_save_file, "Save result in JSON format into a file");
      cmd->add_flag("-d,--dont-broadcast", tx_dont_broadcast,
                    "Don't broadcast transaction to the network (just print to stdout)");
      cmd->add_flag("--return-packed", tx_return_packed,
                    "Used in conjunction with --dont-broadcast to get the packed transaction");
      cmd->add_option("-r,--ref-block", tx_ref_block_num_or_id,
                      "Set the reference block num or block id used for TAPOS (Transaction as Proof-of-Stake)");
      cmd->add_flag("--use-old-rpc", tx_use_old_rpc,
                    "Use old RPC push_transaction, rather than new RPC send_transaction");
      cmd->add_flag("--use-old-send-rpc", tx_use_old_send_rpc,
                    "Use old RPC send_transaction, rather than new RPC /v2/chain/send_transaction");
      cmd->add_option("--compression", tx_compression, "Compression for transaction 'none' or 'zlib'")->transform(
            CLI::CheckedTransformer(compression_type_map, CLI::ignore_case));

      string msg = "An account and permission level to authorize, as in 'account@permission'";
      if (!default_permission.empty())
         msg += " (defaults to '" + default_permission + "')";
      cmd->add_option("-p,--permission", tx_permission, msg.c_str());

      cmd->add_option("--max-cpu-usage-ms", tx_max_cpu_usage,
                      "Set an upper limit on the milliseconds of cpu usage budget, for the execution of the transaction (defaults to 0 which means no limit)");
      cmd->add_option("--max-net-usage", tx_max_net_usage,
                      "Set an upper limit on the net usage budget, in bytes, for the transaction (defaults to 0 which means no limit)");

      cmd->add_option("-t,--return-failure-trace", tx_rtn_failure_trace,
                      "Return partial traces on failed transactions");
   }


   void add_standard_transaction_options_plus_signing(CLI::App *cmd, string default_permission = "") {
      add_standard_transaction_options(cmd, default_permission);
      signing_keys_opt.add_option(cmd);
   }

   vector<chain::permission_level> get_account_permissions(const vector<string> &permissions) {
      auto fixedPermissions = permissions | boost::adaptors::transformed([](const string &p) {
         vector<string> pieces;
         split(pieces, p, boost::algorithm::is_any_of("@"));
         if (pieces.size() == 1) pieces.push_back("active");
         return chain::permission_level{.actor = chain::name(pieces[0]), .permission = chain::name(pieces[1])};
      });
      vector<chain::permission_level> accountPermissions;
      boost::range::copy(fixedPermissions, back_inserter(accountPermissions));
      return accountPermissions;
   }

   vector<chain::permission_level>
   get_account_permissions(const vector<string> &permissions, const chain::permission_level &default_permission) {
      if (permissions.empty())
         return vector<chain::permission_level>{default_permission};
      else
         return get_account_permissions(tx_permission);
   }

   struct variant_wrapper {
      const fc::variant &obj;

      explicit variant_wrapper(const fc::variant &o) : obj(o) {}

      variant_wrapper get_or_null(const char *key) const {
         fc::variant null;
         if (obj.is_object()) {
            auto &o = obj.get_object();
            auto r = o.find(key);
            if (r != o.end())
               return variant_wrapper{r->value()};
         }
         return variant_wrapper{null};
      }

      const fc::variant *operator->() const { return &obj; }
   };

   eosio::chain_apis::read_only::get_consensus_parameters_results get_consensus_parameters() {
      return call(this, default_url,
                  get_consensus_parameters_func).as<eosio::chain_apis::read_only::get_consensus_parameters_results>();
   }

   eosio::chain_apis::read_only::get_info_results get_info() {
      return call(this, default_url, get_info_func).as<eosio::chain_apis::read_only::get_info_results>();
   }

   string generate_nonce_string() {
      return fc::to_string(fc::time_point::now().time_since_epoch().count());
   }

   chain::action generate_nonce_action() {
      return chain::action({}, chain::config::null_account_name, chain::name("nonce"),
                           fc::raw::pack(fc::time_point::now().time_since_epoch().count()));
   }

   eosio::abi* abieos_abi_resolver(const chain::name &account) {
      auto it = abi_resolver_cache.find(account);
      if (it == abi_resolver_cache.end()) {
         if (abi_files_override.find(account) != abi_files_override.end()) {
            std::ifstream file(abi_files_override[account], std::ios::binary);
            std::string abi_json((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
            return &abi_resolver_cache.try_emplace(account, abi_json).first->second;
         } else {
            const auto raw_abi_result = call(this, get_raw_abi_func, fc::mutable_variant_object("account_name", account));
            const auto raw_abi_blob = raw_abi_result["abi"].as_blob().data;
            if (raw_abi_blob.size() != 0)
               return &abi_resolver_cache.try_emplace(account, raw_abi_blob).first->second;
            else {
               my_err << "ABI for contract " << account.to_string()
                         << " not found. Action data will be shown in hex only." << std::endl;
               return nullptr;
            }
         }
      }
      return &(it->second);
   };

   //resolver for ABI serializer to decode actions in proposed transaction in multisig contract
   std::optional<chain::abi_serializer> abi_serializer_resolver(const chain::name &account) {
      auto it = abi_serializer_cache.find(account);
      if (it == abi_serializer_cache.end()) {

         std::optional<chain::abi_serializer> abis;
         if (abi_files_override.find(account) != abi_files_override.end()) {
            abis.emplace(fc::json::from_file(abi_files_override[account]).as<chain::abi_def>(),
                         chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         } else {
            const auto raw_abi_result = call(this, get_raw_abi_func, fc::mutable_variant_object("account_name", account));
            const auto raw_abi_blob = raw_abi_result["abi"].as_blob().data;
            if (raw_abi_blob.size() != 0) {
               abis.emplace(fc::raw::unpack<chain::abi_def>(raw_abi_blob),
                            chain::abi_serializer::create_yield_function(abi_serializer_max_time));
            } else {
               my_err << "ABI for contract " << account.to_string()
                         << " not found. Action data will be shown in hex only." << std::endl;
            }
         }
         abi_serializer_cache.emplace(account, abis);

         return abis;
      }

      return it->second;
   };

   std::optional<chain::abi_serializer> abi_serializer_resolver_empty(const chain::name &account) {
      return std::optional<chain::abi_serializer>();
   };

   void prompt_for_wallet_password(string &pw, const string &name) {
      if (pw.size() == 0 && name != "SecureEnclave") {
         my_out << "password: ";
         fc::set_console_echo(false);
         std::getline(std::cin, pw, '\n');
         fc::set_console_echo(true);
      }
   }

   fc::variant determine_required_keys(const chain::signed_transaction &trx) {
      // TODO better error checking
      //wdump((trx));
      const auto &public_keys = call(this, wallet_url, wallet_public_keys);
      auto get_arg = fc::mutable_variant_object
            ("transaction", (chain::transaction) trx)
            ("available_keys", public_keys);
      const auto &required_keys = call(this, get_required_keys, get_arg);
      return required_keys["required_keys"];
   }

   void
   sign_transaction(chain::signed_transaction &trx, fc::variant &required_keys, const chain::chain_id_type &chain_id) {
      fc::variants sign_args = {fc::variant(trx), required_keys, fc::variant(chain_id)};
      const auto &signed_trx = call(this, wallet_url, wallet_sign_trx, sign_args);
      trx = signed_trx.as<chain::signed_transaction>();
   }

   fc::variant push_transaction(chain::signed_transaction &trx,
                                const std::vector<chain::public_key_type> &signing_keys = std::vector<chain::public_key_type>()) {
      auto info = get_info();

      if (trx.signatures.size() == 0) { // #5445 can't change txn content if already signed
         trx.expiration = fc::time_point::now() + tx_expiration;

         // Set tapos, default to last irreversible block if it's not specified by the user
         chain::block_id_type ref_block_id = info.last_irreversible_block_id;
         try {
            fc::variant ref_block;
            if (!tx_ref_block_num_or_id.empty()) {
               ref_block = call(this, get_block_func, fc::mutable_variant_object("block_num_or_id", tx_ref_block_num_or_id));
               ref_block_id = ref_block["id"].as<chain::block_id_type>();
            }
         } EOS_RETHROW_EXCEPTIONS(chain::invalid_ref_block_exception,
                                  "Invalid reference block num or id: {block_num_or_id}",
                                  ("block_num_or_id", tx_ref_block_num_or_id));
         trx.set_reference_block(ref_block_id);

         if (tx_force_unique) {
            trx.context_free_actions.emplace_back(generate_nonce_action());
         }

         trx.max_cpu_usage_ms = tx_max_cpu_usage;
         trx.max_net_usage_words = (tx_max_net_usage + 7) / 8;
      }

      if (!tx_skip_sign) {
         fc::variant required_keys;
         if (signing_keys.size() > 0) {
            required_keys = fc::variant(signing_keys);
         } else {
            required_keys = determine_required_keys(trx);
         }
         sign_transaction(trx, required_keys, info.chain_id);
      }

      chain::packed_transaction::compression_type compression = to_compression_type(tx_compression);
      if (!tx_dont_broadcast) {
         EOSC_ASSERT(my_err, !(tx_use_old_rpc && tx_use_old_send_rpc),
                     "ERROR: --use-old-rpc and --use-old-send-rpc are mutually exclusive");
         chain::packed_transaction_v0 pt_v0(trx, compression);
         if (tx_use_old_rpc) {
            EOSC_ASSERT(my_err, !tx_read_only, "ERROR: --read-only can not be used with --use-old-rpc");
            EOSC_ASSERT(my_err, !tx_rtn_failure_trace, "ERROR: --return-failure-trace can not be used with --use-old-rpc");
            return call(this, push_txn_func, pt_v0);
         } else if (tx_use_old_send_rpc) {
            EOSC_ASSERT(my_err, !tx_read_only, "ERROR: --read-only can not be used with --use-old-send-rpc");
            EOSC_ASSERT(my_err, !tx_rtn_failure_trace, "ERROR: --return-failure-trace can not be used with --use-old-send-rpc");
            return call(this, send_txn_func, pt_v0);
         } else {
            if (!amqp_address.empty()) {
               using namespace std::chrono_literals;

               fc::variant result;
               eosio::transaction_msg msg{chain::packed_transaction(std::move(trx), true, compression)};
               auto buf = fc::raw::pack(msg);
               const auto &tid = std::get<chain::packed_transaction>(msg).id();
               string id = tid.str();
               eosio::amqp_handler qp_trx(amqp_address, fc::seconds(5), fc::milliseconds(100),
                                          [this](const std::string &err) {
                                             my_err << "AMQP trx error: " << err << std::endl;
                                             exit(1);
                                          });

               auto stop_promise = std::make_shared<std::promise<fc::variant>>();
               auto stop_future = stop_promise->get_future();

               if (!amqp_reply_to.empty()) {
                  qp_trx.start_consume(amqp_reply_to,
                                       [&](const AMQP::Message &message, amqp_handler::delivery_tag_t delivery_tag,
                                           bool redelivered) {

                                          // either the future has been set, or the future has been got
                                          if (!stop_future.valid() ||
                                              stop_future.wait_for(0s) == std::future_status::ready) {
                                             return;
                                          }

                                          // check correlation ID to make sure it is the reply msg for this trx
                                          if (message.correlationID() != id) {
                                             // not for this transaction, skip further processing
                                             my_err << fmt::format("Consumed message not for this transaction {i}, continue checking other messages\n",
                                                  fmt::arg("i", message.correlationID()));
                                             return;
                                          }

                                          // read the trace out
                                          input_stream ds(message.body(), message.bodySize());
                                          eosio::transaction_trace_msg msg;
                                          try {
                                             from_bin(msg, ds);
                                          } catch (...) {
                                             my_err << "Failed to parse the reply message as a transaction_trace_msg, not expected.\n";
                                             // can't parse the message as transaction_trace_msg
                                             // skip further processing this message
                                             return;
                                          }

                                          // transaction_trace_msg can be
                                          //   eosio::transaction_trace_exception
                                          //   eosio::transaction_trace_message
                                          //   eosio::block_uuid_message
                                          if (std::holds_alternative<eosio::transaction_trace_message>(msg)) {
                                             my_err << fmt::format("Transaction consumed: {i}\n", fmt::arg("i", id));
                                             // we check the type already, if exception is still thrown, it's a fatal
                                             // error, and let it throw to fail the cleos process
                                             auto trace_message = std::get<eosio::transaction_trace_message>(msg);
                                             // we convert the trace to a JSON then to a variant in the result
                                             // this is to re-use the existing library and generate consistent
                                             // variant/JSON as the other parts.
                                             // the performance cost is fine for cleos.
                                             auto json_str = eosio::convert_to_json(trace_message.trace);
                                             auto result = fc::mutable_variant_object()
                                                   ("transaction_id", id)
                                                   ("status", "executed")
                                                   ("trace", fc::json::from_string(json_str));
                                             stop_promise->set_value(result);
                                          } else if (std::holds_alternative<eosio::transaction_trace_exception>(msg)) {
                                             my_err << fmt::format("Transaction consumed: {i} returns an exception\n", fmt::arg("i", id));
                                             auto trace_exception = std::get<eosio::transaction_trace_exception>(msg);
                                             auto json_str = eosio::convert_to_json(trace_exception);
                                             auto result = fc::mutable_variant_object()
                                                   ("transaction_id", id)
                                                   ("status", "failed")
                                                   ("exception", fc::json::from_string(json_str));
                                             stop_promise->set_value(result);
                                          } else if (std::holds_alternative<eosio::block_uuid_message>(msg)) {
                                             // pass, we don't process this message
                                          } else {
                                             my_err << "Reply-to message contains unrecognized type, not expected\n";
                                             // pass, we don't process this message further
                                          }
                                       }, false, true);
               }

               qp_trx.publish("", amqp_queue_name, id, amqp_reply_to, std::move(buf));
               my_err << fmt::format("Transaction sent: {i}\n", fmt::arg("i", id));

               result = fc::mutable_variant_object()
                     ("transaction_id", id)
                     ("status", "submitted");

               if (!amqp_reply_to.empty()) {
                  // wait for the reply, if it is the direct reply-to
                  auto status = stop_future.wait_for(10s);
                  if (status == std::future_status::ready) {
                     result = stop_future.get();
                  } else {
                     my_err << "Transaction reply-to did not arrive on time within 10s, no further waiting\n";
                  }
               }
               return result;
            } else {
               try {
                  auto args = fc::mutable_variant_object()
                        ("return_failure_traces", tx_rtn_failure_trace)
                        ("transaction", pt_v0);
                  if (tx_read_only) {
                     return call(this, send_ro_txns_func, args);
                  } else {
                     return call(this, send_txn_func_v2, args);
                  }
               } catch (chain::missing_chain_api_plugin_exception &) {
                  if (tx_read_only || tx_rtn_failure_trace) {
                     my_err << "New RPC /v2/chain/send_transaction or send_ro_transaction may not be supported."
                               << std::endl
                               << "Add flag --use-old-send-rpc or --use-old-rpc to use old RPC send_transaction or "
                               << std::endl
                               << "push_transaction instead or submit your transaction to a different node."
                               << std::endl;
                     throw;
                  }
                  return call(this, send_txn_func, pt_v0);  // With compatible options, silently fall back to v1 API
               }
            }
         }
      } else {
         if (!tx_return_packed) {
            try {
               fc::variant unpacked_data_trx;
               chain::abi_serializer::to_variant(trx, unpacked_data_trx, [&](const chain::name &account){return this->abi_serializer_resolver(account);},
                                                 chain::abi_serializer::create_yield_function(abi_serializer_max_time));
               return unpacked_data_trx;
            } catch (...) {
               return fc::variant(trx);
            }
         } else {
            return fc::variant(chain::packed_transaction_v0(trx, compression));
         }
      }
   }

   fc::variant push_actions(std::vector<chain::action> &&actions,
                            const std::vector<chain::public_key_type> &signing_keys = std::vector<chain::public_key_type>()) {
      chain::signed_transaction trx;
      trx.actions = std::forward<decltype(actions)>(actions);

      return push_transaction(trx, signing_keys);
   }

   void print_return_value(chain::name account, eosio::name act, const fc::variant &at) {
      std::string return_value, return_value_prefix{"return value: "};
      const auto &iter_hex = at.get_object().find("return_value_hex_data");

      if (iter_hex != at.get_object().end()) {
         auto *abi = abieos_abi_resolver(account);
         if (abi) {
            auto bin_hex = iter_hex->value().as_string();
            vector<char> bin(bin_hex.size() / 2);
            fc::from_hex(bin_hex, bin.data(), bin.size());
            return_value = abi->action_result_bin_to_json(act, eosio::input_stream(bin));
            if (return_value.empty()) {
               return_value = bin_hex;
               return_value_prefix = "return value (hex): ";
            }
         }
      }

      if (!return_value.empty()) {
         my_out << "=>" << std::setw(46) << std::right << return_value_prefix << return_value << "\n";
      }
   }

   void print_action(const fc::variant &at) {
      auto receiver = at["receiver"].as_string();
      const auto &act = at["act"].get_object();
      auto code = act["account"].as_string();
      auto func = act["name"].as_string();
      auto args = fc::json::to_string(act["data"], fc::time_point::maximum());
      auto console = at["console"].as_string();

      /*
   if( code == "eosio" && func == "setcode" )
      args = args.substr(40)+"...";
   if( chain::name(code) == chain::config::system_account_name && func == "setabi" )
      args = args.substr(40)+"...";
   */
      if (args.size() > 100) args = args.substr(0, 100) + "...";
      my_out << "#" << std::setw(14) << right << receiver << " <= " << std::setw(28) << std::left << (code + "::" + func)
           << " " << args << "\n";
      print_return_value(chain::name(code), eosio::name(func), at);
      if (console.size()) {
         std::stringstream ss(console);
         string line;
         while (std::getline(ss, line)) {
            my_out << ">> " << clean_output(std::move(line)) << "\n";
            if (!verbose) break;
            line.clear();
         }
      }
   }

   chain::bytes variant_to_bin(const chain::account_name &account, const chain::action_name &action,
                               const fc::variant &action_args_var) {
      auto abis = abi_serializer_resolver(account);
      FC_ASSERT(abis, "No ABI found for {contract}", ("contract", account));

      auto action_type = abis->get_action_type(action);
      FC_ASSERT(!action_type.empty(), "Unknown action {action} in contract {contract}",
                ("action", action)("contract", account));
      return abis->variant_to_binary(action_type, action_args_var,
                                     chain::abi_serializer::create_yield_function(abi_serializer_max_time));
   }

   chain::bytes action_json_to_bin(const chain::account_name &account, const chain::action_name &action,
                                   const std::string &json_str) {
      if (json_str.size()) {
         if (json_str[0] != '{') {
            // this is not actually a json, use the old varinat mehtod to handle it
            return variant_to_bin(account, action,
                                  fc::json::from_string(json_str, fc::json::parse_type::relaxed_parser));

         } else {
            auto *abi = abieos_abi_resolver(account);
            if (abi) {
               auto itr = abi->action_types.find(eosio::name(action.to_uint64_t()));
               FC_ASSERT(itr != abi->action_types.end(), "Unknown action {action} in contract {contract}",
                         ("action", action)("contract", account));
               return abi->convert_to_bin(itr->second.c_str(), json_str);
            }
         }
      }
      return {};
   }

   fc::variant bin_to_variant(const chain::account_name &account, const chain::action_name &action,
                              const chain::bytes &action_args) {
      auto abis = abi_serializer_resolver(account);
      FC_ASSERT(abis, "No ABI found for {contract}", ("contract", account));

      auto action_type = abis->get_action_type(action);
      FC_ASSERT(!action_type.empty(), "Unknown action {action} in contract {contract}",
                ("action", action)("contract", account));
      return abis->binary_to_variant(action_type, action_args,
                                     chain::abi_serializer::create_yield_function(abi_serializer_max_time));
   }

   std::string json_from_file_or_string(const string &file_or_str) {
      regex r("^[ \t]*[\{\[]");
      bool is_file = false;

      // when file_or_str is long, fc::is_regular_file(file_or_str) may through exceptions
      // we catch the exceptions, and consider the file_or_str is not pointing to a file
      try {
         if (!regex_search(file_or_str, r) && fc::is_regular_file(file_or_str)) {
            is_file = true;
         }
      } catch (...) {
      }

      if (is_file) {
         std::ifstream file(file_or_str, std::ios::binary);
         return std::string((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
      } else {
         return file_or_str;
      }
   }

   fc::variant variant_from_file_or_string(const string &file_or_str,
                                           fc::json::parse_type ptype = fc::json::parse_type::legacy_parser) {
      try {
         return fc::json::from_string(json_from_file_or_string(file_or_str), ptype);
      } EOS_RETHROW_EXCEPTIONS(chain::json_parse_exception, "Fail to parse JSON: {string}", ("string", file_or_str));
   }

   void print_action_tree(const fc::variant &action) {
      print_action(action);
      if (action.get_object().contains("inline_traces")) {
         const auto &inline_traces = action["inline_traces"].get_array();
         for (const auto &t: inline_traces) {
            print_action_tree(t);
         }
      }
   }

   void print_result(const fc::variant &result) {
      try {
         if (result.is_object() && result.get_object().contains("processed")) {
            const auto &processed = result["processed"];
            const auto &transaction_id = processed["id"].as_string();
            string status;
            if (processed.get_object().contains("receipt")) {
               const auto &receipt = processed["receipt"];
               if (receipt.is_object()) {
                  status = receipt["status"].as_string();
                  my_err << status << " transaction: " << transaction_id << "  "
                       << receipt["net_usage_words"].as_int64() * 8
                       << " bytes  " << receipt["cpu_usage_us"].as_int64() << " us\n";
               }
            }
            if (status.empty()) {
               my_err << "failed transaction: " << transaction_id << "  \n";
            }

            if (status.empty() || status == "failed") {
               auto soft_except = processed["except"].as<std::optional<fc::exception>>();
               if (soft_except) {
                  my_err << fmt::format("{e}", fmt::arg("e", soft_except->to_detail_string()));
                  throw explained_exception();
               }
            } else {
               const auto &actions = processed["action_traces"].get_array();
               for (const auto &a: actions) {
                  print_action_tree(a);
               }
               my_err << "warning: transaction executed locally, but may not be confirmed by the network yet" << std::endl;
            }
         } else {
            my_err << fc::json::to_pretty_string(result) << endl;
         }
      } FC_CAPTURE_AND_RETHROW((fc::json::to_string(result, fc::time_point::now() + fc::exception::format_time_limit)))
   }

   void send_actions(std::vector<chain::action> &&actions,
                     const std::vector<chain::public_key_type> &signing_keys = std::vector<chain::public_key_type>()) {
      std::ofstream out;
      if (tx_json_save_file.length()) {
         out.open(tx_json_save_file);
         EOSC_ASSERT(my_err, !out.fail(), "ERROR: Failed to create file \"{p}\"", ("p", tx_json_save_file));
      }
      auto result = push_actions(std::move(actions), signing_keys);

      string jsonstr;
      if (tx_json_save_file.length()) {
         jsonstr = fc::json::to_pretty_string(result);
         out << jsonstr;
         out.close();
      }
      if (tx_print_json) {
         if (jsonstr.length() == 0) {
            jsonstr = fc::json::to_pretty_string(result);
         }
         my_out << jsonstr << endl;

         if (!variant_wrapper(result).get_or_null("processed").get_or_null("except").get_or_null("code")->is_null()) {
            throw explained_exception();
         }

      } else {
         print_result(result);
      }
   }

   chain::permission_level to_permission_level(const std::string &s) {
      auto at_pos = s.find('@');
      return chain::permission_level{chain::name(s.substr(0, at_pos)), chain::name(s.substr(at_pos + 1))};
   }

   chain::action create_newaccount(const chain::name &creator, const chain::name &newaccount, chain::authority owner,
                                   chain::authority active) {
      return chain::action{
            get_account_permissions(tx_permission, {creator, chain::config::active_name}),
            chain::newaccount{
                  .creator      = creator,
                  .name         = newaccount,
                  .owner        = owner,
                  .active       = active
            }
      };
   }

   chain::action create_action(const vector<chain::permission_level> &authorization, const chain::account_name &code,
                               const chain::action_name &act, const fc::variant &args) {
      return chain::action{authorization, code, act, variant_to_bin(code, act, args)};
   }

   chain::action
   create_buyram(const chain::name &creator, const chain::name &newaccount, const chain::asset &quantity) {
      fc::variant act_payload = fc::mutable_variant_object()
            ("payer", creator.to_string())
            ("receiver", newaccount.to_string())
            ("quant", quantity.to_string());
      return create_action(get_account_permissions(tx_permission, {creator, chain::config::active_name}),
                           chain::config::system_account_name, chain::name("buyram"), act_payload);
   }

   chain::action create_buyrambytes(const chain::name &creator, const chain::name &newaccount, uint32_t numbytes) {
      fc::variant act_payload = fc::mutable_variant_object()
            ("payer", creator.to_string())
            ("receiver", newaccount.to_string())
            ("bytes", numbytes);
      return create_action(get_account_permissions(tx_permission, {creator, chain::config::active_name}),
                           chain::config::system_account_name, chain::name("buyrambytes"), act_payload);
   }

   chain::action create_delegate(const chain::name &from, const chain::name &receiver, const chain::asset &net,
                                 const chain::asset &cpu, bool transfer) {
      fc::variant act_payload = fc::mutable_variant_object()
            ("from", from.to_string())
            ("receiver", receiver.to_string())
            ("stake_net_quantity", net.to_string())
            ("stake_cpu_quantity", cpu.to_string())
            ("transfer", transfer);
      return create_action(get_account_permissions(tx_permission, {from, chain::config::active_name}),
                           chain::config::system_account_name, chain::name("delegatebw"), act_payload);
   }

   fc::variant
   regproducer_variant(const chain::account_name &producer, const chain::public_key_type &key, const string &url,
                       uint16_t location) {
      return fc::mutable_variant_object()
            ("producer", producer)
            ("producer_key", key)
            ("url", url)
            ("location", location);
   }

   chain::action
   create_open(const string &contract, const chain::name &owner, chain::symbol sym, const chain::name &ram_payer) {
      auto open_ = fc::mutable_variant_object
            ("owner", owner)
            ("symbol", sym)
            ("ram_payer", ram_payer);
      return chain::action{
            get_account_permissions(tx_permission, {ram_payer, chain::config::active_name}),
            chain::name(contract), chain::name("open"),
            variant_to_bin(chain::name(contract), chain::name("open"), open_)
      };
   }

   chain::action
   create_transfer(const string &contract, const chain::name &sender, const chain::name &recipient, chain::asset amount,
                   const string &memo) {

      auto transfer = fc::mutable_variant_object
            ("from", sender)
            ("to", recipient)
            ("quantity", amount)
            ("memo", memo);

      return chain::action{
            get_account_permissions(tx_permission, {sender, chain::config::active_name}),
            chain::name(contract), "transfer"_n, variant_to_bin(chain::name(contract), "transfer"_n, transfer)
      };
   }

   chain::action create_setabi(const chain::name &account, const chain::bytes &abi) {
      return chain::action{
            get_account_permissions(tx_permission, {account, chain::config::active_name}),
            chain::setabi{
                  .account   = account,
                  .abi       = abi
            }
      };
   }

   chain::action create_setabi2(const chain::name &account, const chain::bytes &abi) {
      fc::variant setabi2 = fc::mutable_variant_object()
            ("account", account)
            ("abi", abi);
      return create_action(
            get_account_permissions(tx_permission, {account, chain::config::active_name}),
            chain::config::system_account_name, chain::name("setabi2"), setabi2);
   }

   chain::action create_setcode(const chain::name &account, const chain::bytes &code) {
      return chain::action{
            get_account_permissions(tx_permission, {account, chain::config::active_name}),
            chain::setcode{
                  .account   = account,
                  .vmtype    = 0,
                  .vmversion = 0,
                  .code      = code
            }
      };
   }

   chain::action create_setcode2(const chain::name &account, const chain::bytes &code) {
      fc::variant setcode2 = fc::mutable_variant_object()
            ("account", account)
            ("vmtype", 0)
            ("vmversion", 0)
            ("code", code);
      return create_action(
            get_account_permissions(tx_permission, {account, chain::config::active_name}),
            chain::config::system_account_name, chain::name("setcode2"), setcode2);
   }

   chain::action create_updateauth(const chain::name &account, const chain::name &permission, const chain::name &parent,
                                   const chain::authority &auth) {
      return chain::action{get_account_permissions(tx_permission, {account, chain::config::active_name}),
                           chain::updateauth{account, permission, parent, auth}};
   }

   chain::action create_deleteauth(const chain::name &account, const chain::name &permission) {
      return chain::action{get_account_permissions(tx_permission, {account, chain::config::active_name}),
                           chain::deleteauth{account, permission}};
   }

   chain::action create_linkauth(const chain::name &account, const chain::name &code, const chain::name &type,
                                 const chain::name &requirement) {
      return chain::action{get_account_permissions(tx_permission, {account, chain::config::active_name}),
                           chain::linkauth{account, code, type, requirement}};
   }

   chain::action create_unlinkauth(const chain::name &account, const chain::name &code, const chain::name &type) {
      return chain::action{get_account_permissions(tx_permission, {account, chain::config::active_name}),
                           chain::unlinkauth{account, code, type}};
   }

   chain::authority parse_json_authority(const std::string &authorityJsonOrFile) {
      fc::variant authority_var = variant_from_file_or_string(authorityJsonOrFile);
      try {
         return authority_var.as<chain::authority>();
      } EOS_RETHROW_EXCEPTIONS(chain::authority_type_exception, "Invalid authority format '{data}'",
                               ("data", fc::json::to_string(authority_var, fc::time_point::maximum())))
   }

   chain::authority parse_json_authority_or_key(const std::string &authorityJsonOrFile) {
      if (is_public_key_str(authorityJsonOrFile)) {
         try {
            return chain::authority(chain::public_key_type(authorityJsonOrFile));
         } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid public key: {public_key}",
                                  ("public_key", authorityJsonOrFile))
      } else {
         auto result = parse_json_authority(authorityJsonOrFile);
         result.sort_fields();
         EOS_ASSERT(chain::validate(result), chain::authority_type_exception,
                    "Authority failed validation! ensure that keys, accounts, and waits are sorted and that the threshold is valid and satisfiable!");
         return result;
      }
   }

   chain::asset to_asset(chain::account_name code, const string &s) {
      auto a = chain::asset::from_string(s);
      chain::symbol_code sym = a.get_symbol().to_symbol_code();
      auto it = to_asset_cache.find(make_pair(code, sym));
      auto sym_str = a.symbol_name();
      if (it == to_asset_cache.end()) {
         auto json = call(this, get_currency_stats_func, fc::mutable_variant_object("json", false)
               ("code", code)
               ("symbol", sym_str)
         );
         auto obj = json.get_object();
         auto obj_it = obj.find(sym_str);
         if (obj_it != obj.end()) {
            auto result = obj_it->value().as<eosio::chain_apis::read_only::get_currency_stats_result>();
            auto p = to_asset_cache.emplace(make_pair(code, sym), result.max_supply.get_symbol());
            it = p.first;
         } else {
            EOS_THROW(chain::symbol_type_exception, "Symbol {s} is not supported by token contract {c}",
                      ("s", sym_str)("c", code));
         }
      }
      auto expected_symbol = it->second;
      if (a.decimals() < expected_symbol.decimals()) {
         auto factor = expected_symbol.precision() / a.precision();
         a = chain::asset(a.get_amount() * factor, expected_symbol);
      } else if (a.decimals() > expected_symbol.decimals()) {
         EOS_THROW(chain::symbol_type_exception, "Too many decimal digits in {a}, only {d} supported",
                   ("a", a)("d", expected_symbol.decimals()));
      } // else precision matches
      return a;
   }

   inline chain::asset to_asset(const string &s) {
      return to_asset("eosio.token"_n, s);
   }

   struct set_account_permission_subcommand {
      string account;
      string permission;
      string authority_json_or_file;
      string parent;
      bool add_code = false;
      bool remove_code = false;

      set_account_permission_subcommand(CLI::App *accountCmd, cleos_client& client) {
         auto permissions = accountCmd->add_subcommand("permission", "Set parameters dealing with account permissions");
         permissions->add_option("account", account,
                                 "The account to set/delete a permission authority for")->required();
         permissions->add_option("permission", permission,
                                 "The permission name to set/delete an authority for")->required();
         permissions->add_option("authority", authority_json_or_file,
                                 "[delete] NULL, [create/update] public key, JSON string or filename defining the authority, [code] contract name");
         permissions->add_option("parent", parent,
                                 "[create] The permission name of this parents permission, defaults to 'active'");
         permissions->add_flag("--add-code", add_code,
                               fmt::format("[code] add '{code}' permission to specified permission authority",
                                           fmt::arg("code", chain::name(chain::config::eosio_code_name))));
         std::string remove_code_desc = "[code] remove " + chain::name(chain::config::eosio_code_name).to_string() +
                                        " permission from specified permission authority";
         permissions->add_flag("--remove-code", remove_code, remove_code_desc);

         client.add_standard_transaction_options(permissions, "account@active");

         permissions->callback([this, &client=client] {
            EOSC_ASSERT(client.my_err, !(add_code && remove_code), "ERROR: Either --add-code or --remove-code can be set");
            EOSC_ASSERT(client.my_err, (add_code ^ remove_code) || !authority_json_or_file.empty(),
                        "ERROR: authority should be specified unless add or remove code permission");

            chain::authority auth;

            bool need_parent = parent.empty() && (chain::name(permission) != chain::name("owner"));
            bool need_auth = add_code || remove_code;

            if (!need_auth && boost::iequals(authority_json_or_file, "null")) {
               client.send_actions({client.create_deleteauth(chain::name(account), chain::name(permission))});
               return;
            }

            if (need_parent || need_auth) {
               fc::variant json = call(&client, get_account_func, fc::mutable_variant_object("account_name", account));
               auto res = json.as<eosio::chain_apis::read_only::get_account_results>();
               auto itr = std::find_if(res.permissions.begin(), res.permissions.end(), [&](const auto &perm) {
                  return perm.perm_name == chain::name(permission);
               });

               if (need_parent) {
                  // see if we can auto-determine the proper parent
                  if (itr != res.permissions.end()) {
                     parent = (*itr).parent.to_string();
                  } else {
                     // if this is a new permission and there is no parent we default to "active"
                     parent = chain::config::active_name.to_string();
                  }
               }

               if (need_auth) {
                  auto actor = (authority_json_or_file.empty()) ? chain::name(account) : chain::name(
                        authority_json_or_file);
                  auto code_name = chain::config::eosio_code_name;

                  if (itr != res.permissions.end()) {
                     // fetch existing authority
                     auth = std::move((*itr).required_auth);

                     auto code_perm = chain::permission_level{actor, code_name};
                     auto itr2 = std::lower_bound(auth.accounts.begin(), auth.accounts.end(), code_perm,
                                                  [&](const auto &perm_level, const auto &value) {
                                                     return perm_level.permission <
                                                            value; // Safe since valid authorities must order the permissions in accounts in ascending order
                                                  });

                     if (add_code) {
                        if (itr2 != auth.accounts.end() && itr2->permission == code_perm) {
                           // authority already contains code permission, promote its weight to satisfy threshold
                           if ((*itr2).weight < auth.threshold) {
                              if (auth.threshold > std::numeric_limits<chain::weight_type>::max()) {
                                 client.my_err << "ERROR: Threshold is too high to be satisfied by sole code permission"
                                           << std::endl;
                                 return;
                              }
                              client.my_err << "The weight of" << actor << "@" << code_name << " in " << permission
                                        << "permission authority will be increased up to threshold" << std::endl;
                              (*itr2).weight = static_cast<chain::weight_type>(auth.threshold);
                           } else {
                              client.my_err << "ERROR: The permission " << permission << " already contains " << actor
                                        << "@" << code_name << std::endl;
                              return;
                           }
                        } else {
                           // add code permission to specified authority
                           if (auth.threshold > std::numeric_limits<chain::weight_type>::max()) {
                              client.my_err << "ERROR: Threshold is too high to be satisfied by sole code permission"
                                        << std::endl;
                              return;
                           }
                           auth.accounts.insert(itr2, chain::permission_level_weight{
                                 .permission = {actor, code_name},
                                 .weight = static_cast<chain::weight_type>(auth.threshold)
                           });
                        }
                     } else {
                        if (itr2 != auth.accounts.end() && itr2->permission == code_perm) {
                           // remove code permission, if authority becomes empty by the removal of code permission, delete permission
                           auth.accounts.erase(itr2);
                           if (auth.keys.empty() && auth.accounts.empty() && auth.waits.empty()) {
                              client.send_actions({client.create_deleteauth(chain::name(account), chain::name(permission))});
                              return;
                           }
                        } else {
                           // authority doesn't contain code permission
                           client.my_err << "ERROR: " << actor << "@" << code_name << " does not exist in " << permission
                                     << " permission authority" << std::endl;
                           return;
                        }
                     }
                  } else {
                     if (add_code) {
                        // create new permission including code permission
                        auth.threshold = 1;
                        auth.accounts.push_back(chain::permission_level_weight{
                              .permission = {actor, code_name},
                              .weight = 1
                        });
                     } else {
                        // specified permission doesn't exist, so failed to remove code permission from it
                        client.my_err << "ERROR: The permission " << permission << " does not exist" << std::endl;
                        return;
                     }
                  }
               }
            }

            if (!need_auth) {
               auth = client.parse_json_authority_or_key(authority_json_or_file);
            }

            client.send_actions({client.create_updateauth(chain::name(account), chain::name(permission), chain::name(parent), auth)});
         });
      }
   };

   struct set_action_permission_subcommand {
      string accountStr;
      string codeStr;
      string typeStr;
      string requirementStr;

      set_action_permission_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto permissions = actionRoot->add_subcommand("permission", "Set paramaters dealing with account permissions");
         permissions->add_option("account", accountStr,
                                 "The account to set/delete a permission authority for")->required();
         permissions->add_option("code", codeStr, "The account that owns the code for the action")->required();
         permissions->add_option("type", typeStr, "The type of the action")->required();
         permissions->add_option("requirement", requirementStr,
                                 "[delete] NULL, [set/update] The permission name require for executing the given action")->required();

         client.add_standard_transaction_options_plus_signing(permissions, "account@active");

         permissions->callback([this, &client=client] {
            chain::name account = chain::name(accountStr);
            chain::name code = chain::name(codeStr);
            chain::name type = chain::name(typeStr);
            bool is_delete = boost::iequals(requirementStr, "null");

            if (is_delete) {
               client.send_actions({client.create_unlinkauth(account, code, type)}, client.signing_keys_opt.get_keys());
            } else {
               chain::name requirement = chain::name(requirementStr);
               client.send_actions({client.create_linkauth(account, code, type, requirement)}, client.signing_keys_opt.get_keys());
            }
         });
      }
   };


   bool local_port_used() {
      using namespace boost::asio;

      io_service ios;
      local::stream_protocol::endpoint endpoint(wallet_url.substr(strlen("unix://")));
      local::stream_protocol::socket socket(ios);
      boost::system::error_code ec;
      socket.connect(endpoint, ec);

      return !ec;
   }

   void try_local_port(uint32_t duration) {
      using namespace std::chrono;
      auto start_time = duration_cast<std::chrono::milliseconds>(system_clock::now().time_since_epoch()).count();
      while (!local_port_used()) {
         if (duration_cast<std::chrono::milliseconds>(system_clock::now().time_since_epoch()).count() - start_time >
             duration) {
            my_err << "Unable to connect to " << key_store_executable_name << ", if " << key_store_executable_name
                      << " is running please kill the process and try again.\n";
            throw connection_exception(fc::log_messages{
                  FC_LOG_MESSAGE(error, "Unable to connect to {k}", ("k", key_store_executable_name))});
         }
      }
   }

   void ensure_keosd_running(CLI::App *app) {
      if (no_auto_keosd)
         return;
      // get, version, net, convert do not require keosd
      if (tx_skip_sign || app->got_subcommand("get") || app->got_subcommand("version") || app->got_subcommand("net") ||
          app->got_subcommand("convert"))
         return;
      if (app->get_subcommand("create")->got_subcommand("key")) // create key does not require wallet
         return;
      if (app->get_subcommand("multisig")->got_subcommand("review")) // multisig review does not require wallet
         return;
      if (auto *subapp = app->get_subcommand("system")) {
         if (subapp->got_subcommand("listproducers") || subapp->got_subcommand("listbw") ||
             subapp->got_subcommand("bidnameinfo")) // system list* do not require wallet
            return;
      }
      if (wallet_url != default_wallet_url)
         return;

      if (local_port_used())
         return;

      boost::filesystem::path binPath = boost::dll::program_location();
      binPath.remove_filename();
      // This extra check is necessary when running cleos like this: ./cleos ...
      if (binPath.filename_is_dot())
         binPath.remove_filename();
      binPath.append(key_store_executable_name); // if cleos and keosd are in the same installation directory
      if (!boost::filesystem::exists(binPath)) {
         binPath.remove_filename().remove_filename().append("keosd").append(key_store_executable_name);
      }

      if (boost::filesystem::exists(binPath)) {
         namespace bp = boost::process;
         binPath = boost::filesystem::canonical(binPath);

         vector<std::string> pargs;
         pargs.push_back("--http-server-address");
         pargs.push_back("");
         pargs.push_back("--https-server-address");
         pargs.push_back("");
         pargs.push_back("--unix-socket-path");
         pargs.push_back(string(key_store_executable_name) + ".sock");

         ::boost::process::child keos(binPath, pargs,
                                      bp::std_in.close(),
                                      bp::std_out > bp::null,
                                      bp::std_err > bp::null);
         if (keos.running()) {
            my_err << binPath << " launched" << std::endl;
            keos.detach();
            try_local_port(2000);
         } else {
            my_err << "No wallet service listening on " << wallet_url << ". Failed to launch " << binPath
                      << std::endl;
         }
      } else {
         my_err << "No wallet service listening on "
                   << ". Cannot automatically start " << key_store_executable_name << " because "
                   << key_store_executable_name << " was not found." << std::endl;
      }
   }


   bool obsoleted_option_host_port(CLI::results_t) {
      my_err << "Host and port options (-H, --wallet-host, etc.) have been replaced with -u/--url and --wallet-url\n"
                   "Use for example -u http://localhost:8888 or --url https://example.invalid/\n";
      exit(1);
      return false;
   };

   struct register_producer_subcommand {
      string producer_str;
      string producer_key_str;
      string url;
      uint16_t loc = 0;

      register_producer_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto register_producer = actionRoot->add_subcommand("regproducer", "Register a new producer");
         register_producer->add_option("account", producer_str, "The account to register as a producer")->required();
         register_producer->add_option("producer_key", producer_key_str, "The producer's public key")->required();
         register_producer->add_option("url", url, "The URL where info about producer can be found", true);
         register_producer->add_option("location", loc, "Relative location for purpose of nearest neighbor scheduling",
                                       true);
         client.add_standard_transaction_options_plus_signing(register_producer, "account@active");


         register_producer->callback([this, &client=client] {
            chain::public_key_type producer_key;
            try {
               producer_key = chain::public_key_type(producer_key_str);
            } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid producer public key: {public_key}",
                                     ("public_key", producer_key_str))

            auto regprod_var = client.regproducer_variant(chain::name(producer_str), producer_key, url, loc);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(producer_str), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "regproducer"_n, regprod_var)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct create_account_subcommand {
      string creator;
      string account_name;
      string owner_key_str;
      string active_key_str;
      string stake_net;
      string stake_cpu;
      uint32_t buy_ram_bytes_in_kbytes = 0;
      uint32_t buy_ram_bytes = 0;
      string buy_ram_eos;
      bool transfer = false;
      bool simple = false;

      create_account_subcommand(CLI::App *actionRoot, bool s, cleos_client& client) : simple(s) {
         auto createAccount = actionRoot->add_subcommand(
               (simple ? "account" : "newaccount"),
               (simple ? "Create a new account on the blockchain (assumes system contract does not restrict RAM usage)"
                       : "Create a new account on the blockchain with initial resources")
         );
         createAccount->add_option("creator", creator, "The name of the account creating the new account")->required();
         createAccount->add_option("name", account_name, "The name of the new account")->required();
         createAccount->add_option("OwnerKey", owner_key_str,
                                   "The owner public key, permission level, or authority for the new account")->required();
         createAccount->add_option("ActiveKey", active_key_str,
                                   "The active public key, permission level, or authority for the new account");

         if (!simple) {
            createAccount->add_option("--stake-net", stake_net,
                                      ("The amount of tokens delegated for net bandwidth"))->required();
            createAccount->add_option("--stake-cpu", stake_cpu,
                                      ("The amount of tokens delegated for CPU bandwidth"))->required();
            createAccount->add_option("--buy-ram-kbytes", buy_ram_bytes_in_kbytes,
                                      ("The amount of RAM bytes to purchase for the new account in kibibytes (KiB)"));
            createAccount->add_option("--buy-ram-bytes", buy_ram_bytes,
                                      ("The amount of RAM bytes to purchase for the new account in bytes"));
            createAccount->add_option("--buy-ram", buy_ram_eos,
                                      ("The amount of RAM bytes to purchase for the new account in tokens"));
            createAccount->add_flag("--transfer", transfer,
                                    ("Transfer voting power and right to unstake tokens to receiver"));
         }

         client.add_standard_transaction_options_plus_signing(createAccount, "creator@active");

         createAccount->callback([this, &client=client] {
            chain::authority owner, active;
            if (owner_key_str.find('{') != string::npos) {
               try {
                  owner = client.parse_json_authority_or_key(owner_key_str);
               } EOS_RETHROW_EXCEPTIONS(explained_exception, "Invalid owner authority: {authority}",
                                        ("authority", owner_key_str))
            } else if (owner_key_str.find('@') != string::npos) {
               try {
                  owner = chain::authority(client.to_permission_level(owner_key_str));
               } EOS_RETHROW_EXCEPTIONS(explained_exception, "Invalid owner permission level: {permission}",
                                        ("permission", owner_key_str))
            } else {
               try {
                  owner = chain::authority(chain::public_key_type(owner_key_str));
               } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid owner public key: {public_key}",
                                        ("public_key", owner_key_str));
            }

            if (active_key_str.empty()) {
               active = owner;
            } else if (active_key_str.find('{') != string::npos) {
               try {
                  active = client.parse_json_authority_or_key(active_key_str);
               } EOS_RETHROW_EXCEPTIONS(explained_exception, "Invalid active authority: {authority}",
                                        ("authority", owner_key_str))
            } else if (active_key_str.find('@') != string::npos) {
               try {
                  active = chain::authority(client.to_permission_level(active_key_str));
               } EOS_RETHROW_EXCEPTIONS(explained_exception, "Invalid active permission level: {permission}",
                                        ("permission", active_key_str))
            } else {
               try {
                  active = chain::authority(chain::public_key_type(active_key_str));
               } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid active public key: {public_key}",
                                        ("public_key", active_key_str));
            }

            auto create = client.create_newaccount(chain::name(creator), chain::name(account_name), owner, active);
            if (!simple) {
               EOSC_ASSERT(client.my_err, buy_ram_eos.size() || buy_ram_bytes_in_kbytes || buy_ram_bytes,
                           "ERROR: One of --buy-ram, --buy-ram-kbytes or --buy-ram-bytes should have non-zero value");
               EOSC_ASSERT(client.my_err, !buy_ram_bytes_in_kbytes || !buy_ram_bytes,
                           "ERROR: --buy-ram-kbytes and --buy-ram-bytes cannot be set at the same time");
               chain::action buyram = !buy_ram_eos.empty() ? client.create_buyram(chain::name(creator),
                                                                           chain::name(account_name),
                                                                                  client.to_asset(buy_ram_eos))
                                                           : client.create_buyrambytes(chain::name(creator),
                                                                                chain::name(account_name),
                                                                                (buy_ram_bytes_in_kbytes) ? (
                                                                                      buy_ram_bytes_in_kbytes * 1024)
                                                                                                          : buy_ram_bytes);
               auto net = client.to_asset(stake_net);
               auto cpu = client.to_asset(stake_cpu);
               if (net.get_amount() != 0 || cpu.get_amount() != 0) {
                  chain::action delegate = client.create_delegate(chain::name(creator), chain::name(account_name), net, cpu,
                                                           transfer);
                  client.send_actions({create, buyram, delegate});
               } else {
                  client.send_actions({create, buyram});
               }
            } else {
               client.send_actions({create});
            }
         });
      }
   };

   struct unregister_producer_subcommand {
      string producer_str;

      unregister_producer_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto unregister_producer = actionRoot->add_subcommand("unregprod", "Unregister an existing producer");
         unregister_producer->add_option("account", producer_str,
                                         "The account to unregister as a producer")->required();
         client.add_standard_transaction_options_plus_signing(unregister_producer, "account@active");

         unregister_producer->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("producer", producer_str);

            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(producer_str), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "unregprod"_n, act_payload)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct vote_producer_proxy_subcommand {
      string voter_str;
      string proxy_str;

      vote_producer_proxy_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto vote_proxy = actionRoot->add_subcommand("proxy", "Vote your stake through a proxy");
         vote_proxy->add_option("voter", voter_str, "The voting account")->required();
         vote_proxy->add_option("proxy", proxy_str, "The proxy account")->required();
         client.add_standard_transaction_options_plus_signing(vote_proxy, "voter@active");

         vote_proxy->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter_str)
                  ("proxy", proxy_str)
                  ("producers", std::vector<chain::account_name>{});
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(voter_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "voteproducer"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct vote_producers_subcommand {
      string voter_str;
      vector<std::string> producer_names;

      vote_producers_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto vote_producers = actionRoot->add_subcommand("prods", "Vote for one or more producers");
         vote_producers->add_option("voter", voter_str, "The voting account")->required();
         vote_producers->add_option("producers", producer_names,
                                    "The account(s) to vote for. All options from this position and following will be treated as the producer list.")->required();
         client.add_standard_transaction_options_plus_signing(vote_producers, "voter@active");

         vote_producers->callback([this, &client=client] {

            std::sort(producer_names.begin(), producer_names.end());

            fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter_str)
                  ("proxy", "")
                  ("producers", producer_names);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(voter_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "voteproducer"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct approve_producer_subcommand {
      string voter;
      string producer_name;

      approve_producer_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto approve_producer = actionRoot->add_subcommand("approve", "Add one producer to list of voted producers");
         approve_producer->add_option("voter", voter, "The voting account")->required();
         approve_producer->add_option("producer", producer_name, "The account to vote for")->required();
         client.add_standard_transaction_options_plus_signing(approve_producer, "voter@active");

         approve_producer->callback([this, &client=client] {
            auto result = call(&client, get_table_func, fc::mutable_variant_object("json", true)
                  ("code", chain::name(chain::config::system_account_name).to_string())
                  ("scope", chain::name(chain::config::system_account_name).to_string())
                  ("table", "voters")
                  ("table_key", "owner")
                  ("lower_bound", chain::name(voter).to_uint64_t())
                  ("upper_bound", chain::name(voter).to_uint64_t() + 1)
                  // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                  // Change to voter.value when cleos no longer needs to support nodeos versions older than 1.5.0
                  ("limit", 1)
            );
            auto res = result.as<eosio::chain_apis::table_query::get_table_rows_result>();
            // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
            // Although since this subcommand will actually change the voter's vote, it is probably better to just keep this check to protect
            //  against future potential chain_plugin bugs.
            if (res.rows.empty() || res.rows[0].get_object()["owner"].as_string() != chain::name(voter).to_string()) {
               client.my_err << "Voter info not found for account " << voter << std::endl;
               return;
            }
            EOS_ASSERT(1 == res.rows.size(), chain::multiple_voter_info, "More than one voter_info for account");
            auto prod_vars = res.rows[0]["producers"].get_array();
            vector<chain::name> prods;
            for (auto &x: prod_vars) {
               prods.push_back(chain::name(x.as_string()));
            }
            prods.push_back(chain::name(producer_name));
            std::sort(prods.begin(), prods.end());
            auto it = std::unique(prods.begin(), prods.end());
            if (it != prods.end()) {
               client.my_err << "Producer \"" << producer_name << "\" is already on the list." << std::endl;
               return;
            }
            fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter)
                  ("proxy", "")
                  ("producers", prods);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(voter), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "voteproducer"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct unapprove_producer_subcommand {
      string voter;
      string producer_name;

      unapprove_producer_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto approve_producer = actionRoot->add_subcommand("unapprove",
                                                            "Remove one producer from list of voted producers");
         approve_producer->add_option("voter", voter, "The voting account")->required();
         approve_producer->add_option("producer", producer_name,
                                      "The account to remove from voted producers")->required();
         client.add_standard_transaction_options_plus_signing(approve_producer, "voter@active");

         approve_producer->callback([this, &client=client] {
            auto result = call(&client, get_table_func, fc::mutable_variant_object("json", true)
                  ("code", chain::name(chain::config::system_account_name).to_string())
                  ("scope", chain::name(chain::config::system_account_name).to_string())
                  ("table", "voters")
                  ("table_key", "owner")
                  ("lower_bound", chain::name(voter).to_uint64_t())
                  ("upper_bound", chain::name(voter).to_uint64_t() + 1)
                  // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                  // Change to voter.value when cleos no longer needs to support nodeos versions older than 1.5.0
                  ("limit", 1)
            );
            auto res = result.as<eosio::chain_apis::table_query::get_table_rows_result>();
            // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
            // Although since this subcommand will actually change the voter's vote, it is probably better to just keep this check to protect
            //  against future potential chain_plugin bugs.
            if (res.rows.empty() || res.rows[0].get_object()["owner"].as_string() != chain::name(voter).to_string()) {
               client.my_err << "Voter info not found for account " << voter << std::endl;
               return;
            }
            EOS_ASSERT(1 == res.rows.size(), chain::multiple_voter_info, "More than one voter_info for account");
            auto prod_vars = res.rows[0]["producers"].get_array();
            vector<chain::name> prods;
            for (auto &x: prod_vars) {
               prods.push_back(chain::name(x.as_string()));
            }
            auto it = std::remove(prods.begin(), prods.end(), chain::name(producer_name));
            if (it == prods.end()) {
               client.my_err << "Cannot remove: producer \"" << producer_name << "\" is not on the list." << std::endl;
               return;
            }
            prods.erase(it, prods.end()); //should always delete only one element
            fc::variant act_payload = fc::mutable_variant_object()
                  ("voter", voter)
                  ("proxy", "")
                  ("producers", prods);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(voter), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "voteproducer"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct list_producers_subcommand {
      bool print_json = false;
      uint32_t limit = 50;
      std::string lower;

      list_producers_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto list_producers = actionRoot->add_subcommand("listproducers", "List producers");
         list_producers->add_flag("--json,-j", print_json, "Output in JSON format");
         list_producers->add_option("-l,--limit", limit, "The maximum number of rows to return");
         list_producers->add_option("-L,--lower", lower, "Lower bound value of key, defaults to first");
         list_producers->callback([this, &client=client] {
            auto rawResult = call(&client, get_producers_func, fc::mutable_variant_object
                  ("json", true)("lower_bound", lower)("limit", limit));
            if (print_json) {
               client.my_out << fc::json::to_pretty_string(rawResult) << std::endl;
               return;
            }
            auto result = rawResult.as<eosio::chain_apis::read_only::get_producers_result>();
            if (result.rows.empty()) {
               client.my_out << "No producers found" << std::endl;
               return;
            }
            auto weight = result.total_producer_vote_weight;
            if (!weight)
               weight = 1;
            printf("%-13s %-57s %-59s %s\n", "Producer", "Producer key", "Url", "Scaled votes");
            for (auto &row: result.rows)
               printf("%-13.13s %-57.57s %-59.59s %1.4f\n",
                      row["owner"].as_string().c_str(),
                      row["producer_key"].as_string().c_str(),
                      clean_output(row["url"].as_string()).c_str(),
                      row["total_votes"].as_double() / weight);
            if (!result.more.empty())
               client.my_out << "-L " << clean_output(result.more) << " for more" << std::endl;
         });
      }
   };

   struct get_schedule_subcommand {
      bool print_json = false;

      void print(const char *name, const fc::variant &schedule) {
         if (schedule.is_null()) {
            printf("%s schedule empty\n\n", name);
            return;
         }
         printf("%s schedule version %s\n", name, schedule["version"].as_string().c_str());
         printf("    %-13s %s\n", "Producer", "Producer Authority");
         printf("    %-13s %s\n", "=============", "==================");
         for (auto &row: schedule["producers"].get_array()) {
            if (row.get_object().contains("block_signing_key")) {
               // pre 2.0
               printf("    %-13s %s\n", row["producer_name"].as_string().c_str(),
                      row["block_signing_key"].as_string().c_str());
            } else {
               printf("    %-13s ", row["producer_name"].as_string().c_str());
               auto a = row["authority"].as<chain::block_signing_authority>();
               static_assert(std::is_same<decltype(a), std::variant<chain::block_signing_authority_v0>>::value,
                             "Updates maybe needed if block_signing_authority changes");
               chain::block_signing_authority_v0 auth = std::get<chain::block_signing_authority_v0>(a);
               printf("%s\n", fc::json::to_string(auth, fc::time_point::maximum()).c_str());
            }
         }
         printf("\n");
      }

      get_schedule_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto get_schedule = actionRoot->add_subcommand("schedule", "Retrieve the producer schedule");
         get_schedule->add_flag("--json,-j", print_json, "Output in JSON format");
         get_schedule->callback([this, &client=client] {
            auto result = call(&client, get_schedule_func, fc::mutable_variant_object());
            if (print_json) {
               client.my_out << fc::json::to_pretty_string(result) << std::endl;
               return;
            }
            print("active", result["active"]);
            print("pending", result["pending"]);
            print("proposed", result["proposed"]);
         });
      }
   };

   struct get_transaction_id_subcommand {
      string trx_to_check;

      get_transaction_id_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto get_transaction_id = actionRoot->add_subcommand("transaction_id",
                                                              "Get transaction id given transaction object");
         get_transaction_id->add_option("transaction", trx_to_check,
                                        "The JSON string or filename defining the transaction which transaction id we want to retrieve")->required();

         get_transaction_id->callback([&] {
            try {
               fc::variant trx_var = client.variant_from_file_or_string(trx_to_check);
               if (trx_var.is_object()) {
                  fc::variant_object &vo = trx_var.get_object();
                  // if actions.data & actions.hex_data provided, use the hex_data since only currently support unexploded data
                  if (vo.contains("actions")) {
                     if (vo["actions"].is_array()) {
                        fc::mutable_variant_object mvo = vo;
                        fc::variants &action_variants = mvo["actions"].get_array();
                        for (auto &action_v: action_variants) {
                           if (!action_v.is_object()) {
                              client.my_err << "Empty 'action' in transaction" << endl;
                              return;
                           }
                           fc::variant_object &action_vo = action_v.get_object();
                           if (action_vo.contains("data") && action_vo.contains("hex_data")) {
                              fc::mutable_variant_object maction_vo = action_vo;
                              maction_vo["data"] = maction_vo["hex_data"];
                              action_vo = maction_vo;
                              vo = mvo;
                           } else if (action_vo.contains("data")) {
                              if (!action_vo["data"].is_string()) {
                                 client.my_err << "get transaction_id only supports un-exploded 'data' (hex form)"
                                           << std::endl;
                                 return;
                              }
                           }
                        }
                     } else {
                        client.my_err << "transaction json 'actions' is not an array" << std::endl;
                        return;
                     }
                  } else {
                     client.my_err << "transaction json does not include 'actions'" << std::endl;
                     return;
                  }
                  auto trx = trx_var.as<chain::transaction>();
                  chain::transaction_id_type id = trx.id();
                  if (id == chain::transaction().id()) {
                     client.my_err << "file/string does not represent a transaction" << std::endl;
                  } else {
                     client.my_out << string(id) << std::endl;
                  }
               } else {
                  client.my_err << "file/string does not represent a transaction" << std::endl;
               }
            } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Fail to parse transaction JSON '{data}'",
                                     ("data", trx_to_check))
         });
      }
   };

   struct delegate_bandwidth_subcommand {
      string from_str;
      string receiver_str;
      string stake_net_amount;
      string stake_cpu_amount;
      string stake_storage_amount;
      string buy_ram_amount;
      uint32_t buy_ram_bytes = 0;
      bool transfer = false;

      delegate_bandwidth_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto delegate_bandwidth = actionRoot->add_subcommand("delegatebw", "Delegate bandwidth");
         delegate_bandwidth->add_option("from", from_str, "The account to delegate bandwidth from")->required();
         delegate_bandwidth->add_option("receiver", receiver_str,
                                        "The account to receive the delegated bandwidth")->required();
         delegate_bandwidth->add_option("stake_net_quantity", stake_net_amount,
                                        "The amount of tokens to stake for network bandwidth")->required();
         delegate_bandwidth->add_option("stake_cpu_quantity", stake_cpu_amount,
                                        "The amount of tokens to stake for CPU bandwidth")->required();
         delegate_bandwidth->add_option("--buyram", buy_ram_amount, "The amount of tokens to buy RAM with");
         delegate_bandwidth->add_option("--buy-ram-bytes", buy_ram_bytes, "The amount of RAM to buy in bytes");
         delegate_bandwidth->add_flag("--transfer", transfer,
                                      "Transfer voting power and right to unstake tokens to receiver");
         client.add_standard_transaction_options_plus_signing(delegate_bandwidth, "from@active");

         delegate_bandwidth->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("stake_net_quantity", client.to_asset(stake_net_amount))
                  ("stake_cpu_quantity", client.to_asset(stake_cpu_amount))
                  ("transfer", transfer);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            std::vector<chain::action> acts{
                  client.create_action(accountPermissions, chain::config::system_account_name, "delegatebw"_n, act_payload)};
            EOSC_ASSERT(client.my_err, !(buy_ram_amount.size()) || !buy_ram_bytes,
                        "ERROR: --buyram and --buy-ram-bytes cannot be set at the same time");
            if (buy_ram_amount.size()) {
               acts.push_back(
                     client.create_buyram(chain::name(from_str), chain::name(receiver_str), client.to_asset(buy_ram_amount)));
            } else if (buy_ram_bytes) {
               acts.push_back(client.create_buyrambytes(chain::name(from_str), chain::name(receiver_str), buy_ram_bytes));
            }
            client.send_actions(std::move(acts), client.signing_keys_opt.get_keys());
         });
      }
   };

   struct undelegate_bandwidth_subcommand {
      string from_str;
      string receiver_str;
      string unstake_net_amount;
      string unstake_cpu_amount;
      uint64_t unstake_storage_bytes;

      undelegate_bandwidth_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto undelegate_bandwidth = actionRoot->add_subcommand("undelegatebw", "Undelegate bandwidth");
         undelegate_bandwidth->add_option("from", from_str, "The account undelegating bandwidth")->required();
         undelegate_bandwidth->add_option("receiver", receiver_str,
                                          "The account to undelegate bandwidth from")->required();
         undelegate_bandwidth->add_option("unstake_net_quantity", unstake_net_amount,
                                          "The amount of tokens to undelegate for network bandwidth")->required();
         undelegate_bandwidth->add_option("unstake_cpu_quantity", unstake_cpu_amount,
                                          "The amount of tokens to undelegate for CPU bandwidth")->required();
         client.add_standard_transaction_options_plus_signing(undelegate_bandwidth, "from@active");

         undelegate_bandwidth->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("unstake_net_quantity", client.to_asset(unstake_net_amount))
                  ("unstake_cpu_quantity", client.to_asset(unstake_cpu_amount));
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "undelegatebw"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct bidname_subcommand {
      string bidder_str;
      string newname_str;
      string bid_amount;

      bidname_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto bidname = actionRoot->add_subcommand("bidname", "Name bidding");
         bidname->add_option("bidder", bidder_str, "The bidding account")->required();
         bidname->add_option("newname", newname_str, "The bidding name")->required();
         bidname->add_option("bid", bid_amount, "The amount of tokens to bid")->required();
         client.add_standard_transaction_options_plus_signing(bidname, "bidder@active");

         bidname->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("bidder", bidder_str)
                  ("newname", newname_str)
                  ("bid", client.to_asset(bid_amount));
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(bidder_str), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "bidname"_n, act_payload)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct bidname_info_subcommand {
      bool print_json = false;
      string newname;

      bidname_info_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto list_producers = actionRoot->add_subcommand("bidnameinfo", "Get bidname info");
         list_producers->add_flag("--json,-j", print_json, "Output in JSON format");
         list_producers->add_option("newname", newname, "The bidding name")->required();
         list_producers->callback([this, &client=client] {
            auto rawResult = call(&client, get_table_func, fc::mutable_variant_object("json", true)
                  ("code", chain::name(chain::config::system_account_name).to_string())
                  ("scope", chain::name(chain::config::system_account_name).to_string())
                  ("table", "namebids")
                  ("lower_bound", chain::name(newname).to_uint64_t())
                  ("upper_bound", chain::name(newname).to_uint64_t() + 1)
                  // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                  // Change to newname.value when cleos no longer needs to support nodeos versions older than 1.5.0
                  ("limit", 1));
            if (print_json) {
               client.my_out << fc::json::to_pretty_string(rawResult) << std::endl;
               return;
            }
            auto result = rawResult.as<eosio::chain_apis::table_query::get_table_rows_result>();
            // Condition in if statement below can simply be res.rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
            if (result.rows.empty() ||
                result.rows[0].get_object()["newname"].as_string() != chain::name(newname).to_string()) {
               client.my_out << "No bidname record found" << std::endl;
               return;
            }
            const auto &row = result.rows[0];
            string time = row["last_bid_time"].as_string();
            try {
               time = (string) fc::time_point(fc::microseconds(fc::to_uint64(time)));
            } catch (fc::parse_error_exception &) {
            }
            int64_t bid = row["high_bid"].as_int64();
            client.my_out << std::left << std::setw(18) << "bidname:" << std::right << std::setw(24)
                      << row["newname"].as_string() << "\n"
                      << std::left << std::setw(18) << "highest bidder:" << std::right << std::setw(24)
                      << row["high_bidder"].as_string() << "\n"
                      << std::left << std::setw(18) << "highest bid:" << std::right << std::setw(24)
                      << (bid > 0 ? bid : -bid) << "\n"
                      << std::left << std::setw(18) << "last bid time:" << std::right << std::setw(24) << time
                      << std::endl;
            if (bid < 0) client.my_out << "This auction has already closed" << std::endl;
         });
      }
   };

   struct list_bw_subcommand {
      string account;
      bool print_json = false;

      list_bw_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto list_bw = actionRoot->add_subcommand("listbw", "List delegated bandwidth");
         list_bw->add_option("account", account, "The account delegated bandwidth")->required();
         list_bw->add_flag("--json,-j", print_json, "Output in JSON format");

         list_bw->callback([this, &client=client] {
            //get entire table in scope of user account
            auto result = call(&client, get_table_func, fc::mutable_variant_object("json", true)
                  ("code", chain::name(chain::config::system_account_name).to_string())
                  ("scope", chain::name(account).to_string())
                  ("table", "delband")
            );
            if (!print_json) {
               auto res = result.as<eosio::chain_apis::table_query::get_table_rows_result>();
               if (!res.rows.empty()) {
                  client.my_out << std::setw(13) << std::left << "Receiver" << std::setw(21) << std::left << "Net bandwidth"
                            << std::setw(21) << std::left << "CPU bandwidth" << std::endl;
                  for (auto &r: res.rows) {
                     client.my_out << std::setw(13) << std::left << r["to"].as_string()
                               << std::setw(21) << std::left << r["net_weight"].as_string()
                               << std::setw(21) << std::left << r["cpu_weight"].as_string()
                               << std::endl;
                  }
               } else {
                  client.my_err << "Delegated bandwidth not found" << std::endl;
               }
            } else {
               client.my_out << fc::json::to_pretty_string(result) << std::endl;
            }
         });
      }
   };

   struct buyram_subcommand {
      string from_str;
      string receiver_str;
      string amount;
      bool kbytes = false;
      bool bytes = false;

      buyram_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto buyram = actionRoot->add_subcommand("buyram", "Buy RAM");
         buyram->add_option("payer", from_str, "The account paying for RAM")->required();
         buyram->add_option("receiver", receiver_str, "The account receiving bought RAM")->required();
         buyram->add_option("amount", amount,
                            "The amount of tokens to pay for RAM, or number of bytes/kibibytes of RAM if --bytes/--kbytes is set")->required();
         buyram->add_flag("--kbytes,-k", kbytes, "The amount to buy in kibibytes (KiB)");
         buyram->add_flag("--bytes,-b", bytes, "The amount to buy in bytes");
         client.add_standard_transaction_options_plus_signing(buyram, "payer@active");
         buyram->callback([this, &client=client] {
            EOSC_ASSERT(client.my_err, !kbytes || !bytes, "ERROR: --kbytes and --bytes cannot be set at the same time");
            if (kbytes || bytes) {
               client.send_actions({client.create_buyrambytes(chain::name(from_str), chain::name(receiver_str),
                                                fc::to_uint64(amount) * ((kbytes) ? 1024ull : 1ull))},
                                   client.signing_keys_opt.get_keys());
            } else {
               client.send_actions({client.create_buyram(chain::name(from_str), chain::name(receiver_str), client.to_asset(amount))},
                                   client.signing_keys_opt.get_keys());
            }
         });
      }
   };

   struct sellram_subcommand {
      string from_str;
      string receiver_str;
      uint64_t amount;

      sellram_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto sellram = actionRoot->add_subcommand("sellram", "Sell RAM");
         sellram->add_option("account", receiver_str, "The account to receive tokens for sold RAM")->required();
         sellram->add_option("bytes", amount, "The amount of RAM bytes to sell")->required();
         client.add_standard_transaction_options_plus_signing(sellram, "account@active");

         sellram->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("account", receiver_str)
                  ("bytes", amount);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(receiver_str), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "sellram"_n, act_payload)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct claimrewards_subcommand {
      string owner;

      claimrewards_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto claim_rewards = actionRoot->add_subcommand("claimrewards", "Claim producer rewards");
         claim_rewards->add_option("owner", owner, "The account to claim rewards for")->required();
         client.add_standard_transaction_options_plus_signing(claim_rewards, "owner@active");

         claim_rewards->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, "claimrewards"_n,
                                        act_payload)}, client.signing_keys_opt.get_keys());
         });
      }
   };

   struct regproxy_subcommand {
      string proxy;

      regproxy_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto register_proxy = actionRoot->add_subcommand("regproxy", "Register an account as a proxy (for voting)");
         register_proxy->add_option("proxy", proxy, "The proxy account to register")->required();
         client.add_standard_transaction_options_plus_signing(register_proxy, "proxy@active");

         register_proxy->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("proxy", proxy)
                  ("isproxy", true);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(proxy), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "regproxy"_n, act_payload)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct unregproxy_subcommand {
      string proxy;

      unregproxy_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto unregister_proxy = actionRoot->add_subcommand("unregproxy",
                                                            "Unregister an account as a proxy (for voting)");
         unregister_proxy->add_option("proxy", proxy, "The proxy account to unregister")->required();
         client.add_standard_transaction_options_plus_signing(unregister_proxy, "proxy@active");

         unregister_proxy->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("proxy", proxy)
                  ("isproxy", false);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(proxy), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, "regproxy"_n, act_payload)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct deposit_subcommand {
      string owner_str;
      string amount_str;
      const chain::name act_name{"deposit"_n};

      deposit_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto deposit = actionRoot->add_subcommand("deposit",
                                                   "Deposit into owner's REX fund by transfering from owner's liquid token balance");
         deposit->add_option("owner", owner_str, "Account which owns the REX fund")->required();
         deposit->add_option("amount", amount_str, "Amount to be deposited into REX fund")->required();
         client.add_standard_transaction_options_plus_signing(deposit, "owner@active");
         deposit->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                                client.signing_keys_opt.get_keys());
         });
      }
   };

   struct withdraw_subcommand {
      string owner_str;
      string amount_str;
      const chain::name act_name{"withdraw"_n};

      withdraw_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto withdraw = actionRoot->add_subcommand("withdraw",
                                                    "Withdraw from owner's REX fund by transfering to owner's liquid token balance");
         withdraw->add_option("owner", owner_str, "Account which owns the REX fund")->required();
         withdraw->add_option("amount", amount_str, "Amount to be withdrawn from REX fund")->required();
         client.add_standard_transaction_options_plus_signing(withdraw, "owner@active");
         withdraw->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct buyrex_subcommand {
      string from_str;
      string amount_str;
      const chain::name act_name{"buyrex"_n};

      buyrex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto buyrex = actionRoot->add_subcommand("buyrex", "Buy REX using tokens in owner's REX fund");
         buyrex->add_option("from", from_str, "Account buying REX tokens")->required();
         buyrex->add_option("amount", amount_str,
                            "Amount to be taken from REX fund and used in buying REX")->required();
         client.add_standard_transaction_options_plus_signing(buyrex, "from@active");
         buyrex->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                                client.signing_keys_opt.get_keys());
         });
      }
   };

   struct lendrex_subcommand {
      string from_str;
      string amount_str;
      const chain::name act_name1{"deposit"_n};
      const chain::name act_name2{"buyrex"_n};

      lendrex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto lendrex = actionRoot->add_subcommand("lendrex",
                                                   "Deposit tokens to REX fund and use the tokens to buy REX");
         lendrex->add_option("from", from_str, "Account buying REX tokens")->required();
         lendrex->add_option("amount", amount_str, "Amount of liquid tokens to be used in buying REX")->required();
         client.add_standard_transaction_options_plus_signing(lendrex, "from@active");
         lendrex->callback([this, &client=client] {
            fc::variant act_payload1 = fc::mutable_variant_object()
                  ("owner", from_str)
                  ("amount", amount_str);
            fc::variant act_payload2 = fc::mutable_variant_object()
                  ("from", from_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions(
                  {client.create_action(accountPermissions, chain::config::system_account_name, act_name1, act_payload1),
                   client.create_action(accountPermissions, chain::config::system_account_name, act_name2, act_payload2)},
                  client.signing_keys_opt.get_keys());
         });
      }
   };

   struct unstaketorex_subcommand {
      string owner_str;
      string receiver_str;
      string from_net_str;
      string from_cpu_str;
      const chain::name act_name{"unstaketorex"_n};

      unstaketorex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto unstaketorex = actionRoot->add_subcommand("unstaketorex", "Buy REX using staked tokens");
         unstaketorex->add_option("owner", owner_str, "Account buying REX tokens")->required();
         unstaketorex->add_option("receiver", receiver_str, "Account that tokens have been staked to")->required();
         unstaketorex->add_option("from_net", from_net_str,
                                  "Amount to be unstaked from Net resources and used in REX purchase")->required();
         unstaketorex->add_option("from_cpu", from_cpu_str,
                                  "Amount to be unstaked from CPU resources and used in REX purchase")->required();
         client.add_standard_transaction_options_plus_signing(unstaketorex, "owner@active");
         unstaketorex->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner_str)
                  ("receiver", receiver_str)
                  ("from_net", from_net_str)
                  ("from_cpu", from_cpu_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                                client.signing_keys_opt.get_keys());
         });
      }
   };

   struct sellrex_subcommand {
      string from_str;
      string rex_str;
      const chain::name act_name{"sellrex"_n};

      sellrex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto sellrex = actionRoot->add_subcommand("sellrex", "Sell REX tokens");
         sellrex->add_option("from", from_str, "Account selling REX tokens")->required();
         sellrex->add_option("rex", rex_str, "Amount of REX tokens to be sold")->required();
         client.add_standard_transaction_options_plus_signing(sellrex, "from@active");
         sellrex->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("rex", rex_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                                client.signing_keys_opt.get_keys());
         });
      }
   };

   struct cancelrexorder_subcommand {
      string owner_str;
      const chain::name act_name{"cnclrexorder"_n};

      cancelrexorder_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto cancelrexorder = actionRoot->add_subcommand("cancelrexorder",
                                                          "Cancel queued REX sell order if one exists");
         cancelrexorder->add_option("owner", owner_str, "Owner account of sell order")->required();
         client.add_standard_transaction_options_plus_signing(cancelrexorder, "owner@active");
         cancelrexorder->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct rentcpu_subcommand {
      string from_str;
      string receiver_str;
      string loan_payment_str;
      string loan_fund_str;
      const chain::name act_name{"rentcpu"_n};

      rentcpu_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto rentcpu = actionRoot->add_subcommand("rentcpu", "Rent CPU bandwidth for 30 days");
         rentcpu->add_option("from", from_str, "Account paying rent fees")->required();
         rentcpu->add_option("receiver", receiver_str, "Account to whom rented CPU bandwidth is staked")->required();
         rentcpu->add_option("loan_payment", loan_payment_str,
                             "Loan fee to be paid, used to calculate amount of rented bandwidth")->required();
         rentcpu->add_option("loan_fund", loan_fund_str,
                             "Loan fund to be used in automatic renewal, can be 0 tokens")->required();
         client.add_standard_transaction_options_plus_signing(rentcpu, "from@active");
         rentcpu->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("loan_payment", loan_payment_str)
                  ("loan_fund", loan_fund_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct rentnet_subcommand {
      string from_str;
      string receiver_str;
      string loan_payment_str;
      string loan_fund_str;
      const chain::name act_name{"rentnet"_n};

      rentnet_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto rentnet = actionRoot->add_subcommand("rentnet", "Rent Network bandwidth for 30 days");
         rentnet->add_option("from", from_str, "Account paying rent fees")->required();
         rentnet->add_option("receiver", receiver_str,
                             "Account to whom rented Network bandwidth is staked")->required();
         rentnet->add_option("loan_payment", loan_payment_str,
                             "Loan fee to be paid, used to calculate amount of rented bandwidth")->required();
         rentnet->add_option("loan_fund", loan_fund_str,
                             "Loan fund to be used in automatic renewal, can be 0 tokens")->required();
         client.add_standard_transaction_options_plus_signing(rentnet, "from@active");
         rentnet->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("receiver", receiver_str)
                  ("loan_payment", loan_payment_str)
                  ("loan_fund", loan_fund_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct fundcpuloan_subcommand {
      string from_str;
      string loan_num_str;
      string payment_str;
      const chain::name act_name{"fundcpuloan"_n};

      fundcpuloan_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto fundcpuloan = actionRoot->add_subcommand("fundcpuloan", "Deposit into a CPU loan fund");
         fundcpuloan->add_option("from", from_str, "Loan owner")->required();
         fundcpuloan->add_option("loan_num", loan_num_str, "Loan ID")->required();
         fundcpuloan->add_option("payment", payment_str, "Amount to be deposited")->required();
         client.add_standard_transaction_options_plus_signing(fundcpuloan, "from@active");
         fundcpuloan->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("loan_num", loan_num_str)
                  ("payment", payment_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct fundnetloan_subcommand {
      string from_str;
      string loan_num_str;
      string payment_str;
      const chain::name act_name{"fundnetloan"_n};

      fundnetloan_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto fundnetloan = actionRoot->add_subcommand("fundnetloan", "Deposit into a Network loan fund");
         fundnetloan->add_option("from", from_str, "Loan owner")->required();
         fundnetloan->add_option("loan_num", loan_num_str, "Loan ID")->required();
         fundnetloan->add_option("payment", payment_str, "Amount to be deposited")->required();
         client.add_standard_transaction_options_plus_signing(fundnetloan, "from@active");
         fundnetloan->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("loan_num", loan_num_str)
                  ("payment", payment_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct defcpuloan_subcommand {
      string from_str;
      string loan_num_str;
      string amount_str;
      const chain::name act_name{"defcpuloan"_n};

      defcpuloan_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto defcpuloan = actionRoot->add_subcommand("defundcpuloan", "Withdraw from a CPU loan fund");
         defcpuloan->add_option("from", from_str, "Loan owner")->required();
         defcpuloan->add_option("loan_num", loan_num_str, "Loan ID")->required();
         defcpuloan->add_option("amount", amount_str, "Amount to be withdrawn")->required();
         client.add_standard_transaction_options_plus_signing(defcpuloan, "from@active");
         defcpuloan->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("loan_num", loan_num_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct defnetloan_subcommand {
      string from_str;
      string loan_num_str;
      string amount_str;
      const chain::name act_name{"defnetloan"_n};

      defnetloan_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto defnetloan = actionRoot->add_subcommand("defundnetloan", "Withdraw from a Network loan fund");
         defnetloan->add_option("from", from_str, "Loan owner")->required();
         defnetloan->add_option("loan_num", loan_num_str, "Loan ID")->required();
         defnetloan->add_option("amount", amount_str, "Amount to be withdrawn")->required();
         client.add_standard_transaction_options_plus_signing(defnetloan, "from@active");
         defnetloan->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("from", from_str)
                  ("loan_num", loan_num_str)
                  ("amount", amount_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(from_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct mvtosavings_subcommand {
      string owner_str;
      string rex_str;
      const chain::name act_name{"mvtosavings"_n};

      mvtosavings_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto mvtosavings = actionRoot->add_subcommand("mvtosavings", "Move REX tokens to savings bucket");
         mvtosavings->add_option("owner", owner_str, "REX owner")->required();
         mvtosavings->add_option("rex", rex_str, "Amount of REX to be moved to savings bucket")->required();
         client.add_standard_transaction_options_plus_signing(mvtosavings, "owner@active");
         mvtosavings->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner_str)
                  ("rex", rex_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct mvfrsavings_subcommand {
      string owner_str;
      string rex_str;
      const chain::name act_name{"mvfrsavings"_n};

      mvfrsavings_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto mvfrsavings = actionRoot->add_subcommand("mvfromsavings", "Move REX tokens out of savings bucket");
         mvfrsavings->add_option("owner", owner_str, "REX owner")->required();
         mvfrsavings->add_option("rex", rex_str, "Amount of REX to be moved out of savings bucket")->required();
         client.add_standard_transaction_options_plus_signing(mvfrsavings, "owner@active");
         mvfrsavings->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("owner", owner_str)
                  ("rex", rex_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct updaterex_subcommand {
      string owner_str;
      const chain::name act_name{"updaterex"_n};

      updaterex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto updaterex = actionRoot->add_subcommand("updaterex", "Update REX owner vote stake and vote weight");
         updaterex->add_option("owner", owner_str, "REX owner")->required();
         client.add_standard_transaction_options_plus_signing(updaterex, "owner@active");
         updaterex->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct consolidate_subcommand {
      string owner_str;
      const chain::name act_name{"consolidate"_n};

      consolidate_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto consolidate = actionRoot->add_subcommand("consolidate",
                                                       "Consolidate REX maturity buckets into one that matures in 4 days");
         consolidate->add_option("owner", owner_str, "REX owner")->required();
         client.add_standard_transaction_options_plus_signing(consolidate, "owner@active");
         consolidate->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct rexexec_subcommand {
      string user_str;
      string max_str;
      const chain::name act_name{"rexexec"_n};

      rexexec_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto rexexec = actionRoot->add_subcommand("rexexec",
                                                   "Perform REX maintenance by processing expired loans and unfilled sell orders");
         rexexec->add_option("user", user_str, "User executing the action")->required();
         rexexec->add_option("max", max_str,
                             "Maximum number of CPU loans, Network loans, and sell orders to be processed")->required();
         client.add_standard_transaction_options_plus_signing(rexexec, "user@active");
         rexexec->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()
                  ("user", user_str)
                  ("max", max_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(user_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct closerex_subcommand {
      string owner_str;
      const chain::name act_name{"closerex"_n};

      closerex_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto closerex = actionRoot->add_subcommand("closerex", "Delete unused REX-related user table entries");
         closerex->add_option("owner", owner_str, "REX owner")->required();
         client.add_standard_transaction_options_plus_signing(closerex, "owner@active");
         closerex->callback([this, &client=client] {
            fc::variant act_payload = fc::mutable_variant_object()("owner", owner_str);
            auto accountPermissions = client.get_account_permissions(client.tx_permission,
                                                              {chain::name(owner_str), chain::config::active_name});
            client.send_actions({client.create_action(accountPermissions, chain::config::system_account_name, act_name, act_payload)},
                         client.signing_keys_opt.get_keys());
         });
      }
   };

   struct activate_subcommand {
      string feature_name_str;

      activate_subcommand(CLI::App *actionRoot, cleos_client& client) {
         auto activate = actionRoot->add_subcommand("activate",
                                                    "Activate system feature by feature name eg: KV_DATABASE");
         activate->add_option("feature", feature_name_str,
                              "The system feature name to be activated, must be one of below(lowercase also works):\nPREACTIVATE_FEATURE\nONLY_LINK_TO_EXISTING_PERMISSION\nFORWARD_SETCODE\nKV_DATABASE\nWTMSIG_BLOCK_SIGNATURES\nREPLACE_DEFERRED\nNO_DUPLICATE_DEFERRED_ID\nRAM_RESTRICTIONS\nWEBAUTHN_KEY\nBLOCKCHAIN_PARAMETERS\nDISALLOW_EMPTY_PRODUCER_SCHEDULE\nONLY_BILL_FIRST_AUTHORIZER\nRESTRICT_ACTION_TO_SELF\nCONFIGURABLE_WASM_LIMITS\nACTION_RETURN_VALUE\nFIX_LINKAUTH_RESTRICTION\nGET_SENDER")->required();
         activate->fallthrough(false);
         activate->callback([this, &client=client] {
            /// map feature name to feature digest
            std::unordered_map<std::string, std::string> map_name_digest{
                  {"PREACTIVATE_FEATURE", "0ec7e080177b2c02b278d5088611686b49d739925a92d9bfcacd7fc6b74053bd"},
                  {"ONLY_LINK_TO_EXISTING_PERMISSION", "1a99a59d87e06e09ec5b028a9cbb7749b4a5ad8819004365d02dc4379a8b7241"},
                  {"FORWARD_SETCODE", "2652f5f96006294109b3dd0bbde63693f55324af452b799ee137a81a905eed25"},
                  {"KV_DATABASE", "825ee6288fb1373eab1b5187ec2f04f6eacb39cb3a97f356a07c91622dd61d16"},
                  {"WTMSIG_BLOCK_SIGNATURES", "299dcb6af692324b899b39f16d5a530a33062804e41f09dc97e9f156b4476707"},
                  {"REPLACE_DEFERRED", "ef43112c6543b88db2283a2e077278c315ae2c84719a8b25f25cc88565fbea99"},
                  {"NO_DUPLICATE_DEFERRED_ID", "4a90c00d55454dc5b059055ca213579c6ea856967712a56017487886a4d4cc0f"},
                  {"RAM_RESTRICTIONS", "4e7bf348da00a945489b2a681749eb56f5de00b900014e137ddae39f48f69d67"},
                  {"WEBAUTHN_KEY", "4fca8bd82bbd181e714e283f83e1b45d95ca5af40fb89ad3977b653c448f78c2"},
                  {"BLOCKCHAIN_PARAMETERS", "5443fcf88330c586bc0e5f3dee10e7f63c76c00249c87fe4fbf7f38c082006b4"},
                  {"DISALLOW_EMPTY_PRODUCER_SCHEDULE", "68dcaa34c0517d19666e6b33add67351d8c5f69e999ca1e37931bc410a297428"},
                  {"ONLY_BILL_FIRST_AUTHORIZER", "8ba52fe7a3956c5cd3a656a3174b931d3bb2abb45578befc59f283ecd816a405"},
                  {"RESTRICT_ACTION_TO_SELF", "ad9e3d8f650687709fd68f4b90b41f7d825a365b02c23a636cef88ac2ac00c43"},
                  {"CONFIGURABLE_WASM_LIMITS", "bf61537fd21c61a60e542a5d66c3f6a78da0589336868307f94a82bccea84e88"},
                  {"ACTION_RETURN_VALUE", "c3a6138c5061cf291310887c0b5c71fcaffeab90d5deb50d3b9e687cead45071"},
                  {"FIX_LINKAUTH_RESTRICTION", "e0fb64b1085cc5538970158d05a009c24e276fb94e1a0bf6a528b48fbc4ff526"},
                  {"GET_SENDER", "f0af56d2c5a48d60a4a5b5c903edfb7db3a736a94ed589d0b797df33ff9d3e1d"}
            };
            // push system feature
            string contract_account = "eosio";
            string action = "activate";
            string data;
            std::locale loc;
            vector<std::string> permissions = {"eosio"};
            for (auto &c: feature_name_str) c = std::toupper(c, loc);
            if (map_name_digest.find(feature_name_str) != map_name_digest.end()) {
               std::string feature_digest = map_name_digest[feature_name_str];
               data = "[\"" + feature_digest + "\"]";
            } else {
               client.my_out << "Can't find system feature : " << feature_name_str << std::endl;
               return;
            }
            fc::variant action_args_var;
            action_args_var = client.variant_from_file_or_string(data, fc::json::parse_type::relaxed_parser);
            auto accountPermissions = client.get_account_permissions(permissions);
            client.send_actions({chain::action{accountPermissions, chain::name(contract_account), chain::name(action),
                                        client.variant_to_bin(chain::name(contract_account), chain::name(action),
                                                       action_args_var)}}, client.signing_keys_opt.get_keys());
         });
      }
   };

   void get_account(const string &accountName, const string &coresym, bool json_format) {
      fc::variant json;
      if (coresym.empty()) {
         json = call(this, get_account_func, fc::mutable_variant_object("account_name", accountName));
      } else {
         json = call(this, get_account_func, fc::mutable_variant_object("account_name", accountName)("expected_core_symbol",
                                                                                               chain::symbol::from_string(
                                                                                                     coresym)));
      }

      auto res = json.as<eosio::chain_apis::read_only::get_account_results>();
      if (!json_format) {
         chain::asset staked;
         chain::asset unstaking;

         if (res.core_liquid_balance) {
            unstaking = chain::asset(0,
                                     res.core_liquid_balance->get_symbol()); // Correct core symbol for unstaking asset.
            staked = chain::asset(0, res.core_liquid_balance->get_symbol());    // Correct core symbol for staked asset.
         }

         my_out << "created: " << string(res.created) << std::endl;

         if (res.privileged) my_out << "privileged: true" << std::endl;

         constexpr size_t indent_size = 5;
         const string indent(indent_size, ' ');

         my_out << "permissions: " << std::endl;
         unordered_map<chain::name, vector<chain::name>/*children*/> tree;
         vector<chain::name> roots; //we don't have multiple roots, but we can easily handle them here, so let's do it just in case
         unordered_map<chain::name, eosio::chain_apis::permission> cache;
         for (auto &perm: res.permissions) {
            if (perm.parent) {
               tree[perm.parent].push_back(perm.perm_name);
            } else {
               roots.push_back(perm.perm_name);
            }
            auto name = perm.perm_name; //keep copy before moving `perm`, since thirst argument of emplace can be evaluated first
            // looks a little crazy, but should be efficient
            cache.insert(std::make_pair(name, std::move(perm)));
         }

         using dfs_fn_t = std::function<void(const eosio::chain_apis::permission &, int)>;
         std::function<void(chain::account_name, int, dfs_fn_t &)> dfs_exec = [&](chain::account_name name, int depth,
                                                                                  dfs_fn_t &f) -> void {
            auto &p = cache.at(name);

            f(p, depth);
            auto it = tree.find(name);
            if (it != tree.end()) {
               auto &children = it->second;
               sort(children.begin(), children.end());
               for (auto &n: children) {
                  // we have a tree, not a graph, so no need to check for already visited nodes
                  dfs_exec(n, depth + 1, f);
               }
            } // else it's a leaf node
         };

         dfs_fn_t print_auth = [&](const eosio::chain_apis::permission &p, int depth) -> void {
            my_out << indent << std::string(depth * 3, ' ') << p.perm_name << ' ' << std::setw(5)
                      << p.required_auth.threshold << ":    ";

            const char *sep = "";
            for (auto it = p.required_auth.keys.begin(); it != p.required_auth.keys.end(); ++it) {
               my_out << sep << it->weight << ' ' << it->key.to_string();
               sep = ", ";
            }
            for (auto &acc: p.required_auth.accounts) {
               my_out << sep << acc.weight << ' ' << acc.permission.actor.to_string() << '@'
                         << acc.permission.permission.to_string();
               sep = ", ";
            }
            my_out << std::endl;
         };
         std::sort(roots.begin(), roots.end());
         for (auto r: roots) {
            dfs_exec(r, 0, print_auth);
         }
         my_out << std::endl;

         my_out << "permission links: " << std::endl;
         dfs_fn_t print_links = [&](const eosio::chain_apis::permission &p, int) -> void {
            if (p.linked_actions) {
               if (!p.linked_actions->empty()) {
                  my_out << indent << p.perm_name.to_string() + ":" << std::endl;
                  for (auto it = p.linked_actions->begin(); it != p.linked_actions->end(); ++it) {
                     auto action_value = it->action ? it->action->to_string() : std::string("*");
                     my_out << indent << indent << it->account << "::" << action_value << std::endl;
                  }
               }
            }
         };

         for (auto r: roots) {
            dfs_exec(r, 0, print_links);
         }

         // print linked actions
         my_out << indent << "eosio.any: " << std::endl;
         for (const auto &it: res.eosio_any_linked_actions) {
            auto action_value = it.action ? it.action->to_string() : std::string("*");
            my_out << indent << indent << it.account << "::" << action_value << std::endl;
         }

         my_out << std::endl;

         auto to_pretty_net = [](int64_t nbytes, uint8_t width_for_units = 5) {
            if (nbytes == -1) {
               // special case. Treat it as unlimited
               return std::string("unlimited");
            }

            string unit = "bytes";
            double bytes = static_cast<double> (nbytes);
            if (bytes >= 1024 * 1024 * 1024 * 1024ll) {
               unit = "TiB";
               bytes /= 1024 * 1024 * 1024 * 1024ll;
            } else if (bytes >= 1024 * 1024 * 1024) {
               unit = "GiB";
               bytes /= 1024 * 1024 * 1024;
            } else if (bytes >= 1024 * 1024) {
               unit = "MiB";
               bytes /= 1024 * 1024;
            } else if (bytes >= 1024) {
               unit = "KiB";
               bytes /= 1024;
            }
            std::stringstream ss;
            ss << setprecision(4);
            ss << bytes << " ";
            if (width_for_units > 0)
               ss << std::left << setw(width_for_units);
            ss << unit;
            return ss.str();
         };


         my_out << "memory: " << std::endl
                   << indent << "quota: " << std::setw(15) << to_pretty_net(res.ram_quota) << "  used: "
                   << std::setw(15) << to_pretty_net(res.ram_usage) << std::endl << std::endl;

         my_out << "net bandwidth: " << std::endl;
         if (res.total_resources.is_object()) {
            auto net_total = to_asset(res.total_resources.get_object()["net_weight"].as_string());

            if (net_total.get_symbol() != unstaking.get_symbol()) {
               // Core symbol of nodeos responding to the request is different than core symbol built into cleos
               unstaking = chain::asset(0, net_total.get_symbol()); // Correct core symbol for unstaking asset.
               staked = chain::asset(0, net_total.get_symbol()); // Correct core symbol for staked asset.
            }

            if (res.self_delegated_bandwidth.is_object()) {
               chain::asset net_own = chain::asset::from_string(
                     res.self_delegated_bandwidth.get_object()["net_weight"].as_string());
               staked = net_own;

               auto net_others = net_total - net_own;

               my_out << indent << "staked:" << std::setw(20) << net_own
                         << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                         << indent << "delegated:" << std::setw(17) << net_others
                         << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
            } else {
               auto net_others = net_total;
               my_out << indent << "delegated:" << std::setw(17) << net_others
                         << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
            }
         }


         auto to_pretty_time = [](int64_t nmicro, uint8_t width_for_units = 5) {
            if (nmicro == -1) {
               // special case. Treat it as unlimited
               return std::string("unlimited");
            }
            string unit = "us";
            double micro = static_cast<double>(nmicro);

            if (micro > 1000000 * 60 * 60ll) {
               micro /= 1000000 * 60 * 60ll;
               unit = "hr";
            } else if (micro > 1000000 * 60) {
               micro /= 1000000 * 60;
               unit = "min";
            } else if (micro > 1000000) {
               micro /= 1000000;
               unit = "sec";
            } else if (micro > 1000) {
               micro /= 1000;
               unit = "ms";
            }
            std::stringstream ss;
            ss << setprecision(4);
            ss << micro << " ";
            if (width_for_units > 0)
               ss << std::left << setw(width_for_units);
            ss << unit;
            return ss.str();
         };

         my_out << std::fixed << setprecision(3);
         my_out << indent << std::left << std::setw(11) << "used:" << std::right << std::setw(18);
         if (res.net_limit.current_used) {
            my_out << to_pretty_net(*res.net_limit.current_used) << "\n";
         } else {
            my_out << to_pretty_net(res.net_limit.used) << "    ( out of date )\n";
         }
         my_out << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18)
                   << to_pretty_net(res.net_limit.available) << "\n";
         my_out << indent << std::left << std::setw(11) << "limit:" << std::right << std::setw(18)
                   << to_pretty_net(res.net_limit.max) << "\n";
         my_out << std::endl;

         my_out << "cpu bandwidth:" << std::endl;

         if (res.total_resources.is_object()) {
            auto cpu_total = to_asset(res.total_resources.get_object()["cpu_weight"].as_string());

            if (res.self_delegated_bandwidth.is_object()) {
               chain::asset cpu_own = chain::asset::from_string(
                     res.self_delegated_bandwidth.get_object()["cpu_weight"].as_string());
               staked += cpu_own;

               auto cpu_others = cpu_total - cpu_own;

               my_out << indent << "staked:" << std::setw(20) << cpu_own
                         << std::string(11, ' ') << "(total stake delegated from account to self)" << std::endl
                         << indent << "delegated:" << std::setw(17) << cpu_others
                         << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
            } else {
               auto cpu_others = cpu_total;
               my_out << indent << "delegated:" << std::setw(17) << cpu_others
                         << std::string(11, ' ') << "(total staked delegated to account from others)" << std::endl;
            }
         }

         my_out << std::fixed << setprecision(3);
         my_out << indent << std::left << std::setw(11) << "used:" << std::right << std::setw(18);
         if (res.cpu_limit.current_used) {
            my_out << to_pretty_time(*res.cpu_limit.current_used) << "\n";
         } else {
            my_out << to_pretty_time(res.cpu_limit.used) << "    ( out of date )\n";
         }
         my_out << indent << std::left << std::setw(11) << "available:" << std::right << std::setw(18)
                   << to_pretty_time(res.cpu_limit.available) << "\n";
         my_out << indent << std::left << std::setw(11) << "limit:" << std::right << std::setw(18)
                   << to_pretty_time(res.cpu_limit.max) << "\n";
         my_out << std::endl;

         if (res.refund_request.is_object()) {
            auto obj = res.refund_request.get_object();
            auto request_time = fc::time_point_sec::from_iso_string(obj["request_time"].as_string());
            fc::time_point refund_time = request_time + fc::days(3);
            auto now = res.head_block_time;
            chain::asset net = chain::asset::from_string(obj["net_amount"].as_string());
            chain::asset cpu = chain::asset::from_string(obj["cpu_amount"].as_string());
            unstaking = net + cpu;

            if (unstaking > chain::asset(0, unstaking.get_symbol())) {
               my_out << std::fixed << setprecision(3);
               my_out << "unstaking tokens:" << std::endl;
               my_out << indent << std::left << std::setw(25) << "time of unstake request:" << std::right
                         << std::setw(20) << string(request_time);
               if (now >= refund_time) {
                  my_out << " (available to claim now with 'eosio::refund' action)\n";
               } else {
                  my_out << " (funds will be available in " << to_pretty_time((refund_time - now).count(), 0)
                            << ")\n";
               }
               my_out << indent << std::left << std::setw(25) << "from net bandwidth:" << std::right << std::setw(18)
                         << net << std::endl;
               my_out << indent << std::left << std::setw(25) << "from cpu bandwidth:" << std::right << std::setw(18)
                         << cpu << std::endl;
               my_out << indent << std::left << std::setw(25) << "total:" << std::right << std::setw(18) << unstaking
                         << std::endl;
               my_out << std::endl;
            }
         }

         if (res.core_liquid_balance) {
            my_out << res.core_liquid_balance->get_symbol().name() << " balances: " << std::endl;
            my_out << indent << std::left << std::setw(11)
                      << "liquid:" << std::right << std::setw(18) << *res.core_liquid_balance << std::endl;
            my_out << indent << std::left << std::setw(11)
                      << "staked:" << std::right << std::setw(18) << staked << std::endl;
            my_out << indent << std::left << std::setw(11)
                      << "unstaking:" << std::right << std::setw(18) << unstaking << std::endl;
            my_out << indent << std::left << std::setw(11) << "total:" << std::right << std::setw(18)
                      << (*res.core_liquid_balance + staked + unstaking) << std::endl;
            my_out << std::endl;
         }

         if (res.rex_info.is_object()) {
            auto &obj = res.rex_info.get_object();
            chain::asset vote_stake = chain::asset::from_string(obj["vote_stake"].as_string());
            chain::asset rex_balance = chain::asset::from_string(obj["rex_balance"].as_string());
            my_out << rex_balance.get_symbol().name() << " balances: " << std::endl;
            my_out << indent << std::left << std::setw(11)
                      << "balance:" << std::right << std::setw(18) << rex_balance << std::endl;
            my_out << indent << std::left << std::setw(11)
                      << "staked:" << std::right << std::setw(18) << vote_stake << std::endl;
            my_out << std::endl;
         }

         if (res.voter_info.is_object()) {
            auto &obj = res.voter_info.get_object();
            string proxy = obj["proxy"].as_string();
            if (proxy.empty()) {
               auto &prods = obj["producers"].get_array();
               my_out << "producers:";
               if (!prods.empty()) {
                  for (size_t i = 0; i < prods.size(); ++i) {
                     if (i % 3 == 0) {
                        my_out << std::endl << indent;
                     }
                     my_out << std::setw(16) << std::left << prods[i].as_string();
                  }
                  my_out << std::endl;
               } else {
                  my_out << indent << "<not voted>" << std::endl;
               }
            } else {
               my_out << "proxy:" << indent << proxy << std::endl;
            }
         }
         my_out << std::endl;
      } else {
         my_out << fc::json::to_pretty_string(json) << std::endl;
      }
   }

   bool header_opt_callback(CLI::results_t res) {
      vector<string>::iterator itr;

      for (itr = res.begin(); itr != res.end(); itr++) {
         headers.push_back(*itr);
      }

      return true;
   };

   bool abi_files_overide_callback(CLI::results_t account_abis) {
      for (vector<string>::iterator itr = account_abis.begin(); itr != account_abis.end(); ++itr) {
         size_t delim = itr->find(":");
         std::string acct_name, abi_path;
         if (delim != std::string::npos) {
            acct_name = itr->substr(0, delim);
            abi_path = itr->substr(delim + 1);
         }
         if (acct_name.length() == 0 || abi_path.length() == 0) {
            my_err << "please specify --abi-file in form of <contract name>:<abi file path>.";
            return false;
         }
         abi_files_override[chain::name(acct_name)] = abi_path;
      }
      return true;
   };

   bool find_and_replace_default_config_file_and_default_url_callback(const CLI::results_t &res) {
      if (res.size() == 0) return false;
      CLI::detail::lexical_conversion<std::string, std::string>(res, default_config_file);
      config_json_data config_jd;

      // check config json file exist
      if (!boost::filesystem::exists(default_config_file)) {
         my_err << "Can't find config file " << default_config_file << std::endl;
         my_err << "Config file can't be found\n";
         return false;
      }

      fc::json::from_file(default_config_file).as<config_json_data>(config_jd);
      if (config_jd.default_url.length() > 0) {
         default_url = config_jd.default_url;
      }

      return true;
   };

   bool find_and_replace_alias_with_url_callback(const CLI::results_t &res) {
      if (res.size() == 0) return false;
      CLI::detail::lexical_conversion<std::string, std::string>(res, server_alias);
      config_json_data config_jd;
      if (server_alias.length() > 0) {
         // check config json file exist
         if (!boost::filesystem::exists(default_config_file)) {
            my_err << "Can't find config file " << default_config_file << std::endl;
            my_err << "Config file can't be found\n";
            return false;
         }

         bool is_alias_found = false;
         fc::json::from_file(default_config_file).as<config_json_data>(config_jd);
         for (const auto &aup: config_jd.aups) {
            if (aup.alias == server_alias) {
               default_url = aup.url;
               is_alias_found = true;
               break;
            }
         }
         if (!is_alias_found) {
            my_err << "Can't find alias " << server_alias << " in the config file " << default_config_file
                      << ", please make sure the alias you input after -a is exist in the config file." << std::endl;
            my_err << "Alias can't be found\n";
            return false;
         }
      }
      return true;
   };

   int cleos(int argc, const char **argv) {
      context = eosio::client::http::create_http_context();
      wallet_url = default_wallet_url;

      CLI::App app{"Command Line Interface to EOSIO Client"};
      app.require_subcommand();
      // Hide obsolete options by putting them into a group with an empty name.
      app.add_option("-H,--host", [this](auto& res){return this->obsoleted_option_host_port(res);},
                     fmt::format("The host where {n} is running", fmt::arg("n", node_executable_name)))->group("");
      app.add_option("-p,--port", [this](auto& res){return this->cleos_client::obsoleted_option_host_port(res);},
                     fmt::format("The port where {n} is running", fmt::arg("n", node_executable_name)))->group("");
      app.add_option("--wallet-host", [this](auto& res){return this->cleos_client::obsoleted_option_host_port(res);},
                     fmt::format("The host where {k} is running", fmt::arg("k", key_store_executable_name)))->group("");
      app.add_option("--wallet-port", [this](auto& res){return this->cleos_client::obsoleted_option_host_port(res);},
                     fmt::format("The port where {k} is running", fmt::arg("k", key_store_executable_name)))->group("");

      app.add_option("-u,--url", default_url,
                     fmt::format("The http/https URL where {n} is running", fmt::arg("n", node_executable_name)), true);
      app.add_option("--wallet-url", wallet_url,
                     fmt::format("The http/https URL where {k} is running", fmt::arg("k", key_store_executable_name)),
                     true);
      app.add_option("-c, --config", [this](auto& res){return this->find_and_replace_default_config_file_and_default_url_callback(res);},
                     "The config file which have alias url pairs so as to using short alias instead of long url in cleos command line",
                     true);
      app.add_option("-a, --alias", [this](auto& res){return this->find_and_replace_alias_with_url_callback(res);},
                     "The server alias to use which must be in the config file, if use this option, don't use -u",
                     true);
      app.add_option("--abi-file", [this](auto& res){return this->abi_files_overide_callback(res);},
                     "In form of <contract name>:<abi file path>, use a local abi file for serialization and deserialization instead of getting the abi data from the blockchain; repeat this option to pass multiple abi files for different contracts")->type_size(
            0, 1000);

      app.add_option("--amqp", amqp_address, "The ampq URL where AMQP is running amqp://USER:PASSWORD@ADDRESS:PORT",
                     false)->envname(EOSIO_AMQP_ADDRESS_ENV_VAR);
      app.add_option("--amqp-queue-name", amqp_queue_name, "The ampq queue to send transaction to", true);
      app.add_option("--amqp-reply-to", amqp_reply_to,
                     "The ampq reply to string, can be the pseudo direct reply-to queue or a normal queue from which cleos may consume all messages away",
                     false);

      app.add_option("-r,--header", [this](auto& res){return this->header_opt_callback(res);},
                     "Pass specific HTTP header; repeat this option to pass multiple headers");
      app.add_flag("-n,--no-verify", no_verify, "Don't verify peer certificate when using HTTPS");
      app.add_flag("--no-auto-" + string(key_store_executable_name), no_auto_keosd,
                   fmt::format("Don't automatically launch a {k} if one is not currently running",
                               fmt::arg("k", key_store_executable_name)));
      app.parse_complete_callback([&app, this] { this->ensure_keosd_running(&app); });

      app.add_flag("-v,--verbose", verbose, "Output verbose errors and action console output");
      app.add_flag("--print-request", print_request, "Print HTTP request to STDERR");
      app.add_flag("--print-response", print_response, "Print HTTP response to STDERR");

      if (boost::filesystem::exists(default_config_file)) {
         config_json_data config_jd;
         fc::json::from_file(default_config_file).as<config_json_data>(config_jd);
         if (config_jd.default_url.length() > 0) default_url = config_jd.default_url;
      }

      auto version = app.add_subcommand("version", "Retrieve version information");
      version->require_subcommand();

      version->add_subcommand("client", "Retrieve basic version information of the client")->callback([this] {
         my_out << eosio::version::version_client() << '\n';
      });

      version->add_subcommand("full", "Retrieve full version information of the client")->callback([this] {
         my_out << eosio::version::version_full() << '\n';
      });

      // Create subcommand
      auto create = app.add_subcommand("create", "Create various items, on and off the blockchain");
      create->require_subcommand();

      bool r1 = false;
      string key_file;
      bool print_console = false;
      // create key
      auto create_key = create->add_subcommand("key",
                                               "Create a new keypair and print the public and private keys")->callback(
            [this, &r1, &key_file, &print_console]() {
               if (key_file.empty() && !print_console) {
                  my_err << "ERROR: Either indicate a file using \"--file\" or pass \"--to-console\"" << std::endl;
                  return;
               }

               auto pk = r1 ? chain::private_key_type::generate_r1() : chain::private_key_type::generate();
               auto privs = pk.to_string();
               auto pubs = pk.get_public_key().to_string();
               if (print_console) {
                  my_out << "Private key: " << privs << std::endl;
                  my_out << "Public key: " << pubs << std::endl;
               } else {
                  my_err << "saving keys to " << key_file << std::endl;
                  std::ofstream out(key_file.c_str());
                  out << "Private key: " << privs << std::endl;
                  out << "Public key: " << pubs << std::endl;
               }
            });
      create_key->add_flag("--r1", r1, "Generate a key using the R1 curve (iPhone), instead of the K1 curve (Bitcoin)");
      create_key->add_option("-f,--file", key_file,
                             "Name of file to write private/public key output to. (Must be set, unless \"--to-console\" is passed");
      create_key->add_flag("--to-console", print_console, "Print private/public keys to console.");

      // create account
      auto createAccount = create_account_subcommand(create, true /*simple*/, *this);

      // convert subcommand
      auto convert = app.add_subcommand("convert",
                                        "Pack and unpack transactions"); // TODO also add converting action args based on abi from here ?
      convert->require_subcommand();

      // pack transaction
      string plain_signed_transaction_json;
      bool pack_action_data_flag = false;
      auto pack_transaction = convert->add_subcommand("pack_transaction", "From plain signed JSON to packed form");
      pack_transaction->add_option("transaction", plain_signed_transaction_json,
                                   "The plain signed JSON (string)")->required();
      pack_transaction->add_flag("--pack-action-data", pack_action_data_flag,
                                 fmt::format("Pack all action data within transaction, needs interaction with {n}",
                                             fmt::arg("n", node_executable_name)));
      pack_transaction->callback([&] {
         fc::variant trx_var = variant_from_file_or_string(plain_signed_transaction_json);
         if (pack_action_data_flag) {
            chain::signed_transaction trx;
            try {
               chain::abi_serializer::from_variant(trx_var, trx, [&](const chain::name &account){return this->abi_serializer_resolver(account);},
                                                   chain::abi_serializer::create_yield_function(
                                                         abi_serializer_max_time));
            } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid transaction format: '{data}'",
                                     ("data", fc::json::to_string(trx_var, fc::time_point::maximum())))
            my_out << fc::json::to_pretty_string(
                  chain::packed_transaction_v0(trx, chain::packed_transaction_v0::compression_type::none)) << std::endl;
         } else {
            try {
               chain::signed_transaction trx = trx_var.as<chain::signed_transaction>();
               my_out << fc::json::to_pretty_string(fc::variant(
                     chain::packed_transaction_v0(trx, chain::packed_transaction_v0::compression_type::none)))
                         << std::endl;
            } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception,
                                     "Fail to convert transaction, --pack-action-data likely needed")
         }
      });

      // unpack transaction
      string packed_transaction_json;
      bool unpack_action_data_flag = false;
      auto unpack_transaction = convert->add_subcommand("unpack_transaction", "From packed to plain signed JSON form");
      unpack_transaction->add_option("transaction", packed_transaction_json,
                                     "The packed transaction JSON (string containing packed_trx and optionally compression fields)")->required();
      unpack_transaction->add_flag("--unpack-action-data", unpack_action_data_flag,
                                   fmt::format("Unpack all action data within transaction, needs interaction with {n}",
                                               fmt::arg("n", node_executable_name)));
      unpack_transaction->callback([&] {
         fc::variant packed_trx_var = variant_from_file_or_string(packed_transaction_json);
         chain::packed_transaction_v0 packed_trx;
         try {
            fc::from_variant<chain::packed_transaction_v0>(packed_trx_var, packed_trx);
         } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid packed transaction format: '{data}'",
                                  ("data", fc::json::to_string(packed_trx_var, fc::time_point::maximum())))
         const chain::signed_transaction &strx = packed_trx.get_signed_transaction();
         fc::variant trx_var;
         if (unpack_action_data_flag) {
            chain::abi_serializer::to_variant(strx, trx_var, [&](const chain::name &account){return this->abi_serializer_resolver(account);},
                                              chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         } else {
            trx_var = strx;
         }
         my_out << fc::json::to_pretty_string(trx_var) << std::endl;
      });

      // pack action data
      string unpacked_action_data_account_string;
      string unpacked_action_data_name_string;
      string unpacked_action_data_string;
      auto pack_action_data = convert->add_subcommand("pack_action_data", "From JSON action data to packed form");
      pack_action_data->add_option("account", unpacked_action_data_account_string,
                                   "The name of the account hosting the contract")->required();
      pack_action_data->add_option("name", unpacked_action_data_name_string,
                                   "The name of the function called by this action")->required();
      pack_action_data->add_option("unpacked_action_data", unpacked_action_data_string,
                                   "The action data expressed as JSON")->required();
      pack_action_data->callback([&] {
         std::string unpacked_action_data_json = json_from_file_or_string(unpacked_action_data_string);
         chain::bytes packed_action_data_string = action_json_to_bin(chain::name(unpacked_action_data_account_string),
                                                                     chain::name(unpacked_action_data_name_string),
                                                                     unpacked_action_data_json);
         my_out << fc::to_hex(packed_action_data_string.data(), packed_action_data_string.size()) << std::endl;
      });

      // unpack action data
      string packed_action_data_account_string;
      string packed_action_data_name_string;
      string packed_action_data_string;
      auto unpack_action_data = convert->add_subcommand("unpack_action_data", "From packed to JSON action data form");
      unpack_action_data->add_option("account", packed_action_data_account_string,
                                     "The name of the account that hosts the contract")->required();
      unpack_action_data->add_option("name", packed_action_data_name_string,
                                     "The name of the function that's called by this action")->required();
      unpack_action_data->add_option("packed_action_data", packed_action_data_string,
                                     "The action data expressed as packed hex string")->required();
      unpack_action_data->callback([&] {
         EOS_ASSERT(packed_action_data_string.size() >= 2, chain::transaction_type_exception,
                    "No packed_action_data found");
         vector<char> packed_action_data_blob(packed_action_data_string.size() / 2);
         fc::from_hex(packed_action_data_string, packed_action_data_blob.data(), packed_action_data_blob.size());
         fc::variant unpacked_action_data_json = bin_to_variant(chain::name(packed_action_data_account_string),
                                                                chain::name(packed_action_data_name_string),
                                                                packed_action_data_blob);
         my_out << fc::json::to_pretty_string(unpacked_action_data_json) << std::endl;
      });

      // validate subcommand
      auto validate = app.add_subcommand("validate", "Validate transactions");
      validate->require_subcommand();

      // validate signatures
      string trx_json_to_validate;
      string str_chain_id;
      auto validate_signatures = validate->add_subcommand("signatures", "Validate signatures and recover public keys");
      validate_signatures->add_option("transaction", trx_json_to_validate,
                                      "The JSON string or filename defining the transaction to validate",
                                      true)->required();
      validate_signatures->add_option("-c,--chain-id", str_chain_id,
                                      "The chain id that will be used in signature verification");

      validate_signatures->callback([&] {
         fc::variant trx_var = variant_from_file_or_string(trx_json_to_validate);
         chain::signed_transaction trx;
         try {
            chain::abi_serializer::from_variant(trx_var, trx, [&](const chain::name &account){return this->abi_serializer_resolver_empty(account);},
                                                chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid transaction format: '{data}'",
                                  ("data", fc::json::to_string(trx_var, fc::time_point::maximum())))

         std::optional<chain::chain_id_type> chain_id;

         if (str_chain_id.size() == 0) {
            auto info = get_info();
            chain_id = info.chain_id;
         } else {
            chain_id = chain::chain_id_type(str_chain_id);
         }

         fc::flat_set<chain::public_key_type> recovered_pub_keys;
         trx.get_signature_keys(*chain_id, fc::time_point::maximum(), recovered_pub_keys, false);

         my_out << fc::json::to_pretty_string(recovered_pub_keys) << std::endl;
      });

      // Get subcommand
      auto get = app.add_subcommand("get", "Retrieve various items and information from the blockchain");
      get->require_subcommand();

      // get info
      get->add_subcommand("info", "Get current blockchain information")->callback([this] {
         my_out << fc::json::to_pretty_string(this->get_info()) << std::endl;
      });

      // get consensus parameters
      get->add_subcommand("consensus_parameters", "Get current blockchain consensus parameters")->callback([this] {
         my_out << fc::json::to_pretty_string(this->get_consensus_parameters()) << std::endl;
      });

      // get block
      string blockArg;
      bool get_bhs = false;
      bool get_binfo = false;
      auto getBlock = get->add_subcommand("block", "Retrieve a full block from the blockchain");
      getBlock->add_option("block", blockArg, "The number or ID of the block to retrieve")->required();
      getBlock->add_flag("--header-state", get_bhs, "Get block header state from fork database instead");
      getBlock->add_flag("--info", get_binfo, "Get block info from the blockchain by block num only");
      getBlock->callback([&blockArg, &get_bhs, &get_binfo, this] {
         EOSC_ASSERT(my_err, !(get_bhs && get_binfo), "ERROR: Either --header-state or --info can be set");
         if (get_binfo) {
            std::optional<int64_t> block_num;
            try {
               block_num = fc::to_int64(blockArg);
            } catch (...) {
               // error is handled in assertion below
            }
            EOSC_ASSERT(my_err, block_num && (*block_num > 0), "Invalid block num: {block_num}", ("block_num", blockArg));
            const auto arg = fc::variant_object("block_num", static_cast<uint32_t>(*block_num));
            my_out << fc::json::to_pretty_string(call(this, get_block_info_func, arg)) << std::endl;
         } else {
            const auto arg = fc::variant_object("block_num_or_id", blockArg);
            if (get_bhs) {
               my_out << fc::json::to_pretty_string(call(this, get_block_header_state_func, arg)) << std::endl;
            } else {
               my_out << fc::json::to_pretty_string(call(this, get_block_func, arg)) << std::endl;
            }
         }
      });

      // get account
      string accountName;
      string coresym;
      bool print_json = false;
      auto getAccount = get->add_subcommand("account", "Retrieve an account from the blockchain");
      getAccount->add_option("name", accountName, "The name of the account to retrieve")->required();
      getAccount->add_option("core-symbol", coresym, "The expected core symbol of the chain you are querying");
      getAccount->add_flag("--json,-j", print_json, "Output in JSON format");
      getAccount->callback([&]() { get_account(accountName, coresym, print_json); });

      // get code
      string codeFilename;
      string abiFilename;
      bool code_as_wasm = true;
      auto getCode = get->add_subcommand("code", "Retrieve the code and ABI for an account");
      getCode->add_option("name", accountName, "The name of the account whose code should be retrieved")->required();
      getCode->add_option("-c,--code", codeFilename, "The name of the file to save the contract wasm to");
      getCode->add_option("-a,--abi", abiFilename, "The name of the file to save the contract .abi to");
      getCode->add_flag("--wasm", code_as_wasm, "Save contract as wasm (ignored, default)");
      getCode->callback([&] {
         string code_hash, wasm, abi;
         try {
            const auto result = call(this, get_raw_code_and_abi_func,
                                     fc::mutable_variant_object("account_name", accountName));
            const std::vector<char> wasm_v = result["wasm"].as_blob().data;
            const std::vector<char> abi_v = result["abi"].as_blob().data;

            fc::sha256 hash;
            if (wasm_v.size())
               hash = fc::sha256::hash(wasm_v.data(), wasm_v.size());
            code_hash = (string) hash;

            wasm = string(wasm_v.begin(), wasm_v.end());
            abi = fc::json::pretty_print(eosio::abi_def::bin_to_json({abi_v.data(), abi_v.size()}), 2);
         }
         catch (chain::missing_chain_api_plugin_exception &) {
            //see if this is an old nodeos that doesn't support get_raw_code_and_abi
            const auto old_result = call(this, get_code_func,
                                         fc::mutable_variant_object("account_name", accountName)("code_as_wasm",
                                                                                                 code_as_wasm));
            code_hash = old_result["code_hash"].as_string();
            wasm = old_result["wasm"].as_string();
            my_out << "Warning: communicating to older " << node_executable_name
                      << " which returns malformed binary wasm" << std::endl;
            auto old_result_abi = old_result["abi"].as_blob().data;
            abi = fc::json::pretty_print(eosio::abi_def::bin_to_json({old_result_abi.data(), old_result_abi.size()}),
                                         2);
         }

         my_out << "code hash: " << code_hash << std::endl;

         if (codeFilename.size()) {
            my_out << "saving wasm to " << codeFilename << std::endl;

            std::ofstream out(codeFilename.c_str());
            out << wasm;
         }
         if (abiFilename.size()) {
            my_out << "saving abi to " << abiFilename << std::endl;
            std::ofstream abiout(abiFilename.c_str());
            abiout << abi;
         }
      });

      // get abi
      string filename;
      auto getAbi = get->add_subcommand("abi", "Retrieve the ABI for an account");
      getAbi->add_option("name", accountName, "The name of the account whose abi should be retrieved")->required();
      getAbi->add_option("-f,--file", filename,
                         "The name of the file to save the contract .abi to instead of writing to console");
      getAbi->callback([&] {
         const auto raw_abi_result = call(this, get_raw_abi_func, fc::mutable_variant_object("account_name", accountName));
         const auto raw_abi_blob = raw_abi_result["abi"].as_blob().data;
         if (raw_abi_blob.size() != 0) {
            const auto abi = fc::json::pretty_print(
                  eosio::abi_def::bin_to_json({raw_abi_blob.data(), raw_abi_blob.size()}), 2);
            if (filename.size()) {
               my_err << "saving abi to " << filename << std::endl;
               std::ofstream abiout(filename.c_str());
               abiout << abi;
            } else {
               my_out << abi << "\n";
            }
         } else {
            FC_THROW_EXCEPTION(chain::key_not_found_exception, "Key {key}", ("key", "abi"));
         }
      });

      // get table
      string scope;
      string code;
      string table;
      string lower;
      string upper;
      string table_key;
      string key_type;
      string encode_type{"dec"};
      bool binary = false;
      uint32_t limit = 10;
      string index_position;
      bool reverse = false;
      bool show_payer = false;
      auto getTable = get->add_subcommand("table", "Retrieve the contents of a database table");
      getTable->add_option("account", code, "The account who owns the table")->required();
      getTable->add_option("scope", scope, "The scope within the contract in which the table is found")->required();
      getTable->add_option("table", table, "The name of the table as specified by the contract abi")->required();
      getTable->add_option("-l,--limit", limit, "The maximum number of rows to return");
      getTable->add_option("-k,--key", table_key, "Deprecated");
      getTable->add_option("-L,--lower", lower, "JSON representation of lower bound value of key, defaults to first");
      getTable->add_option("-U,--upper", upper, "JSON representation of upper bound value of key, defaults to last");
      getTable->add_option("--index", index_position,
                           "Index number, 1 - primary (first), 2 - secondary index (in order defined by multi_index), 3 - third index, etc.\n"
                           "\t\t\t\tNumber or name of index can be specified, e.g. 'secondary' or '2'.");
      getTable->add_option("--key-type", key_type,
                           "The key type of --index, primary only supports (i64), all others support (i64, i128, i256, float64, float128, ripemd160, sha256).\n"
                           "\t\t\t\tSpecial type 'name' indicates an account name.");
      getTable->add_option("--encode-type", encode_type,
                           "The encoding type of key_type (i64 , i128 , float64, float128) only support decimal encoding e.g. 'dec'"
                           "i256 - supports both 'dec' and 'hex', ripemd160 and sha256 is 'hex' only");
      getTable->add_flag("-b,--binary", binary,
                         "Return the value as BINARY rather than using abi to interpret as JSON");
      getTable->add_flag("-r,--reverse", reverse, "Iterate in reverse order");
      getTable->add_flag("--show-payer", show_payer, "Show RAM payer");


      getTable->callback([&] {
         auto result = call(this, get_table_func, fc::mutable_variant_object("json", !binary)
               ("code", code)
               ("scope", scope)
               ("table", table)
               ("table_key", table_key) // not used
               ("lower_bound", lower)
               ("upper_bound", upper)
               ("limit", limit)
               ("key_type", key_type)
               ("index_position", index_position)
               ("encode_type", encode_type)
               ("reverse", reverse)
               ("show_payer", show_payer)
         );

         my_out << fc::json::to_pretty_string(result)
                   << std::endl;
      });

      // get kv_table
      string index_name;
      string index_value;
      encode_type = "bytes";
      auto getKvTable = get->add_subcommand("kv_table", "Retrieve the contents of a database kv_table");
      getKvTable->add_option("account", code, "The account who owns the table")->required();
      getKvTable->add_option("table", table, "The name of the kv_table as specified by the contract abi")->required();
      getKvTable->add_option("index_name", index_name,
                             "The name of the kv_table index as specified by the contract abi")->required();
      getKvTable->add_option("-l,--limit", limit, "The maximum number of rows to return");
      getKvTable->add_option("-i,--index", index_value, "Index value");
      getKvTable->add_option("-L,--lower", lower, "lower bound value of index, optional with -r");
      getKvTable->add_option("-U,--upper", upper, "upper bound value of index, optional without -r");
      getKvTable->add_option("--encode-type", encode_type,
                             "The encoding type of index_value, lower bound, upper bound"
                             " 'bytes' for hexdecimal encoded bytes"
                             " 'string' for string value"
                             " 'dec' for decimal encoding of (uint[64|32|16|8], int[64|32|16|8], float64)"
                             " 'hex' for hexdecimal encoding of (uint[64|32|16|8], int[64|32|16|8], sha256, ripemd160");
      getKvTable->add_flag("-b,--binary", binary,
                           "Return the value as BINARY rather than using abi to interpret as JSON");
      getKvTable->add_flag("-r,--reverse", reverse, "Iterate in reverse order");
      getKvTable->add_flag("--show-payer", show_payer, "Show RAM payer");


      getKvTable->callback([&] {
         auto result = call(this, get_kv_table_func, fc::mutable_variant_object("json", !binary)
               ("code", code)
               ("table", table)
               ("index_name", index_name)
               ("index_value", index_value)
               ("lower_bound", lower)
               ("upper_bound", upper)
               ("limit", limit)
               ("encode_type", encode_type)
               ("reverse", reverse)
               ("show_payer", show_payer)
         );

         my_out << fc::json::to_pretty_string(result)
                   << std::endl;
      });

      auto getScope = get->add_subcommand("scope", "Retrieve a list of scopes and tables owned by a contract");
      getScope->add_option("contract", code, "The contract who owns the table")->required();
      getScope->add_option("-t,--table", table, "The name of the table as filter");
      getScope->add_option("-l,--limit", limit, "The maximum number of rows to return");
      getScope->add_option("-L,--lower", lower, "Lower bound of scope");
      getScope->add_option("-U,--upper", upper, "Upper bound of scope");
      getScope->add_flag("-r,--reverse", reverse, "Iterate in reverse order");
      getScope->callback([&] {
         auto result = call(this, get_table_by_scope_func, fc::mutable_variant_object("code", code)
               ("table", table)
               ("lower_bound", lower)
               ("upper_bound", upper)
               ("limit", limit)
               ("reverse", reverse)
         );
         my_out << fc::json::to_pretty_string(result)
                   << std::endl;
      });

      // currency accessors
      // get currency balance
      string symbol;
      bool currency_balance_print_json = false;
      auto get_currency = get->add_subcommand("currency", "Retrieve information related to standard currencies");
      get_currency->require_subcommand();
      auto get_balance = get_currency->add_subcommand("balance",
                                                      "Retrieve the balance of an account for a given currency");
      get_balance->add_option("contract", code, "The contract that operates the currency")->required();
      get_balance->add_option("account", accountName, "The account to query balances for")->required();
      get_balance->add_option("symbol", symbol,
                              "The symbol for the currency if the contract operates multiple currencies");
      get_balance->add_flag("--json,-j", currency_balance_print_json, "Output in JSON format");
      get_balance->callback([&] {
         auto result = call(this, get_currency_balance_func, fc::mutable_variant_object
               ("account", accountName)
               ("code", code)
               ("symbol", symbol.empty() ? fc::variant() : symbol)
         );
         if (!currency_balance_print_json) {
            const auto &rows = result.get_array();
            for (const auto &r: rows) {
               my_out << clean_output(r.as_string()) << std::endl;
            }
         } else {
            my_out << fc::json::to_pretty_string(result) << std::endl;
         }
      });

      auto get_currency_stats = get_currency->add_subcommand("stats", "Retrieve the stats of for a given currency");
      get_currency_stats->add_option("contract", code, "The contract that operates the currency")->required();
      get_currency_stats->add_option("symbol", symbol,
                                     "The symbol for the currency if the contract operates multiple currencies")->required();
      get_currency_stats->callback([&] {
         auto result = call(this, get_currency_stats_func, fc::mutable_variant_object("json", false)
               ("code", code)
               ("symbol", symbol)
         );

         my_out << fc::json::to_pretty_string(result)
                   << std::endl;
      });

      // get accounts
      string public_key_str;
      auto getAccounts = get->add_subcommand("accounts", "Retrieve accounts associated with a public key");
      getAccounts->add_option("public_key", public_key_str, "The public key to retrieve accounts for")->required();
      getAccounts->callback([&] {
         chain::public_key_type public_key;
         try {
            public_key = chain::public_key_type(public_key_str);
         } EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid public key: {public_key}",
                                  ("public_key", public_key_str))
         auto arg = fc::mutable_variant_object("public_key", public_key);
         my_out << fc::json::to_pretty_string(call(this, get_key_accounts_func, arg)) << std::endl;
      });

      // get servants
      string controllingAccount;
      auto getServants = get->add_subcommand("servants", "Retrieve accounts which are servants of a given account ");
      getServants->add_option("account", controllingAccount, "The name of the controlling account")->required();
      getServants->callback([&] {
         auto arg = fc::mutable_variant_object("controlling_account", controllingAccount);
         my_out << fc::json::to_pretty_string(call(this, get_controlled_accounts_func, arg)) << std::endl;
      });

      // get transaction (history api plugin)
      string transaction_id_str;
      uint32_t block_num_hint = 0;
      auto getTransaction = get->add_subcommand("transaction", "Retrieve a transaction from the blockchain");
      getTransaction->add_option("id", transaction_id_str, "ID of the transaction to retrieve")->required();
      getTransaction->add_option("-b,--block-hint", block_num_hint, "The block number this transaction may be in");
      getTransaction->callback([&] {
         auto arg = fc::mutable_variant_object("id", transaction_id_str);
         if (block_num_hint > 0) {
            arg = arg("block_num_hint", block_num_hint);
         }
         my_out << fc::json::to_pretty_string(call(this, get_transaction_func, arg)) << std::endl;
      });

      // get transaction_trace (trace api plugin)
      auto getTransactionTrace = get->add_subcommand("transaction_trace", "Retrieve a transaction from trace logs");
      getTransactionTrace->add_option("id", transaction_id_str, "ID of the transaction to retrieve")->required();
      getTransactionTrace->callback([&] {
         auto arg = fc::mutable_variant_object("id", transaction_id_str);
         my_out << fc::json::to_pretty_string(call(this, get_transaction_trace_func, arg)) << std::endl;
      });

      // get block_trace
      string blockNum;
      auto getBlockTrace = get->add_subcommand("block_trace", "Retrieve a block from trace logs");
      getBlockTrace->add_option("block", blockNum, "The number of the block to retrieve")->required();

      getBlockTrace->callback([&] {
         auto arg = fc::mutable_variant_object("block_num", blockNum);
         my_out << fc::json::to_pretty_string(call(this, get_block_trace_func, arg)) << std::endl;
      });

      // get actions
      string account_name;
      string skip_seq_str;
      string num_seq_str;
      bool printjson = false;
      bool fullact = false;
      bool prettyact = false;
      bool printconsole = false;

      int32_t pos_seq = -1;
      int32_t offset = -20;
      auto getActions = get->add_subcommand("actions",
                                            "Retrieve all actions with specific account name referenced in authorization or receiver");
      getActions->add_option("account_name", account_name, "Name of account to query on")->required();
      getActions->add_option("pos", pos_seq, "Sequence number of action for this account, -1 for last");
      getActions->add_option("offset", offset,
                             "Get actions [pos,pos+offset] for positive offset or [pos-offset,pos) for negative offset");
      getActions->add_flag("--json,-j", printjson, "Print full JSON");
      getActions->add_flag("--full", fullact, "Don't truncate action output");
      getActions->add_flag("--pretty", prettyact, "Pretty print full action JSON");
      getActions->add_flag("--console", printconsole, "Print console output generated by action ");
      getActions->callback([&] {
         fc::mutable_variant_object arg;
         arg("account_name", account_name);
         arg("pos", pos_seq);
         arg("offset", offset);

         auto result = call(this, get_actions_func, arg);


         if (printjson) {
            my_out << fc::json::to_pretty_string(result) << std::endl;
         } else {
            auto &traces = result["actions"].get_array();
            uint32_t lib = result["last_irreversible_block"].as_uint64();


            my_out << "#" << setw(5) << "seq" << "  " << setw(24) << left << "when" << "  " << setw(24) << right
                 << "contract::action" << " => " << setw(13) << left << "receiver" << " " << setw(11) << left
                 << "trx id..." << " args\n";
            my_out << "================================================================================================================\n";
            for (const auto &trace: traces) {
               std::stringstream out;
               if (trace["block_num"].as_uint64() <= lib)
                  out << "#";
               else
                  out << "?";

               out << setw(5) << trace["account_action_seq"].as_uint64() << "  ";
               out << setw(24) << trace["block_time"].as_string() << "  ";

               const auto &at = trace["action_trace"].get_object();

               auto id = at["trx_id"].as_string();
               const auto &receipt = at["receipt"];
               auto receiver = receipt["receiver"].as_string();
               const auto &act = at["act"].get_object();
               auto code = act["account"].as_string();
               auto func = act["name"].as_string();
               string args;
               if (prettyact) {
                  args = fc::json::to_pretty_string(act["data"]);
               } else {
                  args = fc::json::to_string(act["data"], fc::time_point::maximum());
                  if (!fullact) {
                     args = args.substr(0, 60) + "...";
                  }
               }
               out << std::setw(24) << std::right << (code + "::" + func) << " => " << left << std::setw(13)
                   << receiver;

               out << " " << setw(11) << (id.substr(0, 8) + "...");

               if (fullact || prettyact) out << "\n";
               else out << " ";

               out << args;//<< "\n";

               if (trace["block_num"].as_uint64() <= lib) {
                  my_err << fmt::format("{m}", fmt::arg("m", out.str())) << std::endl;
               } else {
                  my_err << fmt::format("{m}", fmt::arg("m", out.str())) << std::endl;
               }
               if (printconsole) {
                  auto console = at["console"].as_string();
                  if (console.size()) {
                     stringstream sout;
                     std::stringstream ss(console);
                     string line;
                     while (std::getline(ss, line)) {
                        sout << ">> " << clean_output(std::move(line)) << "\n";
                        if (!fullact) break;
                        line.clear();
                     }
                     my_err << sout.str();
                  }
               }
            }
         }
      });

      get_schedule_subcommand{get, *this};
      auto getTransactionId = get_transaction_id_subcommand{get, *this};

      auto getCmd = get->add_subcommand("best", "Display message based on account name");
      getCmd->add_option("name", accountName, "The name of the account to use")->required();
      uint8_t easterMsg[] = {
            0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7,
            0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5,
            0xca, 0xf1, 0x3b, 0x61,
            0x41, 0xb1, 0xee, 0x61, 0x5f, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x26,
            0xcc, 0xda, 0x9c, 0x7d,
            0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xb9, 0x98, 0xa4, 0x45, 0x5f, 0x29,
            0x39, 0xd7, 0x94, 0xb6,
            0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1,
            0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf7, 0xa6, 0xdd, 0x61, 0x26, 0xcc, 0xda,
            0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbe, 0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5,
            0x96, 0xb4, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84, 0x52, 0x24, 0xfd, 0xaa, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x63,
            0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f,
            0x7e, 0x0e, 0x20, 0x47,
            0x01, 0x1d, 0x1f, 0x1a, 0xe3, 0xbc, 0xe9, 0xac, 0xb9, 0xbe, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6,
            0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x00, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf1, 0x39, 0x63, 0x43, 0xb3,
            0xec, 0x47, 0x5f, 0x58,
            0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd5, 0x90, 0xb2, 0x77, 0x23,
            0xaa, 0xc7, 0xb8, 0x86,
            0x52, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x61,
            0x5f, 0x5a, 0x76, 0x83,
            0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47,
            0x01, 0x1d, 0x1f, 0x18,
            0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x00,
            0xff, 0xa8, 0xbf, 0xf5, 0x29, 0xd1, 0x28, 0xbe, 0xdb, 0xf3, 0x39, 0x61, 0x41, 0xb1, 0xee, 0x63, 0x5d, 0x58,
            0x74, 0x81, 0x32, 0xd2,
            0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xda, 0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f,
            0x1d, 0x18, 0xe1, 0xbe,
            0xeb, 0xae, 0xbb, 0x98, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x00, 0xff, 0xa8,
            0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x95,
            0x4f, 0xc3, 0x4a, 0xd6,
            0xaa, 0x88, 0xb0, 0xdf, 0x61, 0x26, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18,
            0xe1, 0xbe, 0xeb, 0xae,
            0xbb, 0xbc, 0xa6, 0x45, 0x5f, 0x29, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x24,
            0xff, 0xaa, 0xbf, 0xf5,
            0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2,
            0x48, 0xd4, 0xbb, 0xf5,
            0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7b, 0x73, 0x24, 0x47, 0x01, 0x1d, 0x1d, 0x1c, 0x9c, 0xab,
            0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8,
            0xbd, 0xf7, 0x29, 0xd8,
            0x21, 0xb7, 0xc8, 0xf3, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x47, 0x5f, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4,
            0xbb, 0xf5, 0xa4, 0xdf,
            0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae,
            0xbb, 0xbc, 0xa6, 0x43,
            0x20, 0x3e, 0x39, 0xd7, 0x96, 0xb4, 0x77, 0x23, 0xbd, 0xb8, 0xbe, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5,
            0x2b, 0xda, 0x23, 0xb5,
            0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x76, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7,
            0xa4, 0xdf, 0x63, 0x24,
            0xce, 0xfc, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x47, 0x5d, 0x2b,
            0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x02, 0xf4, 0xa3, 0xab, 0xf5, 0x2b, 0xda,
            0x21, 0xb7, 0xc8, 0xf3,
            0x39, 0x77, 0x3e, 0xa2, 0xee, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf,
            0x63, 0x24, 0xce, 0xd8,
            0x9e, 0x7f, 0x7e, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7,
            0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5,
            0xca, 0xf1, 0x39, 0x63,
            0x43, 0xb3, 0xf8, 0x1e, 0x4c, 0x5a, 0x74, 0x81, 0x32, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa6, 0xdf, 0x61, 0x35,
            0xb3, 0xcc, 0x9e, 0x7f,
            0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x29,
            0x3b, 0xd5, 0x96, 0xb4,
            0x77, 0x21, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x24, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1,
            0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x31, 0xb3, 0xdc,
            0x9e, 0x7f, 0x7e, 0x0e,
            0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a, 0xe3, 0xbe, 0xeb, 0xae, 0xbf, 0xc1, 0xb3, 0x47, 0x5d, 0x2b, 0x39, 0xd7,
            0x94, 0xb6, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf3, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x47,
            0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f,
            0x7e, 0x0e, 0x20, 0x47,
            0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xef, 0xd3, 0xae, 0xbc, 0xa6, 0x47, 0x5d, 0x29, 0x3b, 0xd5, 0x96, 0xb4,
            0x77, 0x21, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x15, 0x82, 0xac, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58,
            0x74, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23,
            0xaa, 0xd4, 0xc7, 0x90,
            0x50, 0x00, 0xff, 0xa8, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63,
            0x49, 0x25, 0x65, 0x83,
            0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0c, 0x22, 0x45,
            0x03, 0x1f, 0x1d, 0x1a,
            0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x00,
            0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf3, 0x32, 0x1e, 0x41, 0xb3, 0xec, 0x63, 0x5d, 0x58,
            0x76, 0x83, 0x30, 0xd0,
            0x4a, 0xd6, 0xb9, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7d, 0x03, 0x05, 0x22, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe,
            0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x29, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21, 0xaa, 0xc5, 0xba, 0x84,
            0x50, 0x24, 0xff, 0xa8,
            0xbf, 0xf5, 0x2b, 0xda, 0x4f, 0xb5, 0x91, 0xf1, 0x7e, 0x63, 0x01, 0xb3, 0xb6, 0x63, 0x5d, 0x58, 0x74, 0x81,
            0x32, 0xd2, 0x48, 0xd4,
            0xbb, 0xe0, 0xa9, 0xd2, 0x76, 0x24, 0xce, 0xd8, 0x9e, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1f, 0x18,
            0xe1, 0xbe, 0xeb, 0xae,
            0xbb, 0xbc, 0xa6, 0x52, 0x50, 0x26, 0x2d, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x6c,
            0xff, 0xf3, 0xbf, 0xb2,
            0x29, 0x98, 0x21, 0xef, 0xc8, 0xf3, 0x3b, 0x63, 0x43, 0xb3, 0xec, 0x47, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2,
            0x48, 0xd4, 0xbb, 0xf5,
            0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x09, 0xea, 0xaf,
            0xe0, 0xac, 0xbb, 0xbc,
            0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5, 0x96, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xfd, 0xa3,
            0xae, 0xfe, 0x2f, 0xda,
            0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x30, 0xd0, 0x4a, 0xd6,
            0xb9, 0xf7, 0xa6, 0xdf,
            0x63, 0x24, 0xce, 0xfc, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x77, 0x18, 0xa0, 0xbe, 0xb7, 0xae,
            0xbb, 0xbc, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x77, 0x5e, 0xad, 0xc7, 0xb7, 0x81, 0x50, 0x02, 0xfd, 0xaa, 0xbd, 0xf7,
            0x29, 0xd8, 0x23, 0xb5,
            0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x58, 0x55, 0x76, 0x85, 0x4f, 0xd0, 0x48, 0xd4, 0xbb, 0xf5,
            0xa4, 0xdf, 0x63, 0x24,
            0xce, 0xd8, 0xe7, 0x7f, 0x39, 0x0e, 0x7a, 0x45, 0x47, 0x1f, 0x1d, 0x1a, 0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0x98,
            0xa6, 0x47, 0x5d, 0x2b,
            0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda,
            0x23, 0xb5, 0xdf, 0xfc,
            0x2d, 0x63, 0x47, 0xce, 0xee, 0x63, 0x5f, 0x5a, 0x76, 0x83, 0x30, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf,
            0x63, 0x24, 0xce, 0xda,
            0xe3, 0x7b, 0x7e, 0x1a, 0x2d, 0x52, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47,
            0x5d, 0x2b, 0x3b, 0xd5,
            0x96, 0xb4, 0x77, 0x21, 0xaa, 0xc5, 0xba, 0x84, 0x50, 0x24, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5,
            0xb0, 0xf1, 0x7f, 0x63,
            0x08, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xaa, 0xfe, 0xa4, 0xdf, 0x61, 0x59,
            0xca, 0xd8, 0x9c, 0x7d,
            0x7c, 0x0c, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xb8, 0xdb, 0x45, 0x5d, 0x2b,
            0x32, 0xc6, 0x94, 0xb6,
            0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xd2, 0xbf, 0xb3, 0x29, 0x91, 0x21, 0xb7, 0xc8, 0xf3,
            0x3b, 0x63, 0x43, 0xb3,
            0xec, 0x47, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8,
            0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1f, 0x62, 0x1d, 0xe1, 0xbe, 0xeb, 0xab, 0xb6, 0xa8, 0xa6, 0x45, 0x5f, 0x2b, 0x39, 0xd7,
            0x94, 0xb6, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84, 0x44, 0x0d, 0xea, 0xa8, 0xbf, 0xf5, 0x2e, 0xa7, 0x21, 0xb5, 0xca, 0xf1, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x63,
            0x5d, 0x58, 0x74, 0x81, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa6, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9e, 0x7f,
            0x7e, 0x0e, 0x20, 0x47,
            0x6d, 0x1d, 0x54, 0x18, 0xbc, 0xbe, 0xb1, 0xae, 0xb4, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb3,
            0x78, 0x21, 0xa8, 0xc7,
            0xb8, 0x86, 0x5b, 0x11, 0xff, 0xaa, 0xbd, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3,
            0xfd, 0x68, 0x5d, 0x58,
            0x74, 0x81, 0x26, 0xdf, 0x5d, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xb4, 0x9e, 0x34, 0x7e, 0x53,
            0x22, 0x1d, 0x03, 0x12,
            0x1d, 0x1a, 0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xbe, 0xdb, 0xf1, 0x3b, 0x61, 0x41, 0xb3, 0xf9, 0x6e,
            0x48, 0x58, 0x74, 0x81,
            0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x31, 0xc3, 0xcc, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x4c,
            0x10, 0x1d, 0x1f, 0x18,
            0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21, 0xaa, 0xc5,
            0xba, 0x84, 0x50, 0x24,
            0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58,
            0x74, 0x81, 0x32, 0xd2,
            0x5c, 0xd9, 0xae, 0xf5, 0xa6, 0xdd, 0x61, 0x26, 0xce, 0xc9, 0x95, 0x7d, 0x7e, 0x0e, 0x20, 0x47, 0x03, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe,
            0xe9, 0xa5, 0xaa, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd2, 0x99, 0xb4, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x00, 0xff, 0xa8,
            0xbf, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf3, 0x3b, 0x63, 0x43, 0xb3, 0xec, 0x47, 0x5d, 0x58, 0x74, 0x81,
            0x32, 0xd2, 0x48, 0xd4,
            0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x04, 0x60, 0x1d, 0x18,
            0xe3, 0xbc, 0xe9, 0xac,
            0xbb, 0xa8, 0xab, 0x42, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xbf, 0x89, 0x44, 0x00,
            0xff, 0xa8, 0xbf, 0xf5,
            0x2b, 0xd8, 0x5e, 0xb0, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x83, 0x30, 0xd0,
            0x4a, 0xd6, 0xb9, 0xf7,
            0xa6, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe,
            0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd5, 0x9f, 0xa7, 0x75, 0x21, 0xaa, 0xc7, 0xb8, 0x86, 0x52, 0x00, 0xfb, 0xd5,
            0xbd, 0xf5, 0x2b, 0xda,
            0x23, 0xb5, 0xca, 0xf1, 0x39, 0x61, 0x3e, 0xb7, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x59, 0xdf,
            0xbb, 0xf5, 0xa4, 0xdf,
            0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a, 0xe1, 0xbe, 0xeb, 0xae,
            0xbb, 0x98, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x21, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5,
            0x2b, 0xce, 0x2e, 0xa0,
            0xca, 0xf3, 0x3b, 0x61, 0x41, 0xb1, 0xec, 0x63, 0x5f, 0x25, 0x70, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5,
            0xa4, 0xdb, 0x1e, 0x26,
            0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x14, 0x10, 0x0b, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x47, 0x5d, 0x29,
            0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x24, 0xfd, 0xa8, 0xbf, 0xf5, 0x2b, 0xda,
            0x23, 0xb5, 0xca, 0xf1,
            0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x74, 0x83, 0x32, 0xd6, 0x35, 0xd6, 0xb9, 0xf7, 0xa6, 0xdd,
            0x61, 0x24, 0xce, 0xd8,
            0x9e, 0x7a, 0x73, 0x1a, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xf5, 0xb3, 0xee, 0xae, 0xbb, 0xbc, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7,
            0x96, 0xcb, 0x70, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf7, 0x29, 0xd8, 0x21, 0xb7,
            0xc8, 0xf3, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x47, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24,
            0xce, 0xd8, 0x9e, 0x7f,
            0x7c, 0x0e, 0x22, 0x3a, 0x05, 0x1d, 0x1d, 0x1a, 0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x45, 0x56, 0x3a,
            0x39, 0xd7, 0x94, 0xb6,
            0x75, 0x23, 0xb9, 0xce, 0xb8, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb1, 0xb7, 0xf3,
            0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58, 0x74, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc,
            0x9c, 0x7d, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa4, 0x45, 0x5f, 0x2b, 0x2d, 0xaa,
            0x9f, 0xb3, 0x77, 0x23,
            0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xfd, 0xa8, 0xaa, 0xf8, 0x3f, 0xda, 0x23, 0xb5, 0xca, 0xe4, 0x34, 0x76,
            0x43, 0xb3, 0xec, 0x63,
            0x5d, 0x58, 0x74, 0x81, 0x32, 0xd0, 0x4d, 0xdf, 0xc6, 0xf7, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f,
            0x7e, 0x0c, 0x22, 0x45,
            0x03, 0x1f, 0x1d, 0x1a, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa4, 0x45, 0x5f, 0x2b, 0x39, 0xd7, 0x94, 0xb6,
            0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x52, 0x02, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x36, 0xa4, 0xc1, 0xe0, 0x2c, 0x61, 0x43, 0xb3,
            0xec, 0x61, 0x5d, 0x58,
            0x74, 0x90, 0x39, 0xd2, 0x48, 0xd4, 0xb9, 0xfe, 0xb5, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7c, 0x1b,
            0x31, 0x4c, 0x10, 0x08,
            0x1d, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x29, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21,
            0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x24, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf3, 0x3b, 0x61, 0x41, 0xb1, 0xee, 0x61,
            0x5f, 0x5a, 0x76, 0x83,
            0x30, 0xd0, 0x48, 0xd4, 0xb9, 0xf0, 0xb5, 0xd4, 0x67, 0x31, 0xcc, 0xd8, 0x9e, 0x7f, 0x7e, 0x1a, 0x2d, 0x52,
            0x01, 0x1d, 0x1a, 0x15,
            0xf5, 0xbe, 0xeb, 0xae, 0xbb, 0xbe, 0xb3, 0x56, 0x56, 0x3a, 0x2c, 0xd5, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x00,
            0xff, 0xa8, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x47, 0x5f, 0x5a,
            0x76, 0x83, 0x30, 0xd0,
            0x4a, 0xd6, 0xb9, 0xf7, 0xa6, 0xdd, 0x61, 0x26, 0xcc, 0xda, 0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xaa,
            0xee, 0xa5, 0xb0, 0xb8, 0xb2, 0x47, 0x5d, 0x2b, 0x3d, 0xaa, 0x96, 0xb4, 0x08, 0x27, 0xa8, 0xc5, 0xb8, 0x90,
            0x54, 0x0b, 0xf4, 0xad,
            0xbd, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58, 0x76, 0x83,
            0x30, 0xd0, 0x4a, 0xd6,
            0xb9, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a,
            0xe3, 0xbc, 0xe9, 0xac,
            0xb9, 0xbe, 0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x44, 0x04,
            0xf4, 0xa3, 0xbb, 0xe1,
            0x29, 0xa7, 0x26, 0xb1, 0xb7, 0xf3, 0x2d, 0x67, 0x48, 0xb8, 0xe9, 0x77, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2,
            0x48, 0xd4, 0xbb, 0xf5,
            0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x18, 0xe1, 0xbe,
            0xeb, 0xae, 0xbb, 0x98,
            0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x21, 0xaa, 0xc7, 0xb8, 0x86, 0x52, 0x02, 0xfd, 0xaa,
            0xbd, 0xf7, 0x2b, 0xda,
            0x23, 0xb5, 0xca, 0xf1, 0x3b, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5f, 0x4c, 0x70, 0x8a, 0x23, 0xd9, 0x45, 0xd9,
            0xb0, 0xe4, 0xaf, 0xdb,
            0x77, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae,
            0xbb, 0xbc, 0xa6, 0x47,
            0x5f, 0x29, 0x3b, 0xd5, 0x96, 0xb4, 0x77, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x24, 0xfd, 0xaa, 0xbd, 0xf7,
            0x29, 0xd8, 0x21, 0xb7,
            0xc8, 0xf3, 0x3b, 0x61, 0x41, 0xb1, 0xee, 0x61, 0x5f, 0x5a, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xb9, 0xf7,
            0xa4, 0xdf, 0x63, 0x24,
            0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0c, 0x35, 0x43, 0x7c, 0x60, 0x1b, 0x0d, 0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x47, 0x5d, 0x2b,
            0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xaa, 0xbd, 0xf7, 0x29, 0xd8,
            0x21, 0xb7, 0xca, 0xf1,
            0x39, 0x63, 0x43, 0xb3, 0xec, 0x47, 0x5f, 0x5a, 0x76, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa6, 0xdd,
            0x61, 0x26, 0xcc, 0xda,
            0x9e, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x03, 0x1f, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47,
            0x5d, 0x2b, 0x39, 0xd7,
            0x96, 0xb4, 0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5,
            0xca, 0xf1, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x63, 0x5d, 0x5a, 0x76, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24,
            0xce, 0xfc, 0x9c, 0x7d,
            0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a, 0xe3, 0xbc, 0xe9, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b,
            0x3b, 0xd5, 0x96, 0xb6,
            0x75, 0x23, 0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1,
            0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8,
            0x9c, 0x7d, 0x7c, 0x0c,
            0x22, 0x45, 0x03, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5,
            0x96, 0xb4, 0x77, 0x21,
            0xa8, 0xc5, 0xba, 0x84, 0x50, 0x00, 0xff, 0xa8, 0xbd, 0xf7, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63,
            0x43, 0xb3, 0xec, 0x63,
            0x5d, 0x58, 0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x6b,
            0x7a, 0x1a, 0x20, 0x47,
            0x01, 0x1d, 0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbe, 0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5, 0x96, 0xb6,
            0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x24, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3,
            0xec, 0x63, 0x5d, 0x58,
            0x74, 0x81, 0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x53, 0x4c, 0x3f, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x02, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x47,
            0x5d, 0x58, 0x74, 0x81,
            0x32, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xda, 0x8a, 0x6b, 0x7c, 0x0e, 0x20, 0x47,
            0x01, 0x1d, 0x1f, 0x18,
            0xe1, 0xbe, 0xe9, 0xba, 0xaf, 0xbe, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb4, 0x77, 0x37, 0xaa, 0xc7,
            0xba, 0x84, 0x50, 0x02,
            0xfd, 0xaa, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x3b, 0x61, 0x57, 0xb1, 0xee, 0x63, 0x5d, 0x5a,
            0x76, 0x83, 0x30, 0xd0,
            0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9c, 0x7f, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbc,
            0xeb, 0xba, 0xaa, 0xad, 0xa2, 0x43, 0x4c, 0x3a, 0x3c, 0xd5, 0x94, 0xb6, 0x75, 0x23, 0xbd, 0xd4, 0xab, 0x80,
            0x54, 0x11, 0xee, 0xad,
            0xbd, 0xf5, 0x2b, 0xda, 0x36, 0xbe, 0xdb, 0xf5, 0x3d, 0x66, 0x41, 0xb3, 0xec, 0x77, 0x59, 0x49, 0x09, 0x95,
            0x32, 0xd2, 0x48, 0xd4,
            0xae, 0xe4, 0xb5, 0xdb, 0x67, 0x35, 0xdf, 0xdc, 0x9c, 0x7f, 0x7c, 0x0c, 0x22, 0x45, 0x01, 0x1d, 0x1f, 0x18,
            0xe1, 0xbc, 0xeb, 0xae,
            0xbb, 0x98, 0xa4, 0x45, 0x5f, 0x2b, 0x39, 0xd7, 0x96, 0xb4, 0x77, 0x21, 0xaa, 0xc5, 0xae, 0xf9, 0x55, 0x02,
            0xff, 0xa8, 0xbf, 0xe1,
            0x56, 0xde, 0x23, 0xb5, 0xca, 0xf5, 0x44, 0x76, 0x41, 0xb3, 0xec, 0x63, 0x49, 0x49, 0x7f, 0x83, 0x32, 0xd2,
            0x59, 0xa9, 0xb9, 0xf5,
            0xa4, 0xdf, 0x63, 0x24, 0xce, 0xd8, 0x9e, 0x6b, 0x73, 0x1a, 0x20, 0x47, 0x01, 0x18, 0x62, 0x0d, 0xe3, 0xbe,
            0xeb, 0xae, 0xb9, 0xad,
            0xdb, 0x53, 0x5d, 0x29, 0x3b, 0xd7, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc7, 0xba, 0x84, 0x50, 0x24, 0xfd, 0xaa,
            0xbd, 0xf7, 0x29, 0xd8,
            0x21, 0xb7, 0xc8, 0xf3, 0x3b, 0x63, 0x52, 0xbe, 0xe8, 0x67, 0x59, 0x5c, 0x70, 0x85, 0x39, 0xaf, 0x4a, 0xd4,
            0xaf, 0xf8, 0xb1, 0xdf,
            0x63, 0x24, 0xce, 0xd8, 0x9e, 0x7d, 0x03, 0x0a, 0x20, 0x47, 0x03, 0x19, 0x14, 0x09, 0xe4, 0xbc, 0xeb, 0xae,
            0xbb, 0xbc, 0xa6, 0x53,
            0x50, 0x3f, 0x39, 0xd7, 0x96, 0xbb, 0x70, 0x23, 0xa8, 0xc5, 0xba, 0x86, 0x50, 0x02, 0x82, 0xb9, 0xbf, 0xf7,
            0x29, 0xda, 0x23, 0xb5,
            0xca, 0xf1, 0x39, 0x61, 0x43, 0xb3, 0xec, 0x47, 0x5f, 0x5a, 0x76, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7,
            0xa6, 0xdf, 0x72, 0x59,
            0xcc, 0xda, 0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45, 0x03, 0x1d, 0x0b, 0x15, 0xf4, 0xbe, 0xeb, 0xae, 0xbb, 0xbc,
            0xa6, 0x45, 0x20, 0x2f,
            0x39, 0xd7, 0x94, 0xb6, 0x77, 0x36, 0xac, 0xce, 0xbf, 0x84, 0x50, 0x00, 0xff, 0xbc, 0xb2, 0xe1, 0x2b, 0xda,
            0x21, 0xb8, 0xcf, 0xf1,
            0x39, 0x63, 0x41, 0xb1, 0xec, 0x61, 0x20, 0x49, 0x74, 0x83, 0x30, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa6, 0xdd,
            0x63, 0x24, 0xce, 0xfc,
            0x9c, 0x7d, 0x7e, 0x0c, 0x22, 0x45, 0x03, 0x1f, 0x1d, 0x1a, 0xe3, 0xbe, 0xff, 0xd3, 0xbf, 0xbe, 0xa6, 0x47,
            0x5d, 0x2b, 0x3b, 0xd5,
            0x94, 0xb6, 0x77, 0x27, 0xd5, 0xd0, 0xb8, 0x84, 0x50, 0x00, 0xeb, 0xb9, 0xb4, 0xf7, 0x2b, 0xda, 0x21, 0xb7,
            0xca, 0xf1, 0x39, 0x67,
            0x3e, 0xb1, 0xec, 0x63, 0x5d, 0x4c, 0x79, 0x95, 0x32, 0xd2, 0x48, 0xd0, 0xc6, 0xe0, 0xa6, 0xdf, 0x63, 0x24,
            0xcc, 0xc9, 0xe3, 0x6b,
            0x7c, 0x0c, 0x20, 0x47, 0x01, 0x1d, 0x1f, 0x1a, 0xe3, 0xbe, 0xeb, 0xae, 0xbb, 0x98, 0xa4, 0x45, 0x5f, 0x29,
            0x3b, 0xd5, 0x96, 0xb4,
            0x77, 0x21, 0xaa, 0xc7, 0xba, 0x90, 0x54, 0x11, 0xee, 0xac, 0xbb, 0xf1, 0x3a, 0xce, 0x23, 0xb5, 0xca, 0xf1,
            0x2c, 0x72, 0x52, 0xb7,
            0xe8, 0x72, 0x4c, 0x5c, 0x76, 0x81, 0x32, 0xd0, 0x4d, 0xc5, 0xbf, 0xf1, 0xb5, 0xd4, 0x76, 0x24, 0xce, 0xd8,
            0x9e, 0x6b, 0x03, 0x1a,
            0x20, 0x47, 0x01, 0x1d, 0x0a, 0x09, 0xf0, 0xba, 0xef, 0xbf, 0xaa, 0xb8, 0xa4, 0x47, 0x5f, 0x29, 0x39, 0xd7,
            0x94, 0xb6, 0x75, 0x21,
            0xa8, 0xc5, 0xba, 0x84, 0x50, 0x24, 0xfd, 0xaa, 0xbd, 0xf7, 0x29, 0xd8, 0x21, 0xb7, 0xc8, 0xf3, 0x3b, 0x61,
            0x41, 0xb3, 0xec, 0x61,
            0x49, 0x4c, 0x60, 0x83, 0x30, 0xd2, 0x48, 0xd4, 0xbb, 0xf5, 0xa4, 0xdf, 0x61, 0x30, 0xda, 0xcc, 0x9c, 0x7f,
            0x7e, 0x0e, 0x20, 0x45,
            0x03, 0x1f, 0x0b, 0x0c, 0xf5, 0xbc, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x45, 0x5f, 0x29, 0x39, 0xd7, 0x94, 0xb6,
            0x75, 0x23, 0xaa, 0xd1,
            0xae, 0x90, 0x52, 0x00, 0xfd, 0xaa, 0xbd, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xc8, 0xf3, 0x39, 0x63, 0x43, 0xb3,
            0xec, 0x47, 0x5f, 0x5a,
            0x76, 0x83, 0x30, 0xd0, 0x4a, 0xd6, 0xb9, 0xf7, 0xa6, 0xdd, 0x61, 0x26, 0xcc, 0xda, 0x9e, 0x7f, 0x7e, 0x0e,
            0x20, 0x47, 0x01, 0x1d,
            0x1f, 0x18, 0xe1, 0xbe, 0xeb, 0xae, 0xbb, 0xbc, 0xa6, 0x47, 0x5d, 0x2b, 0x39, 0xd7, 0x94, 0xb6, 0x75, 0x23,
            0xa8, 0xc5, 0xba, 0x84,
            0x50, 0x00, 0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf3, 0x39, 0x63, 0x43, 0xb1, 0xee, 0x61,
            0x5f, 0x5a, 0x76, 0x81,
            0x32, 0xd2, 0x48, 0xd4, 0xb9, 0xf7, 0xa4, 0xdf, 0x63, 0x24, 0xce, 0xfc, 0x9c, 0x7d, 0x7c, 0x0c, 0x22, 0x45,
            0x03, 0x1f, 0x1d, 0x1a,
            0xe3, 0xbc, 0xe9, 0xac, 0xb9, 0xbe, 0xa4, 0x45, 0x5f, 0x29, 0x3b, 0xd5, 0x94, 0xb6, 0x75, 0x23, 0xa8, 0xc5,
            0xba, 0x84, 0x50, 0x00,
            0xff, 0xa8, 0xbf, 0xf5, 0x2b, 0xda, 0x23, 0xb5, 0xca, 0xf1, 0x39, 0x63, 0x43, 0xb3, 0xec, 0x63, 0x5d, 0x58,
            0x74, 0x81, 0x32, 0xd2,
            0x48, 0xd4, 0xbb, 0xf7, 0xa6, 0xdd, 0x61, 0x26, 0xcc, 0xda, 0x9c, 0x7d, 0x7e, 0x0e, 0x20, 0x47, 0x01, 0x1f,
            0x1d, 0x18, 0xe1, 0xbe,
            0xeb, 0xae, 0xbb, 0x98, 0x7f
      };
      getCmd->callback([&]() {
         fc::sha256 easterHash("f354ee99e2bc863ce19d80b843353476394ebc3530a51c9290d629065bacc3b3");
         if (easterHash != fc::sha256::hash(accountName.c_str(), accountName.size())) {
            my_out << "Try again!" << std::endl;
         } else {
            fc::sha512 accountHash = fc::sha512::hash(accountName.c_str(), accountName.size());
            for (unsigned int i = 0; i < sizeof(easterMsg); i++) {
               easterMsg[i] ^= accountHash.data()[i % 64];
            }
            easterMsg[sizeof(easterMsg) - 1] = 0;
            my_out << easterMsg << std::endl;
         }
      });

      // set subcommand
      auto setSubcommand = app.add_subcommand("set", "Set or update blockchain state");
      setSubcommand->require_subcommand();

      // set contract subcommand
      string account;
      string contractPath;
      string wasmPath;
      string abiPath;
      bool shouldSend = true;
      bool contract_clear = false;
      bool suppress_duplicate_check = false;
      bool run_setcode2 = false;
      bool run_setabi2 = false;
      auto codeSubcommand = setSubcommand->add_subcommand("code", "Create or update the code on an account");
      codeSubcommand->add_option("account", account, "The account to set code for")->required();
      codeSubcommand->add_option("code-file", wasmPath, "The path containing the contract WASM");//->required();
      codeSubcommand->add_flag("-c,--clear", contract_clear, "Remove code on an account");
      codeSubcommand->add_flag("--suppress-duplicate-check", suppress_duplicate_check, "Don't check for duplicate");
      codeSubcommand->add_flag("--run-setcode2", run_setcode2, "Run setcode2");

      auto abiSubcommand = setSubcommand->add_subcommand("abi", "Create or update the abi on an account");
      abiSubcommand->add_option("account", account, "The account to set the ABI for")->required();
      abiSubcommand->add_option("abi-file", abiPath, "The path containing the contract ABI");//->required();
      abiSubcommand->add_flag("-c,--clear", contract_clear, "Remove abi on an account");
      abiSubcommand->add_flag("--suppress-duplicate-check", suppress_duplicate_check, "Don't check for duplicate");
      abiSubcommand->add_flag("--run-setabi2", run_setabi2, "Run setabi2");

      auto contractSubcommand = setSubcommand->add_subcommand("contract",
                                                              "Create or update the contract on an account");
      contractSubcommand->add_option("account", account, "The account to publish a contract for")
            ->required();
      contractSubcommand->add_option("contract-dir", contractPath, "The path containing the .wasm and .abi");
      // ->required();
      contractSubcommand->add_option("wasm-file", wasmPath,
                                     "The file containing the contract WASM relative to contract-dir");
//                     ->check(CLI::ExistingFile);
      auto abi = contractSubcommand->add_option("abi-file,-a,--abi", abiPath,
                                                "The ABI for the contract relative to contract-dir");
//                                ->check(CLI::ExistingFile);
      contractSubcommand->add_flag("-c,--clear", contract_clear, "Remove contract on an account");
      contractSubcommand->add_flag("--suppress-duplicate-check", suppress_duplicate_check, "Don't check for duplicate");

      std::vector<chain::action> actions;
      auto set_code_callback = [&]() {

         std::vector<char> old_wasm;
         bool duplicate = false;
         fc::sha256 old_hash, new_hash;
         if (!suppress_duplicate_check) {
            try {
               const auto result = call(this, get_code_hash_func, fc::mutable_variant_object("account_name", account));
               old_hash = fc::sha256(result["code_hash"].as_string());
            } catch (...) {
               my_err << "Failed to get existing code hash, continue without duplicate check..." << std::endl;
               suppress_duplicate_check = true;
            }
         }

         chain::bytes code_bytes;
         if (!contract_clear) {
            std::string wasm;
            fc::path cpath = fc::canonical(fc::path(contractPath));

            if (wasmPath.empty()) {
               wasmPath = (cpath / (cpath.filename().generic_string() + ".wasm")).generic_string();
            } else if (boost::filesystem::path(wasmPath).is_relative()) {
               wasmPath = (cpath / wasmPath).generic_string();
            }

            my_err << ("Reading WASM from " + wasmPath + "...").c_str() << std::endl;
            fc::read_file_contents(wasmPath, wasm);
            EOS_ASSERT(!wasm.empty(), chain::wasm_file_not_found, "no wasm file found {f}", ("f", wasmPath));

            const string binary_wasm_header("\x00\x61\x73\x6d\x01\x00\x00\x00", 8);
            if (wasm.compare(0, 8, binary_wasm_header))
               my_err << "WARNING: " << wasmPath
                         << " doesn't look like a binary WASM file. Is it something else, like WAST? Trying anyway..."
                         << std::endl;
            code_bytes = chain::bytes(wasm.begin(), wasm.end());
         } else {
            code_bytes = chain::bytes();
         }

         if (!suppress_duplicate_check) {
            if (code_bytes.size()) {
               new_hash = fc::sha256::hash(&(code_bytes[0]), code_bytes.size());
            }
            duplicate = (old_hash == new_hash);
         }

         if (!duplicate) {
            if (run_setcode2)
               actions.emplace_back(create_setcode2(chain::name(account), code_bytes));
            else
               actions.emplace_back(create_setcode(chain::name(account), code_bytes));
            if (shouldSend) {
               my_err << "Setting Code..." << std::endl;
               if (tx_compression == tx_compression_type::default_compression)
                  tx_compression = tx_compression_type::zlib;
               send_actions(std::move(actions), signing_keys_opt.get_keys());
            }
         } else {
            my_err << "Skipping set code because the new code is the same as the existing code" << std::endl;
         }
      };

      auto set_abi_callback = [&]() {

         chain::bytes old_abi;
         bool duplicate = false;
         if (!suppress_duplicate_check) {
            try {
               const auto result = call(this, get_raw_abi_func, fc::mutable_variant_object("account_name", account));
               old_abi = result["abi"].as_blob().data;
            } catch (...) {
               my_err << "Failed to get existing raw abi, continue without duplicate check..." << std::endl;
               suppress_duplicate_check = true;
            }
         }

         chain::bytes abi_bytes;
         if (!contract_clear) {
            fc::path cpath = fc::canonical(fc::path(contractPath));

            if (abiPath.empty()) {
               abiPath = (cpath / (cpath.filename().generic_string() + ".abi")).generic_string();
            } else if (boost::filesystem::path(abiPath).is_relative()) {
               abiPath = (cpath / abiPath).generic_string();
            }

            EOS_ASSERT(fc::exists(abiPath), chain::abi_file_not_found, "no abi file found {f}", ("f", abiPath));

            std::ifstream abi_file(abiPath, std::ios::binary);
            std::vector<char> input_json((std::istreambuf_iterator<char>(abi_file)),
                                         std::istreambuf_iterator<char>());
            input_json.push_back('\0'); // make sure we have 0 at the end of the string

            eosio::json_token_stream stream(input_json.data());
            abi_bytes = eosio::convert_to_bin(eosio::from_json<eosio::abi_def>(stream));
         } else {
            abi_bytes = chain::bytes();
         }

         if (!suppress_duplicate_check) {
            duplicate = (old_abi.size() == abi_bytes.size() &&
                         std::equal(old_abi.begin(), old_abi.end(), abi_bytes.begin()));
         }

         if (!duplicate) {
            try {
               if (run_setabi2)
                  actions.emplace_back(create_setabi2(chain::name(account), abi_bytes));
               else
                  actions.emplace_back(create_setabi(chain::name(account), abi_bytes));
            } EOS_RETHROW_EXCEPTIONS(chain::abi_type_exception, "Fail to parse ABI JSON")
            if (shouldSend) {
               my_err << "Setting ABI..." << std::endl;
               if (tx_compression == tx_compression_type::default_compression)
                  tx_compression = tx_compression_type::zlib;
               send_actions(std::move(actions), signing_keys_opt.get_keys());
            }
         } else {
            my_err << "Skipping set abi because the new abi is the same as the existing abi" << std::endl;
         }
      };

      add_standard_transaction_options_plus_signing(contractSubcommand, "account@active");
      add_standard_transaction_options_plus_signing(codeSubcommand, "account@active");
      add_standard_transaction_options_plus_signing(abiSubcommand, "account@active");
      contractSubcommand->callback([&] {
         if (!contract_clear)
            EOS_ASSERT(!contractPath.empty(), chain::contract_exception, " contract-dir {f} is null ",
                       ("f", contractPath));
         shouldSend = false;
         set_code_callback();
         set_abi_callback();
         if (actions.size()) {
            my_err << "Publishing contract..." << std::endl;
            if (tx_compression == tx_compression_type::default_compression)
               tx_compression = tx_compression_type::zlib;
            send_actions(std::move(actions), signing_keys_opt.get_keys());
         } else {
            my_out << "no transaction is sent" << std::endl;
         }
      });
      codeSubcommand->callback(set_code_callback);
      abiSubcommand->callback(set_abi_callback);

      // set account
      auto setAccount = setSubcommand->add_subcommand("account",
                                                      "Set or update blockchain account state")->require_subcommand();

      // set account permission
      auto setAccountPermission = set_account_permission_subcommand(setAccount, *this);

      // set action
      auto setAction = setSubcommand->add_subcommand("action",
                                                     "Set or update blockchain action state")->require_subcommand();

      // set action permission
      auto setActionPermission = set_action_permission_subcommand(setAction, *this);

      // Transfer subcommand
      string con = "eosio.token";
      string sender;
      string recipient;
      string amount;
      string memo;
      bool pay_ram = false;

      auto transfer = app.add_subcommand("transfer", "Transfer tokens from account to account");
      transfer->add_option("sender", sender, "The account sending tokens")->required();
      transfer->add_option("recipient", recipient, "The account receiving tokens")->required();
      transfer->add_option("amount", amount, "The amount of tokens to send")->required();
      transfer->add_option("memo", memo, "The memo for the transfer");
      transfer->add_option("--contract,-c", con, "The contract that controls the token");
      transfer->add_flag("--pay-ram-to-open", pay_ram, "Pay RAM to open recipient's token balance row");

      add_standard_transaction_options_plus_signing(transfer, "sender@active");
      transfer->callback([&] {
         if (tx_force_unique && memo.size() == 0) {
            // use the memo to add a nonce
            memo = generate_nonce_string();
            tx_force_unique = false;
         }

         auto transfer_amount = to_asset(chain::name(con), amount);
         auto transfer = create_transfer(con, chain::name(sender), chain::name(recipient), transfer_amount, memo);
         if (!pay_ram) {
            send_actions({transfer}, signing_keys_opt.get_keys());
         } else {
            auto open_ = create_open(con, chain::name(recipient), transfer_amount.get_symbol(), chain::name(sender));
            send_actions({open_, transfer}, signing_keys_opt.get_keys());
         }
      });

      // Net subcommand
      string new_host;
      auto net = app.add_subcommand("net", "Interact with local p2p network connections");
      net->require_subcommand();
      auto connect = net->add_subcommand("connect", "Start a new connection to a peer");
      connect->add_option("host", new_host, "The hostname:port to connect to.")->required();
      connect->callback([&] {
         const auto &v = call(this, default_url, net_connect, new_host);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      auto disconnect = net->add_subcommand("disconnect", "Close an existing connection");
      disconnect->add_option("host", new_host, "The hostname:port to disconnect from.")->required();
      disconnect->callback([&] {
         const auto &v = call(this, default_url, net_disconnect, new_host);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      auto status = net->add_subcommand("status", "Status of existing connection");
      status->add_option("host", new_host, "The hostname:port to query status of connection")->required();
      status->callback([&] {
         const auto &v = call(this, default_url, net_status, new_host);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      auto connections = net->add_subcommand("peers", "Status of all existing peers");
      connections->callback([&] {
         const auto &v = call(this, default_url, net_connections);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });



      // Wallet subcommand
      auto wallet = app.add_subcommand("wallet", "Interact with local wallet");
      wallet->require_subcommand();
      // create wallet
      string wallet_name = "default";
      string password_file;
      auto createWallet = wallet->add_subcommand("create", "Create a new wallet locally");
      createWallet->add_option("-n,--name", wallet_name, "The name of the new wallet", true);
      createWallet->add_option("-f,--file", password_file,
                               "Name of file to write wallet password output to. (Must be set, unless \"--to-console\" is passed");
      createWallet->add_flag("--to-console", print_console, "Print password to console.");
      createWallet->callback([&wallet_name, &password_file, &print_console, this] {
         EOSC_ASSERT(my_err, !password_file.empty() ^ print_console,
                     "ERROR: Either indicate a file using \"--file\" or pass \"--to-console\"");
         EOSC_ASSERT(my_err, password_file.empty() || !std::ofstream(password_file.c_str()).fail(),
                     "ERROR: Failed to create file in specified path");

         const auto &v = call(this, this->wallet_url, wallet_create, wallet_name);
         my_out << "Creating wallet: " << wallet_name << std::endl;
         my_out << "Save password to use in the future to unlock this wallet." << std::endl;
         my_out << "Without password imported keys will not be retrievable." << std::endl;
         if (print_console) {
            my_out << fc::json::to_pretty_string(v) << std::endl;
         } else {
            my_err << "saving password to " << password_file << std::endl;
            auto password_str = fc::json::to_pretty_string(v);
            boost::replace_all(password_str, "\"", "");
            std::ofstream out(password_file.c_str());
            out << password_str;
         }
      });

      // open wallet
      auto openWallet = wallet->add_subcommand("open", "Open an existing wallet");
      openWallet->add_option("-n,--name", wallet_name, "The name of the wallet to open");
      openWallet->callback([&wallet_name, this] {
         call(this, this->wallet_url, wallet_open, wallet_name);
         my_out << "Opened: " << wallet_name << std::endl;
      });

      // lock wallet
      auto lockWallet = wallet->add_subcommand("lock", "Lock wallet");
      lockWallet->add_option("-n,--name", wallet_name, "The name of the wallet to lock");
      lockWallet->callback([&wallet_name, this] {
         call(this, this->wallet_url, wallet_lock, wallet_name);
         my_out << "Locked: " << wallet_name << std::endl;
      });

      // lock all wallets
      auto locakAllWallets = wallet->add_subcommand("lock_all", "Lock all unlocked wallets");
      locakAllWallets->callback([this] {
         call(this, this->wallet_url, wallet_lock_all);
         my_out << "Locked All Wallets" << std::endl;
      });

      // unlock wallet
      string wallet_pw;
      auto unlockWallet = wallet->add_subcommand("unlock", "Unlock wallet");
      unlockWallet->add_option("-n,--name", wallet_name, "The name of the wallet to unlock");
      unlockWallet->add_option("--password", wallet_pw, "The password returned by wallet create")->expected(0, 1);
      unlockWallet->callback([&wallet_name, &wallet_pw, this] {
         this->prompt_for_wallet_password(wallet_pw, wallet_name);

         fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw)};
         call(this, this->wallet_url, wallet_unlock, vs);
         my_out << "Unlocked: " << wallet_name << std::endl;
      });

      // import keys into wallet
      string wallet_key_str;
      auto importWallet = wallet->add_subcommand("import", "Import private key into wallet");
      importWallet->add_option("-n,--name", wallet_name, "The name of the wallet to import key into");
      importWallet->add_option("--private-key", wallet_key_str, "Private key in WIF format to import")->expected(0, 1);
      importWallet->callback([&wallet_name, &wallet_key_str, this] {
         if (wallet_key_str.size() == 0) {
            my_out << "private key: ";
            fc::set_console_echo(false);
            std::getline(std::cin, wallet_key_str, '\n');
            fc::set_console_echo(true);
         }

         chain::private_key_type wallet_key;
         try {
            wallet_key = chain::private_key_type(wallet_key_str);
         } catch (...) {
            EOS_THROW(chain::private_key_type_exception, "Invalid private key")
         }
         chain::public_key_type pubkey = wallet_key.get_public_key();

         fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_key)};
         call(this, this->wallet_url, wallet_import_key, vs);
         my_out << "imported private key for: " << pubkey.to_string() << std::endl;
      });

      // remove keys from wallet
      string wallet_rm_key_str;
      auto removeKeyWallet = wallet->add_subcommand("remove_key", "Remove key from wallet");
      removeKeyWallet->add_option("-n,--name", wallet_name, "The name of the wallet to remove key from");
      removeKeyWallet->add_option("key", wallet_rm_key_str, "Public key in WIF format to remove")->required();
      removeKeyWallet->add_option("--password", wallet_pw, "The password returned by wallet create")->expected(0, 1);
      removeKeyWallet->callback([&wallet_name, &wallet_pw, &wallet_rm_key_str, this] {
         this->prompt_for_wallet_password(wallet_pw, wallet_name);
         chain::public_key_type pubkey;
         try {
            pubkey = chain::public_key_type(wallet_rm_key_str);
         } catch (...) {
            EOS_THROW(chain::public_key_type_exception, "Invalid public key: {public_key}",
                      ("public_key", wallet_rm_key_str))
         }
         fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw), fc::variant(wallet_rm_key_str)};
         call(this, wallet_url, wallet_remove_key, vs);
         my_out << "removed private key for: " << wallet_rm_key_str << std::endl;
      });

      // create a key within wallet
      string wallet_create_key_type;
      auto createKeyInWallet = wallet->add_subcommand("create_key", "Create private key within wallet");
      createKeyInWallet->add_option("-n,--name", wallet_name, "The name of the wallet to create key into", true);
      createKeyInWallet->add_option("key_type", wallet_create_key_type, "Key type to create (K1/R1)", true)->type_name(
            "K1/R1");
      createKeyInWallet->callback([&wallet_name, &wallet_create_key_type, this] {
         //an empty key type is allowed -- it will let the underlying wallet pick which type it prefers
         fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_create_key_type)};
         const auto &v = call(this, this->wallet_url, wallet_create_key, vs);
         my_out << "Created new private key with a public key of: " << fc::json::to_pretty_string(v) << std::endl;
      });

      // list wallets
      auto listWallet = wallet->add_subcommand("list", "List opened wallets, * = unlocked");
      listWallet->callback([this] {
         my_out << "Wallets:" << std::endl;
         const auto &v = call(this, this->wallet_url, wallet_list);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      // list keys
      auto listKeys = wallet->add_subcommand("keys", "List of public keys from all unlocked wallets.");
      listKeys->callback([this] {
         const auto &v = call(this, this->wallet_url, wallet_public_keys);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      // list private keys
      auto listPrivKeys = wallet->add_subcommand("private_keys",
                                                 "List of private keys from an unlocked wallet in wif or PVT_R1 format.");
      listPrivKeys->add_option("-n,--name", wallet_name, "The name of the wallet to list keys from", true);
      listPrivKeys->add_option("--password", wallet_pw, "The password returned by wallet create")->expected(0, 1);
      listPrivKeys->callback([&wallet_name, &wallet_pw, this] {
         this->prompt_for_wallet_password(wallet_pw, wallet_name);
         fc::variants vs = {fc::variant(wallet_name), fc::variant(wallet_pw)};
         const auto &v = call(this, this->wallet_url, wallet_list_keys, vs);
         my_out << fc::json::to_pretty_string(v) << std::endl;
      });

      auto stopKeosd = wallet->add_subcommand("stop",
                                              fmt::format("Stop {k}.", fmt::arg("k", key_store_executable_name)));
      stopKeosd->callback([this] {
         const auto &v = call(this, this->wallet_url, keosd_stop);
         if (!v.is_object() || v.get_object().size() != 0) { //on success keosd responds with empty object
            my_err << fc::json::to_pretty_string(v) << std::endl;
         } else {
            my_out << "OK" << std::endl;
         }
      });

      // sign subcommand
      string trx_json_to_sign;
      string str_private_key;
      str_chain_id = {};
      string str_private_key_file;
      string str_public_key;
      string signature_provider;
      bool push_trx = false;

      auto sign = app.add_subcommand("sign", "Sign a transaction");
      sign->add_option("transaction", trx_json_to_sign,
                       "The JSON string or filename defining the transaction to sign", true)->required();
      auto private_key_opt = sign
            ->add_option("-k,--private-key", str_private_key,
                         "The private key that will be used to sign the transaction")
            ->expected(0, 1);
      sign->add_option("--public-key", str_public_key,
                       fmt::format("Ask {exec} to sign with the corresponding private key of the given public key",
                                   fmt::arg("exec", key_store_executable_name)));
      sign->add_option("-c,--chain-id", str_chain_id, "The chain id that will be used to sign the transaction");
      sign->add_flag("-p,--push-transaction", push_trx, "Push transaction after signing");
      sign
            ->add_option("--signature-provider", signature_provider,
                         "The signature provider that will be used to sign the transaction")
            ->expected(0, 1);
      CLI::deprecate_option(private_key_opt, "--signature-provider");

      auto fix_trx_data = [this](fc::variant& unpacked_data_trx) {
         if (unpacked_data_trx.is_object()) {
            fc::variant_object &vo = unpacked_data_trx.get_object();
            // if actions.data & actions.hex_data provided, use the hex_data since only currently support unexploded data
            if (vo.contains("actions")) {
               if (vo["actions"].is_array()) {
                  fc::mutable_variant_object mvo = vo;
                  fc::variants &action_variants = mvo["actions"].get_array();
                  for (auto &action_v: action_variants) {
                     if (!action_v.is_object()) {
                        my_err << "Empty 'action' in transaction" << endl;
                        continue;
                     }
                     fc::variant_object &action_vo = action_v.get_object();
                     if (action_vo.contains("data") && action_vo.contains("hex_data")) {
                        if (action_vo["data"].is_string()) {
                           fc::mutable_variant_object maction_vo = action_vo;
                           maction_vo["data"] = maction_vo["hex_data"];
                           action_vo = maction_vo;
                           vo = mvo;
                        }
                     }
                  }
               } else {
                  my_err << "transaction json 'actions' is not an array" << std::endl;
               }
            } else {
               my_err << "transaction json does not include 'actions'" << std::endl;
            }
         }
      };

      sign->callback([&] {
         EOSC_ASSERT(my_err, str_private_key.empty() || str_public_key.empty(),
                     "ERROR: Either -k/--private-key or --public-key or none of them can be set");

         EOSC_ASSERT(my_err, str_private_key.empty() || signature_provider.empty(),
                     "ERROR: Either -k/--private-key or --signature_provider or none of them can be set");

         EOSC_ASSERT(my_err, str_public_key.empty() || signature_provider.empty(),
                     "ERROR: Either --public-key or --signature_provider or none of them can be set");

         fc::variant trx_var = variant_from_file_or_string(trx_json_to_sign);

         // If transaction was packed, unpack it before signing
         bool was_packed_trx = false;
         if (trx_var.is_object()) {
            fc::variant_object &vo = trx_var.get_object();
            if (vo.contains("packed_trx")) {
               chain::packed_transaction_v0 packed_trx;
               try {
                  fc::from_variant<chain::packed_transaction_v0>(trx_var, packed_trx);
               }
               EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid packed transaction format: '{data}'",
                                      ("data", fc::json::to_string(trx_var, fc::time_point::maximum())))
               const chain::signed_transaction &strx = packed_trx.get_signed_transaction();
               trx_var = strx;
               was_packed_trx = true;
            }
            else {
               fix_trx_data(trx_var);
            }
         }

         chain::signed_transaction trx;
         try {
            chain::abi_serializer::from_variant(trx_var, trx, [&](const chain::name &account){return this->abi_serializer_resolver_empty(account);},
                                                chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         }
         EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid transaction format: '{data}'",
                                ("data", fc::json::to_string(trx_var, fc::time_point::maximum())))

         std::optional<chain::chain_id_type> chain_id;

         if (str_chain_id.size() == 0) {
            auto info = get_info();
            chain_id = info.chain_id;
         } else {
            chain_id = chain::chain_id_type(str_chain_id);
         }

         if (str_public_key.size() > 0) {
            chain::public_key_type pub_key;
            try {
               pub_key = chain::public_key_type(str_public_key);
            }
            EOS_RETHROW_EXCEPTIONS(chain::public_key_type_exception, "Invalid public key: {public_key}",
                                   ("public_key", str_public_key))
            fc::variant keys_var(fc::flat_set<chain::public_key_type>{pub_key});
            sign_transaction(trx, keys_var, *chain_id);
         } else {
            if (!signature_provider.empty()) {
               const auto &[pubkey, provider] =
                     eosio::app().get_plugin<signature_provider_plugin>().signature_provider_for_specification(
                           signature_provider);
               chain::digest_type digest = trx.sig_digest(*chain_id, trx.context_free_data);
               chain::signature_type siguature = provider(digest);
               trx.signatures.push_back(siguature);

            } else {
               if (str_private_key.size() == 0) {
                  my_err << "private key: ";
                  fc::set_console_echo(false);
                  std::getline(std::cin, str_private_key, '\n');
                  fc::set_console_echo(true);
               }
               chain::private_key_type priv_key;
               try {
                  priv_key = chain::private_key_type(str_private_key);
               }
               EOS_RETHROW_EXCEPTIONS(chain::private_key_type_exception, "Invalid private key")
               trx.sign(priv_key, *chain_id);
            }
         }

         if (push_trx) {
            // no need to sign again
            auto old_tx_skip_sign = tx_skip_sign;
            tx_skip_sign = true;
            auto trx_result = push_transaction(trx, {});
            tx_skip_sign = old_tx_skip_sign;
            my_out << fc::json::to_pretty_string(trx_result) << std::endl;
         } else {
            if (was_packed_trx) { // pack it as before
               my_out << fc::json::to_pretty_string(
                     chain::packed_transaction_v0(trx, chain::packed_transaction_v0::compression_type::none))
                         << std::endl;
            } else {
               my_out << fc::json::to_pretty_string(trx) << std::endl;
            }
         }
      });

      // Push subcommand
      auto push = app.add_subcommand("push", "Push arbitrary transactions to the blockchain");
      push->require_subcommand();

      // push action
      string contract_account;
      string action;
      string data;
      vector<string> permissions;
      auto actionsSubcommand = push->add_subcommand("action", "Push a transaction with a single action");
      actionsSubcommand->fallthrough(false);
      actionsSubcommand->add_option("account", contract_account,
                                    "The account providing the contract to execute", true)->required();
      actionsSubcommand->add_option("action", action,
                                    "A JSON string or filename defining the action to execute on the contract",
                                    true)->required();
      actionsSubcommand->add_option("data", data, "The arguments to the contract")->required();

      add_standard_transaction_options_plus_signing(actionsSubcommand);
      actionsSubcommand->callback([&] {
         std::string action_json;
         if (!data.empty()) {
            action_json = json_from_file_or_string(data);
         }
         auto accountPermissions = get_account_permissions(tx_permission);

         send_actions({chain::action{accountPermissions, chain::name(contract_account), chain::name(action),
                                     action_json_to_bin(chain::name(contract_account), chain::name(action),
                                                        action_json)}}, signing_keys_opt.get_keys());
      });

      // push transaction
      string trx_to_push;
      std::vector<string> extra_signatures;
      CLI::callback_t extra_sig_opt_callback = [&](CLI::results_t res) {
         vector<string>::iterator itr;
         for (itr = res.begin(); itr != res.end(); ++itr) {
            extra_signatures.push_back(*itr);
         }
         return true;
      };
      auto trxSubcommand = push->add_subcommand("transaction", "Push an arbitrary JSON transaction");
      trxSubcommand->add_option("transaction", trx_to_push,
                                "The JSON string or filename defining the transaction to push")->required();
      trxSubcommand->add_option("--signature", extra_sig_opt_callback,
                                "append a signature to the transaction; repeat this option to append multiple signatures")->type_size(
            0, 1000);
      add_standard_transaction_options_plus_signing(trxSubcommand);
      trxSubcommand->add_flag("-o,--read-only", tx_read_only, "Specify a transaction is read-only");

      trxSubcommand->callback([&] {
         fc::variant trx_var = variant_from_file_or_string(trx_to_push);
         chain::signed_transaction trx;
         try {
            trx = trx_var.as<chain::signed_transaction>();
         } catch (const std::exception &) {
            // unable to convert so try via abi
            chain::abi_serializer::from_variant(trx_var, trx, [&](const chain::name &account){return this->abi_serializer_resolver(account);},
                                                chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         }
         for (const string &sig: extra_signatures) {
            trx.signatures.push_back(fc::crypto::signature(sig));
         }
         my_out << fc::json::to_pretty_string(push_transaction(trx, signing_keys_opt.get_keys())) << std::endl;
      });

      // push transactions
      string trxsJson;
      auto trxsSubcommand = push->add_subcommand("transactions", "Push an array of arbitrary JSON transactions");
      trxsSubcommand->add_option("transactions", trxsJson,
                                 "The JSON string or filename defining the array of the transactions to push")->required();
      trxsSubcommand->callback([&] {
         fc::variant trx_var = variant_from_file_or_string(trxsJson);
         auto trxs_result = call(this, push_txns_func, trx_var);
         my_out << fc::json::to_pretty_string(trxs_result) << std::endl;
      });

      // multisig subcommand
      auto msig = app.add_subcommand("multisig", "Multisig contract commands");
      msig->require_subcommand();

      // multisig propose
      string proposal_name;
      string requested_perm;
      string transaction_perm;
      string proposed_transaction;
      string proposed_contract;
      string proposed_action;
      string proposer;
      unsigned int proposal_expiration_hours = 24;
      CLI::callback_t parse_expiration_hours = [&](CLI::results_t res) -> bool {
         unsigned int value_s;
         if (res.size() == 0 || !CLI::detail::lexical_cast(res[0], value_s)) {
            return false;
         }

         proposal_expiration_hours = static_cast<uint64_t>(value_s);
         return true;
      };

      auto propose_action = msig->add_subcommand("propose", "Propose action");
      add_standard_transaction_options_plus_signing(propose_action, "proposer@active");
      propose_action->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      propose_action->add_option("requested_permissions", requested_perm,
                                 "The JSON string or filename defining requested permissions")->required();
      propose_action->add_option("trx_permissions", transaction_perm,
                                 "The JSON string or filename defining transaction permissions")->required();
      propose_action->add_option("contract", proposed_contract,
                                 "The contract to which deferred transaction should be delivered")->required();
      propose_action->add_option("action", proposed_action, "The action of deferred transaction")->required();
      propose_action->add_option("data", proposed_transaction,
                                 "The JSON string or filename defining the action to propose")->required();
      propose_action->add_option("proposer", proposer, "Account proposing the transaction");
      propose_action->add_option("proposal_expiration", parse_expiration_hours,
                                 "Proposal expiration interval in hours");

      propose_action->callback([&] {
         fc::variant requested_perm_var = variant_from_file_or_string(requested_perm);
         fc::variant transaction_perm_var = variant_from_file_or_string(transaction_perm);
         fc::variant trx_var = variant_from_file_or_string(proposed_transaction);
         chain::transaction proposed_trx;
         try {
            proposed_trx = trx_var.as<chain::transaction>();
         } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Invalid transaction format: '{data}'",
                                  ("data", fc::json::to_string(trx_var, fc::time_point::maximum())))
         chain::bytes proposed_trx_serialized = variant_to_bin(chain::name(proposed_contract),
                                                               chain::name(proposed_action), trx_var);

         vector<chain::permission_level> reqperm;
         try {
            reqperm = requested_perm_var.as<vector<chain::permission_level>>();
         } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Wrong requested permissions format: '{data}'",
                                  ("data", fc::json::to_string(requested_perm_var, fc::time_point::now() +
                                                                                   fc::exception::format_time_limit)));

         vector<chain::permission_level> trxperm;
         try {
            trxperm = transaction_perm_var.as<vector<chain::permission_level>>();
         } EOS_RETHROW_EXCEPTIONS(chain::transaction_type_exception, "Wrong transaction permissions format: '{data}'",
                                  ("data", fc::json::to_string(transaction_perm_var, fc::time_point::now() +
                                                                                     fc::exception::format_time_limit)));

         auto accountPermissions = get_account_permissions(tx_permission);
         if (accountPermissions.empty()) {
            if (!proposer.empty()) {
               accountPermissions = vector<chain::permission_level>{
                     {chain::name(proposer), chain::config::active_name}};
            } else {
               EOS_THROW(chain::missing_auth_exception,
                         "Authority is not provided (either by multisig parameter <proposer> or -p)");
            }
         }
         if (proposer.empty()) {
            proposer = chain::name(accountPermissions.at(0).actor).to_string();
         }

         chain::transaction trx;

         trx.expiration = fc::time_point_sec(fc::time_point::now() + fc::hours(proposal_expiration_hours));
         trx.ref_block_num = 0;
         trx.ref_block_prefix = 0;
         trx.max_net_usage_words = 0;
         trx.max_cpu_usage_ms = 0;
         trx.delay_sec = 0;
         trx.actions = {chain::action(trxperm, chain::name(proposed_contract), chain::name(proposed_action),
                                      proposed_trx_serialized)};

         fc::to_variant(trx, trx_var);

         auto args = fc::mutable_variant_object()
               ("proposer", proposer)
               ("proposal_name", proposal_name)
               ("requested", requested_perm_var)
               ("trx", trx_var);

         send_actions({chain::action{accountPermissions, "eosio.msig"_n, "propose"_n,
                                     variant_to_bin("eosio.msig"_n, "propose"_n, args)}}, signing_keys_opt.get_keys());
      });

      //multisig propose transaction
      auto propose_trx = msig->add_subcommand("propose_trx", "Propose transaction");
      add_standard_transaction_options_plus_signing(propose_trx, "proposer@active");
      propose_trx->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      propose_trx->add_option("requested_permissions", requested_perm,
                              "The JSON string or filename defining requested permissions")->required();
      propose_trx->add_option("transaction", trx_to_push,
                              "The JSON string or filename defining the transaction to push")->required();
      propose_trx->add_option("proposer", proposer, "Account proposing the transaction");

      propose_trx->callback([&] {
         fc::variant requested_perm_var = variant_from_file_or_string(requested_perm);
         fc::variant trx_var = variant_from_file_or_string(trx_to_push);

         auto accountPermissions = get_account_permissions(tx_permission);
         if (accountPermissions.empty()) {
            if (!proposer.empty()) {
               accountPermissions = vector<chain::permission_level>{
                     {chain::name(proposer), chain::config::active_name}};
            } else {
               EOS_THROW(chain::missing_auth_exception,
                         "Authority is not provided (either by multisig parameter <proposer> or -p)");
            }
         }
         if (proposer.empty()) {
            proposer = chain::name(accountPermissions.at(0).actor).to_string();
         }

         auto args = fc::mutable_variant_object()
               ("proposer", proposer)
               ("proposal_name", proposal_name)
               ("requested", requested_perm_var)
               ("trx", trx_var);

         send_actions({chain::action{accountPermissions, "eosio.msig"_n, "propose"_n,
                                     variant_to_bin("eosio.msig"_n, "propose"_n, args)}}, signing_keys_opt.get_keys());
      });


      // multisig review
      bool show_approvals_in_multisig_review = false;
      auto review = msig->add_subcommand("review", "Review transaction");
      review->add_option("proposer", proposer, "The proposer name (string)")->required();
      review->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      review->add_flag("--show-approvals", show_approvals_in_multisig_review,
                       "Show the status of the approvals requested within the proposal");

      review->callback([&] {
         const auto result1 = call(this, get_table_func, fc::mutable_variant_object("json", true)
               ("code", "eosio.msig")
               ("scope", proposer)
               ("table", "proposal")
               ("table_key", "")
               ("lower_bound", chain::name(proposal_name).to_uint64_t())
               ("upper_bound", chain::name(proposal_name).to_uint64_t() + 1)
               // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
               // Change to chain::name(proposal_name).value when cleos no longer needs to support nodeos versions older than 1.5.0
               ("limit", 1)
         );
         //my_out << fc::json::to_pretty_string(result) << std::endl;

         const auto &rows1 = result1.get_object()["rows"].get_array();
         // Condition in if statement below can simply be rows.empty() when cleos no longer needs to support nodeos versions older than 1.5.0
         if (rows1.empty() || rows1[0].get_object()["proposal_name"] != proposal_name) {
            my_err << "Proposal not found" << std::endl;
            return;
         }

         const auto &proposal_object = rows1[0].get_object();

         enum class approval_status {
            unapproved,
            approved,
            invalidated
         };

         std::map<chain::permission_level, std::pair<fc::time_point, approval_status>> all_approvals;
         std::map<chain::account_name, std::pair<fc::time_point, vector<decltype(all_approvals)::iterator>>> provided_approvers;

         bool new_multisig = true;
         if (show_approvals_in_multisig_review) {
            fc::variants rows2;

            try {
               const auto &result2 = call(this, get_table_func, fc::mutable_variant_object("json", true)
                     ("code", "eosio.msig")
                     ("scope", proposer)
                     ("table", "approvals2")
                     ("table_key", "")
                     ("lower_bound", chain::name(proposal_name).to_uint64_t())
                     ("upper_bound", chain::name(proposal_name).to_uint64_t() + 1)
                     // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                     // Change to chain::name(proposal_name).value when cleos no longer needs to support nodeos versions older than 1.5.0
                     ("limit", 1)
               );
               rows2 = result2.get_object()["rows"].get_array();
            } catch (...) {
               new_multisig = false;
            }

            if (!rows2.empty() && rows2[0].get_object()["proposal_name"] == proposal_name) {
               const auto &approvals_object = rows2[0].get_object();

               for (const auto &ra: approvals_object["requested_approvals"].get_array()) {
                  const auto &ra_obj = ra.get_object();
                  auto pl = ra["level"].as<chain::permission_level>();
                  all_approvals.emplace(pl,
                                        std::make_pair(ra["time"].as<fc::time_point>(), approval_status::unapproved));
               }

               for (const auto &pa: approvals_object["provided_approvals"].get_array()) {
                  const auto &pa_obj = pa.get_object();
                  auto pl = pa["level"].as<chain::permission_level>();
                  auto res = all_approvals.emplace(pl, std::make_pair(pa["time"].as<fc::time_point>(),
                                                                      approval_status::approved));
                  provided_approvers[pl.actor].second.push_back(res.first);
               }
            } else {
               const auto result3 = call(this, get_table_func, fc::mutable_variant_object("json", true)
                     ("code", "eosio.msig")
                     ("scope", proposer)
                     ("table", "approvals")
                     ("table_key", "")
                     ("lower_bound", chain::name(proposal_name).to_uint64_t())
                     ("upper_bound", chain::name(proposal_name).to_uint64_t() + 1)
                     // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                     // Change to chain::name(proposal_name).value when cleos no longer needs to support nodeos versions older than 1.5.0
                     ("limit", 1)
               );
               const auto &rows3 = result3.get_object()["rows"].get_array();
               if (rows3.empty() || rows3[0].get_object()["proposal_name"] != proposal_name) {
                  my_err << "Proposal not found" << std::endl;
                  return;
               }

               const auto &approvals_object = rows3[0].get_object();

               for (const auto &ra: approvals_object["requested_approvals"].get_array()) {
                  auto pl = ra.as<chain::permission_level>();
                  all_approvals.emplace(pl, std::make_pair(fc::time_point{}, approval_status::unapproved));
               }

               for (const auto &pa: approvals_object["provided_approvals"].get_array()) {
                  auto pl = pa.as<chain::permission_level>();
                  auto res = all_approvals.emplace(pl, std::make_pair(fc::time_point{}, approval_status::approved));
                  provided_approvers[pl.actor].second.push_back(res.first);
               }
            }

            if (new_multisig) {
               for (auto &a: provided_approvers) {
                  const auto result4 = call(this, get_table_func, fc::mutable_variant_object("json", true)
                        ("code", "eosio.msig")
                        ("scope", "eosio.msig")
                        ("table", "invals")
                        ("table_key", "")
                        ("lower_bound", a.first.to_uint64_t())
                        ("upper_bound", a.first.to_uint64_t() + 1)
                        // Less than ideal upper_bound usage preserved so cleos can still work with old buggy nodeos versions
                        // Change to chain::name(proposal_name).value when cleos no longer needs to support nodeos versions older than 1.5.0
                        ("limit", 1)
                  );
                  const auto &rows4 = result4.get_object()["rows"].get_array();
                  if (rows4.empty() || rows4[0].get_object()["account"].as<chain::name>() != a.first) {
                     continue;
                  }

                  auto invalidation_time = rows4[0].get_object()["last_invalidation_time"].as<fc::time_point>();
                  a.second.first = invalidation_time;

                  for (auto &itr: a.second.second) {
                     if (invalidation_time >= itr->second.first) {
                        itr->second.second = approval_status::invalidated;
                     }
                  }
               }
            }
         }

         auto trx_hex = proposal_object["chain::packed_transaction"].as_string();
         vector<char> trx_blob(trx_hex.size() / 2);
         fc::from_hex(trx_hex, trx_blob.data(), trx_blob.size());
         chain::transaction trx = fc::raw::unpack<chain::transaction>(trx_blob);

         fc::mutable_variant_object obj;
         obj["proposer"] = proposer;
         obj["proposal_name"] = proposal_object["proposal_name"];
         obj["transaction_id"] = trx.id();

         for (const auto &entry: proposal_object) {
            if (entry.key() == "proposal_name") continue;
            obj.set(entry.key(), entry.value());
         }

         fc::variant trx_var;
         chain::abi_serializer abi;
         abi.to_variant(trx, trx_var, [&](const chain::name &account){return this->abi_serializer_resolver(account);},
                        chain::abi_serializer::create_yield_function(abi_serializer_max_time));
         obj["transaction"] = trx_var;

         if (show_approvals_in_multisig_review) {
            fc::variants approvals;

            for (const auto &approval: all_approvals) {
               fc::mutable_variant_object approval_obj;
               approval_obj["level"] = approval.first;
               switch (approval.second.second) {
                  case approval_status::unapproved: {
                     approval_obj["status"] = "unapproved";
                     if (approval.second.first != fc::time_point{}) {
                        approval_obj["last_unapproval_time"] = approval.second.first;
                     }
                  }
                     break;
                  case approval_status::approved: {
                     approval_obj["status"] = "approved";
                     if (new_multisig) {
                        approval_obj["last_approval_time"] = approval.second.first;
                     }
                  }
                     break;
                  case approval_status::invalidated: {
                     approval_obj["status"] = "invalidated";
                     approval_obj["last_approval_time"] = approval.second.first;
                     approval_obj["invalidation_time"] = provided_approvers[approval.first.actor].first;
                  }
                     break;
               }

               approvals.push_back(std::move(approval_obj));
            }

            obj["approvals"] = std::move(approvals);
         }

         my_out << fc::json::to_pretty_string(obj) << std::endl;
      });

      string perm;
      string proposal_hash;
      auto approve_or_unapprove = [&](const string &action) {
         fc::variant perm_var = variant_from_file_or_string(perm);

         auto args = fc::mutable_variant_object()
               ("proposer", proposer)
               ("proposal_name", proposal_name)
               ("level", perm_var);

         if (proposal_hash.size()) {
            args("proposal_hash", proposal_hash);
         }

         auto accountPermissions = get_account_permissions(tx_permission,
                                                           {chain::name(proposer), chain::config::active_name});
         send_actions({chain::action{accountPermissions, "eosio.msig"_n, chain::name(action),
                                     variant_to_bin("eosio.msig"_n, chain::name(action), args)}},
                      signing_keys_opt.get_keys());
      };

      // multisig approve
      auto approve = msig->add_subcommand("approve", "Approve proposed transaction");
      add_standard_transaction_options_plus_signing(approve, "proposer@active");
      approve->add_option("proposer", proposer, "The proposer name (string)")->required();
      approve->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      approve->add_option("permissions", perm,
                          "The JSON string of filename defining approving permissions")->required();
      approve->add_option("proposal_hash", proposal_hash,
                          "Hash of proposed transaction (i.e. transaction ID) to optionally enforce as a condition of the approval");
      approve->callback([&] { approve_or_unapprove("approve"); });

      // multisig unapprove
      auto unapprove = msig->add_subcommand("unapprove", "Unapprove proposed transaction");
      add_standard_transaction_options_plus_signing(unapprove, "proposer@active");
      unapprove->add_option("proposer", proposer, "The proposer name (string)")->required();
      unapprove->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      unapprove->add_option("permissions", perm,
                            "The JSON string of filename defining approving permissions")->required();
      unapprove->callback([&] { approve_or_unapprove("unapprove"); });

      // multisig invalidate
      string invalidator;
      auto invalidate = msig->add_subcommand("invalidate", "Invalidate all multisig approvals of an account");
      add_standard_transaction_options_plus_signing(invalidate, "invalidator@active");
      invalidate->add_option("invalidator", invalidator, "Invalidator name (string)")->required();
      invalidate->callback([&] {
         auto args = fc::mutable_variant_object()
               ("account", invalidator);

         auto accountPermissions = get_account_permissions(tx_permission,
                                                           {chain::name(invalidator), chain::config::active_name});
         send_actions({chain::action{accountPermissions, "eosio.msig"_n, "invalidate"_n,
                                     variant_to_bin("eosio.msig"_n, "invalidate"_n, args)}},
                      signing_keys_opt.get_keys());
      });

      // multisig cancel
      string canceler;
      auto cancel = msig->add_subcommand("cancel", "Cancel proposed transaction");
      add_standard_transaction_options_plus_signing(cancel, "canceler@active");
      cancel->add_option("proposer", proposer, "The proposer name (string)")->required();
      cancel->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      cancel->add_option("canceler", canceler, "The canceler name (string)");
      cancel->callback([&]() {
                          auto accountPermissions = get_account_permissions(tx_permission);
                          if (accountPermissions.empty()) {
                             if (!canceler.empty()) {
                                accountPermissions = vector<chain::permission_level>{
                                      {chain::name(canceler), chain::config::active_name}};
                             } else {
                                EOS_THROW(chain::missing_auth_exception,
                                          "Authority is not provided (either by multisig parameter <canceler> or -p)");
                             }
                          }
                          if (canceler.empty()) {
                             canceler = chain::name(accountPermissions.at(0).actor).to_string();
                          }
                          auto args = fc::mutable_variant_object()
                                ("proposer", proposer)
                                ("proposal_name", proposal_name)
                                ("canceler", canceler);

                          send_actions({chain::action{accountPermissions, "eosio.msig"_n, "cancel"_n,
                                                      variant_to_bin("eosio.msig"_n, "cancel"_n, args)}}, signing_keys_opt.get_keys());
                       }
      );

      // multisig exec
      string executer;
      auto exec = msig->add_subcommand("exec", "Execute proposed transaction");
      add_standard_transaction_options_plus_signing(exec, "executer@active");
      exec->add_option("proposer", proposer, "The proposer name (string)")->required();
      exec->add_option("proposal_name", proposal_name, "The proposal name (string)")->required();
      exec->add_option("executer", executer, "The account paying for execution (string)");
      exec->callback([&] {
                        auto accountPermissions = get_account_permissions(tx_permission);
                        if (accountPermissions.empty()) {
                           if (!executer.empty()) {
                              accountPermissions = vector<chain::permission_level>{
                                    {chain::name(executer), chain::config::active_name}};
                           } else {
                              EOS_THROW(chain::missing_auth_exception,
                                        "Authority is not provided (either by multisig parameter <executer> or -p)");
                           }
                        }
                        if (executer.empty()) {
                           executer = chain::name(accountPermissions.at(0).actor).to_string();
                        }

                        auto args = fc::mutable_variant_object()
                              ("proposer", proposer)
                              ("proposal_name", proposal_name)
                              ("executer", executer);

                        send_actions({chain::action{accountPermissions, "eosio.msig"_n, "exec"_n,
                                                    variant_to_bin("eosio.msig"_n, "exec"_n, args)}}, signing_keys_opt.get_keys());
                     }
      );

      // wrap subcommand
      auto wrap = app.add_subcommand("wrap", "Wrap contract commands");
      wrap->require_subcommand();

      // wrap exec
      string wrap_con = "eosio.wrap";
      executer = "";
      string trx_to_exec;
      auto wrap_exec = wrap->add_subcommand("exec", "Execute a transaction while bypassing authorization checks");
      add_standard_transaction_options_plus_signing(wrap_exec, "executer@active & --contract@active");
      wrap_exec->add_option("executer", executer,
                            "Account executing the transaction and paying for the deferred transaction RAM")->required();
      wrap_exec->add_option("transaction", trx_to_exec,
                            "The JSON string or filename defining the transaction to execute")->required();
      wrap_exec->add_option("--contract,-c", wrap_con, "The account which controls the wrap contract");

      wrap_exec->callback([&] {
         fc::variant trx_var = variant_from_file_or_string(trx_to_exec);

         auto accountPermissions = get_account_permissions(tx_permission);
         if (accountPermissions.empty()) {
            accountPermissions = vector<chain::permission_level>{{chain::name(executer), chain::config::active_name},
                                                                 {chain::name(wrap_con), chain::config::active_name}};
         }

         auto args = fc::mutable_variant_object()
               ("executer", executer)
               ("trx", trx_var);

         send_actions({chain::action{accountPermissions, chain::name(wrap_con), "exec"_n,
                                     variant_to_bin(chain::name(wrap_con), "exec"_n, args)}},
                      signing_keys_opt.get_keys());
      });

      // system subcommand
      auto system = app.add_subcommand("system", "Send eosio.system contract action to the blockchain.");
      system->require_subcommand();

      auto createAccountSystem = create_account_subcommand(system, false /*simple*/, *this);
      auto registerProducer = register_producer_subcommand(system, *this);
      auto unregisterProducer = unregister_producer_subcommand(system, *this);

      auto voteProducer = system->add_subcommand("voteproducer", "Vote for a producer");
      voteProducer->require_subcommand();
      auto voteProxy = vote_producer_proxy_subcommand(voteProducer, *this);
      auto voteProducers = vote_producers_subcommand(voteProducer, *this);
      auto approveProducer = approve_producer_subcommand(voteProducer, *this);
      auto unapproveProducer = unapprove_producer_subcommand(voteProducer, *this);

      auto listProducers = list_producers_subcommand(system, *this);

      auto delegateBandWidth = delegate_bandwidth_subcommand(system, *this);
      auto undelegateBandWidth = undelegate_bandwidth_subcommand(system, *this);
      auto listBandWidth = list_bw_subcommand(system, *this);
      auto bidname = bidname_subcommand(system, *this);
      auto bidnameinfo = bidname_info_subcommand(system, *this);

      auto buyram = buyram_subcommand(system, *this);
      auto sellram = sellram_subcommand(system, *this);

      auto claimRewards = claimrewards_subcommand(system, *this);

      auto regProxy = regproxy_subcommand(system, *this);
      auto unregProxy = unregproxy_subcommand(system, *this);

      auto rex = system->add_subcommand("rex", "Actions related to REX (the resource exchange)");
      rex->require_subcommand();

      auto activate = activate_subcommand(system, *this);

      auto deposit = deposit_subcommand(rex, *this);
      auto withdraw = withdraw_subcommand(rex, *this);
      auto buyrex = buyrex_subcommand(rex, *this);
      auto lendrex = lendrex_subcommand(rex, *this);
      auto unstaketorex = unstaketorex_subcommand(rex, *this);
      auto sellrex = sellrex_subcommand(rex, *this);
      auto cancelrexorder = cancelrexorder_subcommand(rex, *this);
      auto mvtosavings = mvtosavings_subcommand(rex, *this);
      auto mvfromsavings = mvfrsavings_subcommand(rex, *this);
      auto rentcpu = rentcpu_subcommand(rex, *this);
      auto rentnet = rentnet_subcommand(rex, *this);
      auto fundcpuloan = fundcpuloan_subcommand(rex, *this);
      auto fundnetloan = fundnetloan_subcommand(rex, *this);
      auto defcpuloan = defcpuloan_subcommand(rex, *this);
      auto defnetloan = defnetloan_subcommand(rex, *this);
      auto consolidate = consolidate_subcommand(rex, *this);
      auto updaterex = updaterex_subcommand(rex, *this);
      auto rexexec = rexexec_subcommand(rex, *this);
      auto closerex = closerex_subcommand(rex, *this);

      auto handle_error = [&](const auto &e) {
         // attempt to extract the error code if one is present
         if (!print_recognized_errors(e, verbose, my_err)) {
            // Error is not recognized
            if (!print_help_text(e, my_err) || verbose) {
               my_err << fmt::format("Failed with error: {e}\n", fmt::arg("e", verbose ? e.to_detail_string() : e.to_string()));
            }
         }
         return 1;
      };

      // message subcommand
      auto message = app.add_subcommand("message", "Sign an arbitrary message");
      message->require_subcommand();

      auto message_sign = message->add_subcommand("sign", "Sign an arbitrary message");
      // sign subcommand
      string sign_str_private_key;
      string file_to_sign_path;

      message_sign
            ->add_option("--signature-provider", sign_str_private_key,
                         "The signature provider that will be used to sign the data")
            ->expected(0, 1);
      message_sign->add_option("input_file", file_to_sign_path,
                               "Path to filename containing data to sign", true)->required();

      message_sign->callback([&] {
         chain::private_key_type priv_key;
         if (sign_str_private_key.empty()) {
            my_out << "signature provider: ";
            fc::set_console_echo(false);
            std::getline(std::cin, sign_str_private_key, '\n');
            fc::set_console_echo(true);
         }
         const auto &[pubkey, provider] =
               eosio::app().get_plugin<signature_provider_plugin>().signature_provider_for_specification(
                     sign_str_private_key);
         std::ifstream ifs(file_to_sign_path, std::ios::binary);
         EOSC_ASSERT(my_err, ifs, "file not found!");
         fc::sha256 hash = fc::sha256::hash(ifs);
         EOSC_ASSERT(my_err, !ifs.bad() && ifs.eof(), "file read error!");
         my_out << fc::json::to_pretty_string(fc::mutable_variant_object("signature", provider(hash))) << std::endl;
      });

      // recover subcommand
      auto recover = message->add_subcommand("recover", "Recover the public key used to sign the message");
      string signature_to_verify;
      string file_to_verify_path;

      recover->add_option("-s,--signature", signature_to_verify, "Signature to be validated");
      recover->add_option("input_file", file_to_verify_path,
                          "Path to filename containing the data to validate the signature", true)->required();

      recover->callback([&] {

         if (signature_to_verify.empty()) {
            my_out << "signature : ";
            std::getline(std::cin, signature_to_verify, '\n');
         }
         chain::signature_type message_signature(signature_to_verify);

         string message_to_verify;
         fc::read_file_contents(file_to_verify_path, message_to_verify);
         EOSC_ASSERT(my_err, !message_to_verify.empty(), "file not found!");

         fc::sha256 hash = fc::sha256::hash(message_to_verify);
         chain::public_key_type pub_key(message_signature, hash);
         my_out << fc::json::to_pretty_string(fc::mutable_variant_object("public_key", pub_key))
                   << std::endl;
      });

      try {
         app.parse(argc, argv);
      } catch (const CLI::ParseError &e) {
         return app.exit(e);
      } catch (const explained_exception &e) {
         return 1;
      } catch (connection_exception &e) {
         if (verbose) {
            my_err << fmt::format("connect error: {e}\n", fmt::arg("e", e.to_detail_string()));
         }
         return 1;
      } catch (const std::bad_alloc &) {
         my_err << "bad alloc\n";
      } catch (const boost::interprocess::bad_alloc &) {
         my_err << "bad alloc\n";
      } catch (const fc::exception &e) {
         return handle_error(e);
      } catch (const std::exception &e) {
         return handle_error(fc::std_exception_wrapper::from_current_exception(e));
      } catch (const std::string &e) {
         my_err << e << std::endl;
         return 1;
      }

      return 0;
   }
};

template<typename T>
fc::variant call(cleos_client* client,
                 const std::string &url,
                 const std::string &path,
                 const T &v) {
   try {
      auto sp = std::make_unique<eosio::client::http::connection_param>(client->context, parse_url(url) + path,
                                                                        client->no_verify ? false : true, client->headers);
      return eosio::client::http::do_http_call(*sp, fc::variant(v), client->print_request, client->print_response);
   }
   catch (boost::system::system_error &e) {
      std::string prog;
      if (url == client->default_url)
         prog = node_executable_name;
      else if (url == client->wallet_url)
         prog = key_store_executable_name;

      if (prog.size()) {
         client->my_err << "Failed to connect to " << prog << " at " << url << "; is " << prog << " running?\n";
      }

      throw connection_exception(fc::log_messages{FC_LOG_MESSAGE(error, e.what())});
   }
}

template<typename T>
fc::variant call(cleos_client* client,
                 const std::string &path,
                 const T &v) { return call(client, client->default_url, path, fc::variant(v)); }

template<>
fc::variant call(cleos_client* client,
                 const std::string &url,
                 const std::string &path) { return call(client, url, path, fc::variant()); }

FC_REFLECT(alias_url_pair, (alias)(url) )
FC_REFLECT(config_json_data, (default_url)(aups) )
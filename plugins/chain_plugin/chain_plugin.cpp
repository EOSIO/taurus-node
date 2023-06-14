#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/fork_database.hpp>
#include <eosio/chain/block_log.hpp>
#include <eosio/chain/wasm_interface.hpp>
#include <eosio/chain/generated_transaction_object.hpp>
#include <eosio/chain/snapshot.hpp>
#include <eosio/chain/permission_link_object.hpp>
#include <eosio/chain/eosio_contract.hpp>
#include <eosio/resource_monitor_plugin/resource_monitor_plugin.hpp>
#include <chainbase/environment.hpp>
#include <boost/signals2/connection.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <fc/io/json.hpp>
#include <fc/log/trace.hpp>
#include <fc/variant.hpp>
#include <signal.h>

#include <sys/types.h>
#include <sys/wait.h>

using eosio::chain::public_key_type;
using eosio::chain::account_name;

// reflect chainbase::environment for --print-build-info option
FC_REFLECT_ENUM( chainbase::environment::os_t,
                 (OS_LINUX)(OS_MACOS)(OS_WINDOWS)(OS_OTHER) )
FC_REFLECT_ENUM( chainbase::environment::arch_t,
                 (ARCH_X86_64)(ARCH_ARM)(ARCH_RISCV)(ARCH_OTHER) )
FC_REFLECT(chainbase::environment, (debug)(os)(arch)(boost_version)(compiler) )

namespace eosio::detail {
   struct replace_account_keys_t {
      chain::name     account;
      chain::name     permission;
      public_key_type pub_key;
   };
}
FC_REFLECT(eosio::detail::replace_account_keys_t, (account)(permission)(pub_key) )
using namespace eosio::detail;


namespace eosio {
//declare operator<< and validate funciton for read_mode in the same namespace as read_mode itself
namespace chain {

extern void configure_native_module(native_module_config& config, const bfs::path& path);

std::ostream& operator<<(std::ostream& osm, eosio::chain::db_read_mode m) {
   if ( m == eosio::chain::db_read_mode::SPECULATIVE ) {
      osm << "speculative";
   } else if ( m == eosio::chain::db_read_mode::HEAD ) {
      osm << "head";
   } else if ( m == eosio::chain::db_read_mode::READ_ONLY ) { // deprecated
      osm << "read-only";
   } else if ( m == eosio::chain::db_read_mode::IRREVERSIBLE ) {
      osm << "irreversible";
   }

   return osm;
}

void validate(boost::any& v,
              const std::vector<std::string>& values,
              eosio::chain::db_read_mode* /* target_type */,
              int)
{
  using namespace boost::program_options;

  // Make sure no previous assignment to 'v' was made.
  validators::check_first_occurrence(v);

  // Extract the first string from 'values'. If there is more than
  // one string, it's an error, and exception will be thrown.
  std::string const& s = validators::get_single_string(values);

  if ( s == "speculative" ) {
     v = boost::any(eosio::chain::db_read_mode::SPECULATIVE);
  } else if ( s == "head" ) {
     v = boost::any(eosio::chain::db_read_mode::HEAD);
  } else if ( s == "read-only" ) {
     v = boost::any(eosio::chain::db_read_mode::READ_ONLY);
  } else if ( s == "irreversible" ) {
     v = boost::any(eosio::chain::db_read_mode::IRREVERSIBLE);
  } else {
     throw validation_error(validation_error::invalid_option_value);
  }
}

std::ostream& operator<<(std::ostream& osm, eosio::chain::validation_mode m) {
   if ( m == eosio::chain::validation_mode::FULL ) {
      osm << "full";
   } else if ( m == eosio::chain::validation_mode::LIGHT ) {
      osm << "light";
   }

   return osm;
}

void validate(boost::any& v,
              const std::vector<std::string>& values,
              eosio::chain::validation_mode* /* target_type */,
              int)
{
  using namespace boost::program_options;

  // Make sure no previous assignment to 'v' was made.
  validators::check_first_occurrence(v);

  // Extract the first string from 'values'. If there is more than
  // one string, it's an error, and exception will be thrown.
  std::string const& s = validators::get_single_string(values);

  if ( s == "full" ) {
     v = boost::any(eosio::chain::validation_mode::FULL);
  } else if ( s == "light" ) {
     v = boost::any(eosio::chain::validation_mode::LIGHT);
  } else {
     throw validation_error(validation_error::invalid_option_value);
  }
}

std::ostream& operator<<(std::ostream& osm, eosio::chain::backing_store_type b) {
   if ( b == eosio::chain::backing_store_type::CHAINBASE ) {
      osm << "chainbase";
   }

   return osm;
}

void validate(boost::any& v,
              const std::vector<std::string>& values,
              eosio::chain::backing_store_type* /* target_type */,
              int)
{
  using namespace boost::program_options;

  // Make sure no previous assignment to 'v' was made.
  validators::check_first_occurrence(v);

  // Extract the first string from 'values'. If there is more than
  // one string, it's an error, and exception will be thrown.
  std::string const& s = validators::get_single_string(values);

  if ( s == "chainbase" ) {
     v = boost::any(eosio::chain::backing_store_type::CHAINBASE);
  } else {
     throw validation_error(validation_error::invalid_option_value);
  }
}
}

using namespace eosio;
using namespace eosio::chain;
using namespace eosio::chain::config;
using namespace eosio::chain::plugin_interface;
using namespace appbase;
using vm_type = wasm_interface::vm_type;
using fc::flat_map;
using eosio::chain::action_name;

using boost::signals2::scoped_connection;

class chain_plugin_impl {
public:
   chain_plugin_impl()
   :pre_accepted_block_channel(app().get_channel<channels::pre_accepted_block>())
   ,accepted_block_header_channel(app().get_channel<channels::accepted_block_header>())
   ,accepted_block_channel(app().get_channel<channels::accepted_block>())
   ,irreversible_block_channel(app().get_channel<channels::irreversible_block>())
   ,accepted_transaction_channel(app().get_channel<channels::accepted_transaction>())
   ,applied_transaction_channel(app().get_channel<channels::applied_transaction>())
   ,incoming_block_channel(app().get_channel<incoming::channels::block>())
   ,incoming_block_sync_method(app().get_method<incoming::methods::block_sync>())
   ,incoming_transaction_async_method(app().get_method<incoming::methods::transaction_async>())
   {}

   bfs::path                        blocks_dir;
   bool                             readonly = false;
   flat_map<uint32_t,block_id_type> loaded_checkpoints;
   bool                             accept_transactions = false;
   bool                             api_accept_transactions = true;
   bool                             account_queries_enabled = false;

   std::optional<controller::config> chain_config;
   std::optional<controller>         chain;
   std::optional<genesis_state>      genesis;
   //txn_msg_rate_limits              rate_limits;
   std::optional<vm_type>            wasm_runtime;
   fc::microseconds                  abi_serializer_max_time_us;
   std::optional<bfs::path>          snapshot_path;
   // whether the snapshot being loaded is the state snapshot
   bool                              loading_state_snapshot = false;
   std::optional<public_key_type>    replace_producer_keys;
   std::vector<replace_account_keys_t> replace_account_keys;
   bool                              replace_chain_id = false;
   bool                              is_disable_background_snapshots = false;

   // retained references to channels for easy publication
   channels::pre_accepted_block::channel_type&     pre_accepted_block_channel;
   channels::accepted_block_header::channel_type&  accepted_block_header_channel;
   channels::accepted_block::channel_type&         accepted_block_channel;
   channels::irreversible_block::channel_type&     irreversible_block_channel;
   channels::accepted_transaction::channel_type&   accepted_transaction_channel;
   channels::applied_transaction::channel_type&    applied_transaction_channel;
   incoming::channels::block::channel_type&        incoming_block_channel;

   // retained references to methods for easy calling
   incoming::methods::block_sync::method_type&        incoming_block_sync_method;
   incoming::methods::transaction_async::method_type& incoming_transaction_async_method;

   // method provider handles
   methods::get_block_by_number::method_type::handle                 get_block_by_number_provider;
   methods::get_block_by_id::method_type::handle                     get_block_by_id_provider;
   methods::get_head_block_id::method_type::handle                   get_head_block_id_provider;
   methods::get_last_irreversible_block_number::method_type::handle  get_last_irreversible_block_number_provider;

   // scoped connections for chain controller
   std::optional<scoped_connection>                                   pre_accepted_block_connection;
   std::optional<scoped_connection>                                   accepted_block_header_connection;
   std::optional<scoped_connection>                                   accepted_block_connection;
   std::optional<scoped_connection>                                   irreversible_block_connection;
   std::optional<scoped_connection>                                   accepted_transaction_connection;
   std::optional<scoped_connection>                                   applied_transaction_connection;

   std::optional<chain_apis::account_query_db>                        _account_query_db;
};

chain_plugin::chain_plugin()
:my(new chain_plugin_impl()) {
   app().register_config_type<eosio::chain::db_read_mode>();
   app().register_config_type<eosio::chain::validation_mode>();
   app().register_config_type<eosio::chain::backing_store_type>();
   app().register_config_type<chainbase::pinnable_mapped_file::map_mode>();
   app().register_config_type<eosio::chain::wasm_interface::vm_type>();
}

chain_plugin::~chain_plugin(){}

void chain_plugin::set_program_options(options_description& cli, options_description& cfg)
{
   // build wasm_runtime help text
   std::string wasm_runtime_opt = "Override default WASM runtime (";
   std::string wasm_runtime_desc;
   std::string delim;
#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
   wasm_runtime_opt += " \"eos-vm-jit\"";
   wasm_runtime_desc += "\"eos-vm-jit\" : A WebAssembly runtime that compiles WebAssembly code to native x86 code prior to execution.\n";
   delim = ", ";
#endif

#ifdef EOSIO_EOS_VM_RUNTIME_ENABLED
   wasm_runtime_opt += delim + "\"eos-vm\"";
   wasm_runtime_desc += "\"eos-vm\" : A WebAssembly interpreter.\n";
   delim = ", ";
#endif

#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
   wasm_runtime_opt += delim + "\"native-module\"";
   wasm_runtime_desc += "\"native-module\" : Run contracts which compiled as native module.\n";
   delim = ", ";
#endif

#ifdef EOSIO_EOS_VM_OC_DEVELOPER
   wasm_runtime_opt += delim + "\"eos-vm-oc\"";
   wasm_runtime_desc += "\"eos-vm-oc\" : Unsupported. Instead, use one of the other runtimes along with the option enable-eos-vm-oc.\n";
#endif


   wasm_runtime_opt += ")\n" + wasm_runtime_desc;

   std::string default_wasm_runtime_str= eosio::chain::wasm_interface::vm_type_string(eosio::chain::config::default_wasm_runtime);

   cfg.add_options()
         ("blocks-dir", bpo::value<bfs::path>()->default_value("blocks"),
          "the location of the blocks directory (absolute path or relative to application data dir)")
         ("blocks-log-stride", bpo::value<uint32_t>()->default_value(config::default_blocks_log_stride),
         "split the block log file when the head block number is the multiple of the stride\n"
         "When the stride is reached, the current block log and index will be renamed '<blocks-retained-dir>/blocks-<start num>-<end num>.log/index'\n"
         "and a new current block log and index will be created with the most recent block. All files following\n"
         "this format will be used to construct an extended block log.")
         ("max-retained-block-files", bpo::value<uint16_t>()->default_value(config::default_max_retained_block_files),
          "the maximum number of blocks files to retain so that the blocks in those files can be queried.\n"
          "When the number is reached, the oldest block file would be moved to archive dir or deleted if the archive dir is empty.\n"
          "The retained block log files should not be manipulated by users." )
         ("blocks-retained-dir", bpo::value<bfs::path>()->default_value(""),
          "the location of the blocks retained directory (absolute path or relative to blocks dir).\n"
          "If the value is empty, it is set to the value of blocks dir.")
         ("blocks-archive-dir", bpo::value<bfs::path>()->default_value(config::default_blocks_archive_dir_name),
          "the location of the blocks archive directory (absolute path or relative to blocks dir).\n"
          "If the value is empty, blocks files beyond the retained limit will be deleted.\n"
          "All files in the archive directory are completely under user's control, i.e. they won't be accessed by nodeos anymore.")
         ("fix-irreversible-blocks", bpo::value<bool>()->default_value("false"),
          "When the existing block log is inconsistent with the index, allows fixing the block log and index files automatically - that is, "
          "it will take the highest indexed block if it is valid; otherwise it will repair the block log and reconstruct the index.")
         ("protocol-features-dir", bpo::value<bfs::path>()->default_value("protocol_features"),
          "the location of the protocol_features directory (absolute path or relative to application config dir)")
         ("checkpoint", bpo::value<vector<string>>()->composing(), "Pairs of [BLOCK_NUM,BLOCK_ID] that should be enforced as checkpoints.")
         ("wasm-runtime", bpo::value<eosio::chain::wasm_interface::vm_type>()->value_name("runtime")->notifier([](const auto& vm){
#ifndef EOSIO_EOS_VM_OC_DEVELOPER
            //throwing an exception here (like EOS_ASSERT) is just gobbled up with a "Failed to initialize" error :(
            if(vm == wasm_interface::vm_type::eos_vm_oc) {
               elog("EOS VM OC is a tier-up compiler and works in conjunction with the configured base WASM runtime. Enable EOS VM OC via 'eos-vm-oc-enable' option");
               EOS_ASSERT(false, chain::plugin_exception, "");
            }
#endif
         })->default_value(eosio::chain::config::default_wasm_runtime, default_wasm_runtime_str), wasm_runtime_opt.c_str()
         )
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
         ("native-contracts-dir", bpo::value<bfs::path>(), "the location of native contracts, only used with native-module runtime")
#endif
         ("profile-account", boost::program_options::value<vector<string>>()->composing(),
          "The name of an account whose code will be profiled")
         ("abi-serializer-max-time-ms", bpo::value<uint32_t>()->default_value(config::default_abi_serializer_max_time_us / 1000),
          "Override default maximum ABI serialization time allowed in ms")
         ("chain-state-db-size-mb", bpo::value<uint64_t>()->default_value(config::default_state_size / (1024  * 1024)), "Maximum size (in MiB) of the chain state database")
         ("chain-state-db-guard-size-mb", bpo::value<uint64_t>()->default_value(config::default_state_guard_size / (1024  * 1024)), "Safely shut down node when free space remaining in the chain state database drops below this size (in MiB).")
         ("reversible-blocks-db-size-mb", bpo::value<uint64_t>()->default_value(0),
          "(DEPRECATED: no longer used) Maximum size (in MiB) of the reversible blocks database")
         ("reversible-blocks-db-guard-size-mb", bpo::value<uint64_t>()->default_value(0),
          "(DEPRECATED: no longer used) Safely shut down node when free space remaining in the reverseible blocks database drops below this size (in MiB).")
         ("signature-cpu-billable-pct", bpo::value<uint32_t>()->default_value(config::default_sig_cpu_bill_pct / config::percent_1),
          "Percentage of actual signature recovery cpu to bill. Whole number percentages, e.g. 50 for 50%")
         ("chain-threads", bpo::value<uint16_t>()->default_value(config::default_controller_thread_pool_size),
          "Number of worker threads in controller thread pool")
         ("contracts-console", bpo::bool_switch()->default_value(false),
          "print contract's output to console")
         ("telemetry-url", bpo::value<std::string>(),
          "Send Zipkin spans to url. e.g. http://127.0.0.1:9411/api/v2/spans" )
         ("telemetry-service-name", bpo::value<std::string>()->default_value("nodeos"),
          "Zipkin localEndpoint.serviceName sent with each span" )
         ("telemetry-timeout-us", bpo::value<uint32_t>()->default_value(200000),
          "Timeout for sending Zipkin span." )
         ("telemetry-retry-interval-us", bpo::value<uint32_t>()->default_value(30000000),
          "Retry interval for connecting to Zipkin." )
         ("telemetry-wait-timeout-seconds", bpo::value<uint32_t>()->default_value(0),
          "Initial wait time for Zipkin to become available, stop the program if the connection cannot be established within the wait time.")
         ("actor-whitelist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Account added to actor whitelist (may specify multiple times)")
         ("actor-blacklist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Account added to actor blacklist (may specify multiple times)")
         ("contract-whitelist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Contract account added to contract whitelist (may specify multiple times)")
         ("contract-blacklist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Contract account added to contract blacklist (may specify multiple times)")
         ("action-blacklist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Action (in the form code::action) added to action blacklist (may specify multiple times)")
         ("key-blacklist", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Public key added to blacklist of keys that should not be included in authorities (may specify multiple times)")
         ("read-mode", boost::program_options::value<eosio::chain::db_read_mode>()->default_value(eosio::chain::db_read_mode::SPECULATIVE),
          "Database read mode (\"speculative\", \"head\", \"read-only\", \"irreversible\").\n"
          "In \"speculative\" mode: database contains state changes by transactions in the blockchain up to the head block as well as some transactions not yet included in the blockchain.\n"
          "In \"head\" mode: database contains state changes by only transactions in the blockchain up to the head block; transactions received by the node are relayed if valid.\n"
          "In \"read-only\" mode: (DEPRECATED: see p2p-accept-transactions & api-accept-transactions) database contains state changes by only transactions in the blockchain up to the head block; transactions received via the P2P network are not relayed and transactions cannot be pushed via the chain API.\n"
          "In \"irreversible\" mode: database contains state changes by only transactions in the blockchain up to the last irreversible block; transactions received via the P2P network are not relayed and transactions cannot be pushed via the chain API.\n"
          )
         ( "api-accept-transactions", bpo::value<bool>()->default_value(true), "Allow API transactions to be evaluated and relayed if valid.")
         ("validation-mode", boost::program_options::value<eosio::chain::validation_mode>()->default_value(eosio::chain::validation_mode::FULL),
          "Chain validation mode (\"full\" or \"light\").\n"
          "In \"full\" mode all incoming blocks will be fully validated.\n"
          "In \"light\" mode all incoming blocks headers will be fully validated; transactions in those validated blocks will be trusted. \n"
#ifndef EOSIO_NOT_REQUIRE_FULL_VALIDATION
          "Option present due to backwards compatibility, but set always to \"full\". \n"
#endif
         )
         ("trusted-producer", bpo::value<vector<string>>()->composing(), "Indicate a producer whose blocks headers signed by it will be fully validated, but transactions in those validated blocks will be trusted. \n"
#ifndef EOSIO_NOT_REQUIRE_FULL_VALIDATION
          "Option present due to backwards compatibility, but set always to empty. \n"
#endif
         )
         ("disable-ram-billing-notify-checks", bpo::bool_switch()->default_value(false),
          "Disable the check which subjectively fails a transaction if a contract bills more RAM to another account within the context of a notification handler (i.e. when the receiver is not the code of the action).")
#ifdef EOSIO_DEVELOPER
         ("disable-all-subjective-mitigations", bpo::bool_switch()->default_value(false),
          "Disable all subjective mitigations checks in the entire codebase.")
#endif
         ("maximum-variable-signature-length", bpo::value<uint32_t>()->default_value(16384u),
          "Subjectively limit the maximum length of variable components in a variable legnth signature to this size in bytes")
         ("database-map-mode", bpo::value<chainbase::pinnable_mapped_file::map_mode>(),
          "Database map mode (\"heap\", or \"locked\").\n"
          "[deprecated, same as \"heap\"] In \"mapped\" mode database is memory mapped as a file.\n"
#ifndef _WIN32
          "In \"heap\" mode database is preloaded in to swappable memory and will use huge pages if available.\n"
          "In \"locked\" mode database is preloaded, locked in to memory, and will use huge pages if available.\n"
          "When \"persist-data\" option is set to true, the default value of this option is \"mapped\"; otherwise, the default value is \"heap\".\n"
#endif
         )
         ("database-on-invalid-mode", bpo::value<std::string>()->default_value("exit"),
         "Database on invalid mode (\exit\" or \"delete\").\n"
         "In \"exit\" mode the program will exit with error code when database is invalid.\n"
         "In \"delete\" mode database is deleted if it is invalid; will replay block log or sync from genesis.\n"
         )
         ("persist-data", bpo::value<bool>()->default_value(true),
#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
            "Persist blocks, database and eos-vm-oc code cache to disk.\n"
#else
            "Persist blocks and database to disk.\n"
#endif
         )

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
         ("eos-vm-oc-cache-size-mb", bpo::value<uint64_t>()->default_value(eosvmoc::config().cache_size / (1024u*1024u)), "Maximum size (in MiB) of the EOS VM OC code cache")
         ("eos-vm-oc-compile-threads", bpo::value<uint64_t>()->default_value(1u)->notifier([](const auto t) {
               if(t == 0) {
                  elog("eos-vm-oc-compile-threads must be set to a non-zero value");
                  EOS_ASSERT(false, chain::plugin_exception, "");
               }
         }), "Number of threads to use for EOS VM OC tier-up")
         ("eos-vm-oc-code-cache-map-mode", bpo::value<chainbase::pinnable_mapped_file::map_mode>(),
          "Map mode for EOS VM OC code cache (\"heap\", or \"locked\").\n"
          "[deprecated, same as \"heap\"] In \"mapped\" mode code cache is memory mapped as a file.\n"
          "In \"heap\" mode code cache is preloaded in to swappable memory and will use huge pages if available.\n"
          "In \"locked\" mode code cache is preloaded, locked in to memory, and will use huge pages if available.\n"
          "When \"persist-data\" option is set to true, the default value of this option is \"mapped\"; otherwise, the default value is \"heap\".\n"
         )
         ("eos-vm-oc-enable", bpo::bool_switch(), "Enable EOS VM OC tier-up runtime")
#endif
         ("enable-account-queries", bpo::value<bool>()->default_value(false), "enable queries to find accounts by various metadata.")
         ("max-nonprivileged-inline-action-size", bpo::value<uint32_t>()->default_value(config::default_max_nonprivileged_inline_action_size), "maximum allowed size (in bytes) of an inline action for a nonprivileged account")
         ("integrity-hash-on-start", bpo::bool_switch(), "Log the state integrity hash on startup")
         ("integrity-hash-on-stop", bpo::bool_switch(), "Log the state integrity hash on shutdown")
         ;

// TODO: rate limiting
         /*("per-authorized-account-transaction-msg-rate-limit-time-frame-sec", bpo::value<uint32_t>()->default_value(default_per_auth_account_time_frame_seconds),
          "The time frame, in seconds, that the per-authorized-account-transaction-msg-rate-limit is imposed over.")
         ("per-authorized-account-transaction-msg-rate-limit", bpo::value<uint32_t>()->default_value(default_per_auth_account),
          "Limits the maximum rate of transaction messages that an account is allowed each per-authorized-account-transaction-msg-rate-limit-time-frame-sec.")
          ("per-code-account-transaction-msg-rate-limit-time-frame-sec", bpo::value<uint32_t>()->default_value(default_per_code_account_time_frame_seconds),
           "The time frame, in seconds, that the per-code-account-transaction-msg-rate-limit is imposed over.")
          ("per-code-account-transaction-msg-rate-limit", bpo::value<uint32_t>()->default_value(default_per_code_account),
           "Limits the maximum rate of transaction messages that an account's code is allowed each per-code-account-transaction-msg-rate-limit-time-frame-sec.")*/

   cli.add_options()
         ("genesis-json", bpo::value<bfs::path>(), "File to read Genesis State from")
         ("genesis-timestamp", bpo::value<string>(), "override the initial timestamp in the Genesis State file")
         ("print-genesis-json", bpo::bool_switch()->default_value(false),
          "extract genesis_state from blocks.log as JSON, print to console, and exit")
         ("extract-genesis-json", bpo::value<bfs::path>(),
          "extract genesis_state from blocks.log as JSON, write into specified file, and exit")
         ("print-build-info", bpo::bool_switch()->default_value(false),
          "print build environment information to console as JSON and exit")
         ("extract-build-info", bpo::value<bfs::path>(),
          "extract build environment information as JSON, write into specified file, and exit")
         ("snapshot-to-json", bpo::value<bfs::path>(),
          "snapshot file to convert to JSON format, writes to <file>.json (tmp state dir used), and exit")
         ("force-all-checks", bpo::bool_switch()->default_value(false),
          "do not skip any validation checks while replaying blocks (useful for replaying blocks from untrusted source)")
         ("disable-replay-opts", bpo::bool_switch()->default_value(false),
          "disable optimizations that specifically target replay")
         ("replay-blockchain", bpo::bool_switch()->default_value(false),
          "clear chain state database and replay all blocks")
         ("hard-replay-blockchain", bpo::bool_switch()->default_value(false),
          "clear chain state database, recover as many blocks as possible from the block log, and then replay those blocks")
         ("delete-all-blocks", bpo::bool_switch()->default_value(false),
          "clear chain state database and block log")
         ("truncate-at-block", bpo::value<uint32_t>()->default_value(0),
          "stop hard replay / block log recovery at this block number (if set to non-zero number)")
         ("terminate-at-block", bpo::value<uint32_t>()->default_value(0),
          "terminate after reaching this block number (if set to a non-zero number)")
         ("snapshot", bpo::value<bfs::path>(), "File to read Snapshot State from (can be in binary or json format)")
#ifdef EOSIO_NOT_REQUIRE_FULL_VALIDATION
         ("replace-producer-keys", bpo::value<string>(), "Replace producer keys with provided key")
         ("replace-account-key", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Replace account key, e.g. {\"account\":\"root\",\"permission\":\"owner\",\"pub_key\":\"EOS...\"}, can be specified multiple times")
         ("replace-chain-id", bpo::value<string>(), "Replace chain id of snapshot")
#endif
         ("min-initial-block-num", bpo::value<uint32_t>()->default_value(0),
         "minimum last irreversible block (lib) number, fail to start if state/snapshot lib is prior to specified")
         ("disable-background-snapshots", bpo::bool_switch()->default_value(false),
          "Normally snapshots will be written in the background periodically.  Setting this to true disables that behavior.  However on exit background snapshots will continue to be written.")
          ;

}

#define LOAD_VALUE_SET(options, op_name, container) \
if( options.count(op_name) ) { \
   const std::vector<std::string>& ops = options[op_name].as<std::vector<std::string>>(); \
   for( const auto& v : ops ) { \
      container.emplace( eosio::chain::name( v ) ); \
   } \
}

fc::time_point calculate_genesis_timestamp( string tstr ) {
   fc::time_point genesis_timestamp;
   if( strcasecmp (tstr.c_str(), "now") == 0 ) {
      genesis_timestamp = fc::time_point::now();
   } else {
      genesis_timestamp = time_point::from_iso_string( tstr );
   }

   auto epoch_us = genesis_timestamp.time_since_epoch().count();
   auto diff_us = epoch_us % config::block_interval_us;
   if (diff_us > 0) {
      auto delay_us = (config::block_interval_us - diff_us);
      genesis_timestamp += fc::microseconds(delay_us);
      dlog("pausing {us} microseconds to the next interval",("us",delay_us));
   }

   ilog( "Adjusting genesis timestamp to {timestamp}", ("timestamp", genesis_timestamp) );
   return genesis_timestamp;
}

void clear_directory_contents( const fc::path& p ) {
   using boost::filesystem::directory_iterator;

   if( !fc::is_directory( p ) )
      return;

   for( directory_iterator enditr, itr{p}; itr != enditr; ++itr ) {
      fc::remove_all( itr->path() );
   }
}

std::optional<builtin_protocol_feature> read_builtin_protocol_feature( const fc::path& p  ) {
   try {
      return fc::json::from_file<builtin_protocol_feature>( p );
   } catch( const fc::exception& e ) {
      wlog( "problem encountered while reading '{path}':\n{details}",
            ("path", p.generic_string())("details",e.to_detail_string()) );
   } catch( ... ) {
      dlog( "unknown problem encountered while reading '{path}'",
            ("path", p.generic_string()) );
   }
   return {};
}

protocol_feature_set initialize_protocol_features( const fc::path& p, bool populate_missing_builtins = true ) {
   using boost::filesystem::directory_iterator;

   protocol_feature_set pfs;

   bool directory_exists = true;

   if( fc::exists( p ) ) {
      EOS_ASSERT( fc::is_directory( p ), chain::plugin_exception,
                  "Path to protocol-features is not a directory: {path}",
                  ("path", p.generic_string())
      );
   } else {
      if( populate_missing_builtins )
         bfs::create_directories( p );
      else
         directory_exists = false;
   }

   auto log_recognized_protocol_feature = []( const builtin_protocol_feature& f, const digest_type& feature_digest ) {
      if( f.subjective_restrictions.enabled ) {
         if( f.subjective_restrictions.preactivation_required ) {
            if( f.subjective_restrictions.earliest_allowed_activation_time == time_point{} ) {
               ilog( "Support for builtin protocol feature '{codename}' (with digest of '{digest}') is enabled with preactivation required",
                     ("codename", builtin_protocol_feature_codename(f.get_codename()))
                     ("digest", feature_digest)
               );
            } else {
               ilog( "Support for builtin protocol feature '{codename}' (with digest of '{digest}') is enabled with preactivation required and with an earliest allowed activation time of {earliest_time}",
                     ("codename", builtin_protocol_feature_codename(f.get_codename()))
                     ("digest", feature_digest)
                     ("earliest_time", f.subjective_restrictions.earliest_allowed_activation_time)
               );
            }
         } else {
            if( f.subjective_restrictions.earliest_allowed_activation_time == time_point{} ) {
               ilog( "Support for builtin protocol feature '{codename}' (with digest of '{digest}') is enabled without activation restrictions",
                     ("codename", builtin_protocol_feature_codename(f.get_codename()))
                     ("digest", feature_digest)
               );
            } else {
               ilog( "Support for builtin protocol feature '{codename}' (with digest of '{digest}') is enabled without preactivation required but with an earliest allowed activation time of {earliest_time}",
                     ("codename", builtin_protocol_feature_codename(f.get_codename()))
                     ("digest", feature_digest)
                     ("earliest_time", f.subjective_restrictions.earliest_allowed_activation_time)
               );
            }
         }
      } else {
         ilog( "Recognized builtin protocol feature '{codename}' (with digest of '{digest}') but support for it is not enabled",
               ("codename", builtin_protocol_feature_codename(f.get_codename()))
               ("digest", feature_digest)
         );
      }
   };

   map<builtin_protocol_feature_t, fc::path>  found_builtin_protocol_features;
   map<digest_type, std::pair<builtin_protocol_feature, bool> > builtin_protocol_features_to_add;
   // The bool in the pair is set to true if the builtin protocol feature has already been visited to add
   map< builtin_protocol_feature_t, std::optional<digest_type> > visited_builtins;

   // Read all builtin protocol features
   if( directory_exists ) {
      for( directory_iterator enditr, itr{p}; itr != enditr; ++itr ) {
         auto file_path = itr->path();
         if( !fc::is_regular_file( file_path ) || file_path.extension().generic_string().compare( ".json" ) != 0 )
            continue;

         auto f = read_builtin_protocol_feature( file_path );

         if( !f ) continue;

         auto res = found_builtin_protocol_features.emplace( f->get_codename(), file_path );

         EOS_ASSERT( res.second, chain::plugin_exception,
                     "Builtin protocol feature '{codename}' was already included from a previous_file",
                     ("codename", builtin_protocol_feature_codename(f->get_codename()))
                     ("current_file", file_path.generic_string())
                     ("previous_file", res.first->second.generic_string())
         );

         const auto feature_digest = f->digest();

         builtin_protocol_features_to_add.emplace( std::piecewise_construct,
                                                   std::forward_as_tuple( feature_digest ),
                                                   std::forward_as_tuple( *f, false ) );
      }
   }

   // Add builtin protocol features to the protocol feature manager in the right order (to satisfy dependencies)
   using itr_type = map<digest_type, std::pair<builtin_protocol_feature, bool>>::iterator;
   std::function<void(const itr_type&)> add_protocol_feature =
   [&pfs, &builtin_protocol_features_to_add, &visited_builtins, &log_recognized_protocol_feature, &add_protocol_feature]( const itr_type& itr ) -> void {
      if( itr->second.second ) {
         return;
      } else {
         itr->second.second = true;
         visited_builtins.emplace( itr->second.first.get_codename(), itr->first );
      }

      for( const auto& d : itr->second.first.dependencies ) {
         auto itr2 = builtin_protocol_features_to_add.find( d );
         if( itr2 != builtin_protocol_features_to_add.end() ) {
            add_protocol_feature( itr2 );
         }
      }

      pfs.add_feature( itr->second.first );

      log_recognized_protocol_feature( itr->second.first, itr->first );
   };

   for( auto itr = builtin_protocol_features_to_add.begin(); itr != builtin_protocol_features_to_add.end(); ++itr ) {
      add_protocol_feature( itr );
   }

   auto output_protocol_feature = [&p]( const builtin_protocol_feature& f, const digest_type& feature_digest ) {
      static constexpr int max_tries = 10;

      string filename( "BUILTIN-" );
      filename += builtin_protocol_feature_codename( f.get_codename() );
      filename += ".json";

      auto file_path = p / filename;

      EOS_ASSERT( !fc::exists( file_path ), chain::plugin_exception,
                  "Could not save builtin protocol feature with codename '{codename}' because a file at the following path already exists: {path}",
                  ("codename", builtin_protocol_feature_codename( f.get_codename() ))
                  ("path", file_path.generic_string())
      );

      if( fc::json::save_to_file( f, file_path ) ) {
         ilog( "Saved default specification for builtin protocol feature '{codename}' (with digest of '{digest}') to: {path}",
               ("codename", builtin_protocol_feature_codename(f.get_codename()))
               ("digest", feature_digest)
               ("path", file_path.generic_string())
         );
      } else {
         elog( "Error occurred while writing default specification for builtin protocol feature '{codename}' (with digest of '{digest}') to: {path}",
               ("codename", builtin_protocol_feature_codename(f.get_codename()))
               ("digest", feature_digest)
               ("path", file_path.generic_string())
         );
      }
   };

   std::function<digest_type(builtin_protocol_feature_t)> add_missing_builtins =
   [&pfs, &visited_builtins, &output_protocol_feature, &log_recognized_protocol_feature, &add_missing_builtins, populate_missing_builtins]
   ( builtin_protocol_feature_t codename ) -> digest_type {
      auto res = visited_builtins.emplace( codename, std::optional<digest_type>() );
      if( !res.second ) {
         EOS_ASSERT( res.first->second, chain::protocol_feature_exception,
                     "invariant failure: cycle found in builtin protocol feature dependencies"
         );
         return *res.first->second;
      }

      auto f = protocol_feature_set::make_default_builtin_protocol_feature( codename,
      [&add_missing_builtins]( builtin_protocol_feature_t d ) {
         return add_missing_builtins( d );
      } );

      if( !populate_missing_builtins )
         f.subjective_restrictions.enabled = false;

      const auto& pf = pfs.add_feature( f );
      res.first->second = pf.feature_digest;

      log_recognized_protocol_feature( f, pf.feature_digest );

      if( populate_missing_builtins )
         output_protocol_feature( f, pf.feature_digest );

      return pf.feature_digest;
   };

   for( const auto& p : builtin_protocol_feature_codenames ) {
      auto itr = found_builtin_protocol_features.find( p.first );
      if( itr != found_builtin_protocol_features.end() ) continue;

      add_missing_builtins( p.first );
   }

   return pfs;
}

namespace {
  // This can be removed when versions of eosio that support reversible chainbase state file no longer supported.
  void upgrade_from_reversible_to_fork_db(chain_plugin_impl* my) {
     namespace bfs = boost::filesystem;
     bfs::path old_fork_db = my->chain_config->state_dir / config::forkdb_filename;
     bfs::path new_fork_db = my->blocks_dir / config::reversible_blocks_dir_name / config::forkdb_filename;
     if( bfs::exists( old_fork_db ) && bfs::is_regular_file( old_fork_db ) ) {
        bool copy_file = false;
        if( bfs::exists( new_fork_db ) && bfs::is_regular_file( new_fork_db ) ) {
           if( bfs::last_write_time( old_fork_db ) > bfs::last_write_time( new_fork_db ) ) {
              copy_file = true;
           }
        } else {
           copy_file = true;
           bfs::create_directories( my->blocks_dir / config::reversible_blocks_dir_name );
        }
        if( copy_file ) {
           fc::rename( old_fork_db, new_fork_db );
        } else {
           fc::remove( old_fork_db );
        }
     }
  }

  void post_startup(chain_plugin_impl* my) {
     if( my->replace_producer_keys ) {
        my->chain->replace_producer_keys( *my->replace_producer_keys, true );
     }
     for( const auto& rak : my->replace_account_keys ) {
        my->chain->replace_account_keys( rak.account, rak.permission, rak.pub_key );
     }
  }
}

void
chain_plugin::do_hard_replay(const variables_map& options) {
         ilog( "Hard replay requested: deleting state database" );
         clear_directory_contents( my->chain_config->state_dir );
         auto backup_dir = block_log::repair_log( my->blocks_dir, options.at( "truncate-at-block" ).as<uint32_t>(),config::reversible_blocks_dir_name);
}


void chain_plugin::plugin_initialize(const variables_map& options) {
   ilog("initializing chain plugin");

   try {
      if (options.count("telemetry-url")) {
         fc::zipkin_config::init( options["telemetry-url"].as<std::string>(),
                                  options["telemetry-service-name"].as<std::string>(),
                                  options["telemetry-timeout-us"].as<uint32_t>(),
                                  options["telemetry-retry-interval-us"].as<uint32_t>(),
                                  options["telemetry-wait-timeout-seconds"].as<uint32_t>());
      }
      try {
         genesis_state gs; // Check if EOSIO_ROOT_KEY is bad
      } catch ( const std::exception& ) {
         elog( "EOSIO_ROOT_KEY ('{root_key}') is invalid. Recompile with a valid public key.",
               ("root_key", genesis_state::eosio_root_key));
         throw;
      }

      my->chain_config = controller::config();

      if( options.at( "print-build-info" ).as<bool>() || options.count( "extract-build-info") ) {
         if( options.at( "print-build-info" ).as<bool>() ) {
            ilog( "Build environment JSON:\n{e}", ("e", json::to_pretty_string( chainbase::environment() )) );
         }
         if( options.count( "extract-build-info") ) {
            auto p = options.at( "extract-build-info" ).as<bfs::path>();

            if( p.is_relative()) {
               p = bfs::current_path() / p;
            }

            EOS_ASSERT( fc::json::save_to_file( chainbase::environment(), p, true ), chain::misc_exception,
                        "Error occurred while writing build info JSON to '{path}'",
                        ("path", p.generic_string())
            );

            ilog( "Saved build info JSON to '{path}'", ("path", p.generic_string()) );
         }

         EOS_THROW( node_management_success, "reported build environment information" );
      }

      LOAD_VALUE_SET( options, "actor-whitelist", my->chain_config->actor_whitelist );
      LOAD_VALUE_SET( options, "actor-blacklist", my->chain_config->actor_blacklist );
      LOAD_VALUE_SET( options, "contract-whitelist", my->chain_config->contract_whitelist );
      LOAD_VALUE_SET( options, "contract-blacklist", my->chain_config->contract_blacklist );
#ifdef EOSIO_NOT_REQUIRE_FULL_VALIDATION
      LOAD_VALUE_SET( options, "trusted-producer", my->chain_config->trusted_producers );
#endif

      if( options.count( "replace-producer-keys" ) ) {
         my->replace_producer_keys.emplace( options.at( "replace-producer-keys" ).as<string>() );
      }
      if( options.count( "replace-account-key" ) ) {
         const auto& tups = options["replace-account-key"].as<std::vector<std::string>>();
         for( const auto& tup : tups ) {
            try {
               auto rak = fc::json::from_string( tup ).as<replace_account_keys_t>();
               my->replace_account_keys.emplace_back( rak );
            } catch( ... ) {
               elog( "Unable to parse replace-account-key: {t}", ("t", tup) );
               throw;
            }
         }
      }
      std::optional<chain_id_type> chain_id;
      if( options.count("replace-chain-id") ) {
         chain_id = chain_id_type{options.at( "replace-chain-id" ).as<string>()};
         my->replace_chain_id = true;
      }

      if( options.count( "action-blacklist" )) {
         const std::vector<std::string>& acts = options["action-blacklist"].as<std::vector<std::string>>();
         auto& list = my->chain_config->action_blacklist;
         for( const auto& a : acts ) {
            auto pos = a.find( "::" );
            EOS_ASSERT( pos != std::string::npos, chain::plugin_config_exception, "Invalid entry in action-blacklist: '{a}'", ("a", a));
            account_name code( a.substr( 0, pos ));
            action_name act( a.substr( pos + 2 ));
            list.emplace( code, act );
         }
      }

      if( options.count( "key-blacklist" )) {
         const std::vector<std::string>& keys = options["key-blacklist"].as<std::vector<std::string>>();
         auto& list = my->chain_config->key_blacklist;
         for( const auto& key_str : keys ) {
            list.emplace( key_str );
         }
      }

      if( options.count( "blocks-dir" )) {
         auto bld = options.at( "blocks-dir" ).as<bfs::path>();
         if(!bld.empty() && bld.is_relative())
            my->blocks_dir = app().data_dir() / bld;
         else
            my->blocks_dir = bld;

      }

      protocol_feature_set pfs;
      {
         fc::path protocol_features_dir;
         auto pfd = options.at( "protocol-features-dir" ).as<bfs::path>();
         if( pfd.is_relative())
            protocol_features_dir = app().config_dir() / pfd;
         else
            protocol_features_dir = pfd;

         pfs = initialize_protocol_features( protocol_features_dir );
      }

      if( options.count("checkpoint") ) {
         auto cps = options.at("checkpoint").as<vector<string>>();
         my->loaded_checkpoints.reserve(cps.size());
         for( const auto& cp : cps ) {
            auto item = fc::json::from_string(cp).as<std::pair<uint32_t,block_id_type>>();
            auto itr = my->loaded_checkpoints.find(item.first);
            if( itr != my->loaded_checkpoints.end() ) {
               EOS_ASSERT( itr->second == item.second,
                           chain::plugin_config_exception,
                          "redefining existing checkpoint at block number {num}: original: {orig} new: {new}",
                          ("num", item.first)("orig", itr->second)("new", item.second)
               );
            } else {
               my->loaded_checkpoints[item.first] = item.second;
            }
         }
      }

      if( options.count( "wasm-runtime" ))
         my->wasm_runtime = options.at( "wasm-runtime" ).as<vm_type>();

      LOAD_VALUE_SET( options, "profile-account", my->chain_config->profile_accounts );

      if(options.count("abi-serializer-max-time-ms")) {
         my->abi_serializer_max_time_us = fc::microseconds(options.at("abi-serializer-max-time-ms").as<uint32_t>() * 1000);
         my->chain_config->abi_serializer_max_time_us = my->abi_serializer_max_time_us;
      }

      my->chain_config->blog.log_dir                 = my->blocks_dir;
      my->chain_config->state_dir                    = app().data_dir() / config::default_state_dir_name;
      my->chain_config->read_only                    = my->readonly;
      my->chain_config->blog.retained_dir            = options.at("blocks-retained-dir").as<bfs::path>();
      my->chain_config->blog.archive_dir             = options.at("blocks-archive-dir").as<bfs::path>();
      my->chain_config->blog.stride                  = options.at("blocks-log-stride").as<uint32_t>();
      my->chain_config->blog.max_retained_files      = options.at("max-retained-block-files").as<uint16_t>();
      my->chain_config->blog.fix_irreversible_blocks = options.at("fix-irreversible-blocks").as<bool>();

      auto get_provided_genesis = [&]() -> std::optional<genesis_state> {
         if (options.count("genesis-json")) {
            bfs::path genesis_file = options.at("genesis-json").as<bfs::path>();
            if (genesis_file.is_relative()) {
               genesis_file = bfs::current_path() / genesis_file;
            }

            EOS_ASSERT(fc::is_regular_file(genesis_file),
                       chain::plugin_config_exception,
                       "Specified genesis file '{genesis}' does not exist.",
                       ( "genesis", genesis_file.generic_string()));

            genesis_state provided_genesis = fc::json::from_file(genesis_file).as<genesis_state>();

            if (options.count("genesis-timestamp")) {
               provided_genesis.initial_timestamp = calculate_genesis_timestamp(
                     options.at("genesis-timestamp").as<string>());

               ilog("Reading genesis state provided in '{genesis}' but with adjusted genesis timestamp",
                    ( "genesis", genesis_file.generic_string()));
            } else {
               ilog("Reading genesis state provided in '{genesis}'", ( "genesis", genesis_file.generic_string()));
            }

            return provided_genesis;
         } else {
            return {};
         }
      };

      // TODO: after enough long time when we are sure no shared_memory.bin is used any more in any nodeos deployed,
      //       we can do clean up of the code here to not have the shared_memory.bin at all.
      //       So far, the shared_memory.bin will be removed if it exists when nodeos restarts.

      auto shared_mem_path = my->chain_config->state_dir / "shared_memory.bin";

      my->chain_config->db_persistent = false;
#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
      my->chain_config->eosvmoc_config.persistent = false;
#endif

      bool persist_data = options["persist-data"].as<bool>();
      if (!persist_data) {
         my->chain_config->blog.stride = 0;
      }

      if (options.count("database-map-mode") == 0) {
         my->chain_config->db_map_mode = pinnable_mapped_file::map_mode::heap;
      } else {
         my->chain_config->db_map_mode = options.at("database-map-mode").as<pinnable_mapped_file::map_mode>();

         if (my->chain_config->db_map_mode == pinnable_mapped_file::map_mode::mapped) {
            ilog("--database-map-mode = mapped is deprecated. Considering it to be heap mode.");
            my->chain_config->db_map_mode = pinnable_mapped_file::map_mode::heap;
         }
      }

      auto db_on_invalid = options.at("database-on-invalid-mode").as<std::string>();
      if (db_on_invalid == "exit")
         my->chain_config->db_on_invalid = pinnable_mapped_file::on_dirty_mode::throw_on_dirty;
      else if (db_on_invalid == "delete")
         my->chain_config->db_on_invalid = pinnable_mapped_file::on_dirty_mode::delete_on_dirty;
      else {
         EOS_ASSERT(true, chain::plugin_config_exception, "{db_on_invalid} is not a valid database-on-invalid-mode option",
                    ("db_on_invalid", db_on_invalid));
      }

      if (auto resmon_plugin = app().find_plugin<eosio::resource_monitor_plugin>()) {
        resmon_plugin->monitor_directory(my->chain_config->blog.log_dir);
        resmon_plugin->monitor_directory(my->chain_config->state_dir);
      }

      if( options.count( "chain-state-db-size-mb" ))
         my->chain_config->state_size = options.at( "chain-state-db-size-mb" ).as<uint64_t>() * 1024 * 1024;

      if( options.count( "chain-state-db-guard-size-mb" ))
         my->chain_config->state_guard_size = options.at( "chain-state-db-guard-size-mb" ).as<uint64_t>() * 1024 * 1024;

      if( options.count( "reversible-blocks-db-size-mb" ))
         wlog( "reversible-blocks-db-size-mb deprecated and will be removed in future version" );

      if( options.count( "reversible-blocks-db-guard-size-mb" ))
         wlog( "reversible-blocks-db-guard-size-mb deprecated and will be removed in future version" );

      if( options.count( "max-nonprivileged-inline-action-size" ))
         my->chain_config->max_nonprivileged_inline_action_size = options.at( "max-nonprivileged-inline-action-size" ).as<uint32_t>();

      if( options.count( "chain-threads" )) {
         my->chain_config->thread_pool_size = options.at( "chain-threads" ).as<uint16_t>();
         EOS_ASSERT( my->chain_config->thread_pool_size > 0, chain::plugin_config_exception,
                     "chain-threads {num} must be greater than 0", ("num", my->chain_config->thread_pool_size) );
      }

      my->chain_config->sig_cpu_bill_pct = options.at("signature-cpu-billable-pct").as<uint32_t>();
      EOS_ASSERT( my->chain_config->sig_cpu_bill_pct >= 0 && my->chain_config->sig_cpu_bill_pct <= 100, chain::plugin_config_exception,
                  "signature-cpu-billable-pct must be 0 - 100, {pct}", ("pct", my->chain_config->sig_cpu_bill_pct) );
      my->chain_config->sig_cpu_bill_pct *= config::percent_1;

      if( my->wasm_runtime ) {
         my->chain_config->wasm_runtime = *my->wasm_runtime;

#if EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
         if (*my->wasm_runtime == wasm_interface::vm_type::native_module) {
            EOS_ASSERT(options.count("native-contracts-dir"), plugin_config_exception, "native-contracts-dir must be specified when native_module is used");
            configure_native_module(my->chain_config->native_config, options.at("native-contracts-dir").as<bfs::path>());
         }
#endif
      }

      my->chain_config->force_all_checks = options.at( "force-all-checks" ).as<bool>();
      my->chain_config->disable_replay_opts = options.at( "disable-replay-opts" ).as<bool>();
      my->chain_config->contracts_console = options.at( "contracts-console" ).as<bool>();
      my->chain_config->allow_ram_billing_in_notify = options.at( "disable-ram-billing-notify-checks" ).as<bool>();

#ifdef EOSIO_DEVELOPER
      my->chain_config->disable_all_subjective_mitigations = options.at( "disable-all-subjective-mitigations" ).as<bool>();
#endif

      my->chain_config->maximum_variable_signature_length = options.at( "maximum-variable-signature-length" ).as<uint32_t>();

      if( options.count( "terminate-at-block" ))
         my->chain_config->terminate_at_block = options.at( "terminate-at-block" ).as<uint32_t>();

      if( options.count( "extract-genesis-json" ) || options.at( "print-genesis-json" ).as<bool>()) {
         std::optional<genesis_state> gs;

         if( fc::exists( my->blocks_dir / "blocks.log" )) {
            gs = block_log::extract_genesis_state( my->blocks_dir );
            EOS_ASSERT( gs,
                        chain::plugin_config_exception,
                        "Block log at '{path}' does not contain a genesis state, it only has the chain-id.",
                        ("path", (my->blocks_dir / "blocks.log").generic_string())
            );
         } else {
            wlog( "No blocks.log found at '{p}'. Using default genesis state.",
                  ("p", (my->blocks_dir / "blocks.log").generic_string()));
            gs.emplace();
         }

         if( options.at( "print-genesis-json" ).as<bool>()) {
            ilog( "Genesis JSON:\n{genesis}", ("genesis", json::to_pretty_string( *gs )));
         }

         if( options.count( "extract-genesis-json" )) {
            auto p = options.at( "extract-genesis-json" ).as<bfs::path>();

            if( p.is_relative()) {
               p = bfs::current_path() / p;
            }

            EOS_ASSERT( fc::json::save_to_file( *gs, p, true ),
                        chain::misc_exception,
                        "Error occurred while writing genesis JSON to '{path}'",
                        ("path", p.generic_string())
            );

            ilog( "Saved genesis JSON to '{path}'", ("path", p.generic_string()) );
         }

         EOS_THROW( chain::extract_genesis_state_exception, "extracted genesis state from blocks.log" );
      }

      if( options.count("snapshot-to-json") ) {
         my->snapshot_path = options.at( "snapshot-to-json" ).as<bfs::path>();
         EOS_ASSERT( fc::exists(*my->snapshot_path), chain::plugin_config_exception,
                     "Cannot load snapshot, {name} does not exist", ("name", my->snapshot_path->generic_string()) );

         if( !my->replace_chain_id ) {
            // recover genesis information from the snapshot, used for validation code below
            auto infile = std::ifstream( my->snapshot_path->generic_string(), (std::ios::in | std::ios::binary) );
            istream_snapshot_reader reader( infile );
            reader.validate();
            chain_id = controller::extract_chain_id( reader );
            infile.close();
         }

         boost::filesystem::path temp_dir = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
         my->chain_config->state_dir = temp_dir / "state";
         my->blocks_dir = temp_dir / "blocks";
         my->chain_config->blog.log_dir = my->blocks_dir;
         try {
            auto shutdown = [](){ return app().quit(); };
            auto check_shutdown = [](){ return app().is_quiting(); };
            auto infile = std::ifstream(my->snapshot_path->generic_string(), (std::ios::in | std::ios::binary));
            auto reader = std::make_shared<istream_snapshot_reader>(infile, !my->replace_chain_id);
            my->chain.emplace( *my->chain_config, std::move(pfs), *chain_id );
            my->chain->add_indices();
            my->chain->startup(shutdown, check_shutdown, reader);
            infile.close();
            post_startup( my.get() );
            app().quit(); // shutdown as we will be finished after writing the snapshot

            ilog("Writing snapshot: {s}", ("s", my->snapshot_path->generic_string() + ".json"));
            auto snap_out = std::ofstream( my->snapshot_path->generic_string() + ".json", (std::ios::out) );
            auto writer = std::make_shared<ostream_json_snapshot_writer>( snap_out );
            my->chain->write_snapshot( writer );
            writer->finalize();
            snap_out.flush();
            snap_out.close();
         } catch (const chain::database_guard_exception& e) {
            log_guard_exception(e);
            // make sure to properly close the db
            my->chain.reset();
            fc::remove_all(temp_dir);
            throw;
         }
         my->chain.reset();
         fc::remove_all(temp_dir);
         ilog("Completed writing snapshot: {s}", ("s", my->snapshot_path->generic_string() + ".json"));
         ilog("==== Ignore any additional log messages. ====");

         EOS_THROW( node_management_success, "extracted json from snapshot" );
      }

      // move fork_db to new location
      upgrade_from_reversible_to_fork_db( my.get() );

      if( options.at( "delete-all-blocks" ).as<bool>()) {
         ilog( "Deleting state database and blocks" );
         if( options.at( "truncate-at-block" ).as<uint32_t>() > 0 )
            wlog( "The --truncate-at-block option does not make sense when deleting all blocks." );
         clear_directory_contents( my->chain_config->state_dir );
         clear_directory_contents( my->blocks_dir );
      } else if( options.at( "hard-replay-blockchain" ).as<bool>()) {
         do_hard_replay(options);
      } else if( options.at( "replay-blockchain" ).as<bool>()) {
         ilog( "Replay requested: deleting state database" );
         if( options.at( "truncate-at-block" ).as<uint32_t>() > 0 )
            wlog( "The --truncate-at-block option does not work for a regular replay of the blockchain." );
         eosio::chain::db_util::destroy( my->chain_config->state_dir );
      } else if( options.at( "truncate-at-block" ).as<uint32_t>() > 0 ) {
         wlog( "The --truncate-at-block option can only be used with --hard-replay-blockchain." );
      }


      if (options.count( "snapshot" )) {
         my->snapshot_path = options.at("snapshot").as<bfs::path>();
         EOS_ASSERT(fc::exists(*my->snapshot_path), chain::plugin_config_exception,
                    "Cannot load snapshot, {name} does not exist", ( "name", my->snapshot_path->generic_string()));
         EOS_ASSERT(my->snapshot_path->extension().generic_string().compare(".bin") == 0 ||
                    my->snapshot_path->extension().generic_string().compare(".json") == 0, plugin_config_exception,
                    "snapshot, {name} extension not bin or json", ( "name", my->snapshot_path->generic_string()));
      } else {
         // using state snapshot saved; clean the shared_memory.bin file
         if (fc::is_regular_file(shared_mem_path)) {
            ilog("Removing the legacy shared_memory.bin ...");
            fc::remove(shared_mem_path);
         }

         // use the state_snapshot if it exists
         auto state_snapshot_path = my->chain_config->state_dir / "state_snapshot.bin";

         if (fc::is_regular_file(state_snapshot_path)) {
            ilog("Using state snapshot to load states...");
            my->snapshot_path = state_snapshot_path;
            my->loading_state_snapshot = true;
         }
      }

      if (my->snapshot_path) {
         // recover genesis information from the snapshot, used for validation
         if( !my->replace_chain_id ) {
            if ( my->snapshot_path->extension().generic_string().compare( ".bin" ) == 0 ) {
               auto infile = std::ifstream( my->snapshot_path->generic_string(), (std::ios::in | std::ios::binary) );
               istream_snapshot_reader reader( infile );
               reader.validate();
               chain_id = controller::extract_chain_id( reader );
               infile.close();
            } else {
               json_snapshot_reader reader( my->snapshot_path->generic_string() );
               reader.validate();
               chain_id = controller::extract_chain_id( reader );
            }

            auto provided_genesis = get_provided_genesis();
            if (provided_genesis) {
               // if any genesis is provided, the provided genesis' chain ID must match the chain_id from the snapshot
               const auto& provided_genesis_chain_id = provided_genesis->compute_chain_id();
               EOS_ASSERT( *chain_id == provided_genesis_chain_id,
                           chain::plugin_config_exception,
                           "snapshot chain ID ({snapshot_chain_id}) does not match the chain ID ({provided_genesis_chain_id}) from the genesis state provided from the options.",
                           ("snapshot_chain_id",  (*chain_id).str())
                           ("provided_genesis_chain_id", provided_genesis_chain_id.str())
               );
            }
         }

         if (!my->loading_state_snapshot) {
            EOS_ASSERT(!fc::is_regular_file(shared_mem_path),
                       chain::plugin_config_exception,
                       "Snapshot can only be used to initialize an empty database.");
         }

         if( fc::is_regular_file( my->blocks_dir / "blocks.log" ) && !my->replace_chain_id ) {
            auto block_log_genesis = block_log::extract_genesis_state(my->blocks_dir);
            if( block_log_genesis ) {
               const auto& block_log_chain_id = block_log_genesis->compute_chain_id();
               EOS_ASSERT( *chain_id == block_log_chain_id,
                           chain::plugin_config_exception,
                           "snapshot chain ID ({snapshot_chain_id}) does not match the chain ID from the genesis state in the block log ({block_log_chain_id})",
                           ("snapshot_chain_id",  (*chain_id).str())
                           ("block_log_chain_id", block_log_chain_id.str())
               );
            } else {
               const auto& block_log_chain_id = block_log::extract_chain_id(my->blocks_dir);
               EOS_ASSERT( *chain_id == block_log_chain_id,
                           chain::plugin_config_exception,
                           "snapshot chain ID ({snapshot_chain_id}) does not match the chain ID ({block_log_chain_id}) in the block log",
                           ("snapshot_chain_id",  (*chain_id).str())
                           ("block_log_chain_id", block_log_chain_id.str())
               );
            }
         }

      } else {
         if (fc::is_regular_file(shared_mem_path)) {
            // the shared mem file is from the legacy mmap, and useless now, clean up it
            ilog("Removing the legacy shared_memory.bin ...");
            fc::remove(shared_mem_path);
         }

         chain_id = controller::extract_chain_id_from_db( my->chain_config->state_dir );

         std::optional<genesis_state> block_log_genesis;
         std::optional<chain_id_type> block_log_chain_id;

         if( fc::is_regular_file( my->blocks_dir / "blocks.log" ) ) {
            block_log_genesis = block_log::extract_genesis_state( my->blocks_dir );
            if( block_log_genesis ) {
               block_log_chain_id = block_log_genesis->compute_chain_id();
            } else {
               block_log_chain_id = block_log::extract_chain_id( my->blocks_dir );
            }

            if( chain_id ) {
               EOS_ASSERT( *block_log_chain_id == *chain_id, chain::block_log_exception,
                           "Chain ID in blocks.log ({block_log_chain_id}) does not match the existing "
                           " chain ID in state ({state_chain_id}).",
                           ("block_log_chain_id", (*block_log_chain_id).str())
                           ("state_chain_id", (*chain_id).str())
               );
            } else if( block_log_genesis ) {
               ilog( "Starting fresh blockchain state using genesis state extracted from blocks.log." );
               my->genesis = block_log_genesis;
               // Delay setting chain_id until later so that the code handling genesis-json below can know
               // that chain_id still only represents a chain ID extracted from the state (assuming it exists).
            }
         }

         if( options.count( "genesis-json" ) ) {

            auto provided_genesis = *get_provided_genesis();

            if( block_log_genesis ) {
               EOS_ASSERT( *block_log_genesis == provided_genesis, chain::plugin_config_exception,
                           "Genesis state, provided via command line arguments, does not match the existing genesis state"
                           " in blocks.log. It is not necessary to provide genesis state arguments when a full blocks.log "
                           "file already exists."
               );
            } else {
               const auto& provided_genesis_chain_id = provided_genesis.compute_chain_id();
               if( chain_id ) {
                  EOS_ASSERT( provided_genesis_chain_id == *chain_id, chain::plugin_config_exception,
                              "Genesis state, provided via command line arguments, has a chain ID ({provided_genesis_chain_id}) "
                              "that does not match the existing chain ID in the database state ({state_chain_id}). "
                              "It is not necessary to provide genesis state arguments when an initialized database state already exists.",
                              ("provided_genesis_chain_id", provided_genesis_chain_id.str())
                              ("state_chain_id", (*chain_id).str())
                  );
               } else {
                  if( block_log_chain_id ) {
                     EOS_ASSERT( provided_genesis_chain_id == *block_log_chain_id, chain::plugin_config_exception,
                                 "Genesis state, provided via command line arguments, has a chain ID ({provided_genesis_chain_id}) "
                                 "that does not match the existing chain ID in blocks.log ({block_log_chain_id}).",
                                 ("provided_genesis_chain_id", provided_genesis_chain_id.str())
                                 ("block_log_chain_id", (*block_log_chain_id).str())
                     );
                  }

                  chain_id = provided_genesis_chain_id;

                  ilog( "Starting fresh blockchain state using provided genesis state." );
                  my->genesis = std::move(provided_genesis);
               }
            }
         } else {
            EOS_ASSERT( options.count( "genesis-timestamp" ) == 0,
                        chain::plugin_config_exception,
                        "--genesis-timestamp is only valid if also passed in with --genesis-json");
         }

         if( !chain_id ) {
            if( my->genesis ) {
               // Uninitialized state database and genesis state extracted from block log
               chain_id = my->genesis->compute_chain_id();
            } else {
               // Uninitialized state database and no genesis state provided

               EOS_ASSERT( !block_log_chain_id, chain::plugin_config_exception,
                           "Genesis state is necessary to initialize fresh blockchain state but genesis state could not be "
                           "found in the blocks log. Please either load from snapshot or find a blocks log that starts "
                           "from genesis."
               );

               ilog( "Starting fresh blockchain state using default genesis state." );
               my->genesis.emplace();
               chain_id = my->genesis->compute_chain_id();
            }
         }
      }

      if ( options.count("read-mode") ) {
         my->chain_config->read_mode = options.at("read-mode").as<db_read_mode>();
      }
      my->api_accept_transactions = options.at( "api-accept-transactions" ).as<bool>();

      if( my->chain_config->read_mode == db_read_mode::IRREVERSIBLE || my->chain_config->read_mode == db_read_mode::READ_ONLY ) {
         if( my->chain_config->read_mode == db_read_mode::READ_ONLY ) {
            wlog( "read-mode = read-only is deprecated use p2p-accept-transactions = false, api-accept-transactions = false instead." );
         }
         if( my->api_accept_transactions ) {
            my->api_accept_transactions = false;
            std::stringstream ss; ss << my->chain_config->read_mode;
            wlog( "api-accept-transactions set to false due to read-mode: {m}", ("m", ss.str()) );
         }
      }
      if( my->api_accept_transactions ) {
         enable_accept_transactions();
      }

      if ( options.count("validation-mode") ) {
#ifdef EOSIO_NOT_REQUIRE_FULL_VALIDATION
         my->chain_config->block_validation_mode = options.at("validation-mode").as<validation_mode>();
#else
         my->chain_config->block_validation_mode = eosio::chain::validation_mode::FULL;
#endif
      }


#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
      if( options.count("eos-vm-oc-cache-size-mb") )
         my->chain_config->eosvmoc_config.cache_size = options.at( "eos-vm-oc-cache-size-mb" ).as<uint64_t>() * 1024u * 1024u;
      if( options.count("eos-vm-oc-compile-threads") )
         my->chain_config->eosvmoc_config.threads = options.at("eos-vm-oc-compile-threads").as<uint64_t>();
      if( options.count("eos-vm-oc-code-cache-map-mode") == 0)
         my->chain_config->eosvmoc_config.map_mode = pinnable_mapped_file::map_mode::heap;
      else
         my->chain_config->eosvmoc_config.map_mode = options.at("eos-vm-oc-code-cache-map-mode").as<chainbase::pinnable_mapped_file::map_mode>();

      if (my->chain_config->eosvmoc_config.map_mode == pinnable_mapped_file::map_mode::mapped) {
         ilog("--eos-vm-oc-code-cache-map-mode = mapped is deprecated. Considering it to be heap mode.");
         my->chain_config->eosvmoc_config.map_mode = pinnable_mapped_file::map_mode::heap;
      }
#endif

      my->account_queries_enabled = options.at("enable-account-queries").as<bool>();
      my->chain_config->min_initial_block_num = options["min-initial-block-num"].as<uint32_t>();

      my->chain_config->integrity_hash_on_start = options.at("integrity-hash-on-start").as<bool>();
      my->chain_config->integrity_hash_on_stop = options.at("integrity-hash-on-stop").as<bool>();

      my->chain.emplace( *my->chain_config, std::move(pfs), *chain_id );

      // set up method providers
      my->get_block_by_number_provider = app().get_method<methods::get_block_by_number>().register_provider(
            [this]( uint32_t block_num ) -> signed_block_ptr {
               return my->chain->fetch_block_by_number( block_num );
            } );

      my->get_block_by_id_provider = app().get_method<methods::get_block_by_id>().register_provider(
            [this]( block_id_type id ) -> signed_block_ptr {
               return my->chain->fetch_block_by_id( id );
            } );

      my->get_head_block_id_provider = app().get_method<methods::get_head_block_id>().register_provider( [this]() {
         return my->chain->head_block_id();
      } );

      my->get_last_irreversible_block_number_provider = app().get_method<methods::get_last_irreversible_block_number>().register_provider(
            [this]() {
               return my->chain->last_irreversible_block_num();
            } );

      // relay signals to channels
      my->pre_accepted_block_connection = my->chain->pre_accepted_block.connect([this](const signed_block_ptr& blk) {
         auto itr = my->loaded_checkpoints.find( blk->block_num() );
         if( itr != my->loaded_checkpoints.end() ) {
            auto id = blk->calculate_id();
            EOS_ASSERT( itr->second == id, chain::checkpoint_exception,
                        "Checkpoint does not match for block number {num}: expected: {expected} actual: {actual}",
                        ("num", blk->block_num())("expected", itr->second)("actual", id)
            );
         }

         my->pre_accepted_block_channel.publish(priority::medium, blk);
      });

      my->accepted_block_header_connection = my->chain->accepted_block_header.connect(
            [this]( const block_state_ptr& blk ) {
               my->accepted_block_header_channel.publish( priority::medium, blk );
            } );

      my->accepted_block_connection = my->chain->accepted_block.connect( [this]( const block_state_ptr& blk ) {
          if (my->_account_query_db) {
            my->_account_query_db->commit_block(blk);
          }

         my->accepted_block_channel.publish( priority::high, blk );
      } );

      my->irreversible_block_connection = my->chain->irreversible_block.connect( [this]( const block_state_ptr& blk ) {
         my->irreversible_block_channel.publish( priority::low, blk );
      } );

      my->accepted_transaction_connection = my->chain->accepted_transaction.connect(
            [this]( const transaction_metadata_ptr& meta ) {
               my->accepted_transaction_channel.publish( priority::low, meta );
            } );

      my->applied_transaction_connection = my->chain->applied_transaction.connect(
            [this]( std::tuple<const transaction_trace_ptr&, const packed_transaction_ptr&> t ) {
               if (my->_account_query_db) {
                  my->_account_query_db->cache_transaction_trace(std::get<0>(t));
               }

               my->applied_transaction_channel.publish( priority::low, std::get<0>(t) );
            } );

      my->is_disable_background_snapshots = options.at("disable-background-snapshots").as<bool>();

      my->chain->add_indices();
   } FC_LOG_AND_RETHROW()

}

void chain_plugin::plugin_startup()
{ try {
   handle_sighup(); // Sets loggers

   EOS_ASSERT( my->chain_config->read_mode != db_read_mode::IRREVERSIBLE || !accept_transactions(), chain::plugin_config_exception,
               "read-mode = irreversible. transactions should not be enabled by enable_accept_transactions" );
   try {
      auto shutdown = [](){ return app().quit(); };
      auto check_shutdown = [](){ return app().is_quiting(); };

      auto startup_with_snapshot = [&](const bfs::path& snapshot_path) {
         if (snapshot_path.extension().generic_string().compare(".bin") == 0) {
            auto infile = std::ifstream(my->snapshot_path->generic_string(), (std::ios::in | std::ios::binary));
            auto reader = std::make_shared<istream_snapshot_reader>(infile, !my->replace_chain_id);
            my->chain->startup(shutdown, check_shutdown, reader);
            infile.close();
         } else { // JSON snapshot file
            auto reader = std::make_shared<json_snapshot_reader>(snapshot_path.generic_string(), !my->replace_chain_id);
            my->chain->startup(shutdown, check_shutdown, reader);
         }
      };

      if (my->snapshot_path) {
         startup_with_snapshot(*my->snapshot_path);
      } else if( my->genesis ) {
         my->chain->startup(shutdown, check_shutdown, *my->genesis);
      } else {
         my->chain->startup(shutdown, check_shutdown);
      }
      post_startup(my.get());
   } catch (const chain::database_guard_exception& e) {
      log_guard_exception(e);
      // make sure to properly close the db
      my->chain.reset();
      throw;
   }

   if(!my->readonly) {
      ilog("starting chain in read/write mode");
   }

   if (my->genesis) {
      ilog("Blockchain started; head block is #{num}, genesis timestamp is {ts}",
           ("num", my->chain->head_block_num())("ts", (std::string)my->genesis->initial_timestamp));
   }
   else {
      ilog("Blockchain started; head block is #{num}", ("num", my->chain->head_block_num()));
   }

   my->chain_config.reset();

   if (my->account_queries_enabled) {
      my->account_queries_enabled = false;
      try {
         my->_account_query_db.emplace(*my->chain);
         my->account_queries_enabled = true;
      } FC_LOG_AND_DROP(("Unable to enable account queries"));
   }



} FC_CAPTURE_AND_RETHROW() }

void chain_plugin::plugin_shutdown() {

   auto create_state_snapshot = [&]() -> void {
      namespace bfs = boost::filesystem;
      bfs::path temp_path = static_cast<bfs::path>(my->chain->get_config().state_dir) / ".state_snapshot.bin";
      bfs::path snapshot_path = static_cast<bfs::path>(my->chain->get_config().state_dir) / "state_snapshot.bin";

      ilog("Creating state snapshot during shutdown into {p}", ("p", temp_path.generic_string()));

      auto snap_out = std::ofstream(temp_path.generic_string(), (std::ios::out | std::ios::binary));
      auto writer = std::make_shared<chain::ostream_snapshot_writer>(snap_out);

      // producer_plugin::shutdown() has been executed. It finalized the un-finazlied block or marked it failed.

      // abort the pending block and the completing_failed_blockid block if any
      my->chain->abort_block();

      // flush the block log
      my->chain->flush_block_log();
      // now, create the snapshot
      my->chain->write_snapshot(writer);

      writer->finalize();
      snap_out.flush();
      snap_out.close();

      boost::system::error_code ec;
      bfs::rename(temp_path, snapshot_path, ec);
      EOS_ASSERT(!ec, chain::snapshot_finalization_exception,
                 "Unable to finalize valid snapshot for state: [code: {ec}] {message}",
                 ("ec", ec.value())("message", ec.message()));

      ilog("Saved state snapshot into {p}", ("p", snapshot_path.generic_string()));
   };

   my->pre_accepted_block_connection.reset();
   my->accepted_block_header_connection.reset();
   my->accepted_block_connection.reset();
   my->irreversible_block_connection.reset();
   my->accepted_transaction_connection.reset();
   my->applied_transaction_connection.reset();

   create_state_snapshot();

   if(app().is_quiting())
      my->chain->get_wasm_interface().indicate_shutting_down();
   my->chain.reset();
   zipkin_config::shutdown();
}

void chain_plugin::handle_sighup() {
}


chain_apis::read_only chain_plugin::get_read_only_api() const {
   return chain_apis::read_only(chain(), my->_account_query_db, get_abi_serializer_max_time(), my->genesis);
}

chain_apis::table_query chain_plugin::get_table_query_api() const {
   return chain_apis::table_query(chain(), get_abi_serializer_max_time());
}

void chain_plugin::create_snapshot_background() {
   static int bg_pid = 0;
   if (bg_pid != 0) {
      if (0 == kill(bg_pid, 0)) {
         // try to reap the background snapshot creation process
         int bg_status;
         waitpid(bg_pid, &bg_status, WNOHANG);
         if (0 == kill(bg_pid, 0)) {
            ilog("Background snapshot creation process exists and is running. Skip creating a new background process.");
            return;
         }
      }
   }

   // fork() together with SIGKILL. The single thread in the child process
   // - has a copy-on-write whole memory copy with the help of the kernel
   // - creates a snapshot from the memory, writes to a new file, flush it, and atomically rename it for file integrity
   // - SIGKILLs itself, so not touching anything else
   // - the parent nodeos process will reap the background process which SIGKILL'ed itself
   int id = fork();

   if (id == 0) {
      // in child process
      auto create_state_snapshot = [&]() -> void {
         namespace bfs = boost::filesystem;
         bfs::path temp_path = static_cast<bfs::path>(my->chain->get_config().state_dir) / "..state_snapshot.bin";
         bfs::path snapshot_path = static_cast<bfs::path>(my->chain->get_config().state_dir) / "state_snapshot.bin";

         ilog("Background creating state snapshot into {p}", ( "p", temp_path.generic_string()));

         auto snap_out = std::ofstream(temp_path.generic_string(), ( std::ios::out | std::ios::binary ));
         auto writer = std::make_shared<chain::ostream_snapshot_writer>(snap_out);

         // abort the pending block and the completing_failed_blockid block if any
         my->chain->abort_block();

         // flush the block log
         my->chain->flush_block_log();
         // now, create the snapshot
         my->chain->write_snapshot(writer);

         writer->finalize();
         snap_out.flush();
         snap_out.close();

         boost::system::error_code ec;
         bfs::rename(temp_path, snapshot_path, ec);
         EOS_ASSERT(!ec, chain::snapshot_finalization_exception,
                    "Unable to finalize valid snapshot for state: [code: {ec}] {message}",
                    ( "ec", ec.value())("message", ec.message()));

         ilog("Background saved state snapshot into {p}", ( "p", snapshot_path.generic_string()));
      };

      try {
         create_state_snapshot();
      } catch( ... ) {
         elog( "Failed to write background snapshot");
      }


      ilog("Background snapshot creation process exiting.");
      std::raise(SIGKILL);
   }
   else {
      bg_pid = id;
   }
}


bool chain_plugin::accept_block(const signed_block_ptr& block, const block_id_type& id ) {
   return my->incoming_block_sync_method(block, id);
}

void chain_plugin::accept_transaction(const chain::packed_transaction_ptr& trx, next_function<chain::transaction_trace_ptr> next) {
   my->incoming_transaction_async_method(trx, false, false, false, std::move(next));
}

controller& chain_plugin::chain() { return *my->chain; }
const controller& chain_plugin::chain() const { return *my->chain; }

chain::chain_id_type chain_plugin::get_chain_id()const {
   return my->chain->get_chain_id();
}

fc::microseconds chain_plugin::get_abi_serializer_max_time() const {
   return my->abi_serializer_max_time_us;
}

bool chain_plugin::api_accept_transactions() const{
   return my->api_accept_transactions;
}

bool chain_plugin::accept_transactions() const {
   return my->accept_transactions;
}

void chain_plugin::enable_accept_transactions() {
   my->accept_transactions = true;
}


void chain_plugin::log_guard_exception(const chain::guard_exception&e ) {
   if (e.code() == chain::database_guard_exception::code_value) {
      elog("Database has reached an unsafe level of usage, shutting down to avoid corrupting the database.  "
           "Please increase the value set for \"chain-state-db-size-mb\" and restart the process!");
   } else if (e.code() == chain::reversible_guard_exception::code_value) {
      elog("Reversible block database has reached an unsafe level of usage, shutting down to avoid corrupting the database.  "
           "Please increase the value set for \"reversible-blocks-db-size-mb\" and restart the process!");
   }

   dlog("Details: {details}", ("details", e.to_detail_string()));
}

void chain_plugin::handle_guard_exception(const chain::guard_exception& e) {
   log_guard_exception(e);

   elog("database chain::guard_exception, quitting..."); // log string searched for in: tests/nodeos_under_min_avail_ram.py
   // quit the app
   app().quit();
}



bool chain_plugin::account_queries_enabled() const {
   return my->account_queries_enabled;
}

bool chain_plugin::background_snapshots_disabled() const {
   return my->is_disable_background_snapshots;
}

} // namespace eosio

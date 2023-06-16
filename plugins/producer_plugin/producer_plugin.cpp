#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/producer_plugin/producer.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/resource_monitor_plugin/resource_monitor_plugin.hpp>
#include <eosio/chain/to_string.hpp>

#include <fc/io/json.hpp>

#include <boost/asio.hpp>

#include <iostream>
#include <algorithm>

using std::string;
using std::vector;


namespace eosio {

static appbase::abstract_plugin& _producer_plugin = app().register_plugin<producer_plugin>();

using namespace eosio::chain;
using namespace eosio::chain::plugin_interface;

void new_chain_banner(const eosio::chain::controller& db)
{
   std::cerr << "\n"
      "*******************************\n"
      "*                             *\n"
      "*   ------ NEW CHAIN ------   *\n"
      "*   -  Welcome to EOSIO!  -   *\n"
      "*   -----------------------   *\n"
      "*                             *\n"
      "*******************************\n"
      "\n";

   if( db.head_block_state()->header.timestamp.to_time_point() < (fc::time_point::now() - fc::milliseconds(200 * config::block_interval_ms)))
   {
      std::cerr << "Your genesis seems to have an old timestamp\n"
         "Please consider using the --genesis-timestamp option to give your genesis a recent timestamp\n"
         "\n"
         ;
   }
   return;
}

class producer_plugin_impl {
public:
   producer_plugin_impl()
         : prod( new producer( std::unique_ptr<producer_timer_base>{ new producer_timer<boost::asio::deadline_timer>{ app().get_io_service() } },
         [trx_ack_channel{&app().get_channel<plugin_interface::compat::channels::transaction_ack>()}](const fc::exception_ptr& except_ptr, const transaction_metadata_ptr& trx) {
            trx_ack_channel->publish( priority::low, std::pair<fc::exception_ptr, transaction_metadata_ptr>( except_ptr, trx ) );
         },
         [rejected_block_channel{&app().get_channel<plugin_interface::channels::rejected_block>()}](const signed_block_ptr& block) {
            rejected_block_channel->publish( priority::medium, block );
         }) ) {
   }

   incoming::channels::block::channel_type::handle           _incoming_block_subscription;
   incoming::channels::transaction::channel_type::handle     _incoming_transaction_subscription;
   incoming::methods::block_sync::method_type::handle        _incoming_block_sync_provider;
   incoming::methods::transaction_async::method_type::handle _incoming_transaction_async_provider;

   shared_ptr<producer> prod;
   chain_plugin* chain_plug = nullptr;
};

producer_plugin::producer_plugin()
   : my(new producer_plugin_impl()) {
}

producer_plugin::~producer_plugin() {}

void producer_plugin::set_program_options(
   boost::program_options::options_description& command_line_options,
   boost::program_options::options_description& config_file_options)
{
   auto default_priv_key = private_key_type::regenerate<fc::ecc::private_key_shim>(fc::sha256::hash(std::string("nathan")));
   auto private_key_default = std::make_pair(default_priv_key.get_public_key(), default_priv_key );

   boost::program_options::options_description producer_options;

   producer_options.add_options()
         ("enable-stale-production,e", boost::program_options::bool_switch()->notifier([this](bool e){my->prod->_production_enabled = e;}), "Enable block production, even if the chain is stale.")
         ("pause-on-startup,x", boost::program_options::bool_switch()->notifier([this](bool p){my->prod->_pause_production = p;}), "Start this node in a state where production is paused")
         ("max-transaction-time", bpo::value<int32_t>()->default_value(30),
          "Limits the maximum time (in milliseconds) that is allowed a pushed transaction's code to execute before being considered invalid")
         ("max-irreversible-block-age", bpo::value<int32_t>()->default_value( -1 ),
          "Limits the maximum age (in seconds) of the DPOS Irreversible Block for a chain this node will produce blocks on (use negative value to indicate unlimited)")
         ("producer-name,p", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "ID of producer controlled by this node (e.g. inita; may specify multiple times)")
         ("private-key", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "(DEPRECATED - Use signature-provider instead) Tuple of [public key, WIF private key] (may specify multiple times)")
         ("signature-provider", boost::program_options::value<vector<string>>()->composing()->multitoken()->default_value(
               {default_priv_key.get_public_key().to_string() + "=KEY:" + default_priv_key.to_string()},
                default_priv_key.get_public_key().to_string() + "=KEY:" + default_priv_key.to_string()),
               app().get_plugin<signature_provider_plugin>().signature_provider_help_text())
         ("greylist-account", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "account that can not access to extended CPU/NET virtual resources")
         ("greylist-limit", boost::program_options::value<uint32_t>()->default_value(1000),
          "Limit (between 1 and 1000) on the multiple that CPU/NET virtual resources can extend during low usage (only enforced subjectively; use 1000 to not enforce any limit)")
         ("produce-time-offset-us", boost::program_options::value<int32_t>()->default_value(0),
          "Offset of non last block producing time in microseconds. Valid range 0 .. -block_time_interval.")
         ("last-block-time-offset-us", boost::program_options::value<int32_t>()->default_value(-200000),
          "Offset of last block producing time in microseconds. Valid range 0 .. -block_time_interval.")
         ("cpu-effort-percent", bpo::value<uint32_t>()->default_value(config::default_block_cpu_effort_pct / config::percent_1),
          "Percentage of cpu block production time used to produce block. Whole number percentages, e.g. 80 for 80%")
         ("last-block-cpu-effort-percent", bpo::value<uint32_t>()->default_value(config::default_block_cpu_effort_pct / config::percent_1),
          "Percentage of cpu block production time used to produce last block. Whole number percentages, e.g. 80 for 80%")
         ("max-block-cpu-usage-threshold-us", bpo::value<uint32_t>()->default_value( 5000 ),
          "Threshold of CPU block production to consider block full; when within threshold of max-block-cpu-usage block can be produced immediately")
         ("max-block-net-usage-threshold-bytes", bpo::value<uint32_t>()->default_value( 1024 ),
          "Threshold of NET block production to consider block full; when within threshold of max-block-net-usage block can be produced immediately")
         ("subjective-cpu-leeway-us", boost::program_options::value<int32_t>()->default_value( config::default_subjective_cpu_leeway_us ),
          "Time in microseconds allowed for a transaction that starts with insufficient CPU quota to complete and cover its CPU usage.")
         ("override-chain-cpu-limits", bpo::value<bool>()->default_value(false),
          "Allow transaction to run for max-transaction-time ignoring max_block_cpu_usage and max_transaction_cpu_usage.")
         ("incoming-transaction-queue-size-mb", bpo::value<uint16_t>()->default_value( 1024 ),
          "Maximum size (in MiB) of the incoming transaction queue. Exceeding this value will subjectively drop transaction with resource exhaustion.")
         ("disable-api-persisted-trx", bpo::bool_switch()->default_value(false),
          "Disable the re-apply of API transactions.")
         ("disable-subjective-billing", bpo::value<bool>()->default_value(true),
          "Disable subjective CPU billing for API/P2P transactions")
         ("disable-subjective-account-billing", boost::program_options::value<vector<string>>()->composing()->multitoken(),
          "Account which is excluded from subjective CPU billing")
         ("disable-subjective-p2p-billing", bpo::value<bool>()->default_value(true),
          "Disable subjective CPU billing for P2P transactions")
         ("disable-subjective-api-billing", bpo::value<bool>()->default_value(true),
          "Disable subjective CPU billing for API transactions")
         ("producer-threads", bpo::value<uint16_t>()->default_value(config::default_controller_thread_pool_size),
          "Number of worker threads in producer thread pool")
         ("snapshots-dir", bpo::value<bfs::path>()->default_value("snapshots"),
          "the location of the snapshots directory (absolute path or relative to application data dir)")
         ("background-snapshot-write-period-in-blocks", bpo::value<uint32_t>()->default_value(7200),
          "How often to write background snapshots")
          ;
   config_file_options.add(producer_options);
}

bool producer_plugin::has_producers() const
{
   return my->prod->has_producers();
}

bool producer_plugin::is_producing_block() const {
   return my->prod->is_producing_block();
}

bool producer_plugin::is_producer_key(const chain::public_key_type& key) const
{
   return my->prod->is_producer_key(key);
}

chain::signature_type producer_plugin::sign_compact(const chain::public_key_type& key, const fc::sha256& digest) const
{
   return my->prod->sign_compact(key, digest);
}

template<typename T>
T dejsonify(const string& s) {
   return fc::json::from_string(s).as<T>();
}

void producer_plugin::plugin_initialize(const boost::program_options::variables_map& options)
{ try {
   if( options.count( "producer-name" ) ) {
      std::vector<std::string> producers = options["producer-name"].as<std::vector<std::string>>();
      for( const auto& a : producers ) {
         my->prod->_block_producer.add_producer( account_name(a) );
      }
   }

   my->chain_plug = app().find_plugin<chain_plugin>();
   EOS_ASSERT( my->chain_plug, plugin_config_exception, "chain_plugin not found" );
   chain::controller& chain = my->chain_plug->chain();
   my->prod->chain_control = &chain;

   if( options.count("private-key") )
   {
      const std::vector<std::string> key_id_to_wif_pair_strings = options["private-key"].as<std::vector<std::string>>();
      for (const std::string& key_id_to_wif_pair_string : key_id_to_wif_pair_strings)
      {
         try {
            auto key_id_to_wif_pair = dejsonify<std::pair<public_key_type, private_key_type>>(key_id_to_wif_pair_string);
            my->prod->_signature_providers[key_id_to_wif_pair.first] = app().get_plugin<signature_provider_plugin>().signature_provider_for_private_key(key_id_to_wif_pair.second);
            auto blanked_privkey = std::string(key_id_to_wif_pair.second.to_string().size(), '*' );
            wlog("\"private-key\" is DEPRECATED, use \"signature-provider={pub}=KEY:{priv}\"", ("pub",key_id_to_wif_pair.first.to_string())("priv", blanked_privkey));
         } catch ( const std::exception& e ) {
            elog("Malformed private key pair");
         }
      }
   }

   if( options.count("signature-provider") ) {
      const std::vector<std::string> key_spec_pairs = options["signature-provider"].as<std::vector<std::string>>();
      for (const auto& key_spec_pair : key_spec_pairs) {
         try {
            const auto& [pubkey, provider] = app().get_plugin<signature_provider_plugin>().signature_provider_for_specification(key_spec_pair);
            my->prod->_signature_providers[pubkey] = provider;
         } catch(secure_enclave_exception& e) {
            elog("Error with Secure Enclave signature provider: {e}; ignoring {val}", ("e", e.top_message())("val", key_spec_pair));
         } catch (fc::exception& e) {
            elog("Malformed signature provider: \"{val}\": {e}, ignoring!", ("val", key_spec_pair)("e", e.to_string()));
         } catch (...) {
            elog("Malformed signature provider: \"{val}\", ignoring!", ("val", key_spec_pair));
         }
      }
   }

   my->prod->_produce_time_offset_us = options.at("produce-time-offset-us").as<int32_t>();
   EOS_ASSERT( my->prod->_produce_time_offset_us <= 0 && my->prod->_produce_time_offset_us >= -config::block_interval_us, plugin_config_exception,
               "produce-time-offset-us {o} must be 0 .. -{bi}", ("bi", config::block_interval_us)("o", my->prod->_produce_time_offset_us) );

   my->prod->_last_block_time_offset_us = options.at("last-block-time-offset-us").as<int32_t>();
   EOS_ASSERT( my->prod->_last_block_time_offset_us <= 0 && my->prod->_last_block_time_offset_us >= -config::block_interval_us, plugin_config_exception,
               "last-block-time-offset-us {o} must be 0 .. -{bi}", ("bi", config::block_interval_us)("o", my->prod->_last_block_time_offset_us) );

   uint32_t cpu_effort_pct = options.at("cpu-effort-percent").as<uint32_t>();
   EOS_ASSERT( cpu_effort_pct >= 0 && cpu_effort_pct <= 100, plugin_config_exception,
               "cpu-effort-percent {pct} must be 0 - 100", ("pct", cpu_effort_pct) );
      cpu_effort_pct *= config::percent_1;
   int32_t cpu_effort_offset_us =
         -EOS_PERCENT( config::block_interval_us, chain::config::percent_100 - cpu_effort_pct );

   uint32_t last_block_cpu_effort_pct = options.at("last-block-cpu-effort-percent").as<uint32_t>();
   EOS_ASSERT( last_block_cpu_effort_pct >= 0 && last_block_cpu_effort_pct <= 100, plugin_config_exception,
               "last-block-cpu-effort-percent {pct} must be 0 - 100", ("pct", last_block_cpu_effort_pct) );
      last_block_cpu_effort_pct *= config::percent_1;
   int32_t last_block_cpu_effort_offset_us =
         -EOS_PERCENT( config::block_interval_us, chain::config::percent_100 - last_block_cpu_effort_pct );

   my->prod->_produce_time_offset_us = std::min( my->prod->_produce_time_offset_us, cpu_effort_offset_us );
   my->prod->_last_block_time_offset_us = std::min( my->prod->_last_block_time_offset_us, last_block_cpu_effort_offset_us );

   my->prod->_max_block_cpu_usage_threshold_us = options.at( "max-block-cpu-usage-threshold-us" ).as<uint32_t>();
   EOS_ASSERT( my->prod->_max_block_cpu_usage_threshold_us < config::block_interval_us, plugin_config_exception,
               "max-block-cpu-usage-threshold-us {t} must be 0 .. {bi}", ("bi", config::block_interval_us)("t", my->prod->_max_block_cpu_usage_threshold_us) );

   my->prod->_max_block_net_usage_threshold_bytes = options.at( "max-block-net-usage-threshold-bytes" ).as<uint32_t>();

   if( options.at( "subjective-cpu-leeway-us" ).as<int32_t>() != config::default_subjective_cpu_leeway_us ) {
      chain.set_subjective_cpu_leeway( fc::microseconds( options.at( "subjective-cpu-leeway-us" ).as<int32_t>() ) );
   }

   my->prod->_transaction_processor.set_max_transaction_time( fc::milliseconds(options.at("max-transaction-time").as<int32_t>()) );

   my->prod->_max_irreversible_block_age_us = fc::seconds(options.at("max-irreversible-block-age").as<int32_t>());

   auto max_incoming_transaction_queue_size = options.at("incoming-transaction-queue-size-mb").as<uint16_t>() * 1024*1024;

   EOS_ASSERT( max_incoming_transaction_queue_size > 0, plugin_config_exception,
               "incoming-transaction-queue-size-mb {mb} must be greater than 0", ("mb", max_incoming_transaction_queue_size) );

   my->prod->_transaction_processor.set_max_transaction_queue_size( max_incoming_transaction_queue_size );

   if( options.at("disable-api-persisted-trx").as<bool>() ) my->prod->_transaction_processor.disable_persist_until_expired();
   bool disable_subjective_billing = options.at("disable-subjective-billing").as<bool>();
   bool disable_subjective_p2p_billing = options.at("disable-subjective-p2p-billing").as<bool>();
   bool disable_subjective_api_billing = options.at("disable-subjective-api-billing").as<bool>();
   dlog( "disable-subjective-billing: {s}, disable-subjective-p2p-billing: {p2p}, disable-subjective-api-billing: {api}",
         ("s", disable_subjective_billing)("p2p", disable_subjective_p2p_billing)("api", disable_subjective_api_billing) );
   if( !disable_subjective_billing ) {
       disable_subjective_p2p_billing = disable_subjective_api_billing = false;
   } else if( !disable_subjective_p2p_billing || !disable_subjective_api_billing ) {
       disable_subjective_billing = false;
   }
   if( disable_subjective_billing ) {
       my->prod->_transaction_processor.disable_subjective_billing();
       ilog( "Subjective CPU billing disabled" );
   } else if( !disable_subjective_p2p_billing && !disable_subjective_api_billing ) {
       ilog( "Subjective CPU billing enabled" );
   } else {
       if( disable_subjective_p2p_billing ) {
          my->prod->_transaction_processor.disable_subjective_p2p_billing();
          ilog( "Subjective CPU billing of P2P trxs disabled " );
       }
       if( disable_subjective_api_billing ) {
          my->prod->_transaction_processor.disable_subjective_api_billing();
          ilog( "Subjective CPU billing of API trxs disabled " );
       }
   }

   if( options.at("override-chain-cpu-limits").as<bool>() ) {
      chain.set_override_chain_cpu_limits( true );
   }

   auto thread_pool_size = options.at( "producer-threads" ).as<uint16_t>();
   EOS_ASSERT( thread_pool_size > 0, plugin_config_exception,
               "producer-threads {num} must be greater than 0", ("num", thread_pool_size));
   my->prod->_transaction_processor.start( thread_pool_size );

   if( options.count( "snapshots-dir" )) {
      auto sd = options.at( "snapshots-dir" ).as<bfs::path>();
      if( sd.is_relative()) {
         sd = app().data_dir() / sd;
         if (!fc::exists(sd)) {
            fc::create_directories(sd);
         }
      }

      EOS_ASSERT( fc::is_directory(sd), snapshot_directory_not_found_exception,
                  "No such directory '{dir}'", ("dir", sd.generic_string()) );

      my->prod->_pending_snapshot_tracker.set_snapshot_dir( sd );

      if (auto resmon_plugin = app().find_plugin<resource_monitor_plugin>()) {
         resmon_plugin->monitor_directory(sd);
      }
   }

   my->_incoming_block_subscription = app().get_channel<incoming::channels::block>().subscribe(
         [this](const signed_block_ptr& block) {
      try {
         my->prod->on_incoming_block(block, {});
      } catch( ... ) {
         log_and_drop_exceptions();
      }
   });

   my->_incoming_transaction_subscription = app().get_channel<incoming::channels::transaction>().subscribe(
         [this](const packed_transaction_ptr& trx) {
      try {
         my->prod->on_incoming_transaction_async(trx, false, false, false, [](const auto&){});
      } catch( ... ) {
         log_and_drop_exceptions();
      }
   });

   my->_incoming_block_sync_provider = app().get_method<incoming::methods::block_sync>().register_provider(
         [this](const signed_block_ptr& block, const std::optional<block_id_type>& block_id) {
      return my->prod->on_incoming_block(block, block_id);
   });

   my->_incoming_transaction_async_provider = app().get_method<incoming::methods::transaction_async>().register_provider(
         [this](const packed_transaction_ptr& trx, bool persist_until_expired, const bool read_only, const bool return_failure_trace, next_function<transaction_trace_ptr> next) -> void {
      return my->prod->on_incoming_transaction_async(trx, persist_until_expired, read_only, return_failure_trace, next );
   });

   if (options.count("greylist-account")) {
      std::vector<std::string> greylist = options["greylist-account"].as<std::vector<std::string>>();
      greylist_params param;
      for (auto &a : greylist) {
         param.accounts.push_back(account_name(a));
      }
      add_greylist_accounts(param);
   }

   {
      uint32_t greylist_limit = options.at("greylist-limit").as<uint32_t>();
      chain.set_greylist_limit( greylist_limit );
   }

   if( options.count("disable-subjective-account-billing") ) {
      std::vector<std::string> accounts = options["disable-subjective-account-billing"].as<std::vector<std::string>>();
      for( const auto& a : accounts ) {
         my->prod->_transaction_processor.disable_subjective_billing_account( account_name(a) );
      }
   }
   auto write_period = options["background-snapshot-write-period-in-blocks"].as<uint32_t>();
   if (write_period < 1)
      write_period = 1;
   my->prod->background_snapshot_write_period_in_blocks = write_period;
} FC_LOG_AND_RETHROW() }

void producer_plugin::plugin_startup()
{ try {
   handle_sighup(); // Sets loggers

   try {
   ilog("producer plugin:  plugin_startup() begin");

   chain::controller& chain = my->chain_plug->chain();
   EOS_ASSERT( !my->prod->has_producers() || chain.get_read_mode() == chain::db_read_mode::SPECULATIVE, plugin_config_exception,
              "node cannot have any producer-name configured because block production is impossible when read_mode is not \"speculative\"" );

   EOS_ASSERT( !my->prod->has_producers() || chain.get_validation_mode() == chain::validation_mode::FULL, plugin_config_exception,
              "node cannot have any producer-name configured because block production is not safe when validation_mode is not \"full\"" );

   EOS_ASSERT( !my->prod->has_producers() || my->chain_plug->accept_transactions(), plugin_config_exception,
              "node cannot have any producer-name configured because no block production is possible with no [api|p2p]-accepted-transactions" );

   my->prod->_accept_transactions = my->chain_plug->accept_transactions();

   if( my->prod->has_producers() ) {
      ilog("Launching block production for {n} producers at {time}.",
           ("n", my->prod->get_num_producers())("time",fc::time_point::now()));

      if (my->prod->is_production_enabled()) {
         if (chain.head_block_num() == 0) {
            new_chain_banner(chain);
         }
      }
   }

   my->prod->startup();

   ilog("producer plugin:  plugin_startup() end");
   } catch( ... ) {
      // always call plugin_shutdown, even on exception
      plugin_shutdown();
      throw;
   }
} FC_CAPTURE_AND_RETHROW() }

void producer_plugin::plugin_shutdown() {
   ilog("producer plugin:  plugin_shutdown() begin");
   my->prod->shutdown();
   ilog("producer plugin:  plugin_shutdown() end");
}

void producer_plugin::handle_sighup() {
   my->prod->handle_sighup();
}

void producer_plugin::pause() {
   my->prod->pause();
}

void producer_plugin::resume() {
   my->prod->resume();
}

bool producer_plugin::paused() const {
   return my->prod->paused();
}

void producer_plugin::update_runtime_options(const runtime_options& options) {
   chain::controller& chain = my->chain_plug->chain();
   bool check_speculating = false;

   if (options.max_transaction_time) {
      my->prod->set_max_transaction_time( fc::milliseconds(*options.max_transaction_time) );
   }

   if (options.max_irreversible_block_age) {
      my->prod->_max_irreversible_block_age_us =  fc::seconds(*options.max_irreversible_block_age);
      check_speculating = true;
   }

   if (options.produce_time_offset_us) {
      my->prod->_produce_time_offset_us = *options.produce_time_offset_us;
   }

   if (options.last_block_time_offset_us) {
      my->prod->_last_block_time_offset_us = *options.last_block_time_offset_us;
   }

   if (check_speculating && my->prod->_pending_block_mode == pending_block_mode::speculating) {
      my->prod->abort_block();
      my->prod->schedule_production_loop();
   }

   if (options.subjective_cpu_leeway_us) {
      chain.set_subjective_cpu_leeway(fc::microseconds(*options.subjective_cpu_leeway_us));
   }

   if (options.greylist_limit) {
      chain.set_greylist_limit(*options.greylist_limit);
   }
}

producer_plugin::runtime_options producer_plugin::get_runtime_options() const {
   return {
      my->prod->get_max_transaction_time().count() / 1000,
      my->prod->_max_irreversible_block_age_us.count() < 0 ? -1 : my->prod->_max_irreversible_block_age_us.count() / 1'000'000,
      my->prod->_produce_time_offset_us,
      my->prod->_last_block_time_offset_us,
      my->chain_plug->chain().get_subjective_cpu_leeway() ?
            my->chain_plug->chain().get_subjective_cpu_leeway()->count() :
            std::optional<int32_t>(),
      my->chain_plug->chain().get_greylist_limit()
   };
}

void producer_plugin::add_greylist_accounts(const greylist_params& params) {
   chain::controller& chain = my->chain_plug->chain();
   for (auto &acc : params.accounts) {
      chain.add_resource_greylist(acc);
   }
}

void producer_plugin::remove_greylist_accounts(const greylist_params& params) {
   chain::controller& chain = my->chain_plug->chain();
   for (auto &acc : params.accounts) {
      chain.remove_resource_greylist(acc);
   }
}

producer_plugin::greylist_params producer_plugin::get_greylist() const {
   chain::controller& chain = my->chain_plug->chain();
   greylist_params result;
   const auto& list = chain.get_resource_greylist();
   result.accounts.reserve(list.size());
   for (auto &acc: list) {
      result.accounts.push_back(acc);
   }
   return result;
}

producer_plugin::whitelist_blacklist producer_plugin::get_whitelist_blacklist() const {
   chain::controller& chain = my->chain_plug->chain();
   return {
      chain.get_actor_whitelist(),
      chain.get_actor_blacklist(),
      chain.get_contract_whitelist(),
      chain.get_contract_blacklist(),
      chain.get_action_blacklist(),
      chain.get_key_blacklist()
   };
}

void producer_plugin::set_whitelist_blacklist(const producer_plugin::whitelist_blacklist& params) {
   chain::controller& chain = my->chain_plug->chain();
   if(params.actor_whitelist) chain.set_actor_whitelist(*params.actor_whitelist);
   if(params.actor_blacklist) chain.set_actor_blacklist(*params.actor_blacklist);
   if(params.contract_whitelist) chain.set_contract_whitelist(*params.contract_whitelist);
   if(params.contract_blacklist) chain.set_contract_blacklist(*params.contract_blacklist);
   if(params.action_blacklist) chain.set_action_blacklist(*params.action_blacklist);
   if(params.key_blacklist) chain.set_key_blacklist(*params.key_blacklist);
}

integrity_hash_information producer_plugin::get_integrity_hash() const {
   return my->prod->get_integrity_hash();
}

void producer_plugin::create_snapshot(next_function<snapshot_information> next) {
   my->prod->create_snapshot( std::move( next ) );
}

producer_plugin::scheduled_protocol_feature_activations
producer_plugin::get_scheduled_protocol_feature_activations()const {
   return {my->prod->_protocol_features_to_activate};
}

void producer_plugin::schedule_protocol_feature_activations( const scheduled_protocol_feature_activations& schedule ) {
   my->prod->schedule_protocol_feature_activations( schedule.protocol_features_to_activate );
}

fc::variants producer_plugin::get_supported_protocol_features( const get_supported_protocol_features_params& params ) const {
   fc::variants results;
   const chain::controller& chain = my->chain_plug->chain();
   const auto& pfs = chain.get_protocol_feature_manager().get_protocol_feature_set();
   const auto next_block_time = chain.head_block_time() + fc::milliseconds(config::block_interval_ms);

   flat_map<digest_type, bool>  visited_protocol_features;
   visited_protocol_features.reserve( pfs.size() );

   std::function<bool(const protocol_feature&)> add_feature =
   [&results, &pfs, &params, next_block_time, &visited_protocol_features, &add_feature]
   ( const protocol_feature& pf ) -> bool {
      if( ( params.exclude_disabled || params.exclude_unactivatable ) && !pf.enabled ) return false;
      if( params.exclude_unactivatable && ( next_block_time < pf.earliest_allowed_activation_time  ) ) return false;

      auto res = visited_protocol_features.emplace( pf.feature_digest, false );
      if( !res.second ) return res.first->second;

      const auto original_size = results.size();
      for( const auto& dependency : pf.dependencies ) {
         if( !add_feature( pfs.get_protocol_feature( dependency ) ) ) {
            results.resize( original_size );
            return false;
         }
      }

      res.first->second = true;
      results.emplace_back( pf.to_variant(true) );
      return true;
   };

   for( const auto& pf : pfs ) {
      add_feature( pf );
   }

   return results;
}

producer_plugin::get_account_ram_corrections_result
producer_plugin::get_account_ram_corrections( const get_account_ram_corrections_params& params ) const {
   get_account_ram_corrections_result result;
   const auto& db = my->chain_plug->chain().db();

   const auto& idx = db.get_index<chain::account_ram_correction_index, chain::by_name>();
   account_name lower_bound_value{ std::numeric_limits<uint64_t>::lowest() };
   account_name upper_bound_value{ std::numeric_limits<uint64_t>::max() };

   if( params.lower_bound ) {
      lower_bound_value = *params.lower_bound;
   }

   if( params.upper_bound ) {
      upper_bound_value = *params.upper_bound;
   }

   if( upper_bound_value < lower_bound_value )
      return result;

   auto walk_range = [&]( auto itr, auto end_itr ) {
      for( unsigned int count = 0;
           count < params.limit && itr != end_itr;
           ++itr )
      {
         result.rows.push_back( fc::variant( *itr ) );
         ++count;
      }
      if( itr != end_itr ) {
         result.more = itr->name;
      }
   };

   auto lower = idx.lower_bound( lower_bound_value );
   auto upper = idx.upper_bound( upper_bound_value );
   if( params.reverse ) {
      walk_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
   } else {
      walk_range( lower, upper );
   }

   return result;
}

void producer_plugin::log_failed_transaction(const transaction_id_type& trx_id, const packed_transaction_ptr& packed_trx_ptr, const char* reason) const {
   my->prod->log_failed_transaction( trx_id, packed_trx_ptr, reason );
}

bool producer_plugin::execute_incoming_transaction(const chain::transaction_metadata_ptr& trx,
                                                   next_function<chain::transaction_trace_ptr> next )
{
   return my->prod->execute_incoming_transaction( trx, std::move(next) );
}

fc::microseconds producer_plugin::get_max_transaction_time() const {
   return my->prod->get_max_transaction_time();
}

void log_and_drop_exceptions() {
   try {
      throw;
   } catch ( const guard_exception& e ) {
      chain_plugin::handle_guard_exception(e);
   } catch ( const std::bad_alloc& ) {
      handle_bad_alloc();
   } catch ( boost::interprocess::bad_alloc& ) {
      handle_db_exhaustion();
   } catch( const fork_database_exception& e ) {
      elog( "Cannot recover from {e}. Shutting down.", ("e", e.to_detail_string()) );
      appbase::app().quit();
   } catch( fc::exception& er ) {
      wlog( "{details}", ("details",er.to_detail_string()) );
   } catch( const std::exception& e ) {
      fc::exception fce(
                FC_LOG_MESSAGE( warn, "std::exception: {what}: ",("what",e.what()) ),
                fc::std_exception_code,
                BOOST_CORE_TYPEID(e).name(),
                e.what() );
      wlog( "{details}", ("details",fce.to_detail_string()) );
   } catch( ... ) {
      fc::unhandled_exception e(
                FC_LOG_MESSAGE( warn, "unknown: ",  ),
                std::current_exception() );
      wlog( "{details}", ("details",e.to_detail_string()) );
   }
}

} // namespace eosio

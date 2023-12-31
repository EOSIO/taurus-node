#include "cloner_plugin.hpp"
#include "ship_client.hpp"
#include "streams/stream.hpp"
#include "config.hpp"

#include <b1/rodeos/rodeos.hpp>

#include <fc/log/logger.hpp>
#include <fc/log/logger_config.hpp>
#include <fc/io/json.hpp>
#include <fc/log/trace.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>

namespace b1 {

using namespace appbase;
using namespace std::literals;
using namespace eosio::ship_protocol;

namespace asio          = boost::asio;
namespace bpo           = boost::program_options;
namespace ship_protocol = eosio::ship_protocol;
namespace websocket     = boost::beast::websocket;

using asio::ip::tcp;
using boost::beast::flat_buffer;
using boost::system::error_code;

using rodeos::rodeos_db_partition;
using rodeos::rodeos_db_snapshot;
using rodeos::rodeos_filter;

struct cloner_session;

struct filter_ele {
   std::string name;
   std::string wasm;
   uint32_t    index;
};

struct cloner_config : ship_client::connection_config {
   uint32_t    skip_to                   = 0;
   uint32_t    stop_before               = 0;
   bool        exit_on_filter_wasm_error = false;
   std::vector<filter_ele>   filter_list = {};
   bool        profile = false;
   bool        undo_stack_enabled = false;
   uint32_t    force_write_stride = 0;

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
   eosio::chain::eosvmoc::config eosvmoc_config;
#endif
};

struct cloner_plugin_impl : std::enable_shared_from_this<cloner_plugin_impl> {
   std::shared_ptr<cloner_config>                                           config = std::make_shared<cloner_config>();
   std::shared_ptr<cloner_session>                                          session;
   boost::asio::deadline_timer                                              timer;
   std::shared_ptr<streamer_t>                                              streamer;

   cloner_plugin_impl() : timer(app().get_io_service()) {}

   ~cloner_plugin_impl();

   void schedule_retry() {
      timer.expires_from_now(boost::posix_time::seconds(1));
      timer.async_wait([this](auto) {
         ilog("retry...");
         start();
      });
   }

   void start();
};

namespace {
   std::string to_string(const eosio::checksum256& cs) {
      auto bytes = cs.extract_as_byte_array();
      return fc::to_hex((const char*)bytes.data(), bytes.size());
   }
} // namespace

struct cloner_session : ship_client::connection_callbacks, std::enable_shared_from_this<cloner_session> {
   cloner_plugin_impl*                  my = nullptr;
   std::shared_ptr<cloner_config>       config;
   std::shared_ptr<chain_kv::database>  db = app().find_plugin<rocksdb_plugin>()->get_db();
   std::shared_ptr<rodeos_db_partition> partition =
         std::make_shared<rodeos_db_partition>(db, std::vector<char>{}); // todo: prefix

   std::optional<rodeos_db_snapshot>             rodeos_snapshot;
   std::shared_ptr<ship_client::connection_base> connection;
   bool                                          reported_block = false;

   struct filter_type {
      std::unique_ptr<rodeos_filter> filter;
      uint32_t index;
   };

   std::vector<filter_type> filters = {}; // todo: remove

   cloner_session(cloner_plugin_impl* my) : my(my), config(my->config) {
      // todo: remove
      if (!config->filter_list.empty())
         for (auto& filter: config->filter_list) {
#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
	    bfs::path code_cache_dir = app().data_dir() / (filter.name + std::string{"_wasm"});
#endif
            filters.emplace_back( filter_type { std::make_unique<rodeos_filter>(eosio::name{filter.name}, filter.wasm, config->profile
#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
                                                  ,
                                                  code_cache_dir, config->eosvmoc_config
#endif
            ),
                filter.index });
         }
      ilog("number of filters: {n}", ("n", filters.size()));
   }

   void connect(asio::io_context& ioc) {
      rodeos_snapshot.emplace(partition, true, config->undo_stack_enabled);
      rodeos_snapshot->force_write_stride = config->force_write_stride;

      ilog("cloner database status:");
      ilog("    revisions:    {f} - {r}",
           ("f", rodeos_snapshot->undo_stack->first_revision())("r", rodeos_snapshot->undo_stack->revision()));
      ilog("    chain:        {a}", ("a", eosio::convert_to_json(rodeos_snapshot->chain_id)));
      ilog("    head:         {a} {b}",
           ("a", rodeos_snapshot->head)("b", eosio::convert_to_json(rodeos_snapshot->head_id)));
      ilog("    irreversible: {a} {b}",
           ("a", rodeos_snapshot->irreversible)("b", eosio::convert_to_json(rodeos_snapshot->irreversible_id)));

      rodeos_snapshot->end_write(true);
      db->flush(true, true);

      connection = ship_client::make_connection(ioc, *config, shared_from_this());
      connection->connect();
   }

   void received_abi() override {
      ilog("request status");
      connection->send(get_status_request_v0{});
   }

   bool received(get_status_result_v0& status, eosio::input_stream bin) override {
      ilog("nodeos has chain {c}", ("c", eosio::convert_to_json(status.chain_id)));
      if (rodeos_snapshot->chain_id == eosio::checksum256{})
         rodeos_snapshot->chain_id = status.chain_id;
      if (rodeos_snapshot->chain_id != status.chain_id)
         throw std::runtime_error("database is for chain " + eosio::convert_to_json(rodeos_snapshot->chain_id) +
                                  " but nodeos has chain " + eosio::convert_to_json(status.chain_id));
      ilog("request blocks");
      connection->request_blocks(status, std::max(config->skip_to, rodeos_snapshot->head + 1), get_positions(),
                                 ship_client::request_block | ship_client::request_traces |
                                       ship_client::request_deltas);
      return true;
   }

   std::vector<block_position> get_positions() {
      std::vector<block_position> result;
      if (rodeos_snapshot->head) {
         rodeos::db_view_state view_state{ rodeos::state_account, *db, *rodeos_snapshot->write_session,
                                           partition->contract_kv_prefix };
         for (uint32_t i = rodeos_snapshot->irreversible; i <= rodeos_snapshot->head; ++i) {
            auto info = rodeos::get_state_row<rodeos::block_info>(
                  view_state.kv_state.view, std::make_tuple(eosio::name{ "block.info" }, eosio::name{ "primary" }, i));
            if (!info)
               throw std::runtime_error("database is missing block.info for block " + std::to_string(i));
            auto& info0 = std::get<rodeos::block_info_v0>(info->second);
            result.push_back({ info0.num, info0.id });
         }
      }
      return result;
   }

   static uint64_t to_trace_id(const eosio::checksum256& id) { 
      return fc::zipkin_span::to_id(fc::sha256{ reinterpret_cast<const char*>(id.extract_as_byte_array().data()), 32 }); 
   }

   template <typename Get_Blocks_Result>
   bool process_received(Get_Blocks_Result& result, eosio::input_stream bin) {
      if (!result.this_block)
         return true;
      if (config->stop_before && result.this_block->block_num >= config->stop_before) {
         ilog("block {b}: stop requested", ("b", result.this_block->block_num));
         rodeos_snapshot->end_write(true);
         db->flush(false, false);
         return false;
      }
      if (rodeos_snapshot->head && result.this_block->block_num > rodeos_snapshot->head + 1) {
         std::string msg = "state-history plugin is missing block " + std::to_string(rodeos_snapshot->head + 1);
         ilog(msg);
         throw ship_client::retriable_failure(msg);
      }

      using namespace eosio::literals;
      auto trace_id  = to_trace_id(result.this_block->block_id);
      auto token     = fc::zipkin_span::token{ "ship"_n.value, trace_id };
      auto blk_span  = fc_create_span_from_token(token, "process_received");
      fc_add_tag( blk_span, "block_id", to_string( result.this_block->block_id ) );
      fc_add_tag( blk_span, "block_num", result.this_block->block_num );
      
      rodeos_snapshot->start_block(result);
      if (result.this_block->block_num <= rodeos_snapshot->head)
         reported_block = false;

      bool near      = result.this_block->block_num + 4 >= result.last_irreversible.block_num;
      bool write_now = !(result.this_block->block_num % 200) || near;
      if (write_now || !reported_block) {
         static uint64_t log_counter = 0;
         if (log_counter++ % 1000 == 0) {
            ilog("block {b} {i}",
                 ("b", result.this_block->block_num)
                 ("i", result.this_block->block_num <= result.last_irreversible.block_num ? "irreversible" : ""));

         } else {
            dlog("block {b} {i}",
                 ("b", result.this_block->block_num)
                 ("i", result.this_block->block_num <= result.last_irreversible.block_num ? "irreversible" : ""));
         }
      }
      reported_block = true;

      {
         auto write_block_info_span = fc_create_span(blk_span, "write_block_info");
         rodeos_snapshot->write_block_info(result);
      }
      {
         auto write_deltas_span = fc_create_span(blk_span, "write_deltas");
         rodeos_snapshot->write_deltas(result, [] { return app().is_quiting(); });
      }

      if (!filters.empty()) {
         auto filter_span = fc_create_span(blk_span, "filter");

         for (auto& filter: filters) {
            if (my->streamer)
               my->streamer->start_block(result.this_block->block_num, filter.index);
            filter.filter->process(*rodeos_snapshot, result, bin, [&](const char* data, uint64_t data_size) {
               if (my->streamer) {
                  my->streamer->stream_data(data, data_size, filter.index);
               }
            });
            if (my->streamer)
               my->streamer->stop_block(result.this_block->block_num, filter.index);
         }
      }
      if( app().is_quiting() )
         return false;

      rodeos_snapshot->end_block(result, false);
      {
         auto end_block_span = fc_create_span(blk_span, "end_block");
         rodeos_snapshot->end_block(result, false);
      }

      return true;
   }

   bool received(get_blocks_result_v0& result, eosio::input_stream bin) override {
      return process_received(result, bin);
   }

   bool received(get_blocks_result_v1& result, eosio::input_stream bin) override {
      return process_received(result, bin);
   }

   bool received(get_blocks_result_v2& result, eosio::input_stream bin) override {
      return process_received(result, bin);
   }

   void closed(bool retry, bool quitting) override {
      if (quitting) {
         appbase::app().quit();
      }

      if (my) {
         rodeos_snapshot->end_write(true);
         db->flush(true, true);
         my->session.reset();
         if (retry) {
            my->schedule_retry();
         } else if (my->config->exit_on_filter_wasm_error) {
            appbase::app().quit();
         }
      } else {
         wlog("closed did not nothing as my had not been initialized yet");
      }
   }

   ~cloner_session() {}
}; // cloner_session

static abstract_plugin& _cloner_plugin = app().register_plugin<cloner_plugin>();

cloner_plugin_impl::~cloner_plugin_impl() {
   if (session)
      session->my = nullptr;
}

void cloner_plugin_impl::start() {
   session = std::make_shared<cloner_session>(this);
   session->connect(app().get_io_service());
}

cloner_plugin::cloner_plugin() : my(std::make_shared<cloner_plugin_impl>()) {}

cloner_plugin::~cloner_plugin() {}

void cloner_plugin::set_program_options(options_description& cli, options_description& cfg) {
   auto op   = cfg.add_options();
   auto clop = cli.add_options();
   op("clone-connect-to,f", bpo::value<std::string>()->default_value("127.0.0.1:8080"),
      "State-history endpoint to connect to (nodeos)");
   op("clone-unix-connect-to,u", bpo::value<std::string>(),
      "State-history unix path to connect to (nodeos). Takes precedence over tcp endpoint if specified");
   clop("clone-skip-to,k", bpo::value<uint32_t>(), "Skip blocks before [arg]");
   clop("clone-stop,x", bpo::value<uint32_t>(), "Stop before block [arg]");
   op("clone-exit-on-filter-wasm-error", bpo::bool_switch()->default_value(false),
      "Shutdown application if filter wasm throws an exception");
   op("telemetry-url", bpo::value<std::string>(),
      "Send Zipkin spans to url. e.g. http://127.0.0.1:9411/api/v2/spans" );
   op("telemetry-service-name", bpo::value<std::string>()->default_value(b1::rodeos::config::rodeos_executable_name),
      "Zipkin localEndpoint.serviceName sent with each span" );
   op("telemetry-timeout-us", bpo::value<uint32_t>()->default_value(200000),
      "Timeout for sending Zipkin span." );
   op("telemetry-retry-interval-us", bpo::value<uint32_t>()->default_value(30000000),
      "Retry interval for connecting to Zipkin." );
   op("telemetry-wait-timeout-seconds", bpo::value<uint32_t>()->default_value(0),
      "Initial wait time for Zipkin to become available, stop the program if the connection cannot be established within the wait time.");
   // todo: remove
   op("filter-name", bpo::value<std::string>(), "Filter name. Deprecated. Use filter-name-* instead");
   op("filter-wasm", bpo::value<std::string>(), "Filter wasm. Deprecated. Use filter-wams-* instead");

   // Multiple filter contracts support
   for (uint32_t i = 0; i < max_num_streamers; ++i) {
      std::string i_str = std::to_string(i);
      std::string name_str = std::string{"filter-name-"} + i_str;
      std::string wasm_str = std::string{"filter-wasm-"} + i_str;
      op(name_str.c_str(), bpo::value<std::string>(), "Filter name");
      op(wasm_str.c_str(), bpo::value<std::string>(), "Filter wasm");
   }

   op("profile-filter", bpo::bool_switch(), "Enable filter profiling");
   op("enable-undo-stack", bpo::value<bool>()->default_value(false), "Enable undo stack");
   op("force-write-stride", bpo::value<uint32_t>()->default_value(10000),
      "Maximum number of blocks to process before forcing rocksdb to flush. This option is primarily useful to control re-sync durations "
      "under disaster recovery scenarios (when rodeos has unexpectedly exited, the option ensures blocks stored in rocksdb are at most "
      "force-write-stride blocks behind the current head block being processed by rodeos. However, saving too frequently may affect performance. "
      "It is likely that rocksdb itself will save rodeos data more frequently than this setting by flushing memtables to disk, based on various rocksdb "
      "options. It is not recommended to set this to a small value in production use and should be instead used on a DR node. In contrast, when rodeos "
      "exits normally, it saves the last block processed by rodeos into rocksdb and will continue processing "
      "new blocks from that last processed block number when it next starts up.");

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
   op("eos-vm-oc-cache-size-mb",
      bpo::value<uint64_t>()->default_value(eosio::chain::eosvmoc::config().cache_size / (1024u * 1024u)),
      "Maximum size (in MiB) of the EOS VM OC code cache");
   op("eos-vm-oc-compile-threads", bpo::value<uint64_t>()->default_value(1u)->notifier([](const auto t) {
      if (t == 0) {
         elog("eos-vm-oc-compile-threads must be set to a non-zero value");
         EOS_ASSERT(false, eosio::chain::plugin_exception, "");
      }
   }), "Number of threads to use for EOS VM OC tier-up");
   op("eos-vm-oc-code-cache-map-mode", bpo::value<chainbase::pinnable_mapped_file::map_mode>()->default_value(eosio::chain::eosvmoc::config().map_mode),
    "Map mode for EOS VM OC code cache (\"mapped\", \"heap\", or \"locked\").\n"
    "In \"mapped\" mode code cache is memory mapped as a file.\n"
    "In \"heap\" mode code cache is preloaded in to swappable memory and will use huge pages if available.\n"
    "In \"locked\" mode code cache is preloaded, locked in to memory, and will use huge pages if available.\n"
   );
   op("eos-vm-oc-enable", bpo::bool_switch(), "Enable EOS VM OC tier-up runtime");
#endif
}

void cloner_plugin::plugin_initialize(const variables_map& options) {
   try {
      if(options.count("clone-unix-connect-to")) {
         boost::filesystem::path sock_path = options.at("clone-unix-connect-to").as<string>();
         if (sock_path.is_relative())
            sock_path = app().data_dir() / sock_path;
         my->config->connection_config = ship_client::unix_connection_config{sock_path.generic_string()};
      }
      else {
         auto endpoint = options.at("clone-connect-to").as<std::string>();
         if (endpoint.find(':') == std::string::npos)
            throw std::runtime_error("invalid endpoint: " + endpoint);

         auto port               = endpoint.substr(endpoint.find(':') + 1, endpoint.size());
         auto host               = endpoint.substr(0, endpoint.find(':'));
         my->config->connection_config = ship_client::tcp_connection_config{host, port};
      }
      my->config->skip_to     = options.count("clone-skip-to") ? options["clone-skip-to"].as<uint32_t>() : 0;
      my->config->stop_before = options.count("clone-stop") ? options["clone-stop"].as<uint32_t>() : 0;
      my->config->exit_on_filter_wasm_error = options["clone-exit-on-filter-wasm-error"].as<bool>();

      // Old way, deprecated
      if (options.count("filter-name") && options.count("filter-wasm")) {
         my->config->filter_list.emplace_back(filter_ele{options["filter-name"].as<std::string>(), options["filter-wasm"].as<std::string>(), 0});  // index 0
      } else if (options.count("filter-name") || options.count("filter-wasm")) {
         throw std::runtime_error("filter-name and filter-wasm must be used together");
      }

      std::set<std::string> names {};
      for (uint32_t i = 0; i < max_num_streamers; ++i) {
         std::string i_str = std::to_string(i);
         std::string name_str = std::string{"filter-name-"} + i_str;
         std::string wasm_str = std::string{"filter-wasm-"} + i_str;

         if ( options.count(name_str) && options.count(wasm_str) ) {
            std::string name = options[name_str].as<std::string>();
            std::string wasm = options[wasm_str].as<std::string>();

            EOS_ASSERT(names.find(name) == names.end(), eosio::chain::plugin_exception, "Filter name " + name + " used multiple times");
            EOS_ASSERT(my->config->filter_list.size() == 0 || i > 0, eosio::chain::plugin_exception, "legacy and mulitiple filter contracts cannot be mixed");
            my->config->filter_list.emplace_back(filter_ele{name, wasm, i});
	    names.insert(name);
         } else {
	    EOS_ASSERT(options.count(name_str) == 0 && options.count(wasm_str) == 0, eosio::chain::plugin_exception, name_str + " and " + wasm_str + " must be used together");
         }
      }

      my->config->profile = options["profile-filter"].as<bool>();

      EOS_ASSERT(my->config->filter_list.size() <= max_num_streamers, eosio::chain::plugin_exception, "number of filter contracts: {num_names} greater than max_num_streamers: {max_num_streamers}", ("num_names", my->config->filter_list.size()) ("max_num_streamers", max_num_streamers));
      ilog("number of filter contracts: {num_filters}", ("num_filters", my->config->filter_list.size()));

      my->config->undo_stack_enabled = options["enable-undo-stack"].as<bool>();

#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
      if (options.count("eos-vm-oc-cache-size-mb"))
         my->config->eosvmoc_config.cache_size = options.at("eos-vm-oc-cache-size-mb").as<uint64_t>() * 1024u * 1024u;
      if (options.count("eos-vm-oc-compile-threads"))
         my->config->eosvmoc_config.threads = options.at("eos-vm-oc-compile-threads").as<uint64_t>();
      if (options["eos-vm-oc-enable"].as<bool>())
         my->config->eosvmoc_config.tierup = true;
      my->config->eosvmoc_config.persistent = false;
#endif

      if (options.count("telemetry-url")) {
         fc::zipkin_config::init( options["telemetry-url"].as<std::string>(),
                                  options["telemetry-service-name"].as<std::string>(),
                                  options["telemetry-timeout-us"].as<uint32_t>(),
                                  options["telemetry-wait-timeout-seconds"].as<uint32_t>() );
      }
      my->config->force_write_stride = options["force-write-stride"].as<uint32_t>();
   }
   FC_LOG_AND_RETHROW()
}

void cloner_plugin::plugin_startup() {
   handle_sighup();
   my->start();
}

void cloner_plugin::plugin_shutdown() {
   if (my->session)
      my->session->connection->close(false, false);
   my->timer.cancel();
   fc::zipkin_config::shutdown();
   ilog("cloner_plugin stopped");
}

void cloner_plugin::handle_sighup() {
   fc::zipkin_config::handle_sighup();
}

void cloner_plugin::set_streamer(std::shared_ptr<streamer_t> streamer) {
   my->streamer = std::move(streamer);
}

// Check every id in streamers' filter_ids is in my->config->filter_list
void cloner_plugin::validate_filter_ids(std::set<int>&& ids) {
   for (auto &filter: my->config->filter_list) {
      ids.erase(filter.index);
   }
   EOS_ASSERT(ids.empty(), eosio::chain::plugin_exception, "No filter contracts exist for streamers {id} ", ("id", ids));
}

} // namespace b1

#include <eosio/producer_ha_plugin/producer_ha_plugin.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_machine.hpp>
#include <eosio/producer_ha_plugin/nodeos_logger_wrapper.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_manager.hpp>
#include <eosio/http_plugin/http_plugin.hpp>
#include <libnuraft/nuraft.hxx>

#include <eosio/chain/exceptions.hpp>

#include <fc/log/trace.hpp>
#include <fc/exception/exception.hpp>
#include <fc/io/json.hpp>
#include <fc/reflect/variant.hpp>
#include <eosio/chain/to_string.hpp>


#include <chrono>
#include <thread>
#include <unordered_map>
#include <algorithm>
#include <random>

namespace eosio {

static appbase::abstract_plugin& _producer_ha_plugin = app().register_plugin<producer_ha_plugin>();


class producer_ha_plugin_impl {
public:
   producer_ha_plugin_impl();

public:
   std::string config_path;
   producer_ha_config config;

   void load_config();

   void startup();

   void shutdown();

   // whether the node can produce or not
   bool can_produce(bool skip_leader_checking);

   // whether connected to enough peers to form the quorum
   bool is_connected_to_quorum();

   // whether the current group is active and the node is the leader
   bool is_active_and_leader();

   // log server status
   void log_server_status() const;

   // take leadership if Raft allows
   producer_ha_plugin::take_leadership_result take_leadership();

   // get the head block in the state machine
   const chain::signed_block_ptr get_raft_head_block() const;

   // commit the head block to Raft
   void commit_head_block(const chain::signed_block_ptr block);

   producer_ha_plugin::cluster_status query_raft_status();

private:
   // raft launcher
   nuraft::raft_launcher raft_launcher;

   // raft state machine for producer_ha
   nuraft::ptr<nodeos_state_machine> state_machine = nullptr;

   // chain plugin
   eosio::chain_plugin* chain_plug = nullptr;
};

producer_ha_plugin_impl::producer_ha_plugin_impl():
      chain_plug(appbase::app().find_plugin<eosio::chain_plugin>()) {
   EOS_ASSERT(
         chain_plug != nullptr,
         chain::producer_ha_config_exception,
         "producer_ha_plugin_impl cannot get chain_plugin. Should not happen."
   );
}

void producer_ha_plugin_impl::load_config() {
   // load config
   config = fc::json::from_file<producer_ha_config>(config_path);
   ilog("loaded producer_ha_plugin config from {e}.", ("e", config_path));
   ilog("producer_ha_plugin: {e}.", ("e", config));
}

const chain::signed_block_ptr producer_ha_plugin_impl::get_raft_head_block() const {
   if (!state_machine) return nullptr;
   return state_machine->get_head_block();
}

bool producer_ha_plugin_impl::is_active_and_leader() {
   static unsigned long log_counter_standby = 0;
   static unsigned long log_counter_no_leader = 0;

   // if the process is quiting, simply consider as inactive
   if (app().is_quiting()) {
      return false;
   }

   // is not active, do not produce, ever
   if (!config.is_active_raft_cluster) {
      // print out a log in standby mode for every 600 blocks (around 5 mins)
      if (log_counter_standby % 600 == 0) {
         ilog("producer_ha in standby mode, is_active_raft_cluster = false. No block production in standby mode.");
      }
      ++log_counter_standby;
      return false;
   }

   auto svr = raft_launcher.get_raft_server();
   if (!svr) {
      ilog("raft server is not started.");
      return false;
   }

   if (!svr->is_initialized()) {
      ilog("Raft server is not finishing initialization. Not connected to enough cluster peers.");
      // log_server_status();
      return false;
   }

   if (!is_connected_to_quorum()) {
      ilog("Not connected to the enough cluster peers to form a quorum yet. Skip producing this block.");
      // log_server_status();
      return false;
   }

   // only leader can produce
   bool is_leader = svr->is_leader();
   if (!is_leader) {
      auto leader = svr->get_leader();
      if (leader < 0) {
         if (log_counter_no_leader % 5 == 0) {
            ilog("No leader in the Raft group from this nodeos state at current");
         }
         ++log_counter_no_leader;
      } else {
         auto conf = config.get_config(leader);
         dlog("I am not the leader. Leader is {l}: {c}", ("l", leader)("c", conf));
      }
      return false;
   }

   return true;
}

bool producer_ha_plugin_impl::can_produce(bool skip_leader_checking) {
   if (skip_leader_checking) {
      // if the process is quiting, simply consider as inactive
      if (app().is_quiting()) {
         return false;
      }
   } else if (!is_active_and_leader()) {
      return false;
   }

   // make sure the raft state machine is updated to the current term
   auto svr = raft_launcher.get_raft_server();
   auto term = svr->get_term();
   auto commit_term = svr->get_log_term(svr->get_committed_log_idx());
   if (term > commit_term) {
      ilog("Raft committing of historical state logs in progress ... (state machine term: {t}; Raft term: {r})",
           ("t", commit_term)("r", term));
      return false;
   }

   // make sure: head of Raft == current head on chain, before allowing production
   auto chain_head = chain_plug->chain().head_block_header();
   auto raft_head = get_raft_head_block();

   if (!raft_head) {
      ilog("raft_head is nullptr. First time running producer_ha. Skip head block checking.");
   } else {
      if (chain_head.block_num() > raft_head->block_num()) {
         // if the different is larger than 1000, start to print warning messages, for every 100 blocks
         if (chain_head.block_num() > raft_head->block_num() + 1000 && raft_head->block_num() % 100) {
            dlog("Chain head ({c}, ID: {i}) while raft head is ({r}, ID: {s}). Waiting for raft to catch up first ...",
                 ("c", chain_head.block_num())("i", chain_head.calculate_id())
                 ("r", raft_head->block_num())("s", raft_head->calculate_id()));
         }
         return false;
      }

      // If the chain is not synced up with the raft, no production allowed yet
      if (chain_head.block_num() < raft_head->block_num()) {
         ilog("Chain head is at {c} while raft head is at {r}. Waiting for chain head to catch up first ...",
              ("c", chain_head.block_num())("r", raft_head->block_num()));
         return false;
      }

      // If the chain head is not synced up with the raft latest head, no production allowed yet
      if (chain_head.block_num() == raft_head->block_num() && chain_head.calculate_id() != raft_head->calculate_id()) {
         ilog("Chain head ({c}, ID: {i}) while raft head is ({r}, ID: {s}). Waiting for chain head to be updated with the raft head ...",
              ("c", chain_head.block_num())("i", chain_head.calculate_id())
              ("r", raft_head->block_num())("s", raft_head->calculate_id()));
         return false;
      }
   }

   // Good to produce
   return true;
}

bool producer_ha_plugin_impl::is_connected_to_quorum() {
   auto server = raft_launcher.get_raft_server();
   auto sconf = server->get_config();
   const auto& svrs = sconf->get_servers();
   return svrs.size() >= static_cast<size_t>(config.leader_election_quorum_size);
}

void producer_ha_plugin_impl::log_server_status() const {
   auto server = raft_launcher.get_raft_server();
   auto sconf = server->get_config();
   ilog("producer_ha server status: log_idx: {i}; is_leader: {l}",
        ("i", sconf->get_log_idx())("l", server->is_leader()));

   ilog("producer_ha servers:");
   for (const auto& svr: sconf->get_servers()) {
      ilog("{i} {a} {f}",
           ("i", svr->get_id())
           ("a", svr->get_endpoint())
           ("f", svr->is_learner()));
   }
}

void producer_ha_plugin_impl::startup() {
   auto& self_config = config.get_config(config.self);

   nuraft::ptr<nuraft::logger> logger = nuraft::cs_new<logger_wrapper>(config.logging_level);

   // open the database for producer_ha
   auto db_path = app().data_dir() / "producer_ha";
   ilog("producer_ha db in: {d}", ("d", db_path.string()));
   if (!bfs::exists(db_path.parent_path())) {
      ilog("producer_ha db does not exist. Creating empty db ...");
      bfs::create_directories(db_path.parent_path());
   }

   auto db = std::make_shared<nodeos_state_db>(db_path.c_str());

   // Raft state machine
   state_machine = nuraft::cs_new<nodeos_state_machine>(db);

   // Raft log store
   auto log_store = nuraft::cs_new<nodeos_state_log_store>(db);

   // Raft state manager
   nuraft::ptr<nuraft::state_mgr> state_manager = nuraft::cs_new<nodeos_state_manager>(config, db, log_store);

   nuraft::asio_service::options asio_opt;

   if (config.enable_ssl) {
      // use ssl and allowed subject names
      asio_opt.enable_ssl_ = true;
      asio_opt.server_cert_file_ = config.server_cert_file;
      asio_opt.server_key_file_ = config.server_key_file;
      asio_opt.root_cert_file_ = config.root_cert_file;
      asio_opt.verify_sn_ =
            [&allowed_sns = std::as_const(config.allowed_ssl_subject_names)](const std::string& sn) -> bool {
               bool found = std::find(allowed_sns.begin(), allowed_sns.end(), sn) != allowed_sns.end();
               if (!found) {
                  elog("Client using cert with subject name {sn} rejected, not in the allowed_ssl_subject_names list {sns}",
                       ("sn", sn)
                       ("sns", allowed_sns));
               }
               return found;
            };
   }

   nuraft::raft_params params;

   // Raft quorum parameters

   // minimum number of peer to form the quorum for Raft
   params.custom_commit_quorum_size_ = config.leader_election_quorum_size;
   params.custom_election_quorum_size_ = config.leader_election_quorum_size;

   // leadership expiration time, in ms, so that when the leader crashed or when
   // there is network split, the previous leader can automatically stop itself, and the remaining
   // Raft group know it is safet to elect a new leader.
   // In normal case, the current leader can renew its leadership before the expiration time.
   params.leadership_expiry_ = config.leadership_expiry_ms;

   // heartbeat, election timeout, in ms
   params.heart_beat_interval_ = config.heart_beat_interval_ms;

   // do not create background thread for append_entries, so that raft commit latency is smaller
   params.use_bg_thread_for_urgent_commit_ = false;

   // election timeout values, in ms
   // election_timeout_lower_bound should be > leadership_expiry
   params.election_timeout_lower_bound_ = config.election_timeout_lower_bound_ms;
   params.election_timeout_upper_bound_ = config.election_timeout_upper_bound_ms;

   // every that many raft log entries, make a snapshot
   params.snapshot_distance_ = config.snapshot_distance;
   if (params.snapshot_distance_) {
      // keep snapshot_distance_ number of entries in the raft log store
      params.reserved_log_items_ = params.snapshot_distance_;
      params.log_sync_stop_gap_ = params.snapshot_distance_;
   }

   // start the Raft server
   int port_number = self_config.get_listening_port();

   nuraft::raft_server::init_options raft_opt;

   // construct the Raft server yet, but do not start it yet
   raft_opt.start_server_in_constructor_ = false;

   ilog("Starting Raft server {i} listening on port: {p}", ("i", config.self)("p", port_number));

   nuraft::ptr<nuraft::raft_server> server = raft_launcher.init(state_machine,
                                                                state_manager,
                                                                logger,
                                                                port_number,
                                                                asio_opt,
                                                                params,
                                                                raft_opt);

   if (!server) {
      elog("raft_server was not created successfully. Shutdown myself now. "
           "Please check whether the listening port is already in use by other processes.");
      app().quit();
      return;
   }

   // start Raft server as a follower
   server->start_server(false);
   server->yield_leadership(true);

   // add APIs
   auto& producer_ha_ref = app().get_plugin<producer_ha_plugin>();
   auto& http_plug = app().get_plugin<http_plugin>();

   http_plug.add_api(
         {{std::string("/v1/producer_ha/take_leadership"),
           [&producer_ha_ref](string, string body, url_response_callback cb) mutable {
              try {
                 body = parse_params<std::string, http_params_types::no_params_required>(body);
                 auto result = producer_ha_ref.take_leadership();
                 cb(201, fc::variant(result));
              } catch (...) {
                 http_plugin::handle_exception("producer_ha", "take_leadership", body, cb);
              }
           }}
         }, appbase::priority::medium);

   http_plug.add_api(
         {{std::string("/v1/producer_ha/get_info"),
           [&producer_ha_ref](string, string body, url_response_callback cb) mutable {
              try {
                 body = parse_params<std::string, http_params_types::no_params_required>(body);
                 auto result = producer_ha_ref.query_raft_status();
                 cb(200, fc::variant(result));
              } catch (...) {
                 http_plugin::handle_exception("producer_ha", "get_info", body, cb);
              }
           }}
         }, appbase::priority::medium);
}

void producer_ha_plugin_impl::shutdown() {
   raft_launcher.shutdown();
}

producer_ha_plugin::take_leadership_result producer_ha_plugin_impl::take_leadership(){
   producer_ha_plugin::take_leadership_result ret;
   auto svr = raft_launcher.get_raft_server();
   if (!svr) {
      ilog("take_leadership API call: raft_server is not started.");
      ret.success = false;
      ret.info = "raft_server is not started.";
      return ret;
   }

   if(!svr->is_leader_alive()) {
      ret.success = false;
      ret.info = "No alive leader currently, can't use take_leadership command!";
      return ret;
   }

   if(svr->is_leader()) {
      ret.success = true;
      ret.info = "This node is already leader, no request sent.";
      return ret;
   }

   bool result = svr->request_leadership();
   ret.success = result;
   ret.info = result ? "Take_leadership request was sent." : "Failed to send take_leadership request.";
   return ret;
}

void producer_ha_plugin_impl::commit_head_block(const chain::signed_block_ptr block) {
   dlog("Committing head block {i} to Raft.", ("i", block->block_num()));

   // defensive checking: to refuse any block committing when the app is shutting down
   EOS_ASSERT(
         !app().is_quiting(),
         chain::producer_ha_commit_head_exception,
         "Failed to commit block ({n}, ID: {i}) to Raft: app is quiting.",
         ("n", block->block_num())("i", block->calculate_id())
   );

   // construct the Raft logs to be committed
   std::vector<nuraft::ptr<nuraft::buffer>> logs;
   nuraft::ptr<nuraft::buffer> buf = nodeos_state_machine::encode_block(block);
   logs.push_back(buf);

   using raft_result = nuraft::cmd_result<nuraft::ptr<nuraft::buffer>>;

   // try to commit the logs to the Raft group
   auto svr = raft_launcher.get_raft_server();
   nuraft::ptr<raft_result> ret = svr->append_entries(logs);

   EOS_ASSERT(
         ret != nullptr,
         chain::plugin_exception,
         "Raft append_entries(logs) returned nullptr. Should never happen."
   );

   // check commit results
   if (!ret->get_accepted()) {
      // Log append rejected? usually because this node is not a leader.

      // give up leadership
      svr->yield_leadership(true);

      // throw exception out
      EOS_THROW(
            chain::producer_ha_commit_head_exception,
            "Failed to commit block ({n}, ID: {i}) to Raft: not accepted. Result code: {c}",
            ("n", block->block_num())("i", block->calculate_id())("c", static_cast<int32_t>(ret->get_result_code()))
      );
   }

   if (ret->get_result_code() != nuraft::cmd_result_code::OK) {
      // Something went wrong. This node should not broadcast this block out.

      // give up leadership
      svr->yield_leadership(true);

      // throw exception out
      EOS_THROW(
            chain::producer_ha_commit_head_exception,
            "Failed to commit block ({n}, ID: {i}) to Raft: result code is not OK. Result code: {c}",
            ("n", block->block_num())("i", block->calculate_id())("c", static_cast<int32_t>(ret->get_result_code()))
      );
   }

   // commit successfully now
   dlog("Committed head block {n} to Raft. Return code {i}",
        ("n", block->block_num())("i", ret->get()->get_ulong()));
}

producer_ha_plugin::cluster_status producer_ha_plugin_impl::query_raft_status(){
   producer_ha_plugin::cluster_status ret;
   auto svr = raft_launcher.get_raft_server();
   if (!svr) {
      dlog("raft_server is not started.");
      return ret;
   }

   ret.is_active_raft_cluster = config.is_active_raft_cluster;
   nuraft::raft_params params = svr->get_current_params();
   ret.quorum_size = params.custom_election_quorum_size_;
   std::vector<nuraft::ptr<nuraft::srv_config>> configs_out;
   svr->get_srv_config_all(configs_out);
   int32_t leader_id = svr->get_leader();
   ret.leader_id = leader_id;
   for (const auto& sc : configs_out) {
      int32_t id = sc->get_id();
      std::string end_point = sc->get_endpoint();
      auto peer_conf = config.get_config(id);
      if (peer_conf.address != end_point) {
         // print a warning, if they are not the same.
         // Raft may need time to propagate the config
         ilog("Producer_ha peer {i} address configured as {a} while the config in Raft config is {c}",
              ("i", id)("a", peer_conf.address)("c", end_point));
      }
      ret.peers.push_back(peer_conf);
   }
   auto block = state_machine->get_head_block();
   ret.last_committed_block_num = block != nullptr ? block->block_num() : 0;
   return ret;
}

producer_ha_plugin::producer_ha_plugin():
   my(new producer_ha_plugin_impl()) {}

producer_ha_plugin::~producer_ha_plugin() {
}

void producer_ha_plugin::set_program_options(options_description&, options_description& cfg) {
   auto op = cfg.add_options();
   op("producer-ha-config", bpo::value<std::string>(),
      "producer_ha_plugin configuration file path. "
      "The configuration file should contain a JSON string specifying the parameters, "
      "whether the producer_ha cluster is active or standby, self ID, and the peers (including this node itself) "
      "configurations with ID (>=0), endpoint address and listening_port (optional, used only if the port is "
      "different from the port in its endpoint address).\n"
      "Example (for peer 1 whose address is defined in peers too):\n"
      "{\n"
      "  \"is_active_raft_cluster\": true,\n"
      "  \"leader_election_quorum_size\": 2,\n"
      "  \"self\": 1,\n"
      "  \"logging_level\": 3,\n"
      "  \"peers\": [\n"
      "    {\n"
      "      \"id\": 1,\n"
      "      \"listening_port\": 8988,\n"
      "      \"address\": \"localhost:8988\"\n"
      "    },\n"
      "    {\n"
      "      \"id\": 2,\n"
      "      \"address\": \"localhost:8989\"\n"
      "    },\n"
      "    {\n"
      "      \"id\": 3,\n"
      "      \"address\": \"localhost:8990\"\n"
      "    }\n"
      "  ]\n"
      "}\n"
      "\n"
      "logging_levels:\n"
      "   <= 2: error\n"
      "      3: warn\n"
      "      4: info\n"
      "      5: debug\n"
      "   >= 6: all\n");
}

void producer_ha_plugin::plugin_initialize(const variables_map& options) {
   try {
      // Handle options
      EOS_ASSERT(options.count("producer-ha-config"), chain::plugin_config_exception,
                 "producer-ha-config is required for producer_ha plugin.");
      my->config_path = options.at("producer-ha-config").as<string>();
      ilog("producer_ha configuration file: {p}", ("p", my->config_path));
      my->load_config();
      if (!my->config.is_active_raft_cluster) {
         ilog("producer_ha in standby mode, is_active_raft_cluster = false. No block production in standby mode.");
      }
   } FC_LOG_AND_RETHROW()
}

void producer_ha_plugin::plugin_startup() {
   my->startup();
}

void producer_ha_plugin::plugin_shutdown() {
   ilog("shutdown...");
   my->shutdown();
   ilog("exit shutdown");
}

// get a const copy of the config
const producer_ha_config& producer_ha_plugin::get_config() const {
   return my->config;
}

bool producer_ha_plugin::disabled() const {
   static auto state = get_state();
   if (state == registered) {
      // Only if the plugin is not enabled, keep the default original behavior.
      //
      // Otherwise, even when the status changes to stopped, ask the producer_ha plugin first.
      // We prefer safety to flexibility.
      return true;
   } else {
      return false;
   }
}


bool producer_ha_plugin::enabled() const {
   return !disabled();
}

bool producer_ha_plugin::is_active_raft_cluster() const {
   return my->config.is_active_raft_cluster;
}

bool producer_ha_plugin::can_produce(bool skip_leader_checking) {
   if (disabled()) {
      return true;
   }

   return my->can_produce(skip_leader_checking);
}

bool producer_ha_plugin::is_active_and_leader() {
   if (disabled()) {
      return false;
   }

   return my->is_active_and_leader();
}

producer_ha_plugin::cluster_status producer_ha_plugin::query_raft_status(){
   if (disabled()) {
      return {};
   }
   return my->query_raft_status();
}

chain::signed_block_ptr producer_ha_plugin::get_raft_head_block() const {
   if (disabled()) return nullptr;
   return my->get_raft_head_block();
}

void producer_ha_plugin::commit_head_block(const chain::signed_block_ptr block) {
   if (disabled()) {
      return;
   }

   return my->commit_head_block(block);
}

producer_ha_plugin::take_leadership_result producer_ha_plugin::take_leadership() {
   if (disabled()) {
      take_leadership_result ret;
      ret.info = "Not allowed. Producer_ha_plugin is disabled.";
      return ret;
   }

   return my->take_leadership();
}

}

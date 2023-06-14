#pragma once

#include <libnuraft/nuraft.hxx>

#include <eosio/producer_ha_plugin/nodeos_state_log_store.hpp>
#include <eosio/producer_ha_plugin/producer_ha_plugin.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_db.hpp>

#include <boost/filesystem.hpp>

#include <sstream>

namespace eosio {

class nodeos_state_manager : public nuraft::state_mgr {
public:
   // keys for db addresses
   inline static const std::string config_key = "conf";
   inline static const std::string state_key = "state";

   nodeos_state_manager(
         const producer_ha_config& config,
         const std::shared_ptr<nodeos_state_db> db,
         const nuraft::ptr<nodeos_state_log_store> log_store) {
      prodha_config_ = config;
      db_ = db;

      // self info
      auto& self_config = config.get_config(config.self);
      my_id_ = self_config.id;

      // log store
      log_store_ = log_store;
   }

   ~nodeos_state_manager() {}

   void log_server_list(const std::list<nuraft::ptr<nuraft::srv_config>>& svrs) {
      for (const auto& svr: svrs) {
         ilog("Server {i}: address {a}, is_learner {l}",
              ("i", svr->get_id())("a", svr->get_endpoint())("l", svr->is_learner()));
      }
   }

   // load config for a NuRaft cluster
   nuraft::ptr<nuraft::cluster_config> load_config() override {
      dlog("state_manager::load_config()");
      auto clus_config = nuraft::cs_new<nuraft::cluster_config>();

      auto buf = db_->read(nodeos_state_db::manager, config_key);

      if (buf) {
         clus_config = nuraft::cluster_config::deserialize(*buf);
         ilog("nodeos_state_manager::load_config() -> (log_idx: {l})", ("l", clus_config->get_log_idx()));
         log_server_list(clus_config->get_servers());
      } else {
         ilog("producer_ha db does not contain Raft cluster_config yet.");
      }

      const int32_t new_quorum_size = prodha_config_.leader_election_quorum_size;
      const std::vector<producer_ha_config>::size_type new_peers_size = prodha_config_.peers.size();

      std::string old_user_ctx = clus_config->get_user_ctx();
      dlog("get user context of NuRaft cluster config = \"{x}\"", ("x", old_user_ctx));
      if (old_user_ctx.empty()) {
         immutable_ha_config ihc { new_quorum_size, new_peers_size };
         std::string new_user_ctx = ihc.to_string();
         clus_config->set_user_ctx(new_user_ctx);
         dlog("set user context of NuRaft cluster config = \"{x}\"", ("x", new_user_ctx));
      } else {
         try {
            const immutable_ha_config old_ihc = immutable_ha_config::from_string(old_user_ctx);
            const int32_t old_quorum_size = old_ihc.quorum_size;
            if (new_quorum_size != old_quorum_size) {
               elog("check failed - inconsistent quorum size: new ({new}) != old ({old})",
                    ("new", new_quorum_size)("old", old_quorum_size));
               app().quit();
            } else {
               dlog("check passed - consistent quorum size ({new})", ("new", new_quorum_size));
            }
            const std::vector<producer_ha_config>::size_type old_peers_size = old_ihc.peers_size;
            if (new_peers_size != old_peers_size) {
               elog("check failed - inconsistent peers size: new ({new}) != old ({old})",
                    ("new", new_peers_size)("old", old_peers_size));
               app().quit();
            } else {
               dlog("check passed - consistent peers size ({new})", ("new", new_peers_size));
            }
         } catch (const std::runtime_error &e) {
            elog(std::string("check failed - ") + e.what());
            app().quit();
         } catch (...) {
            elog(std::string("check failed - unexpected error"));
            app().quit();
         }
      }

      // Raft cluster_config: all peers, including self
      std::list<nuraft::ptr<nuraft::srv_config>> svrs = clus_config->get_servers();

      for (auto& peer: prodha_config_.peers) {
         bool existing = false;
         for (auto& svr: svrs) {
            if (svr->get_id() == peer.id) {
               existing = true;
               if (svr->get_endpoint() != peer.address) {
                  auto new_svr = nuraft::cs_new<nuraft::srv_config>(
                        svr->get_id(),
                        svr->get_dc_id(),
                        peer.address,
                        svr->get_aux(),
                        svr->is_learner(),
                        svr->get_priority()
                  );
                  svr.swap(new_svr);
               }
            }
         }
         if (!existing) {
            svrs.push_back(nuraft::cs_new<nuraft::srv_config>(peer.id, peer.address));
         }
      }
      clus_config->get_servers().clear();
      for (auto svr: svrs) {
         clus_config->get_servers().push_back(svr);
      }

      ilog("Raft servers used by this instance:");
      log_server_list(clus_config->get_servers());

      return clus_config;
   }

   void save_config(const nuraft::cluster_config& config) override {
      dlog("state_manager::save_config() <- (log_idx: {l})", ("l", config.get_log_idx()));
      nuraft::ptr<nuraft::buffer> buf = config.serialize();
      db_->write(nodeos_state_db::manager, config_key, buf);
      db_->flush();
   }

   void save_state(const nuraft::srv_state& state) override {
      dlog("state_manager::save_state() <- (term: {t})", ("t", state.get_term()));
      nuraft::ptr<nuraft::buffer> buf = state.serialize();
      db_->write(nodeos_state_db::manager, state_key, buf);
      db_->flush();
   }

   nuraft::ptr<nuraft::srv_state> read_state() override {
      dlog("state_manager::read_state()");
      auto state = nuraft::cs_new<nuraft::srv_state>();
      auto buf = db_->read(nodeos_state_db::manager, state_key);
      if (buf) {
         state = nuraft::srv_state::deserialize(*buf);
      } else {
         ilog("producer_ha db does not contain state. Starting with an empty one.");
      }
      ilog("nodeos_state_manager::read_state() -> (term: {t})", ("t", state->get_term()));
      return state;
   }

   nuraft::ptr<nuraft::log_store> load_log_store() override {
      return log_store_;
   }

   nuraft::int32 server_id() override {
      return my_id_;
   }

   void system_exit(const int exit_code) override {
   }

private:
   // We maintain a simple config class here to stay independent from producer_ha_config.
   // If producer_ha_config should expand (i.e. have more fields) in future, it won't cause
   // inconsistency problems in config check.
   struct immutable_ha_config {
      const int32_t quorum_size;
      const std::vector<producer_ha_config>::size_type peers_size;

      immutable_ha_config(const int32_t qs, const std::vector<producer_ha_config>::size_type ps) :
         quorum_size(qs), peers_size(ps) {}

      std::string to_string() const {
         return std::to_string(quorum_size) + " " + std::to_string(peers_size);
      }

      static immutable_ha_config from_string(const std::string& str) {
         std::istringstream iss(str);
         int32_t qs;
         std::vector<producer_ha_config>::size_type ps;
         if (!(iss >> qs >> ps)) {
            std::string msg = "cannot convert to immutable_ha_config from string=\"" + str + "\".";
            throw std::runtime_error(msg);
         }
         return {qs, ps};
      }
   };

private:
   // this node's ID
   int my_id_;

   // producer_ha_plugin configuration
   producer_ha_config prodha_config_;

   // rocksdb for persisting states
   std::shared_ptr<nodeos_state_db> db_;

   // log store
   nuraft::ptr<nodeos_state_log_store> log_store_;
};

};

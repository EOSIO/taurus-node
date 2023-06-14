#pragma once

#include <libnuraft/nuraft.hxx>

#include <appbase/application.hpp>

#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>

#include <fc/reflect/reflect.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/operations.hpp>

#include <algorithm>
namespace eosio {

using namespace appbase;

struct producer_ha_config_peer;
struct producer_ha_config;

/**
 *  Producer HA plugin: provide producer HA by allowing a single producer to
 *  produce, through consensus among a Raft group formed by all producers with leadership expiration,
 *  and safety checking.
 */

class producer_ha_plugin : public appbase::plugin<producer_ha_plugin> {
public:
   producer_ha_plugin();

   virtual ~producer_ha_plugin();

   APPBASE_PLUGIN_REQUIRES()

   struct cluster_status {
      bool is_active_raft_cluster = false;
      int32_t quorum_size = 0;
      uint32_t last_committed_block_num = 0;
      int32_t leader_id = -1;
      std::vector<producer_ha_config_peer> peers;
   };

   struct take_leadership_result {
      bool success;
      std::string info;
      take_leadership_result():success(false), info(""){};
      take_leadership_result& operator=(const take_leadership_result & tlr) = default;
   };

   virtual void set_program_options(options_description &, options_description &cfg) override;

   void plugin_initialize(const variables_map &options);

   void plugin_startup();

   void plugin_shutdown();

   // whether the node can produce or not
   bool can_produce(bool skip_leader_checking = false);

   // get a const copy of the config
   const producer_ha_config& get_config() const;

   // whether the producer_ha is active and this node is the leader
   bool is_active_and_leader();

   // Try to make this node to be the leader.
   // if this node is already leader, return true directly.
   // If this node is connected to the Raft cluster, send request.
   // If this node is disconnected from the Raft cluster, return false with failure information
   take_leadership_result take_leadership();

   // commit the new head block to Raft
   // throw exceptions if failures happened.
   void commit_head_block(const chain::signed_block_ptr block);

   // report raft cluster status, together with important parameters
   cluster_status query_raft_status();

   // get the raft head block
   chain::signed_block_ptr get_raft_head_block() const;

   // whether the producer_ha_plugin is enabled and configured
   // skip any checking/operations from the producer_ha plugin if it is disabled
   bool disabled() const;
   bool enabled() const;

   // whether this is the active cluster
   bool is_active_raft_cluster() const;

private:
   std::unique_ptr<class producer_ha_plugin_impl> my;
};

/**
 * Configuration objects
 */
struct producer_ha_config_peer : fc::reflect_init {
   // the peer ID. Should be unique.
   int32_t id = -1;
   // the peer's endpoint address in format ip:port for other peers to connect to
   string address;
   // the port to listen on by producer_ha for Raft. Should be 0 or > 0
   // If listening_port is 0, the port from the address will be used.
   int32_t listening_port = 0;

   int get_address_port() const {
      std::vector<std::string> listening_address_splits;
      boost::split(listening_address_splits, address, boost::is_any_of(":"));
      if (listening_address_splits.size() != 2) {
         EOS_THROW(
               chain::plugin_config_exception,
               "listening_address {c} is not in format host:port!",
               ("c", address)
         );
      } else {
         EOS_ASSERT(
               std::all_of(listening_address_splits[1].begin(), listening_address_splits[1].end(),
                           [](char c) { return std::isdigit(c); }),
               chain::plugin_config_exception,
               "listening_address {c} is not in format host:port where port can only contain numbers!",
               ("c", address)
         );
         return std::stoi(listening_address_splits[1]);
      }
   }

   // get the listening port
   int get_listening_port() const {
      if (listening_port) {
         return listening_port;
      } else {
         return get_address_port();
      }
   }

   void reflector_init() {
      EOS_ASSERT(
            id >= 0,
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: id must be >= 0"
      );

      EOS_ASSERT(
            listening_port >= 0,
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: listening_port must be >= 0"
      );

      // set the port if it is 0
      if (!listening_port) {
         listening_port = get_address_port();
      }
   }
};

struct producer_ha_config : fc::reflect_init {
   // whether this Raft is active (enabled) or not.

   // true: the active region
   // false: the standby region

   // if it is false, the producer_ha will reject production, even for the leader.
   // so the standby region's BPs only sync blocks without trying to produce.
   bool is_active_raft_cluster = false;

   // the quorum size for the Raft protocol configuration
   // should be > peer size / 2
   int32_t leader_election_quorum_size = 0;

   // this node's self ID. From the `self`, this node's config is found from the `peers`.
   int32_t self = -1;

   // logging level for the Raft logger
   // default level: 3 == info
   int32_t logging_level = 3;

   // Leadership expiration time in millisecond
   int32_t leadership_expiry_ms = 2000;

   // A leader will send a heartbeat message to followers if this interval (in milliseconds) has passed since
   // the last replication or heartbeat message.
   int32_t heart_beat_interval_ms = 50;

   // Lower bound of election timer in millisecond
   int32_t election_timeout_lower_bound_ms = 5000;

   // Upper bound of election timer, in millisecond
   int32_t election_timeout_upper_bound_ms = 10000;

   // distance of snapshots (number of Raft commits between 2 snapshots)
   // default value: 1 hour's blocks (0.5 second block time)
   int32_t snapshot_distance = 60 * 60 * 2;

   // the list of peers in the Raft group
   //
   // prefer to have a cleaner JSON file mapped from the C++ struct. set or map's corresponding JSON struct is complex.
   // The JSON file is edited and viewed by users.
   //
   // Regarding performance, the vector size is usually small (3 for example, usually < 10). A linear vector is likely
   // not slower or even faster than a tree based complex structure like set.
   // That said, if later, if the performance turns to be a problem, we can create a lookup table for peers using
   // unordered_map for faster look up.
   vector<producer_ha_config_peer> peers;

   // whether ssl is enabled or not
   bool enable_ssl = false;

   // certificate and key file paths
   std::string server_cert_file;
   std::string server_key_file;

   // root cert file path
   std::string root_cert_file;

   // allow subject names
   vector<std::string> allowed_ssl_subject_names;

   const producer_ha_config_peer& get_config(int id) const {
      for (auto &peer: peers) {
         if (peer.id == id) return peer;
      }

      // the configuration is wrong...
      EOS_THROW(
            chain::plugin_config_exception,
            "producer-ha-config is invalid: ID {i} is not in the peers list!",
            ("i", id)
      );
   }

   void reflector_init() {
      // safety checking
      EOS_ASSERT(
            static_cast<size_t>(leader_election_quorum_size) * 2 > peers.size(),
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: leader_election_quorum_size must be > peer count / 2"
      );

      // make sure self config exists
      auto self_config = get_config(self);

      EOS_ASSERT(
            snapshot_distance > 0,
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: snapshot_distance must be larger than 0"
      );

      EOS_ASSERT(
            static_cast<size_t>(leader_election_quorum_size) < peers.size(),
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: leader_election_quorum_size must be < peer count"
      );

      EOS_ASSERT(
            election_timeout_lower_bound_ms < election_timeout_upper_bound_ms,
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: election_timeout_lower_bound_ms ({l}) must be < election_timeout_upper_bound_ms ({u})", ("l", election_timeout_lower_bound_ms) ("u", election_timeout_upper_bound_ms)
      );

      EOS_ASSERT(
            election_timeout_lower_bound_ms > leadership_expiry_ms,
            chain::plugin_config_exception,
            "Invalid producer_ha_plugin config: election_timeout_lower_bound_ms ({l}) must be > leadership_expiry_ms ({e})", ("l", election_timeout_lower_bound_ms) ("e", leadership_expiry_ms)
      );

      // if enable_ssl is enabled, make sure the files exist for the certs
      if (enable_ssl) {
         EOS_ASSERT(
               boost::filesystem::exists(server_cert_file),
               chain::plugin_config_exception,
               "Invalid producer_ha_plugin config when ssl is enabled: server_cert_file {f} does not exist",
               ("f", server_cert_file)
         );
         EOS_ASSERT(
               boost::filesystem::exists(server_key_file),
               chain::plugin_config_exception,
               "Invalid producer_ha_plugin config when ssl is enabled: server_key_file {f} does not exist",
               ("f", server_key_file)
         );
         EOS_ASSERT(
               boost::filesystem::exists(root_cert_file),
               chain::plugin_config_exception,
               "Invalid producer_ha_plugin config when ssl is enabled: root_cert_file {f} does not exist",
               ("f", root_cert_file)
         );
      }
   }
};
} // eosio namespace


FC_REFLECT(eosio::producer_ha_config_peer, (id)(address)(listening_port))
FC_REFLECT(eosio::producer_ha_config,
           (is_active_raft_cluster)(leader_election_quorum_size)(self)
           (logging_level)
           (leadership_expiry_ms)(heart_beat_interval_ms)
           (election_timeout_lower_bound_ms)(election_timeout_upper_bound_ms)
           (snapshot_distance)
           (peers)
           (enable_ssl)(server_cert_file)(server_key_file)(root_cert_file)(allowed_ssl_subject_names))
FC_REFLECT(eosio::producer_ha_plugin::take_leadership_result, (success)(info))
FC_REFLECT(eosio::producer_ha_plugin::cluster_status, (is_active_raft_cluster)(quorum_size)(last_committed_block_num)(leader_id)(peers))


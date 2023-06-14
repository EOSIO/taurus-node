#pragma once

#include <eosio/chain/plugin_interface.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/net_plugin/connection.hpp>
#include <eosio/net_plugin/sync_manager.hpp>

#include <boost/sml.hpp>

#include <shared_mutex>

namespace eosio {

class producer_plugin;
class chain_plugin;
class net_plugin;

namespace p2p {

class dispatch_manager;

class net_plugin_impl {
   using connection_ptr = typename connection::ptr;
   using connection_wptr = typename connection::wptr;
   struct sml_logger {
      // converts version number to string
      // e.g. 114 -> v1_1_4
      static std::string sml_version() {
         static std::string version;
         if (version.empty()) {
            std::stringstream ss;
            ss << "v" << (uint32_t)BOOST_SML_VERSION / 100 << "_"
                      << (uint32_t)BOOST_SML_VERSION % 100 / 10 << "_"
                      << (uint32_t)BOOST_SML_VERSION % 10;
            version = ss.str();
         }

         return version;
      }
      // returns string of the following format:
      // boost::ext::sml::[version]::
      static std::string sml_prefix() {
         static std::string prefix;
         if (prefix.empty()) {
            std::stringstream ss;
            ss << "boost::ext::sml::" << sml_version() << "::back::";
            prefix = ss.str();
         }

         return prefix;
      }
      // removes pattern from string
      static void remove_from_str(std::string& str, const std::string& pattern ) {
         if (pattern.empty())
            return;

         std::string::size_type pos = 0;
         while (pos < std::string::npos) {
            pos = str.find(pattern, pos);
            if (pos != std::string::npos)
               str.erase( pos, pattern.size() );
         }
      }
      // returns local file path of net plugin
      // this is used to strip physical file path from logs
      static std::string net_plugin_path(const std::string& str) {
         static std::string path;
         if (path.empty()) {
            const std::string prefix = "lambda at ";
            auto pos = str.find(prefix);
            if (pos == std::string::npos)
               return path;

            auto start = pos + prefix.size();
            if (start >= str.size())
               return path;

            auto end = str.find(":", start);

            if (end == std::string::npos)
               return path;

            //find last slash
            auto slash_pos = str.rfind("/", end);
            if (slash_pos == std::string::npos)
               return path;

            path = str.substr(start, slash_pos - start + 1);
         }

         return path;
      }
      static std::string sync_manager_namespace() {
         return "eosio::p2p::sync_manager::";
      }
      //cleans debug string from unnecessary output
      static std::string strip(const char* str) {
         std::string buffer = str;
         remove_from_str(buffer, sml_prefix());
         remove_from_str(buffer, net_plugin_path(buffer));
         remove_from_str(buffer, sync_manager_namespace());
         remove_from_str(buffer, "_name() [T = ");

         return buffer;
      }
      // triggered on fc::exception event
      template <class SM,
                template <typename, typename...> class TEvent, typename T, typename ...Ts,
                std::enable_if_t<std::is_base_of_v<fc::exception, T>, bool> = true>
      void log_process_event(const TEvent<T, Ts...>& ev) {
         fc_elog( net_plugin_impl::get_logger(), "[sml] {ex}", ("ex", ev.exception_.to_detail_string()) );
      }
      // triggered on std::exception event
      template <class SM,
                template <typename, typename...> class TEvent, typename T, typename ...Ts,
                std::enable_if_t<std::is_base_of_v<std::exception, T> &&
                                !std::is_base_of_v<fc::exception, T>, bool> = true>
      void log_process_event(const TEvent<T, Ts...>& ev) {
         fc_elog( net_plugin_impl::get_logger(), "[sml] std::exception {ex}", ("ex", ev.exception_.what()) );
      }
      // triggered on neither fc::exception nor std::exception
      template <class SM,
                template <typename, typename...> class TEvent, typename T, typename ...Ts,
                std::enable_if_t<std::is_same_v<T, boost::sml::_> &&
                                 std::is_same_v<TEvent<T, Ts...>, boost::sml::back::exception<T, Ts...>>, bool> = true>
      void log_process_event(const TEvent<T, Ts...>&) {
         fc_elog( net_plugin_impl::get_logger(), "[sml] unknown exception" );
      }
      // triggered on non-error event
      template <class SM,
                class TEvent>
      void log_process_event(const TEvent&) {
         fc_dlog( net_plugin_impl::get_logger(), "[sml][process_event][{e}]", ("e", strip(boost::sml::aux::get_type_name<TEvent>())) );
      }
      //triggered on every event guard
      template <class SM, class TGuard, class TEvent>
      void log_guard(const TGuard&, const TEvent&, bool result) {
         fc_dlog( net_plugin_impl::get_logger(), "[sml][guard] {g} [event] {e} {r}",
                                                               ("g", strip(boost::sml::aux::get_type_name<TGuard>()))
                                                               ("e", strip(boost::sml::aux::get_type_name<TEvent>()))
                                                               ("r", (result ? "[OK]" : "[Reject]")) );
      }
      // triggered on action execution
      template <class SM, class TAction, class TEvent>
      void log_action(const TAction&, const TEvent&) {
         fc_dlog( net_plugin_impl::get_logger(), "[sml][action] {a} [event] {e}",
                                                                ("a", strip(boost::sml::aux::get_type_name<TAction>()))
                                                                ("e", strip(boost::sml::aux::get_type_name<TEvent>())) );
      }
      // triggered on every event. If state was not changed, source and destination strings will be same
      template <class SM, class TSrcState, class TDstState>
      void log_state_change(const TSrcState& src, const TDstState& dst) {
         fc_dlog( net_plugin_impl::get_logger(), "[sml][transition] {s1} -> {s2}", ("s1", src.c_str())("s2", dst.c_str()) );
      }
   };

   using tcp_acceptor = boost::asio::ip::tcp::acceptor;
   using transaction_subscription = chain::plugin_interface::compat::channels::transaction_ack::channel_type::handle;

public:
   using my_sync_manager  = sync_manager<connection, net_plugin_impl>;
   using sync_man_sm_impl = my_sync_manager::state_machine;
   using sync_manager_sm = boost::sml::sm<sync_man_sm_impl, boost::sml::logger<net_plugin_impl::sml_logger>>;

private:
   static std::shared_ptr<net_plugin_impl>       my_impl;
   mutable std::shared_mutex                     connections_mtx;
   std::set< connection_ptr >                    connections;     // todo: switch to a thread safe container to avoid big mutex over complete collection

   static void destroy();
   static void create_instance();
   static void handle_sighup();

   friend class eosio::net_plugin;
public:
   static sml_logger& get_sml_logger() {
      static sml_logger l;
      return l;
   }

   inline static std::shared_ptr<net_plugin_impl>& get() {
      return my_impl;
   }
   operator sync_manager_sm&() {
      return *get()->sync_sm;
   }
   sync_manager<connection, net_plugin_impl>& sync_man() {
      sync_manager<connection, net_plugin_impl>::state_machine& sync_sm = *get()->sync_sm;
      return *sync_sm.impl;
   }
   sync_manager<connection, net_plugin_impl>::state_machine& sm_impl() const {
      return *get()->sync_sm;
   }
   bool syncing_with_peer() const {
      using namespace boost::sml;
      auto lock = get()->sm_impl().locked_sml_mutex();
      return get()->sync_sm->is("lib_catchup"_s);
   }
   std::string get_state_str() const {
      using namespace boost::sml;

      auto lock = get()->sm_impl().locked_sml_mutex();
      if ( get()->sync_sm->is("in_sync"_s) )
         return "in_sync";
      if ( get()->sync_sm->is("lib_catchup"_s) )
         return "lib_catchup";
      if ( get()->sync_sm->is("head_catchup"_s) )
         return "head_catchup";
      if ( get()->sync_sm->is("error"_s) )
         return "error";

      return "unknown";
   }
   static fc::logger& get_logger() {
      static fc::logger logger;

      return logger;
   }
   inline const std::string& get_log_format() const {
      return peer_log_format;
   }

   std::string                                peer_log_format;
   std::unique_ptr<tcp_acceptor>              acceptor;
   std::atomic<uint32_t>                      current_connection_id{0};

   std::unique_ptr<sync_manager_sm>           sync_sm;
   std::unique_ptr<dispatch_manager>          dispatcher;

   /**
    * Thread safe, only updated in plugin initialize
    *  @{
    */
   std::string                                p2p_address;
   std::string                                p2p_server_address;

   std::vector<std::string>                   supplied_peers;
   std::vector<chain::public_key_type>        allowed_peers; ///< peer keys allowed to connect
   std::map<chain::public_key_type,
            chain::private_key_type>          private_keys; ///< overlapping with producer keys, also authenticating non-producing nodes

   enum possible_connections : char {
      None = 0,
      Producers = 1 << 0,
      Specified = 1 << 1,
      Any = 1 << 2
   };

   possible_connections                       allowed_connections{None};
   boost::asio::steady_timer::duration        connector_period{0};
   boost::asio::steady_timer::duration        txn_exp_period{0};
   boost::asio::steady_timer::duration        resp_expected_period{0};
   std::chrono::milliseconds                  keepalive_interval{std::chrono::milliseconds{32 * 1000}};
   std::chrono::milliseconds                  heartbeat_timeout{keepalive_interval * 2};

   int                                        max_cleanup_time_ms = 0;
   uint32_t                                   max_client_count = 0;
   uint32_t                                   max_nodes_per_host = 1;
   bool                                       p2p_accept_transactions = true;
   bool                                       p2p_reject_incomplete_blocks = true;

   eosio::chain::chain_id_type                chain_id;
   fc::sha256                                 node_id;
   std::string                                user_agent_name;

   chain_plugin*                              chain_plug = nullptr;
   producer_plugin*                           producer_plug = nullptr;
   bool                                       use_socket_read_watermark = false;

   std::mutex                                 connector_check_timer_mtx;
   std::unique_ptr<boost::asio::steady_timer> connector_check_timer;
   int                                        connector_checks_in_flight{0};

   std::mutex                                 expire_timer_mtx;
   std::unique_ptr<boost::asio::steady_timer> expire_timer;

   std::mutex                                 keepalive_timer_mtx;
   std::unique_ptr<boost::asio::steady_timer> keepalive_timer;

   std::atomic<bool>                          in_shutdown{false};

   transaction_subscription                   incoming_transaction_ack_subscription;

   uint16_t                                       thread_pool_size = 2;
   std::optional<eosio::chain::named_thread_pool> thread_pool;

   bool telemetry_span_root = false;

private:
   mutable std::mutex            chain_info_mtx; // protects chain_*
   uint32_t                      chain_lib_num{0};
   uint32_t                      chain_head_blk_num{0};
   uint32_t                      chain_fork_head_blk_num{0};
   chain::block_id_type          chain_lib_id;
   chain::block_id_type          chain_head_blk_id;
   chain::block_id_type          chain_fork_head_blk_id;
   uint32_t                      handshake_backoff_cap_ms = def_handshake_backoff_cap_ms;
   uint32_t                      handshake_backoff_floor_ms = def_handshake_backoff_floor_ms;

public:
   void update_chain_info();
   //         lib_num, head_block_num, fork_head_blk_num, lib_id, head_blk_id, fork_head_blk_id
   std::tuple<uint32_t, uint32_t, uint32_t,
              chain::block_id_type, chain::block_id_type, chain::block_id_type> get_chain_info() const;

   void start_listen_loop();

   void on_accepted_block( const chain::block_state_ptr& bs );
   void on_pre_accepted_block( const chain::signed_block_ptr& bs );
   void transaction_ack(const std::pair<fc::exception_ptr, chain::transaction_metadata_ptr>&);
   void on_irreversible_block( const chain::block_state_ptr& blk );

   void start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection);
   void start_expire_timer();
   void start_monitors();

   void expire();
   void connection_monitor(std::weak_ptr<connection> from_connection, bool reschedule);
   /** \name Peer Timestamps
    *  Time message handling
    *  @{
    */
   /** \brief Peer heartbeat ticker.
    */
   void ticker();
   /** @} */
   /** \brief Determine if a peer is allowed to connect.
    *
    * Checks current connection mode and key authentication.
    *
    * \return False if the peer should not connect, true otherwise.
    */
   bool authenticate_peer(const handshake_message& msg) const;
   /** \brief Retrieve public key used to authenticate with peers.
    *
    * Finds a key to use for authentication.  If this node is a producer, use
    * the front of the producer key map.  If the node is not a producer but has
    * a configured private key, use it.  If the node is neither a producer nor has
    * a private key, returns an empty key.
    *
    * \note On a node with multiple private keys configured, the key with the first
    *       numerically smaller byte will always be used.
    */
   chain::public_key_type get_authentication_key() const;
   /** \brief Returns a signature of the digest using the corresponding private key of the signer.
    *
    * If there are no configured private keys, returns an empty signature.
    */
   chain::signature_type sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const;

   constexpr static uint16_t to_protocol_version(uint16_t v) {
      if (v >= net_version_base) {
         v -= net_version_base;
         return (v > net_version_range) ? 0 : v;
      }
      return 0;
   }

   connection_ptr find_connection(const std::string& host)const; // must call with held mutex

   template<typename Function>
   void for_each_block_connection( Function f ) {
      auto lock = shared_connections_lock();
      for( auto& c : connections ) {
         if( c->is_transactions_only_connection() ) continue;
         if( !f( c ) ) return;
      }
   }

   template<typename Function>
   void for_each_connection( Function f ) {
      auto lock = shared_connections_lock();
      for( auto& c : connections ) {
         if( !f( c ) ) return;
      }
   }

   inline std::shared_lock<std::shared_mutex> shared_connections_lock() const {
      return std::shared_lock<std::shared_mutex>(connections_mtx);
   }

   inline const std::set<connection_ptr>& get_connections() const {
      return connections;
   }

   static uint32_t get_handshake_backoff_floor_ms() {
      return my_impl->handshake_backoff_floor_ms;
   }

   static uint32_t get_handshake_backoff_cap_ms() {
      return my_impl->handshake_backoff_cap_ms;
   }
};

}} //eosio::p2p

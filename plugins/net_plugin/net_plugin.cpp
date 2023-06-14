#include <eosio/net_plugin/connection.hpp>
#include <eosio/net_plugin/net_plugin.hpp>
#include <eosio/net_plugin/protocol.hpp>
#include <eosio/net_plugin/net_plugin_impl.hpp>
#include <eosio/net_plugin/dispatch_manager.hpp>
#include <eosio/net_plugin/sync_manager.hpp>
#include <eosio/chain/types.hpp>

#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/block.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/chain/contract_types.hpp>

#include <fc/network/message_buffer.hpp>
#include <fc/network/ip.hpp>
#include <fc/io/json.hpp>
#include <fc/io/raw.hpp>
#include <fc/log/logger_config.hpp>
#include <fc/log/trace.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/crypto/rand.hpp>
#include <fc/exception/exception.hpp>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/host_name.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <shared_mutex>

using boost::asio::ip::tcp;
using boost::asio::ip::address_v4;
using boost::asio::ip::host_name;
using namespace eosio::chain::plugin_interface;
using namespace eosio::p2p;

namespace eosio {
   static appbase::abstract_plugin& _net_plugin = app().register_plugin<net_plugin>();

   using std::vector;

   using fc::time_point;
   using fc::time_point_sec;
   using eosio::chain::transaction_id_type;
   using eosio::chain::sha256_less;

   template<class enum_type, class=typename std::enable_if<std::is_enum<enum_type>::value>::type>
   inline enum_type& operator|=(enum_type& lhs, const enum_type& rhs)
   {
      using T = std::underlying_type_t <enum_type>;
      return lhs = static_cast<enum_type>(static_cast<T>(lhs) | static_cast<T>(rhs));
   }

   /**
    *  If there is a change to network protocol or behavior, increment net version to identify
    *  the need for compatibility hooks
    */
   constexpr uint16_t proto_explicit_sync = 1;       // version at time of eosio 1.0
   constexpr uint16_t proto_block_id_notify = 2;     // reserved. feature was removed. next net_version should be 3

   net_plugin::net_plugin() {
      p2p::net_plugin_impl::create_instance();
      my = p2p::net_plugin_impl::get();
   }

   net_plugin::~net_plugin() {
      p2p::net_plugin_impl::destroy();
   }

   void net_plugin::set_program_options( options_description& /*cli*/, options_description& cfg )
   {
      cfg.add_options()
         ( "p2p-listen-endpoint", bpo::value<string>()->default_value( "0.0.0.0:9876" ), "The actual host:port used to listen for incoming p2p connections.")
         ( "p2p-server-address", bpo::value<string>(), "An externally accessible host:port for identifying this node. Defaults to p2p-listen-endpoint.")
         ( "p2p-peer-address", bpo::value< vector<string> >()->composing(),
           "The public endpoint of a peer node to connect to. Use multiple p2p-peer-address options as needed to compose a network.\n"
           "  Syntax: host:port[:<trx>|<blk>]\n"
           "  The optional 'trx' and 'blk' indicates to node that only transactions 'trx' or blocks 'blk' should be sent."
           "  Examples:\n"
           "    p2p.eos.io:9876\n"
           "    p2p.trx.eos.io:9876:trx\n"
           "    p2p.blk.eos.io:9876:blk\n")
         ( "p2p-max-nodes-per-host", bpo::value<int>()->default_value(def_max_nodes_per_host), "Maximum number of client nodes from any single IP address")
         ( "p2p-accept-transactions", bpo::value<bool>()->default_value(true), "Allow transactions received over p2p network to be evaluated and relayed if valid.")
         ( "p2p-reject-incomplete-blocks", bpo::value<bool>()->default_value(true), "Reject pruned signed_blocks even in light validation")
         ( "agent-name", bpo::value<string>()->default_value("EOS Test Agent"), "The name supplied to identify this node amongst the peers.")
         ( "allowed-connection", bpo::value<vector<string>>()->multitoken()->default_value({"any"}, "any"), "Can be 'any' or 'producers' or 'specified' or 'none'. If 'specified', peer-key must be specified at least once. If only 'producers', peer-key is not required. 'producers' and 'specified' may be combined.")
         ( "peer-key", bpo::value<vector<string>>()->composing()->multitoken(), "Optional public key of peer allowed to connect.  May be used multiple times.")
         ( "peer-private-key", boost::program_options::value<vector<string>>()->composing()->multitoken(),
           "Tuple of [PublicKey, WIF private key] (may specify multiple times)")
         ( "max-clients", bpo::value<int>()->default_value(def_max_clients), "Maximum number of clients from which connections are accepted, use 0 for no limit")
         ( "connection-cleanup-period", bpo::value<int>()->default_value(def_conn_retry_wait), "number of seconds to wait before cleaning up dead connections")
         ( "max-cleanup-time-msec", bpo::value<int>()->default_value(10), "max connection cleanup time per cleanup call in millisec")
         ( "net-threads", bpo::value<uint16_t>()->default_value(my->thread_pool_size),
           "Number of worker threads in net_plugin thread pool" )
         ( "sync-fetch-span", bpo::value<uint32_t>()->default_value(def_sync_fetch_span), "number of blocks to retrieve in a chunk from any individual peer during synchronization")
         ( "use-socket-read-watermark", bpo::value<bool>()->default_value(false), "Enable experimental socket read watermark optimization")
         ( "peer-log-format", bpo::value<string>()->default_value( "[\"{_name}\" - {_cid} {_ip}:{_port}] " ),
           "The string used to format peers when logging messages about them.  Variables are escaped with {<variable name>}.\n"
           "Available Variables:\n"
           "   _name  \tself-reported name\n\n"
           "   _cid   \tassigned connection id\n\n"
           "   _id    \tself-reported ID (64 hex characters)\n\n"
           "   _sid   \tfirst 8 characters of _peer.id\n\n"
           "   _ip    \tremote IP address of peer\n\n"
           "   _port  \tremote port number of peer\n\n"
           "   _lip   \tlocal IP address connected to peer\n\n"
           "   _lport \tlocal port number connected to peer\n\n")
         ( "p2p-keepalive-interval-ms", bpo::value<int>()->default_value(def_keepalive_interval), "peer heartbeat keepalive message interval in milliseconds")
         ( "telemtry-span-root", bpo::bool_switch(), "generate zipkin root span for blocks received from net-plugin")
         ( "handshake-backoff-floor-ms", bpo::value<uint32_t>()->default_value(def_handshake_backoff_floor_ms), "for a given connection, sending out handshakes more frequently than this value will trigger backoff control mechanism")
         ( "handshake-backoff-cap-ms", bpo::value<uint32_t>()->default_value(def_handshake_backoff_cap_ms), "maximum delay that backoff control will impose on a given connection when sending out a handshake")
        ;
   }

   template<typename T>
   T dejsonify(const string& s) {
      return fc::json::from_string(s).as<T>();
   }

   void net_plugin::plugin_initialize( const variables_map& options ) {
      fc_ilog( p2p::net_plugin_impl::get_logger(), "Initialize net plugin" );
      try {
         p2p::net_plugin_impl::get()->peer_log_format = options.at( "peer-log-format" ).as<string>();

         uint32_t sync_span = options.at( "sync-fetch-span" ).as<uint32_t>();
         std::shared_ptr<net_plugin_impl::my_sync_manager> sync_master( new net_plugin_impl::my_sync_manager(sync_span, p2p::net_plugin_impl::get()) );
         net_plugin_impl::sync_man_sm_impl sync_sm(sync_master);
         auto& lg = p2p::net_plugin_impl::get_sml_logger();
         my->sync_sm.reset( new p2p::net_plugin_impl::sync_manager_sm{sync_sm, lg} );

         my->connector_period = std::chrono::seconds( options.at( "connection-cleanup-period" ).as<int>());
         my->max_cleanup_time_ms = options.at("max-cleanup-time-msec").as<int>();
         my->txn_exp_period = def_txn_expire_wait;
         my->resp_expected_period = def_resp_expected_wait;
         my->max_client_count = options.at( "max-clients" ).as<int>();
         my->max_nodes_per_host = options.at( "p2p-max-nodes-per-host" ).as<int>();
         my->p2p_accept_transactions = options.at( "p2p-accept-transactions" ).as<bool>();
         my->p2p_reject_incomplete_blocks = options.at("p2p-reject-incomplete-blocks").as<bool>();

         my->use_socket_read_watermark = options.at( "use-socket-read-watermark" ).as<bool>();
         my->keepalive_interval = std::chrono::milliseconds( options.at( "p2p-keepalive-interval-ms" ).as<int>() );
         EOS_ASSERT( my->keepalive_interval.count() > 0, chain::plugin_config_exception,
                     "p2p-keepalive_interval-ms must be greater than 0" );

         if( options.count( "p2p-keepalive-interval-ms" )) {
            my->heartbeat_timeout = std::chrono::milliseconds( options.at( "p2p-keepalive-interval-ms" ).as<int>() * 2 );
         }

         if( options.count( "p2p-listen-endpoint" ) && options.at("p2p-listen-endpoint").as<string>().length()) {
            my->p2p_address = options.at( "p2p-listen-endpoint" ).as<string>();
            EOS_ASSERT( my->p2p_address.length() <= p2p::max_p2p_address_length, chain::plugin_config_exception,
                        "p2p-listen-endpoint to long, must be less than {m}", ("m", p2p::max_p2p_address_length) );
         }
         if( options.count( "p2p-server-address" ) ) {
            my->p2p_server_address = options.at( "p2p-server-address" ).as<string>();
            EOS_ASSERT( my->p2p_server_address.length() <= p2p::max_p2p_address_length, chain::plugin_config_exception,
                        "p2p_server_address to long, must be less than {m}", ("m", p2p::max_p2p_address_length) );
         }

         my->thread_pool_size = options.at( "net-threads" ).as<uint16_t>();
         EOS_ASSERT( my->thread_pool_size > 0, chain::plugin_config_exception,
                     "net-threads {num} must be greater than 0", ("num", my->thread_pool_size) );

         if( options.count( "p2p-peer-address" )) {
            my->supplied_peers = options.at( "p2p-peer-address" ).as<vector<string> >();
         }
         if( options.count( "agent-name" )) {
            my->user_agent_name = options.at( "agent-name" ).as<string>();
            EOS_ASSERT( my->user_agent_name.length() <= p2p::max_handshake_str_length, chain::plugin_config_exception,
                        "agent-name to long, must be less than {m}", ("m", p2p::max_handshake_str_length) );
         }

         if( options.count( "allowed-connection" )) {
            const std::vector<std::string> allowed_remotes = options["allowed-connection"].as<std::vector<std::string>>();
            for( const std::string& allowed_remote : allowed_remotes ) {
               if( allowed_remote == "any" )
                  my->allowed_connections |= p2p::net_plugin_impl::Any;
               else if( allowed_remote == "producers" )
                  my->allowed_connections |= p2p::net_plugin_impl::Producers;
               else if( allowed_remote == "specified" )
                  my->allowed_connections |= p2p::net_plugin_impl::Specified;
               else if( allowed_remote == "none" )
                  my->allowed_connections = p2p::net_plugin_impl::None;
            }
         }

         if( my->allowed_connections & p2p::net_plugin_impl::Specified )
            EOS_ASSERT( options.count( "peer-key" ),
                        plugin_config_exception,
                       "At least one peer-key must accompany 'allowed-connection=specified'" );

         if( options.count( "peer-key" )) {
            const std::vector<std::string> key_strings = options["peer-key"].as<std::vector<std::string>>();
            for( const std::string& key_string : key_strings ) {
               my->allowed_peers.push_back( dejsonify<chain::public_key_type>( key_string ));
            }
         }

         if( options.count( "peer-private-key" )) {
            const std::vector<std::string> key_id_to_wif_pair_strings = options["peer-private-key"].as<std::vector<std::string>>();
            for( const std::string& key_id_to_wif_pair_string : key_id_to_wif_pair_strings ) {
               auto key_id_to_wif_pair = dejsonify<std::pair<chain::public_key_type, std::string>>(
                     key_id_to_wif_pair_string );
               my->private_keys[key_id_to_wif_pair.first] = fc::crypto::private_key( key_id_to_wif_pair.second );
            }
         }

         my->chain_plug = app().find_plugin<chain_plugin>();
         EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, ""  );
         my->chain_id = my->chain_plug->get_chain_id();
         fc::rand_pseudo_bytes( my->node_id.data(), my->node_id.data_size());
         const controller& cc = my->chain_plug->chain();

         if( cc.get_read_mode() == db_read_mode::IRREVERSIBLE || cc.get_read_mode() == db_read_mode::READ_ONLY ) {
            if( my->p2p_accept_transactions ) {
               my->p2p_accept_transactions = false;
               string m = cc.get_read_mode() == db_read_mode::IRREVERSIBLE ? "irreversible" : "read-only";
               wlog( "p2p-accept-transactions set to false due to read-mode: {m}", ("m", m) );
            }
         }
         if( my->p2p_accept_transactions ) {
            my->chain_plug->enable_accept_transactions();
         }

         my->telemetry_span_root = options["telemtry-span-root"].as<bool>();

         my->handshake_backoff_floor_ms = options["handshake-backoff-floor-ms"].as<uint32_t>();
         my->handshake_backoff_cap_ms = options["handshake-backoff-cap-ms"].as<uint32_t>();

         EOS_ASSERT(my->handshake_backoff_floor_ms <= my->handshake_backoff_cap_ms,
                    plugin_config_exception,
                    "Handshake backoff floor value should be <= cap value");
      } FC_LOG_AND_RETHROW()
   }

   void net_plugin::plugin_startup() {
      handle_sighup();
      try { try {

      fc_ilog( p2p::net_plugin_impl::get_logger(), "my node_id is {id}", ("id", my->node_id ));

      my->producer_plug = app().find_plugin<producer_plugin>();

      my->thread_pool.emplace( "net", my->thread_pool_size );

      my->dispatcher.reset( new p2p::dispatch_manager( my->thread_pool->get_executor() ) );

      if( !my->p2p_accept_transactions && my->p2p_address.size() ) {
         fc_ilog( p2p::net_plugin_impl::get_logger(), "\n"
               "***********************************\n"
               "* p2p-accept-transactions = false *\n"
               "*    Transactions not forwarded   *\n"
               "***********************************\n" );
      }

      tcp::endpoint listen_endpoint;
      if( my->p2p_address.size() > 0 ) {
         auto host = my->p2p_address.substr( 0, my->p2p_address.find( ':' ));
         auto port = my->p2p_address.substr( host.size() + 1, my->p2p_address.size());
         tcp::resolver resolver( my->thread_pool->get_executor() );
         // Note: need to add support for IPv6 too?
         listen_endpoint = *resolver.resolve( tcp::v4(), host, port );

         my->acceptor.reset( new tcp::acceptor( my->thread_pool->get_executor() ) );

         if( !my->p2p_server_address.empty() ) {
            my->p2p_address = my->p2p_server_address;
         } else {
            if( listen_endpoint.address().to_v4() == address_v4::any()) {
               boost::system::error_code ec;
               auto host = host_name( ec );
               if( ec.value() != boost::system::errc::success ) {
                  FC_THROW_EXCEPTION( fc::invalid_arg_exception,
                                      "Unable to retrieve host_name. {msg}", ("msg", ec.message()));
               }
               auto port = my->p2p_address.substr( my->p2p_address.find( ':' ), my->p2p_address.size());
               my->p2p_address = host + port;
            }
         }
      }

      if( my->acceptor ) {
         try {
           my->acceptor->open(listen_endpoint.protocol());
           my->acceptor->set_option(tcp::acceptor::reuse_address(true));
           my->acceptor->bind(listen_endpoint);
           my->acceptor->listen();
         } catch (const std::exception& e) {
           elog( "net_plugin::plugin_startup failed to bind to port {port}", ("port", listen_endpoint.port()) );
           throw e;
         }
         fc_ilog( p2p::net_plugin_impl::get_logger(), "starting listener, max clients is {mc}",("mc",my->max_client_count) );
         my->start_listen_loop();
      }
      {
         chain::controller& cc = my->chain_plug->chain();
         cc.accepted_block.connect( [my = my]( const block_state_ptr& s ) {
            my->on_accepted_block( s );
         } );
         cc.pre_accepted_block.connect( [my = my]( const signed_block_ptr& s ) {
            my->on_pre_accepted_block( s );
         } );
         cc.irreversible_block.connect( [my = my]( const block_state_ptr& s ) {
            my->on_irreversible_block( s );
         } );
      }

      {
         std::lock_guard<std::mutex> g( my->keepalive_timer_mtx );
         my->keepalive_timer.reset( new boost::asio::steady_timer( my->thread_pool->get_executor() ) );
      }
      my->ticker();

      my->incoming_transaction_ack_subscription = app().get_channel<compat::channels::transaction_ack>().subscribe(
            std::bind(&p2p::net_plugin_impl::transaction_ack, my, std::placeholders::_1));

      my->start_monitors();

      my->update_chain_info();

      for( const auto& seed_node : my->supplied_peers ) {
         connect( seed_node );
      }

      }
      FC_LOG_AND_RETHROW()
      }
      catch( ... ) {
         // always want plugin_shutdown even on exception
         plugin_shutdown();
         throw;
      }
   }

   void net_plugin::handle_sighup() {
      p2p::net_plugin_impl::handle_sighup();
      fc::zipkin_config::handle_sighup();
   }

   void net_plugin::plugin_shutdown() {
      try {
         fc_ilog( p2p::net_plugin_impl::get_logger(), "shutdown.." );
         my->in_shutdown = true;
         {
            std::lock_guard<std::mutex> g( my->connector_check_timer_mtx );
            if( my->connector_check_timer )
               my->connector_check_timer->cancel();
         }{
            std::lock_guard<std::mutex> g( my->expire_timer_mtx );
            if( my->expire_timer )
               my->expire_timer->cancel();
         }{
            std::lock_guard<std::mutex> g( my->keepalive_timer_mtx );
            if( my->keepalive_timer )
               my->keepalive_timer->cancel();
         }

         {
            fc_ilog( p2p::net_plugin_impl::get_logger(), "close {s} connections", ("s", my->connections.size()) );
            std::unique_lock<std::shared_mutex> lock( my->connections_mtx );
            for( auto& con : my->connections ) {
               fc_dlog( p2p::net_plugin_impl::get_logger(), "close: {cid}", ("cid", con->connection_id) );
               con->close( false, true );
            }
            my->connections.clear();
         }

         if( my->thread_pool ) {
            my->thread_pool->stop();
         }

         if( my->acceptor ) {
            boost::system::error_code ec;
            my->acceptor->cancel( ec );
            my->acceptor->close( ec );
         }

         app().post( 0, [me = my](){} );
         fc_ilog( p2p::net_plugin_impl::get_logger(), "exit shutdown" );
      }
      FC_CAPTURE_AND_RETHROW()
   }

   /**
    *  Used to trigger a new connection from RPC API
    */
   string net_plugin::connect( const string& host ) {
      std::unique_lock<std::shared_mutex> lock( my->connections_mtx );
      if( my->find_connection( host ) )
         return "already connected";

      p2p::connection::ptr c = std::make_shared<connection>( host );
      fc_dlog( p2p::net_plugin_impl::get_logger(), "calling active connector: {h}", ("h", host) );
      if( c->resolve_and_connect() ) {
         fc_dlog( p2p::net_plugin_impl::get_logger(), "adding new connection to the list: {host} {cid}", ("host", host)("cid", c->connection_id) );
         c->set_heartbeat_timeout( my->heartbeat_timeout );
         my->connections.insert( c );
      }
      return "added connection";
   }

   string net_plugin::disconnect( const string& host ) {
      std::unique_lock<std::shared_mutex> lock( my->connections_mtx );
      for( auto itr = my->connections.begin(); itr != my->connections.end(); ++itr ) {
         if( (*itr)->peer_address() == host ) {
            fc_ilog( p2p::net_plugin_impl::get_logger(), "disconnecting: {cid}", ("cid", (*itr)->connection_id) );
            (*itr)->close();
            my->connections.erase(itr);
            return "connection removed";
         }
      }
      return "no known connection for host";
   }

   std::optional<connection_status> net_plugin::status( const string& host )const {
      std::shared_lock<std::shared_mutex> lock( my->connections_mtx );
      auto con = my->find_connection( host );
      if( con )
         return con->get_status();
      return std::optional<connection_status>();
   }

   vector<connection_status> net_plugin::connections()const {
      vector<connection_status> result;
      std::shared_lock<std::shared_mutex> g( my->connections_mtx );
      result.reserve( my->connections.size() );
      for( const auto& c : my->connections ) {
         result.push_back( c->get_status() );
      }
      return result;
   }

   // call with connections_mtx
   connection::ptr p2p::net_plugin_impl::find_connection( const string& host )const {
      for( const auto& c : connections )
         if( c->peer_address() == host ) return c;
      return connection::ptr();
   }
}

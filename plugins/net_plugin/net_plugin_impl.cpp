#include <eosio/net_plugin/net_plugin_impl.hpp>
#include <eosio/net_plugin/dispatch_manager.hpp>
#include <eosio/net_plugin/connection.hpp>

#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>

using boost::asio::ip::tcp;
using namespace eosio::chain;

namespace eosio { namespace p2p {

std::shared_ptr<net_plugin_impl> net_plugin_impl::my_impl;

void net_plugin_impl::destroy() {
   my_impl.reset();
}
void net_plugin_impl::create_instance() {
   EOS_ASSERT(!my_impl, fc::exception, "net_plugin_impl instance already exists");
   my_impl.reset( new net_plugin_impl );
}

void net_plugin_impl::handle_sighup() {
   fc::logger::update( "net_plugin_impl", get_logger() );
}

void net_plugin_impl::start_listen_loop() {
   connection_ptr new_connection = std::make_shared<connection>();
   new_connection->connecting = true;
   new_connection->strand.post( [this, new_connection = std::move( new_connection )](){
      acceptor->async_accept( *new_connection->socket,
         boost::asio::bind_executor( new_connection->strand, [new_connection, socket=new_connection->socket, this]( boost::system::error_code ec ) {
         if( !ec ) {
            uint32_t visitors = 0;
            uint32_t from_addr = 0;
            boost::system::error_code rec;
            const auto& paddr_add = socket->remote_endpoint( rec ).address();
            string paddr_str;
            if( rec ) {
               fc_elog( get_logger(), "Error getting remote endpoint: {m}", ("m", rec.message()));
            } else {
               paddr_str = paddr_add.to_string();
               for_each_connection( [&visitors, &from_addr, &paddr_str]( auto& conn ) {
                  if( conn->socket_is_open()) {
                     if( conn->peer_address().empty()) {
                        ++visitors;
                        std::lock_guard<std::mutex> g_conn( conn->conn_mtx );
                        if( paddr_str == conn->remote_endpoint_ip ) {
                           ++from_addr;
                        }
                     }
                  }
                  return true;
               } );
               if( from_addr < max_nodes_per_host && (max_client_count == 0 || visitors < max_client_count)) {
                  fc_ilog( get_logger(), "Accepted new connection: " + paddr_str );
                  new_connection->set_heartbeat_timeout( heartbeat_timeout );
                  if( new_connection->start_session()) {
                     std::unique_lock<std::shared_mutex> lock( connections_mtx );
                     connections.insert( new_connection );
                  }

               } else {
                  if( from_addr >= max_nodes_per_host ) {
                     fc_dlog( get_logger(), "Number of connections ({n}) from {ra} exceeds limit {l}",
                              ("n", from_addr + 1)( "ra", paddr_str )( "l", max_nodes_per_host ));
                  } else {
                     fc_dlog( get_logger(), "max_client_count {m} exceeded", ("m", max_client_count));
                  }
                  // new_connection never added to connections and start_session not called, lifetime will end
                  boost::system::error_code ec;
                  socket->shutdown( tcp::socket::shutdown_both, ec );
                  socket->close( ec );
               }
            }
         } else {
            fc_elog( get_logger(), "Error accepting connection: {m}", ("m", ec.message()));
            // For the listed error codes below, recall start_listen_loop()
            switch (ec.value()) {
               case ECONNABORTED:
               case EMFILE:
               case ENFILE:
               case ENOBUFS:
               case ENOMEM:
               case EPROTO:
                  break;
               default:
                  return;
            }
         }
         start_listen_loop();
      }));
   } );
}

// call only from main application thread
void net_plugin_impl::update_chain_info() {
   controller& cc = chain_plug->chain();
   std::lock_guard<std::mutex> g( chain_info_mtx );
   chain_lib_num = cc.last_irreversible_block_num();
   chain_lib_id = cc.last_irreversible_block_id();
   chain_head_blk_num = cc.head_block_num();
   chain_head_blk_id = cc.head_block_id();
   chain_fork_head_blk_num = cc.fork_db_pending_head_block_num();
   chain_fork_head_blk_id = cc.fork_db_pending_head_block_id();
   fc_dlog( get_logger(), "updating chain info lib {lib}, head {head}, fork {fork}",
            ("lib", chain_lib_num)("head", chain_head_blk_num)("fork", chain_fork_head_blk_num) );
}

//         lib_num, head_blk_num, fork_head_blk_num, lib_id, head_blk_id, fork_head_blk_id
std::tuple<uint32_t, uint32_t, uint32_t, block_id_type, block_id_type, block_id_type>
net_plugin_impl::get_chain_info() const {
   std::lock_guard<std::mutex> g( chain_info_mtx );
   return std::make_tuple(
         chain_lib_num, chain_head_blk_num, chain_fork_head_blk_num,
         chain_lib_id, chain_head_blk_id, chain_fork_head_blk_id );
}

// called from any thread
void net_plugin_impl::start_conn_timer(boost::asio::steady_timer::duration du, std::weak_ptr<connection> from_connection) {
   if( in_shutdown ) return;
   std::lock_guard<std::mutex> g( connector_check_timer_mtx );
   ++connector_checks_in_flight;
   connector_check_timer->expires_from_now( du );
   connector_check_timer->async_wait( [my = get(), from_connection](boost::system::error_code ec) {
         std::unique_lock<std::mutex> g( my->connector_check_timer_mtx );
         int num_in_flight = --my->connector_checks_in_flight;
         g.unlock();
         if( !ec ) {
            my->connection_monitor(from_connection, num_in_flight == 0 );
         } else {
            if( num_in_flight == 0 ) {
               if( my->in_shutdown ) return;
               fc_elog( get_logger(), "Error from connection check monitor: {m}", ("m", ec.message()));
               my->start_conn_timer( my->connector_period, std::weak_ptr<connection>() );
            }
         }
   });
}

// thread safe
void net_plugin_impl::start_expire_timer() {
   if( in_shutdown ) return;
   std::lock_guard<std::mutex> g( expire_timer_mtx );
   expire_timer->expires_from_now( txn_exp_period);
   expire_timer->async_wait( [my = get()]( boost::system::error_code ec ) {
      if( !ec ) {
         my->expire();
      } else {
         if( my->in_shutdown ) return;
         fc_elog( get_logger(), "Error from transaction check monitor: {m}", ("m", ec.message()) );
         my->start_expire_timer();
      }
   } );
}

// thread safe
void net_plugin_impl::ticker() {
   if( in_shutdown ) return;
   std::lock_guard<std::mutex> g( keepalive_timer_mtx );
   keepalive_timer->expires_from_now(keepalive_interval);
   keepalive_timer->async_wait([my = get()]( boost::system::error_code ec ) {
         my->ticker();
         if( ec ) {
            if( my->in_shutdown ) return;
            fc_wlog( get_logger(), "Peer keepalive ticked sooner than expected: {m}", ("m", ec.message()) );
         }

         tstamp current_time = connection::get_time();
         my->for_each_connection( [current_time]( auto& c ) {
            if( c->socket_is_open() ) {
               c->strand.post([c, current_time]() {
                  c->check_heartbeat(current_time);
               } );
            }
            return true;
         } );
      } );
}

void net_plugin_impl::start_monitors() {
   {
      std::lock_guard<std::mutex> g( connector_check_timer_mtx );
      connector_check_timer.reset(new boost::asio::steady_timer( my_impl->thread_pool->get_executor() ));
   }
   {
      std::lock_guard<std::mutex> g( expire_timer_mtx );
      expire_timer.reset( new boost::asio::steady_timer( my_impl->thread_pool->get_executor() ) );
   }
   start_conn_timer(connector_period, std::weak_ptr<connection>());
   start_expire_timer();
}

void net_plugin_impl::expire() {
   auto now = time_point::now();
   uint32_t lib = 0;
   std::tie( lib, std::ignore, std::ignore, std::ignore, std::ignore, std::ignore ) = get_chain_info();
   dispatcher->expire_blocks( lib );
   dispatcher->expire_txns( lib );
   fc_dlog( get_logger(), "expire_txns {n}us", ("n", time_point::now() - now) );

   start_expire_timer();
}

// called from any thread
void net_plugin_impl::connection_monitor(std::weak_ptr<connection> from_connection, bool reschedule ) {
   auto max_time = fc::time_point::now();
   max_time += fc::milliseconds(max_cleanup_time_ms);
   auto from = from_connection.lock();
   std::unique_lock<std::shared_mutex> lock( connections_mtx );
   auto it = (from ? connections.find(from) : connections.begin());
   if (it == connections.end()) it = connections.begin();
   size_t num_rm = 0, num_clients = 0, num_peers = 0;
   while (it != connections.end()) {
      if (fc::time_point::now() >= max_time) {
         connection_wptr wit = *it;
         lock.unlock();
         fc_dlog( get_logger(), "Exiting connection monitor early, ran out of time: {t}", ("t", max_time - fc::time_point::now()) );
         fc_ilog( get_logger(), "p2p client connections: {num}/{max}, peer connections: {pnum}/{pmax}",
                  ("num", num_clients)("max", max_client_count)("pnum", num_peers)("pmax", supplied_peers.size()) );
         if( reschedule ) {
            start_conn_timer( std::chrono::milliseconds( 1 ), wit ); // avoid exhausting
         }
         return;
      }
      (*it)->peer_address().empty() ? ++num_clients : ++num_peers;
      if( !(*it)->socket_is_open() && !(*it)->connecting) {
         if( !(*it)->peer_address().empty() ) {
            if( !(*it)->resolve_and_connect() ) {
               it = connections.erase(it);
               --num_peers; ++num_rm;
               continue;
            }
         } else {
            --num_clients; ++num_rm;
            it = connections.erase(it);
            continue;
         }
      }
      ++it;
   }
   lock.unlock();
   if( num_clients > 0 || num_peers > 0 )
      fc_ilog( get_logger(), "p2p client connections: {num}/{max}, peer connections: {pnum}/{pmax}",
               ("num", num_clients)("max", max_client_count)("pnum", num_peers)("pmax", supplied_peers.size()) );
   fc_dlog( get_logger(), "connection monitor, removed {n} connections", ("n", num_rm) );
   if( reschedule ) {
      start_conn_timer( connector_period, std::weak_ptr<connection>());
   }
}

// called from application thread
void net_plugin_impl::on_accepted_block(const block_state_ptr& bs) {
   update_chain_info();
   controller& cc = chain_plug->chain();
   dispatcher->strand.post( [this, bs]() {
      fc_dlog( get_logger(), "signaled accepted_block, blk num = {num}, id = {id}", ("num", bs->block_num)("id", bs->id) );
      dispatcher->bcast_block( bs->block, bs->id );
   });
}

// called from application thread
void net_plugin_impl::on_pre_accepted_block(const signed_block_ptr& block) {
   update_chain_info();
   controller& cc = chain_plug->chain();
   if( cc.is_trusted_producer(block->producer) ) {
      dispatcher->strand.post( [this, block]() {
         auto id = block->calculate_id();
         fc_dlog( get_logger(), "signaled pre_accepted_block, blk num = {num}, id = {id}", ("num", block->block_num())("id", id) );

         dispatcher->bcast_block( block, id );
      });
   }
}

// called from application thread
void net_plugin_impl::on_irreversible_block( const block_state_ptr& block) {
   fc_dlog( get_logger(), "on_irreversible_block, blk num = {num}, id = {id}", ("num", block->block_num)("id", block->id) );
   update_chain_info();
}

// called from application thread
void net_plugin_impl::transaction_ack(const std::pair<fc::exception_ptr, transaction_metadata_ptr>& results) {
   dispatcher->strand.post( [this, results]() {
      const auto& id = results.second->id();
      if (results.first) {
         fc_dlog( get_logger(), "signaled NACK, trx-id = {id} : {why}", ("id", id)( "why", results.first->to_detail_string() ) );

         uint32_t head_blk_num = 0;
         std::tie( std::ignore, head_blk_num, std::ignore, std::ignore, std::ignore, std::ignore ) = get_chain_info();
         dispatcher->rejected_transaction(results.second->packed_trx(), head_blk_num);
      } else {
         fc_dlog( get_logger(), "signaled ACK, trx-id = {id}", ("id", id) );
         dispatcher->bcast_transaction(results.second->packed_trx());
      }
   });
}

bool net_plugin_impl::authenticate_peer(const handshake_message& msg) const {
   if(allowed_connections == None)
      return false;

   if(allowed_connections == Any)
      return true;

   if(allowed_connections & (Producers | Specified)) {
      auto allowed_it = std::find(allowed_peers.begin(), allowed_peers.end(), msg.key);
      auto private_it = private_keys.find(msg.key);
      bool found_producer_key = false;
      if(producer_plug != nullptr)
         found_producer_key = producer_plug->is_producer_key(msg.key);
      if( allowed_it == allowed_peers.end() && private_it == private_keys.end() && !found_producer_key) {
         fc_elog( get_logger(), "Peer {peer} sent a handshake with an unauthorized key: {key}.",
                  ("peer", msg.p2p_address)("key", msg.key.to_string()) );
         return false;
      }
   }

   if(msg.sig != chain::signature_type() && msg.token != sha256()) {
      sha256 hash = fc::sha256::hash(msg.time);
      if(hash != msg.token) {
         fc_elog( get_logger(), "Peer {peer} sent a handshake with an invalid token.", ("peer", msg.p2p_address) );
         return false;
      }
      chain::public_key_type peer_key;
      try {
         peer_key = crypto::public_key(msg.sig, msg.token, true);
      }
      catch (const std::exception& /*e*/) {
         fc_elog( get_logger(), "Peer {peer} sent a handshake with an unrecoverable key.", ("peer", msg.p2p_address) );
         return false;
      }
      if((allowed_connections & (Producers | Specified)) && peer_key != msg.key) {
         fc_elog( get_logger(), "Peer {peer} sent a handshake with an unauthenticated key.", ("peer", msg.p2p_address) );
         return false;
      }
   }
   else if(allowed_connections & (Producers | Specified)) {
      fc_dlog( get_logger(), "Peer sent a handshake with blank signature and token, but this node accepts only authenticated connections." );
      return false;
   }
   return true;
}

chain::public_key_type net_plugin_impl::get_authentication_key() const {
   if(!private_keys.empty())
      return private_keys.begin()->first;
   /*producer_plugin* pp = app().find_plugin<producer_plugin>();
   if(pp != nullptr && pp->get_state() == abstract_plugin::started)
      return pp->first_producer_public_key();*/
   return chain::public_key_type();
}

chain::signature_type net_plugin_impl::sign_compact(const chain::public_key_type& signer, const fc::sha256& digest) const
{
   auto private_key_itr = private_keys.find(signer);
   if(private_key_itr != private_keys.end())
      return private_key_itr->second.sign(digest);
   if(producer_plug != nullptr && producer_plug->get_state() == abstract_plugin::started)
      return producer_plug->sign_compact(signer, digest);
   return chain::signature_type();
}

}} //eosio::p2p

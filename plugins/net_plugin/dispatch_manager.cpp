#include <eosio/net_plugin/dispatch_manager.hpp>
#include <eosio/net_plugin/net_plugin_impl.hpp>
#include <eosio/net_plugin/sync_manager.hpp>
#include <eosio/net_plugin/buffer_factory.hpp>
#include <eosio/net_plugin/utility.hpp>

using namespace eosio::chain;

namespace eosio { namespace p2p {

// thread safe
bool dispatch_manager::add_peer_block( const block_id_type& blkid, uint32_t connection_id) {
   std::lock_guard<std::mutex> g( blk_state_mtx );
   auto bptr = blk_state.get<by_id>().find( std::make_tuple( connection_id, std::ref( blkid )));
   bool added = (bptr == blk_state.end());
   if( added ) {
      blk_state.insert( {blkid, block_header::num_from_id( blkid ), connection_id} );
   }
   return added;
}

bool dispatch_manager::rm_peer_block( const block_id_type& blkid, uint32_t connection_id) {
   std::lock_guard<std::mutex> g( blk_state_mtx );
   auto bptr = blk_state.get<by_id>().find( std::make_tuple( connection_id, std::ref( blkid )));
   if( bptr == blk_state.end() ) return false;
   blk_state.get<by_id>().erase( bptr );
   return false;
}

bool dispatch_manager::peer_has_block( const block_id_type& blkid, uint32_t connection_id ) const {
   std::lock_guard<std::mutex> g(blk_state_mtx);
   const auto blk_itr = blk_state.get<by_id>().find( std::make_tuple( connection_id, std::ref( blkid )));
   return blk_itr != blk_state.end();
}

bool dispatch_manager::have_block( const block_id_type& blkid ) const {
   std::lock_guard<std::mutex> g(blk_state_mtx);
   const auto& index = blk_state.get<by_peer_block_id>();
   auto blk_itr = index.find( blkid );
   return blk_itr != index.end();
}

bool dispatch_manager::add_peer_txn( const node_transaction_state& nts ) {
   std::lock_guard<std::mutex> g( local_txns_mtx );
   auto tptr = local_txns.get<by_id>().find( std::make_tuple( std::ref( nts.id ), nts.connection_id ) );
   bool added = (tptr == local_txns.end());
   if( added ) {
      local_txns.insert( nts );
   }
   return added;
}

// only adds if tid already exists, returns have_txn( tid )
bool dispatch_manager::add_peer_txn( const transaction_id_type& tid, uint32_t connection_id ) {
   std::lock_guard<std::mutex> g( local_txns_mtx );
   auto tptr = local_txns.get<by_id>().find( tid );
   if( tptr == local_txns.end() ) return false;
   const auto expiration = tptr->expires;

   tptr = local_txns.get<by_id>().find( std::make_tuple( std::ref( tid ), connection_id ) );
   if( tptr == local_txns.end() ) {
      local_txns.insert( node_transaction_state{tid, expiration, 0, connection_id} );
   }
   return true;
}


// thread safe
void dispatch_manager::update_txns_block_num( const signed_block_ptr& sb ) {
   update_block_num ubn( sb->block_num() );
   std::lock_guard<std::mutex> g( local_txns_mtx );
   for( const auto& recpt : sb->transactions ) {
      const transaction_id_type& id = (recpt.trx.index() == 0) ? std::get<transaction_id_type>(recpt.trx)
                                                               : std::get<packed_transaction>(recpt.trx).id();
      auto range = local_txns.get<by_id>().equal_range( id );
      for( auto itr = range.first; itr != range.second; ++itr ) {
         local_txns.modify( itr, ubn );
      }
   }
}

// thread safe
void dispatch_manager::update_txns_block_num( const transaction_id_type& id, uint32_t blk_num ) {
   update_block_num ubn( blk_num );
   std::lock_guard<std::mutex> g( local_txns_mtx );
   auto range = local_txns.get<by_id>().equal_range( id );
   for( auto itr = range.first; itr != range.second; ++itr ) {
      local_txns.modify( itr, ubn );
   }
}

bool dispatch_manager::peer_has_txn( const transaction_id_type& tid, uint32_t connection_id ) const {
   std::lock_guard<std::mutex> g( local_txns_mtx );
   const auto tptr = local_txns.get<by_id>().find( std::make_tuple( std::ref( tid ), connection_id ) );
   return tptr != local_txns.end();
}

bool dispatch_manager::have_txn( const transaction_id_type& tid ) const {
   std::lock_guard<std::mutex> g( local_txns_mtx );
   const auto tptr = local_txns.get<by_id>().find( tid );
   return tptr != local_txns.end();
}

void dispatch_manager::expire_txns( uint32_t lib_num ) {
   size_t start_size = 0, end_size = 0;

   std::unique_lock<std::mutex> g( local_txns_mtx );
   start_size = local_txns.size();
   auto& old = local_txns.get<by_expiry>();
   auto ex_lo = old.lower_bound( fc::time_point_sec( 0 ) );
   auto ex_up = old.upper_bound( time_point::now() );
   old.erase( ex_lo, ex_up );
   g.unlock(); // allow other threads opportunity to use local_txns

   g.lock();
   auto& stale = local_txns.get<by_block_num>();
   stale.erase( stale.lower_bound( 1 ), stale.upper_bound( lib_num ) );
   end_size = local_txns.size();
   g.unlock();

   fc_dlog( net_plugin_impl::get_logger(), "expire_local_txns size {s} removed {r}", ("s", start_size)( "r", start_size - end_size ) );
}

void dispatch_manager::expire_blocks( uint32_t lib_num ) {
   std::lock_guard<std::mutex> g(blk_state_mtx);
   auto& stale_blk = blk_state.get<by_block_num>();
   stale_blk.erase( stale_blk.lower_bound(1), stale_blk.upper_bound(lib_num) );
}

// thread safe
void dispatch_manager::bcast_block(const signed_block_ptr& b, const block_id_type& id) {
   fc_dlog( net_plugin_impl::get_logger(), "bcast block {b}", ("b", b->block_num()) );

   if( net_plugin_impl::get()->syncing_with_peer() ) return;

   block_buffer_factory buff_factory;
   const auto bnum = b->block_num();
   net_plugin_impl::get()->for_each_block_connection( [this, &id, &bnum, &b, &buff_factory]( auto& cp ) {
      fc_dlog( net_plugin_impl::get_logger(), "socket_is_open {s}, connecting {c}, syncing {ss}, connection {cid}",
               ("s", cp->socket_is_open())("c", cp->connecting.load())("ss", cp->syncing.load())("cid", cp->connection_id) );
      if( !cp->current() ) return true;
      send_buffer_type sb = buff_factory.get_send_buffer( b, cp->protocol_version.load() );
      if( !sb ) {
         cp->strand.post( [this, cp, sb{std::move(sb)}, bnum, id]() {
            peer_wlog( cp, "Sending go away for incomplete block #{n} {id}...",
                        ("n", bnum)("id", id.str().substr(8,16)) );
            // unable to convert to v0 signed block and client doesn't support proto_pruned_types, so tell it to go away
            cp->no_retry = go_away_reason::fatal_other;
            cp->enqueue( go_away_message( fatal_other ) );
         } );
         return true;
      }

      cp->strand.post( [this, cp, id, bnum, sb{std::move(sb)}]() {
         cp->latest_blk_time = cp->get_time();
         std::unique_lock<std::mutex> g_conn( cp->conn_mtx );
         bool has_block = cp->last_handshake_recv.last_irreversible_block_num >= bnum;
         g_conn.unlock();
         if( !has_block ) {
            if( !add_peer_block( id, cp->connection_id ) ) {
               peer_dlog( cp, "not bcast block {b}", ("b", bnum) );
               return;
            }
            peer_dlog( cp, "bcast block {b}", ("b", bnum) );
            cp->enqueue_buffer( sb, no_reason );
         }
      });
      return true;
   } );
}

// called from c's connection strand
void dispatch_manager::recv_block(const connection_ptr& c, const block_id_type& id, uint32_t) {
   std::unique_lock<std::mutex> g( c->conn_mtx );
   if (c &&
         c->last_req &&
         c->last_req->req_blocks.mode != none &&
         !c->last_req->req_blocks.ids.empty() &&
         c->last_req->req_blocks.ids.back() == id) {
      peer_dlog( c, "resetting last_req" );
      c->last_req.reset();
   }
   g.unlock();

   peer_dlog(c, "canceling wait");
   c->cancel_wait();
}

void dispatch_manager::rejected_block(const block_id_type& id) {
   fc_dlog( net_plugin_impl::get_logger(), "rejected block {id}", ("id", id) );
}

void dispatch_manager::bcast_transaction(const packed_transaction_ptr& trx) {
   const auto& id = trx->id();
   time_point_sec trx_expiration = trx->expiration();
   node_transaction_state nts = {id, trx_expiration, 0, 0};

   trx_buffer_factory buff_factory;
   net_plugin_impl::get()->for_each_connection( [this, &trx, &nts, &buff_factory]( auto& cp ) {
      if( cp->is_blocks_only_connection() || !cp->current() ) {
         return true;
      }
      nts.connection_id = cp->connection_id;
      if( !add_peer_txn(nts) ) {
         return true;
      }

      send_buffer_type sb = buff_factory.get_send_buffer( trx, cp->protocol_version.load() );
      if( !sb ) return true;
      fc_dlog( net_plugin_impl::get_logger(), "sending trx: {id}, to connection {cid}", ("id", trx->id())("cid", cp->connection_id) );
      cp->strand.post( [cp, sb{std::move(sb)}]() {
         cp->enqueue_buffer( sb, no_reason );
      } );
      return true;
   } );
}

void dispatch_manager::rejected_transaction(const packed_transaction_ptr& trx, uint32_t head_blk_num) {
   fc_dlog( net_plugin_impl::get_logger(), "not sending rejected transaction {tid}", ("tid", trx->id()) );
   // keep rejected transaction around for awhile so we don't broadcast it
   // update its block number so it will be purged when current block number is lib
   if( trx->expiration() > fc::time_point::now() ) { // no need to update blk_num if already expired
      update_txns_block_num( trx->id(), head_blk_num );
   }
}

// called from c's connection strand
void dispatch_manager::recv_notice(const connection_ptr& c, const notice_message& msg, bool) {
   if (msg.known_trx.mode == normal) {
   } else if (msg.known_trx.mode != none) {
      peer_elog( c, "passed a notice_message with something other than a normal on none known_trx" );
      return;
   }
   if (msg.known_blocks.mode == normal) {
      // known_blocks.ids is never > 1
      if( !msg.known_blocks.ids.empty() ) {
         if( msg.known_blocks.pending == 1 ) { // block id notify of 2.0.0, ignore
            return;
         }
      }
   } else if (msg.known_blocks.mode != none) {
      peer_elog( c, "passed a notice_message with something other than a normal on none known_blocks" );
      return;
   }
}

// called from c's connection strand
void dispatch_manager::retry_fetch(const connection_ptr& c) {
   peer_dlog( c, "retry fetch" );
   request_message last_req;
   block_id_type bid;
   {
      std::lock_guard<std::mutex> g_c_conn( c->conn_mtx );
      if( !c->last_req ) {
         return;
      }
      peer_wlog( c, "failed to fetch from peer" );
      if( c->last_req->req_blocks.mode == normal && !c->last_req->req_blocks.ids.empty() ) {
         bid = c->last_req->req_blocks.ids.back();
      } else {
         peer_wlog( c, "no retry, block mpde = {b} trx mode = {t}",
                     ("b", modes_str( c->last_req->req_blocks.mode ))( "t", modes_str( c->last_req->req_trx.mode ) ) );
         return;
      }
      last_req = *c->last_req;
   }
   net_plugin_impl::get()->for_each_block_connection( [this, &c, &last_req, &bid]( auto& conn ) {
      if( conn == c )
         return true;

      {
         std::lock_guard<std::mutex> guard( conn->conn_mtx );
         if( conn->last_req ) {
            return true;
         }
      }

      bool sendit = peer_has_block( bid, conn->connection_id );
      if( sendit ) {
         conn->strand.post( [conn, last_req{std::move(last_req)}]() {
            conn->enqueue( last_req );
            conn->fetch_wait();
            std::lock_guard<std::mutex> g_conn_conn( conn->conn_mtx );
            conn->last_req = last_req;
         } );
         return false;
      }
      return true;
   } );

   // at this point no other peer has it, re-request or do nothing?
   peer_wlog( c, "no peer has last_req" );
   if( c->connected() ) {
      c->enqueue( last_req );
      c->fetch_wait();
   }
}

fc::logger& dispatch_manager::get_logger() {
   return net_plugin_impl::get_logger();
}
const std::string& dispatch_manager::peer_log_format() {
   return net_plugin_impl::get()->peer_log_format;
}

}} //eosio::p2p

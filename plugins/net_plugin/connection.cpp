#include <eosio/net_plugin/connection.hpp>
#include <eosio/net_plugin/net_plugin_impl.hpp>
#include <eosio/net_plugin/dispatch_manager.hpp>
#include <eosio/net_plugin/buffer_factory.hpp>
#include <eosio/net_plugin/utility.hpp>

#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/producer_plugin/producer_plugin.hpp>

#include <fc/log/logger.hpp>

#include <chrono>
#include <thread>

using boost::asio::ip::tcp;
using namespace eosio::chain;
namespace sc = std::chrono;

namespace eosio { namespace p2p {

const string connection::unknown = "<unknown>";

fc::logger& msg_handler::get_logger() {
   return net_plugin_impl::get_logger();
}
const std::string& msg_handler::peer_log_format() {
   return net_plugin_impl::get()->peer_log_format;
}

template<typename T>
void msg_handler::operator()( const T& ) const {
   EOS_ASSERT( false, plugin_config_exception, "Not implemented, call handle_message directly instead" );
}

void msg_handler::operator()( const handshake_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle handshake_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const chain_size_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle chain_size_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const go_away_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle go_away_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const time_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle time_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const notice_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle notice_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const request_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle request_message" );
   c->handle_message( msg );
}

void msg_handler::operator()( const sync_request_message& msg ) const {
   // continue call to handle_message on connection strand
   peer_dlog( c, "handle sync_request_message" );
   c->handle_message( msg );
}

connection::connection( const string& endpoint )
   : peer_addr( endpoint ),
      strand( net_plugin_impl::get()->thread_pool->get_executor() ),
      socket( new tcp_socket( net_plugin_impl::get()->thread_pool->get_executor() ) ),
      log_p2p_address( endpoint ),
      connection_id( ++net_plugin_impl::get()->current_connection_id ),
      response_expected_timer( net_plugin_impl::get()->thread_pool->get_executor() ),
      last_handshake_recv(),
      last_handshake_sent(),
      handshake_backoff_floor(std::chrono::milliseconds(net_plugin_impl::get_handshake_backoff_floor_ms())),
      handshake_backoff_cap(std::chrono::milliseconds(net_plugin_impl::get_handshake_backoff_cap_ms()))
{
   fc_ilog( net_plugin_impl::get_logger(), "created connection {c} to {n}", ("c", connection_id)("n", endpoint) );
   fc_ilog(net_plugin_impl::get_logger(), "handshake backoff control: floor={f}ms, cap={c}ms",
           ("f", net_plugin_impl::get_handshake_backoff_floor_ms())
           ("c", net_plugin_impl::get_handshake_backoff_cap_ms()));
}

connection::connection()
   : peer_addr(),
      strand( net_plugin_impl::get()->thread_pool->get_executor() ),
      socket( new tcp_socket( net_plugin_impl::get()->thread_pool->get_executor() ) ),
      connection_id( ++net_plugin_impl::get()->current_connection_id ),
      response_expected_timer( net_plugin_impl::get()->thread_pool->get_executor() ),
      last_handshake_recv(),
      last_handshake_sent(),
      handshake_backoff_floor(std::chrono::milliseconds(net_plugin_impl::get_handshake_backoff_floor_ms())),
      handshake_backoff_cap(std::chrono::milliseconds(net_plugin_impl::get_handshake_backoff_cap_ms()))
{
   fc_dlog( net_plugin_impl::get_logger(), "new connection object created" );
   fc_ilog(net_plugin_impl::get_logger(), "handshake backoff control: floor={f}ms, cap={c}ms",
           ("f", net_plugin_impl::get_handshake_backoff_floor_ms())
           ("c", net_plugin_impl::get_handshake_backoff_cap_ms()));
}

// called from connection strand
void connection::update_endpoints() {
   boost::system::error_code ec;
   boost::system::error_code ec2;
   auto rep = socket->remote_endpoint(ec);
   auto lep = socket->local_endpoint(ec2);
   log_remote_endpoint_ip = ec ? unknown : rep.address().to_string();
   log_remote_endpoint_port = ec ? unknown : std::to_string(rep.port());
   local_endpoint_ip = ec2 ? unknown : lep.address().to_string();
   local_endpoint_port = ec2 ? unknown : std::to_string(lep.port());
   std::lock_guard<std::mutex> g_conn( conn_mtx );
   remote_endpoint_ip = log_remote_endpoint_ip;
}

// called from connection strand
void connection::update_logger_connection_info() {
  ci.log_p2p_address = log_p2p_address;
  ci.connection_id = connection_id;
  ci.conn_node_id = conn_node_id;
  ci.short_conn_node_id = short_conn_node_id;
  ci.log_remote_endpoint_ip = log_remote_endpoint_ip;
  ci.log_remote_endpoint_port = log_remote_endpoint_port;
  ci.local_endpoint_ip = local_endpoint_ip;
  ci.local_endpoint_port = local_endpoint_port;
}

// called from connection strand
void connection::set_connection_type( const string& peer_add ) {
   // host:port:[<trx>|<blk>]
   string::size_type colon = peer_add.find(':');
   string::size_type colon2 = peer_add.find(':', colon + 1);
   string::size_type end = colon2 == string::npos
         ? string::npos : peer_add.find_first_of( " :+=.,<>!$%^&(*)|-#@\t", colon2 + 1 ); // future proof by including most symbols without using regex
   string host = peer_add.substr( 0, colon );
   string port = peer_add.substr( colon + 1, colon2 == string::npos ? string::npos : colon2 - (colon + 1));
   string type = colon2 == string::npos ? "" : end == string::npos ?
         peer_add.substr( colon2 + 1 ) : peer_add.substr( colon2 + 1, end - (colon2 + 1) );

   if( type.empty() ) {
      fc_dlog( net_plugin_impl::get_logger(), "Setting connection {c} type for: {peer} to both transactions and blocks", ("c", connection_id)("peer", peer_add) );
      connection_type = both;
   } else if( type == "trx" ) {
      fc_dlog( net_plugin_impl::get_logger(), "Setting connection {c} type for: {peer} to transactions only", ("c", connection_id)("peer", peer_add) );
      connection_type = transactions_only;
   } else if( type == "blk" ) {
      fc_dlog( net_plugin_impl::get_logger(), "Setting connection {c} type for: {peer} to blocks only", ("c", connection_id)("peer", peer_add) );
      connection_type = blocks_only;
   } else {
      fc_wlog( net_plugin_impl::get_logger(), "Unknown connection {c} type: {t}, for {peer}", ("c", connection_id)("t", type)("peer", peer_add) );
   }
}

connection_status connection::get_status()const {
   connection_status stat;
   stat.peer = peer_addr;
   stat.connecting = connecting;
   stat.syncing = syncing;
   std::lock_guard<std::mutex> g( conn_mtx );
   stat.last_handshake = last_handshake_recv;
   return stat;
}

// called from connection stand
bool connection::start_session() {
   verify_strand_in_this_thread( strand, __func__, __LINE__ );
   update_endpoints();
   update_logger_connection_info();
   boost::asio::ip::tcp::no_delay nodelay( true );
   boost::system::error_code ec;
   socket->set_option( nodelay, ec );
   if( ec ) {
      peer_elog( this, "connection failed (set_option): {e1}", ( "e1", ec.message() ) );
      close();
      return false;
   } else {
      peer_dlog( this, "connected" );
      socket_open = true;
      start_read_message();
      return true;
   }
}

bool connection::connected() const {
   return socket_is_open() && !connecting;
}

bool connection::current() const {
   return (connected() && !syncing);
}

void connection::flush_queues() {
   buffer_queue.clear_write_queue();
}

void connection::close( bool reconnect, bool shutdown ) {
   strand.post( [self = shared_from_this(), reconnect, shutdown]() {
      connection::_close( self, reconnect, shutdown );
   });
}

// called from connection strand
void connection::_close( const ptr& self, bool reconnect, bool shutdown ) {

   self->socket_open = false;
   boost::system::error_code ec;
   if( self->socket->is_open() ) {
      self->socket->shutdown( tcp_socket::shutdown_both, ec );
      self->socket->close( ec );
   }
   self->socket.reset( new tcp_socket( net_plugin_impl::get()->thread_pool->get_executor() ) );
   self->flush_queues();
   self->connecting = false;
   self->syncing = false;
   self->block_status_monitor_.reset();
   ++self->consecutive_immediate_connection_close;
   bool has_last_req = false;
   {
      std::lock_guard<std::mutex> g_conn( self->conn_mtx );
      has_last_req = self->last_req.has_value();
      self->last_handshake_recv = handshake_message();
      self->last_handshake_sent = handshake_message();
      self->last_close = fc::time_point::now();
      self->conn_node_id = fc::sha256();
   }
   if( has_last_req && !shutdown ) {
      net_plugin_impl::get()->dispatcher->retry_fetch( self->shared_from_this() );
   }
   self->peer_requested.reset();
   self->sent_handshake_count = 0;
   if( !shutdown) {
      try {
         auto lock = net_plugin_impl::get()->sm_impl().locked_sml_mutex();
         net_plugin_impl::get()->sync_sm->process_event( net_plugin_impl::sync_man_sm_impl::close_connection{self} );
      } FC_LOG_AND_RETHROW();
   }
   peer_ilog( self, "closing" );
   self->cancel_wait();

   if( reconnect && !shutdown ) {
      net_plugin_impl::get()->start_conn_timer( std::chrono::milliseconds( 100 ), wptr() );
   }
}

// called from connection strand
void connection::blk_send_branch( const block_id_type& msg_head_id ) {
   uint32_t head_num = 0;
   std::tie( std::ignore, std::ignore, head_num,
               std::ignore, std::ignore, std::ignore ) = net_plugin_impl::get()->get_chain_info();

   peer_dlog(this, "head_num = {h}",("h",head_num));
   if(head_num == 0) {
      notice_message note;
      note.known_blocks.mode = normal;
      note.known_blocks.pending = 0;
      enqueue(note);
      return;
   }
   std::unique_lock<std::mutex> g_conn( conn_mtx );
   if( last_handshake_recv.generation >= 1 ) {
      peer_dlog( this, "maybe truncating branch at = {h}:{id}",
                  ("h", block_header::num_from_id(last_handshake_recv.head_id))("id", last_handshake_recv.head_id) );
   }

   block_id_type lib_id = last_handshake_recv.last_irreversible_block_id;
   g_conn.unlock();
   const auto lib_num = block_header::num_from_id(lib_id);
   if( lib_num == 0 ) return; // if last_irreversible_block_id is null (we have not received handshake or reset)

   app().post( priority::medium, [chain_plug = net_plugin_impl::get()->chain_plug, c = shared_from_this(),
         lib_num, head_num, msg_head_id]() {
      auto msg_head_num = block_header::num_from_id(msg_head_id);
      bool on_fork = msg_head_num == 0;
      bool unknown_block = false;
      if( !on_fork ) {
         try {
            const controller& cc = chain_plug->chain();
            block_id_type my_id = cc.get_block_id_for_num( msg_head_num );
            on_fork = my_id != msg_head_id;
         } catch( const unknown_block_exception& ) {
            unknown_block = true;
         } catch( ... ) {
            on_fork = true;
         }
      }
      if( unknown_block ) {
         c->strand.post( [msg_head_num, c]() {
            peer_ilog( c, "Peer asked for unknown block {mn}, sending: benign_other go away", ("mn", msg_head_num) );
            c->no_retry = benign_other;
            c->enqueue( go_away_message( benign_other ) );
         } );
      } else {
         if( on_fork ) msg_head_num = 0;
         // if peer on fork, start at their last lib, otherwise we can start at msg_head+1
         c->strand.post( [c, msg_head_num, lib_num, head_num]() {
            c->blk_send_branch_impl( msg_head_num, lib_num, head_num );
         } );
      }
   } );
}

// called from connection strand
void connection::blk_send_branch_impl( uint32_t msg_head_num, uint32_t lib_num, uint32_t head_num ) {
   if( !peer_requested ) {
      auto last = msg_head_num != 0 ? msg_head_num : lib_num;
      peer_requested = peer_sync_state( last+1, head_num, last );
   } else {
      auto last = msg_head_num != 0 ? msg_head_num : std::min( peer_requested->last, lib_num );
      uint32_t end   = std::max( peer_requested->end_block, head_num );
      peer_requested = peer_sync_state( last+1, end, last );
   }
   if( peer_requested->start_block <= peer_requested->end_block ) {
      peer_ilog( this, "enqueue {s} - {e}", ("s", peer_requested->start_block)("e", peer_requested->end_block) );
      enqueue_sync_block();
   } else {
      peer_ilog( this, "nothing to enqueue" );
      peer_requested.reset();
   }
}

void connection::blk_send( const block_id_type& blkid ) {
   wptr weak = shared_from_this();
   app().post( priority::medium, [blkid, weak{std::move(weak)}]() {
      ptr c = weak.lock();
      if( !c ) return;
      try {
         controller& cc = net_plugin_impl::get()->chain_plug->chain();
         signed_block_ptr b = cc.fetch_block_by_id( blkid );
         if( b ) {
            fc_dlog( net_plugin_impl::get_logger(), "fetch_block_by_id num {n}, connection {cid}",
                     ("n", b->block_num())("cid", c->connection_id) );
            net_plugin_impl::get()->dispatcher->add_peer_block( blkid, c->connection_id );
            c->strand.post( [c, b{std::move(b)}]() {
               c->enqueue_block( b );
            } );
         } else {
            fc_ilog( net_plugin_impl::get_logger(), "fetch block by id returned null, id {id}, connection {cid}",
                     ("id", blkid)("cid", c->connection_id) );
         }
      } catch( const assert_exception& ex ) {
         fc_elog( net_plugin_impl::get_logger(), "caught assert on fetch_block_by_id, {ex}, id {id}, connection {cid}",
                  ("ex", ex.to_string())("id", blkid)("cid", c->connection_id) );
      } catch( ... ) {
         fc_elog( net_plugin_impl::get_logger(), "caught other exception fetching block id {id}, connection {cid}",
                  ("id", blkid)("cid", c->connection_id) );
      }
   });
}

void connection::stop_send() {
   syncing = false;
}

void connection::send_handshake() {
   strand.post( [c = shared_from_this()]() {
      if (net_plugin_impl::get()->in_shutdown) {
         peer_dlog(c, "net plugin is in shutdown, will not enqueue the handshake, return");
         return;
      }
      std::unique_lock<std::mutex> g_conn( c->conn_mtx );
      // backoff should take place before populate_handshake(), during which the clock time is written in the message
      c->backoff_handshake();
      if( c->populate_handshake( c->last_handshake_sent ) ) {
         static_assert( std::is_same_v<decltype( c->sent_handshake_count ), int16_t>, "INT16_MAX based on int16_t" );
         if( c->sent_handshake_count == INT16_MAX ) c->sent_handshake_count = 1; // do not wrap
         c->last_handshake_sent.generation = ++c->sent_handshake_count;
         auto last_handshake_sent = c->last_handshake_sent;
         g_conn.unlock();
         peer_dlog( c, "Sending handshake generation {g}, lib {lib}, head {head}, id {id}",
                     ("g", last_handshake_sent.generation)
                     ("lib", last_handshake_sent.last_irreversible_block_num)
                     ("head", last_handshake_sent.head_num)("id", last_handshake_sent.head_id.str().substr(8,16)) );
         c->enqueue( last_handshake_sent );
      }
   });
}

// called from connection strand
void connection::check_heartbeat( tstamp current_time ) {
   if( protocol_version >= heartbeat_interval && latest_msg_time > 0 ) {
      if( current_time > latest_msg_time + hb_timeout ) {
         no_retry = benign_other;
         if( !peer_address().empty() ) {
            peer_wlog(this, "heartbeat timed out for peer address");
            close(true);
         } else {
            peer_wlog( this, "heartbeat timed out" );
            close(false);
         }
         return;
      } else {
         const tstamp timeout = std::max(hb_timeout/2, 2*std::chrono::milliseconds(config::block_interval_ms).count());
         if ( current_time > latest_blk_time + timeout ) {
            send_handshake();
            return;
         }
      }
   }

   send_time();
}

// called from connection strand
void connection::send_time() {
   time_message xpkt;
   xpkt.org = rec;
   xpkt.rec = dst;
   xpkt.xmt = get_time();
   org = xpkt.xmt;
   enqueue(xpkt);
}

// called from connection strand
void connection::send_time(const time_message& msg) {
   time_message xpkt;
   xpkt.org = msg.xmt;
   xpkt.rec = msg.dst;
   xpkt.xmt = get_time();
   enqueue(xpkt);
}

// called from connection strand
void connection::queue_write(const std::shared_ptr<vector<char>>& buff,
                              std::function<void(boost::system::error_code, std::size_t)> callback,
                              bool to_sync_queue) {
   if( !buffer_queue.add_write_queue( buff, callback, to_sync_queue )) {
      peer_wlog( this, "write_queue full {s} bytes, giving up on connection", ("s", buffer_queue.write_queue_size()) );
      close();
      return;
   }
   do_queue_write();
}

// called from connection strand
void connection::do_queue_write() {
   if( !buffer_queue.ready_to_send() )
      return;
   if (net_plugin_impl::get()->in_shutdown) {
      peer_dlog(this, "net plugin is in shutdown, will not do queue write, return");
      return;
   }
   ptr c(shared_from_this());

   std::vector<boost::asio::const_buffer> bufs;
   buffer_queue.fill_out_buffer( bufs );

   strand.post( [c{std::move(c)}, bufs{std::move(bufs)}]() {
      boost::asio::async_write( *c->socket, bufs,
         boost::asio::bind_executor( c->strand, [c, socket=c->socket]( boost::system::error_code ec, std::size_t w ) {
         try {
            c->buffer_queue.clear_out_queue();
            // May have closed connection and cleared buffer_queue
            if( !c->socket_is_open() || socket != c->socket ) {
               peer_dlog( c, "async write socket {r} before callback", ("r", c->socket_is_open() ? "changed" : "closed") );
               c->close();
               return;
            }

            if( ec ) {
               if( ec.value() != boost::asio::error::eof ) {
                  peer_elog( c, "Error sending to peer: {i}", ( "i", ec.message() ) );
               } else {
                  peer_wlog( c, "connection closure detected on write" );
               }
               c->close();
               return;
            }

            c->buffer_queue.out_callback( ec, w );

            c->enqueue_sync_block();
            c->do_queue_write();
         } catch ( const std::bad_alloc& ) {
            throw;
         } catch ( const boost::interprocess::bad_alloc& ) {
            throw;
         } catch( const fc::exception& ex ) {
            peer_elog( c, "fc::exception in do_queue_write: {s}", ("s", ex.to_string()) );
         } catch( const std::exception& ex ) {
            peer_elog( c, "std::exception in do_queue_write: {s}", ("s", ex.what()) );
         } catch( ... ) {
            peer_elog( c, "Unknown exception in do_queue_write" );
         }
      }));
   });
}

// called from connection strand
void connection::cancel_sync(go_away_reason reason) {
   peer_dlog( this, "cancel sync reason = {m}, write queue size {o} bytes",
               ("m", reason_str( reason ))("o", buffer_queue.write_queue_size()) );
   cancel_wait();
   flush_queues();
   switch (reason) {
   case validation :
   case fatal_other : {
      no_retry = reason;
      enqueue( go_away_message( reason ));
      break;
   }
   default:
      peer_ilog(this, "sending empty request but not calling sync wait");
      enqueue( sync_request_message{0,0} );
   }
}

// called from connection strand
bool connection::enqueue_sync_block() {
   if( !peer_requested ) {
      return false;
   } else {
      peer_dlog( this, "enqueue sync block {num}", ("num", peer_requested->last + 1) );
   }
   uint32_t num = ++peer_requested->last;
   if(num == peer_requested->end_block) {
      peer_requested.reset();
      peer_ilog( this, "completing enqueue_sync_block {num}", ("num", num) );
   }
   wptr weak = shared_from_this();
   app().post( priority::medium, [num, weak{std::move(weak)}]() {
      ptr c = weak.lock();
      if( !c ) return;
      controller& cc = net_plugin_impl::get()->chain_plug->chain();
      signed_block_ptr sb;
      try {
         sb = cc.fetch_block_by_number( num );
      } FC_LOG_AND_DROP();
      if( sb ) {
         c->strand.post( [c, sb{std::move(sb)}]() {
            c->enqueue_block( sb, true );
         });
      } else {
         c->strand.post( [c, num]() {
            peer_ilog( c, "enqueue sync, unable to fetch block {num}", ("num", num) );
            c->send_handshake();
         });
      }
   });

   return true;
}


// called from connection strand
void connection::enqueue( const net_message& m ) {
   verify_strand_in_this_thread( strand, __func__, __LINE__ );
   go_away_reason close_after_send = no_reason;
   if (std::holds_alternative<go_away_message>(m)) {
      close_after_send = std::get<go_away_message>(m).reason;
   }

   buffer_factory buff_factory;
   auto send_buffer = buff_factory.get_send_buffer( m );
   enqueue_buffer( send_buffer, close_after_send );
}

// called from connection strand
void connection::enqueue_block( const signed_block_ptr& b, bool to_sync_queue) {
   peer_dlog( this, "enqueue block {num}", ("num", b->block_num()) );
   verify_strand_in_this_thread( strand, __func__, __LINE__ );

   block_buffer_factory buff_factory;
   auto sb = buff_factory.get_send_buffer( b, protocol_version.load() );
   if( !sb ) {
      peer_wlog( this, "Sending go away for incomplete block #{n} {id}...",
                  ("n", b->block_num())("id", b->calculate_id().str().substr(8,16)) );
      // unable to convert to v0 signed block and client doesn't support proto_pruned_types, so tell it to go away
      no_retry = go_away_reason::fatal_other;
      enqueue( go_away_message( fatal_other ) );
      return;
   }
   latest_blk_time = get_time();
   enqueue_buffer( sb, no_reason, to_sync_queue);
}

// called from connection strand
void connection::enqueue_buffer( const std::shared_ptr<std::vector<char>>& send_buffer,
                                 go_away_reason close_after_send,
                                 bool to_sync_queue)
{
   ptr self = shared_from_this();
   queue_write(send_buffer,
         [conn{std::move(self)}, close_after_send](boost::system::error_code ec, std::size_t ) {
                     if (ec) return;
                     if (close_after_send != no_reason) {
                        fc_ilog( net_plugin_impl::get_logger(), "sent a go away message: {r}, closing connection {cid}",
                                 ("r", reason_str(close_after_send))("cid", conn->connection_id) );
                        conn->close();
                        return;
                     }
               },
               to_sync_queue);
}

// thread safe
void connection::cancel_wait() {
   std::lock_guard<std::mutex> g( response_expected_timer_mtx );
   response_expected_timer.cancel();
}

// thread safe
void connection::sync_wait() {
   ptr c(shared_from_this());
   std::lock_guard<std::mutex> g( response_expected_timer_mtx );
   response_expected_timer.expires_from_now( net_plugin_impl::get()->resp_expected_period );
   response_expected_timer.async_wait(
         boost::asio::bind_executor( c->strand, [c]( boost::system::error_code ec ) {
            c->sync_timeout( ec );
         } ) );
}

// thread safe
void connection::fetch_wait() {
   ptr c( shared_from_this() );
   std::lock_guard<std::mutex> g( response_expected_timer_mtx );
   response_expected_timer.expires_from_now( net_plugin_impl::get()->resp_expected_period );
   response_expected_timer.async_wait(
         boost::asio::bind_executor( c->strand, [c]( boost::system::error_code ec ) {
            c->fetch_timeout(ec);
         } ) );
}

// called from connection strand
void connection::sync_timeout( boost::system::error_code ec ) {
   if( !ec ) {
      {
         if (!net_plugin_impl::get()->sync_man().is_sync_source(*this))
            return;
      }
      cancel_sync(benign_other);
      {
         auto lock = net_plugin_impl::get()->sm_impl().locked_sml_mutex();
         try {
            net_plugin_impl::get()->sync_sm->process_event(
               net_plugin_impl::sync_man_sm_impl::reassign_fetch{shared_from_this()}
            );
         } FC_LOG_AND_RETHROW();
      }
   } else if( ec != boost::asio::error::operation_aborted ) { // don't log on operation_aborted, called on destroy
      peer_elog( this, "setting timer for sync request got error {ec}", ("ec", ec.message()) );
   }
}

// called from connection strand
void connection::fetch_timeout( boost::system::error_code ec ) {
   if( !ec ) {
      net_plugin_impl::get()->dispatcher->retry_fetch( shared_from_this() );
   } else if( ec != boost::asio::error::operation_aborted ) { // don't log on operation_aborted, called on destroy
      peer_elog( this, "setting timer for fetch request got error {ec}", ("ec", ec.message() ) );
   }
}

// called from connection strand
void connection::request_sync_blocks(uint32_t start, uint32_t end) {
   sync_request_message srm = {start,end};
   enqueue( net_message(srm) );
   sync_wait();
}

// called from any thread
bool connection::resolve_and_connect() {
   switch ( no_retry ) {
      case no_reason:
      case wrong_version:
      case benign_other:
         break;
      default:
         fc_dlog( net_plugin_impl::get_logger(), "Skipping connect due to go_away reason {r}",("r", reason_str( no_retry )));
         return false;
   }

   string::size_type colon = peer_address().find(':');
   if (colon == std::string::npos || colon == 0) {
      fc_elog( net_plugin_impl::get_logger(), "Invalid peer address. must be \"host:port[:<blk>|<trx>]\": {p}", ("p", peer_address()) );
      return false;
   }

   ptr c = shared_from_this();

   if( consecutive_immediate_connection_close > def_max_consecutive_immediate_connection_close || no_retry == benign_other ) {
      auto connector_period_us = std::chrono::duration_cast<std::chrono::microseconds>( net_plugin_impl::get()->connector_period );
      std::lock_guard<std::mutex> g( c->conn_mtx );
      if( last_close == fc::time_point() || last_close > fc::time_point::now() - fc::microseconds( connector_period_us.count() ) ) {
         return true; // true so doesn't remove from valid connections
      }
   }

   strand.post([c]() {
      string::size_type colon = c->peer_address().find(':');
      string::size_type colon2 = c->peer_address().find(':', colon + 1);
      string host = c->peer_address().substr( 0, colon );
      string port = c->peer_address().substr( colon + 1, colon2 == string::npos ? string::npos : colon2 - (colon + 1));
      c->set_connection_type( c->peer_address() );

      auto resolver = std::make_shared<tcp_resolver>( net_plugin_impl::get()->thread_pool->get_executor() );
      wptr weak_conn = c;
      // Note: need to add support for IPv6 too
      resolver->async_resolve( tcp::v4(), host, port, boost::asio::bind_executor( c->strand,
         [resolver, weak_conn, host, port]( const boost::system::error_code& err, tcp::resolver::results_type endpoints ) {
            auto c = weak_conn.lock();
            if( !c ) return;
            if( !err ) {
               c->connect( resolver, endpoints );
            } else {
               fc_elog( net_plugin_impl::get_logger(), "Unable to resolve {host}:{port} {error}",
                        ("host", host)("port", port)( "error", err.message() ) );
               c->connecting = false;
               ++c->consecutive_immediate_connection_close;
            }
      } ) );
   } );
   return true;
}

// called from connection strand
void connection::connect( const std::shared_ptr<tcp::resolver>& resolver, tcp::resolver::results_type endpoints ) {
   switch ( no_retry ) {
      case no_reason:
      case wrong_version:
      case benign_other:
         break;
      default:
         return;
   }
   connecting = true;
   pending_message_buffer.reset();
   buffer_queue.clear_out_queue();
   boost::asio::async_connect( *socket, endpoints,
      boost::asio::bind_executor( strand,
            [resolver, c = shared_from_this(), socket=socket]( const boost::system::error_code& err, const tcp::endpoint& endpoint ) {
         if( !err && socket->is_open() && socket == c->socket ) {
            if( c->start_session() ) {
               c->send_handshake();
            }
         } else {
            fc_elog( net_plugin_impl::get_logger(), "connection failed to {host}:{port} {error}",
                     ("host", endpoint.address().to_string())("port", endpoint.port())( "error", err.message()));
            c->close( false );
         }
   } ) );
}

// only called from strand thread
void connection::start_read_message() {
   try {
      std::size_t minimum_read =
            std::atomic_exchange<decltype(outstanding_read_bytes.load())>( &outstanding_read_bytes, 0 );
      minimum_read = minimum_read != 0 ? minimum_read : message_header_size;

      if (net_plugin_impl::get()->use_socket_read_watermark) {
         const size_t max_socket_read_watermark = 4096;
         std::size_t socket_read_watermark = std::min<std::size_t>(minimum_read, max_socket_read_watermark);
         boost::asio::socket_base::receive_low_watermark read_watermark_opt(socket_read_watermark);
         boost::system::error_code ec;
         socket->set_option( read_watermark_opt, ec );
         if( ec ) {
            peer_elog( this, "unable to set read watermark: {e1}", ("e1", ec.message()) );
         }
      }

      auto completion_handler = [minimum_read](boost::system::error_code ec, std::size_t bytes_transferred) -> std::size_t {
         if (ec || bytes_transferred >= minimum_read ) {
            return 0;
         } else {
            return minimum_read - bytes_transferred;
         }
      };

      uint32_t write_queue_size = buffer_queue.write_queue_size();
      if( write_queue_size > def_max_write_queue_size ) {
         peer_elog( this, "write queue full {s} bytes, giving up on connection, closing", ("s", write_queue_size) );
         close( false );
         return;
      }

      boost::asio::async_read( *socket,
         pending_message_buffer.get_buffer_sequence_for_boost_async_read(), completion_handler,
         boost::asio::bind_executor( strand,
            [conn = shared_from_this(), socket=socket]( boost::system::error_code ec, std::size_t bytes_transferred ) {
            // may have closed connection and cleared pending_message_buffer
            if( !conn->socket_is_open() || socket != conn->socket ) return;

            bool close_connection = false;
            try {
               if( !ec ) {
                  if (bytes_transferred > conn->pending_message_buffer.bytes_to_write()) {
                     peer_elog( conn, "async_read_some callback: bytes_transferred = {bt}, buffer.bytes_to_write = {btw}",
                                 ("bt",bytes_transferred)("btw",conn->pending_message_buffer.bytes_to_write()) );
                  }
                  EOS_ASSERT(bytes_transferred <= conn->pending_message_buffer.bytes_to_write(), plugin_exception, "");
                  conn->pending_message_buffer.advance_write_ptr(bytes_transferred);
                  while (conn->pending_message_buffer.bytes_to_read() > 0) {
                     uint32_t bytes_in_buffer = conn->pending_message_buffer.bytes_to_read();

                     if (bytes_in_buffer < message_header_size) {
                        conn->outstanding_read_bytes = message_header_size - bytes_in_buffer;
                        break;
                     } else {
                        uint32_t message_length;
                        auto index = conn->pending_message_buffer.read_index();
                        conn->pending_message_buffer.peek(&message_length, sizeof(message_length), index);
                        if(message_length > def_send_buffer_size*2 || message_length == 0) {
                           peer_elog( conn, "incoming message length unexpected ({i})", ("i", message_length) );
                           close_connection = true;
                           break;
                        }

                        auto total_message_bytes = message_length + message_header_size;

                        if (bytes_in_buffer >= total_message_bytes) {
                           conn->pending_message_buffer.advance_read_ptr(message_header_size);
                           conn->consecutive_immediate_connection_close = 0;
                           if (!conn->process_next_message(message_length)) {
                              return;
                           }
                        } else {
                           auto outstanding_message_bytes = total_message_bytes - bytes_in_buffer;
                           auto available_buffer_bytes = conn->pending_message_buffer.bytes_to_write();
                           if (outstanding_message_bytes > available_buffer_bytes) {
                              conn->pending_message_buffer.add_space( outstanding_message_bytes - available_buffer_bytes );
                           }

                           conn->outstanding_read_bytes = outstanding_message_bytes;
                           break;
                        }
                     }
                  }
                  if( !close_connection ) conn->start_read_message();
               } else {
                  if (ec.value() != boost::asio::error::eof) {
                     peer_elog( conn, "Error reading message: {m}", ( "m", ec.message() ) );
                  } else {
                     peer_ilog( conn, "Peer closed connection" );
                  }
                  close_connection = true;
               }
            }
            catch ( const std::bad_alloc& )
            {
               throw;
            }
            catch ( const boost::interprocess::bad_alloc& )
            {
               throw;
            }
            catch(const fc::exception &ex)
            {
               peer_elog( conn, "Exception in handling read data {s}", ("s",ex.to_string()) );
               close_connection = true;
            }
            catch(const std::exception &ex) {
               peer_elog( conn, "Exception in handling read data: {s}", ("s",ex.what()) );
               close_connection = true;
            }
            catch (...) {
               peer_elog( conn, "Undefined exception handling read data" );
               close_connection = true;
            }

            if( close_connection ) {
               peer_elog( conn, "Closing connection" );
               conn->close();
            }
      }));
   } catch (...) {
      peer_elog( this, "Undefined exception in start_read_message, closing connection" );
      close();
   }
}

// called from connection strand
bool connection::process_next_message( uint32_t message_length ) {
   try {
      latest_msg_time = get_time();

      // if next message is a block we already have, exit early
      auto peek_ds = pending_message_buffer.create_peek_datastream();
      unsigned_int which{};
      fc::raw::unpack( peek_ds, which );
      if( which == signed_block_which || which == signed_block_v0_which ) {
         latest_blk_time = get_time();
         return process_next_block_message( message_length );

      } else if( which == trx_message_v1_which || which == packed_transaction_v0_which ) {
         return process_next_trx_message( message_length );

      } else {
         auto ds = pending_message_buffer.create_datastream();
         net_message msg;
         fc::raw::unpack( ds, msg );
         msg_handler m( shared_from_this() );
         std::visit( m, msg );
      }

   } catch( const fc::exception& e ) {
      peer_elog( this, "Exception in handling message: {s}", ("s", e.to_detail_string()) );
      close();
      return false;
   }
   return true;
}

// called from connection strand
bool connection::process_next_block_message(uint32_t message_length) {
   auto peek_ds = pending_message_buffer.create_peek_datastream();
   unsigned_int which{};
   fc::raw::unpack( peek_ds, which ); // throw away
   block_header bh;
   fc::raw::unpack( peek_ds, bh );

   const block_id_type blk_id = bh.calculate_id();
   const uint32_t blk_num = bh.block_num();
   if( net_plugin_impl::get()->dispatcher->have_block( blk_id ) ) {
      peer_dlog( this, "canceling wait, already received block {num}, id {id}...",
                  ("num", blk_num)("id", blk_id.str().substr(8,16)) );
      if( app().is_quiting() ) {
         close( false, true );
      } else {
         sync_recv_block( blk_id, blk_num, false );
      }
      cancel_wait();

      pending_message_buffer.advance_read_ptr( message_length );
      return true;
   }
   peer_dlog( this, "received block {num}, id {id}..., latency: {latency}",
               ("num", bh.block_num())("id", blk_id.str().substr(8,16))
               ("latency", (fc::time_point::now() - bh.timestamp).count()/1000) );

   if( !net_plugin_impl::get()->syncing_with_peer() ) { // guard against peer thinking it needs to send us old blocks
      uint32_t lib = 0;
      std::tie( lib, std::ignore, std::ignore, std::ignore, std::ignore, std::ignore ) = net_plugin_impl::get()->get_chain_info();
      if( blk_num < lib ) {
         std::unique_lock<std::mutex> g( conn_mtx );
         const auto last_sent_lib = last_handshake_sent.last_irreversible_block_num;
         g.unlock();
         if( blk_num < last_sent_lib ) {
            peer_ilog( this, "received block {n} less than sent lib {lib}", ("n", blk_num)("lib", last_sent_lib) );
            close();
         } else {
            peer_ilog( this, "received block {n} less than lib {lib}", ("n", blk_num)("lib", lib) );
            net_plugin_impl::get()->sync_man().reset_last_requested_num();
            enqueue( sync_request_message{0, 0} );
            send_handshake();
            cancel_wait();
         }
         pending_message_buffer.advance_read_ptr( message_length );
         return true;
      }
   }

   auto ds = pending_message_buffer.create_datastream();
   fc::raw::unpack( ds, which );
   shared_ptr<signed_block> ptr;
   if( which == signed_block_which ) {
      ptr = std::make_shared<signed_block>();
      fc::raw::unpack( ds, *ptr );
   } else {
      signed_block_v0 sb_v0;
      fc::raw::unpack( ds, sb_v0 );
      ptr = std::make_shared<signed_block>( std::move( sb_v0 ), true );
   }

   auto is_webauthn_sig = []( const fc::crypto::signature& s ) {
      return static_cast<size_t>(s.which()) == fc::get_index<fc::crypto::signature::storage_type, fc::crypto::webauthn::signature>();
   };
   bool has_webauthn_sig = is_webauthn_sig( ptr->producer_signature );

   constexpr auto additional_sigs_eid = additional_block_signatures_extension::extension_id();
   auto exts = ptr->validate_and_extract_extensions();
   if( exts.count( additional_sigs_eid ) ) {
      const auto &additional_sigs = std::get<additional_block_signatures_extension>(exts.lower_bound( additional_sigs_eid )->second).signatures;
      has_webauthn_sig |= std::any_of( additional_sigs.begin(), additional_sigs.end(), is_webauthn_sig );
   }

   if( has_webauthn_sig ) {
      peer_dlog( this, "WebAuthn signed block received, closing connection" );
      close();
      return false;
   }

   handle_message( blk_id, std::move( ptr ) );
   return true;
}

// called from connection strand
bool connection::process_next_trx_message(uint32_t message_length) {
   if( !net_plugin_impl::get()->p2p_accept_transactions ) {
      peer_dlog( this, "p2p-accept-transaction=false - dropping txn" );
      pending_message_buffer.advance_read_ptr( message_length );
      return true;
   }

   const unsigned long trx_in_progress_sz = this->trx_in_progress_size.load();

   auto report_dropping_trx = [](const transaction_id_type& trx_id, const packed_transaction_ptr& packed_trx_ptr, unsigned long trx_in_progress_sz) {
      char reason[72];
      snprintf(reason, 72, "Dropping trx, too many trx in progress %lu bytes", trx_in_progress_sz);
      net_plugin_impl::get()->producer_plug->log_failed_transaction(trx_id, packed_trx_ptr, reason);
   };

   bool have_trx = false;
   shared_ptr<packed_transaction> ptr;
   auto ds = pending_message_buffer.create_datastream();
   const auto buff_size_start = pending_message_buffer.bytes_to_read();
   unsigned_int which{};
   fc::raw::unpack( ds, which );
   if( which == trx_message_v1_which ) {
      std::optional<transaction_id_type> trx_id;
      fc::raw::unpack( ds, trx_id );
      if( trx_id ) {
         if (trx_in_progress_sz > def_max_trx_in_progress_size) {
            report_dropping_trx(*trx_id, ptr, trx_in_progress_sz);
            return true;
         }
         have_trx = net_plugin_impl::get()->dispatcher->add_peer_txn( *trx_id, connection_id );
      }

      if( have_trx ) {
         const auto buff_size_current = pending_message_buffer.bytes_to_read();
         pending_message_buffer.advance_read_ptr( message_length - (buff_size_start - buff_size_current) );
      } else {
         std::shared_ptr<packed_transaction> trx;
         fc::raw::unpack( ds, trx );
         ptr = std::move( trx );

         if (ptr && trx_id && *trx_id != ptr->id()) {
            net_plugin_impl::get()->producer_plug->log_failed_transaction(*trx_id, ptr, "Provided trx_id does not match provided packed_transaction");
            EOS_ASSERT(false, transaction_id_type_exception,
                     "Provided trx_id does not match provided packed_transaction" );
         }

         if( !trx_id ) {
            if (trx_in_progress_sz > def_max_trx_in_progress_size) {
               report_dropping_trx(ptr->id(), ptr, trx_in_progress_sz);
               return true;
            }
            have_trx = net_plugin_impl::get()->dispatcher->have_txn( ptr->id() );
         }
         node_transaction_state nts = {ptr->id(), ptr->expiration(), 0, connection_id};
         net_plugin_impl::get()->dispatcher->add_peer_txn( nts );
      }

   } else {
      packed_transaction_v0 pt_v0;
      fc::raw::unpack( ds, pt_v0 );
      if( trx_in_progress_sz > def_max_trx_in_progress_size) {
         report_dropping_trx(pt_v0.id(), ptr, trx_in_progress_sz);
         return true;
      }
      have_trx = net_plugin_impl::get()->dispatcher->have_txn( pt_v0.id() );
      node_transaction_state nts = {pt_v0.id(), pt_v0.expiration(), 0, connection_id};
      net_plugin_impl::get()->dispatcher->add_peer_txn( nts );
      if ( !have_trx ) {
         ptr = std::make_shared<packed_transaction>( pt_v0, true );
      }
   }

   if( have_trx ) {
      peer_dlog( this, "got a duplicate transaction - dropping" );
      return true;
   }

   handle_message( std::move( ptr ) );
   return true;
}

bool connection::is_valid( const handshake_message& msg ) const {
   // Do some basic validation of an incoming handshake_message, so things
   // that really aren't handshake messages can be quickly discarded without
   // affecting state.
   bool valid = true;
   if (msg.last_irreversible_block_num > msg.head_num) {
      peer_wlog( this, "Handshake message validation: last irreversible block ({i}) is greater than head block ({h})",
               ("i", msg.last_irreversible_block_num)("h", msg.head_num) );
      valid = false;
   }
   if (msg.p2p_address.empty()) {
      peer_wlog( this, "Handshake message validation: p2p_address is null string" );
      valid = false;
   } else if( msg.p2p_address.length() > max_handshake_str_length ) {
      // see max_handshake_str_length comment in protocol.hpp
      peer_wlog( this, "Handshake message validation: p2p_address to large: {p}",
                  ("p", msg.p2p_address.substr(0, max_handshake_str_length) + "...") );
      valid = false;
   }
   if (msg.os.empty()) {
      peer_wlog( this, "Handshake message validation: os field is null string" );
      valid = false;
   } else if( msg.os.length() > max_handshake_str_length ) {
      peer_wlog( this, "Handshake message validation: os field to large: {p}",
                  ("p", msg.os.substr(0, max_handshake_str_length) + "...") );
      valid = false;
   }
   if( msg.agent.length() > max_handshake_str_length ) {
      peer_wlog( this, "Handshake message validation: agent field to large: {p}",
               ("p", msg.agent.substr(0, max_handshake_str_length) + "...") );
      valid = false;
   }
   if ((msg.sig != chain::signature_type() || msg.token != sha256()) && (msg.token != fc::sha256::hash(msg.time))) {
      peer_wlog( this, "Handshake message validation: token field invalid" );
      valid = false;
   }
   return valid;
}

void connection::handle_message( const chain_size_message& ) {
   peer_dlog(this, "received chain_size_message");
}

void connection::handle_message( const handshake_message& msg ) {
   peer_dlog( this, "received handshake_message" );
   if( !is_valid( msg ) ) {
      peer_elog( this, "bad handshake message");
      no_retry = go_away_reason::fatal_other;
      enqueue( go_away_message( fatal_other ) );
      return;
   }
   peer_dlog( this, "received handshake gen {g}, lib {lib}, head {head}",
               ("g", msg.generation)("lib", msg.last_irreversible_block_num)("head", msg.head_num) );

   std::unique_lock<std::mutex> g_conn( conn_mtx );
   last_handshake_recv = msg;
   g_conn.unlock();

   connecting = false;
   if (msg.generation == 1) {
      if( msg.node_id == net_plugin_impl::get()->node_id) {
         peer_elog( this, "Self connection detected node_id {id}. Closing connection", ("id", msg.node_id) );
         no_retry = go_away_reason::self;
         enqueue( go_away_message( go_away_reason::self ) );
         return;
      }

      log_p2p_address = msg.p2p_address;
      update_logger_connection_info();
      if( peer_address().empty() ) {
         set_connection_type( msg.p2p_address );
      }

      std::unique_lock<std::mutex> g_conn( conn_mtx );
      if( peer_address().empty() || last_handshake_recv.node_id == fc::sha256()) {
         auto c_time = last_handshake_sent.time;
         g_conn.unlock();
         peer_dlog( this, "checking for duplicate" );
         auto lock = net_plugin_impl::get()->shared_connections_lock();
         for(const auto& check : net_plugin_impl::get()->get_connections()) {
            if(check.get() == this)
               continue;
            std::unique_lock<std::mutex> g_check_conn( check->conn_mtx );
            fc_dlog( net_plugin_impl::get_logger(), "dup check: connected {c}, {l} =? {r}",
                     ("c", check->connected())("l", check->last_handshake_recv.node_id)("r", msg.node_id) );
            if(check->connected() && check->last_handshake_recv.node_id == msg.node_id) {
               if (net_version < dup_goaway_resolution || msg.network_version < dup_goaway_resolution) {
                  // It's possible that both peers could arrive here at relatively the same time, so
                  // we need to avoid the case where they would both tell a different connection to go away.
                  // Using the sum of the initial handshake times of the two connections, we will
                  // arbitrarily (but consistently between the two peers) keep one of them.

                  auto check_time = check->last_handshake_sent.time + check->last_handshake_recv.time;
                  g_check_conn.unlock();
                  if (msg.time + c_time <= check_time)
                     continue;
               } else if (net_version < dup_node_id_goaway || msg.network_version < dup_node_id_goaway) {
                  if (net_plugin_impl::get()->p2p_address < msg.p2p_address) {
                     fc_dlog( net_plugin_impl::get_logger(), "p2p_address '{lhs}' < msg.p2p_address '{rhs}'",
                              ("lhs", net_plugin_impl::get()->p2p_address)( "rhs", msg.p2p_address ) );
                     // only the connection from lower p2p_address to higher p2p_address will be considered as a duplicate,
                     // so there is no chance for both connections to be closed
                     continue;
                  }
               } else if (net_plugin_impl::get()->node_id < msg.node_id) {
                  fc_dlog( net_plugin_impl::get_logger(), "not duplicate, node_id '{lhs}' < msg.node_id '{rhs}'",
                           ("lhs", net_plugin_impl::get()->node_id)("rhs", msg.node_id) );
                  // only the connection from lower node_id to higher node_id will be considered as a duplicate,
                  // so there is no chance for both connections to be closed
                  continue;
               }

               lock.unlock();
               peer_dlog( this, "sending go_away duplicate, msg.p2p_address: {add}", ("add", msg.p2p_address) );
               go_away_message gam(duplicate);
               gam.node_id = conn_node_id;
               enqueue(gam);
               no_retry = duplicate;
               return;
            }
         }
      } else {
         peer_dlog( this, "skipping duplicate check, addr == {pa}, id = {ni}",
                     ("pa", peer_address())( "ni", last_handshake_recv.node_id ) );
         g_conn.unlock();
      }

      if( msg.chain_id != net_plugin_impl::get()->chain_id ) {
         peer_elog( this, "Peer on a different chain. Closing connection" );
         no_retry = go_away_reason::wrong_chain;
         enqueue( go_away_message(go_away_reason::wrong_chain) );
         return;
      }
      protocol_version = net_plugin_impl::get()->to_protocol_version(msg.network_version);
      if( protocol_version != net_version ) {
         peer_ilog( this, "Local network version: {nv} Remote version: {mnv}",
                     ("nv", net_version)("mnv", protocol_version.load()) );
      }

      conn_node_id = msg.node_id;
      short_conn_node_id = conn_node_id.str().substr( 0, 7 );
      update_logger_connection_info();

      if( !net_plugin_impl::get()->authenticate_peer( msg ) ) {
         peer_elog( this, "Peer not authenticated.  Closing connection." );
         no_retry = go_away_reason::authentication;
         enqueue( go_away_message( go_away_reason::authentication ) );
         return;
      }

      uint32_t peer_lib = msg.last_irreversible_block_num;
      wptr weak = shared_from_this();
      app().post( priority::medium, [peer_lib, chain_plug = net_plugin_impl::get()->chain_plug, weak{std::move(weak)},
                                    msg_lib_id = msg.last_irreversible_block_id]() {
         ptr c = weak.lock();
         if( !c ) return;
         controller& cc = chain_plug->chain();
         uint32_t lib_num = cc.last_irreversible_block_num();

         fc_dlog( net_plugin_impl::get_logger(), "handshake check for fork lib_num = {ln}, peer_lib = {pl}, connection {cid}",
                  ("ln", lib_num)("pl", peer_lib)("cid", c->connection_id) );

         if( peer_lib <= lib_num && peer_lib > 0 ) {
            bool on_fork = false;
            try {
               block_id_type peer_lib_id = cc.get_block_id_for_num( peer_lib );
               on_fork = (msg_lib_id != peer_lib_id);
            } catch( const unknown_block_exception& ) {
               // allow this for now, will be checked on sync
               fc_dlog( net_plugin_impl::get_logger(), "peer last irreversible block {pl} is unknown, connection {cid}",
                        ("pl", peer_lib)("cid", c->connection_id) );
            } catch( ... ) {
               fc_wlog( net_plugin_impl::get_logger(), "caught an exception getting block id for {pl}, connection {cid}",
                        ("pl", peer_lib)("cid", c->connection_id) );
               on_fork = true;
            }
            if( on_fork ) {
               c->strand.post( [c]() {
                  peer_elog( c, "Peer chain is forked, sending: forked go away" );
                  c->no_retry = go_away_reason::forked;
                  c->enqueue( go_away_message( go_away_reason::forked ) );
               } );
            }
         }
      });

      if( sent_handshake_count == 0 ) {
         send_handshake();
      }
   }

   process_handshake(msg);
}

void connection::handle_message( const go_away_message& msg ) {
   peer_wlog( this, "received go_away_message, reason = {r}", ("r", reason_str( msg.reason )) );

   bool retry = no_retry == no_reason; // if no previous go away message
   no_retry = msg.reason;
   if( msg.reason == duplicate ) {
      conn_node_id = msg.node_id;
   }
   if( msg.reason == wrong_version ) {
      if( !retry ) no_retry = fatal_other; // only retry once on wrong version
   }
   else if ( msg.reason == benign_other ) {
      if ( retry ) fc_dlog( net_plugin_impl::get_logger(), "received benign_other reason, retrying to connect");
   }
   else {
      retry = false;
   }
   flush_queues();

   close( retry ); // reconnect if wrong_version
}

void connection::handle_message( const time_message& msg ) {
   peer_dlog( this, "received time_message" );

   /* We've already lost however many microseconds it took to dispatch
      * the message, but it can't be helped.
      */
   msg.dst = get_time();

   // If the transmit timestamp is zero, the peer is horribly broken.
   if(msg.xmt == 0)
      return;                 /* invalid timestamp */

   if(msg.xmt == xmt)
      return;                 /* duplicate packet */

   xmt = msg.xmt;
   rec = msg.rec;
   dst = msg.dst;

   if( msg.org == 0 ) {
      send_time( msg );
      return;  // We don't have enough data to perform the calculation yet.
   }

   double offset = (double(rec - org) + double(msg.xmt - dst)) / 2;
   double NsecPerUsec{1000};

   if( net_plugin_impl::get_logger().is_enabled( fc::log_level::all ) )
      net_plugin_impl::get_logger().log( FC_LOG_MESSAGE( all, "Clock offset is {o}ns ({us}us)",
                                    ("o", offset)( "us", offset / NsecPerUsec ) ) );
   org = 0;
   rec = 0;

   std::unique_lock<std::mutex> g_conn( conn_mtx );
   if( last_handshake_recv.generation == 0 ) {
      g_conn.unlock();
      send_handshake();
   }
}

void connection::handle_message( const notice_message& msg ) {
   // peer tells us about one or more blocks or txns. When done syncing, forward on
   // notices of previously unknown blocks or txns,
   //
   peer_dlog( this, "received notice_message" );
   connecting = false;
   if( msg.known_blocks.ids.size() > 1 ) {
      peer_elog( this, "Invalid notice_message, known_blocks.ids.size {s}, closing connection",
                  ("s", msg.known_blocks.ids.size()) );
      close( false );
      return;
   }
   if( msg.known_trx.mode != none ) {
      if( net_plugin_impl::get_logger().is_enabled( fc::log_level::debug ) ) {
         const block_id_type& blkid = msg.known_blocks.ids.empty() ? block_id_type{} : msg.known_blocks.ids.back();
         peer_dlog( this, "this is a {m} notice with {n} pending blocks: {num} {id}...",
                     ("m", modes_str( msg.known_blocks.mode ))("n", msg.known_blocks.pending)
                     ("num", block_header::num_from_id( blkid ))("id", blkid.str().substr( 8, 16 )) );
      }
   }
   switch (msg.known_trx.mode) {
   case none:
      break;
   case last_irr_catch_up: {
      std::unique_lock<std::mutex> g_conn( conn_mtx );
      last_handshake_recv.head_num = msg.known_blocks.pending;
      g_conn.unlock();
      break;
   }
   case catch_up : {
      break;
   }
   case normal: {
      net_plugin_impl::get()->dispatcher->recv_notice( shared_from_this(), msg, false );
   }
   }

   if( msg.known_blocks.mode != none ) {
      peer_dlog( this, "this is a {m} notice with {n} blocks",
                  ("m", modes_str( msg.known_blocks.mode ))( "n", msg.known_blocks.pending ) );
   }
   switch (msg.known_blocks.mode) {
   case none : {
      break;
   }
   case last_irr_catch_up:
   case catch_up: {
      process_notice( msg );
      break;
   }
   case normal : {
      net_plugin_impl::get()->dispatcher->recv_notice( shared_from_this(), msg, false );
      break;
   }
   default: {
      peer_elog( this, "bad notice_message : invalid known_blocks.mode {m}",
                  ("m", static_cast<uint32_t>(msg.known_blocks.mode)) );
   }
   }
}

void connection::handle_message( const request_message& msg ) {
   if( msg.req_blocks.ids.size() > 1 ) {
      peer_elog( this, "Invalid request_message, req_blocks.ids.size {s}, closing",
                  ("s", msg.req_blocks.ids.size()) );
      close();
      return;
   }

   switch (msg.req_blocks.mode) {
   case catch_up :
      peer_dlog( this, "received request_message:catch_up" );
      blk_send_branch( msg.req_blocks.ids.empty() ? block_id_type() : msg.req_blocks.ids.back() );
      break;
   case normal :
      peer_dlog( this, "received request_message:normal" );
      if( !msg.req_blocks.ids.empty() ) {
         blk_send( msg.req_blocks.ids.back() );
      }
      break;
   default:;
   }


   switch (msg.req_trx.mode) {
   case catch_up :
      break;
   case none :
      if( msg.req_blocks.mode == none ) {
         stop_send();
      }
      [[fallthrough]];
   case normal :
      if( !msg.req_trx.ids.empty() ) {
         peer_elog( this, "Invalid request_message, req_trx.ids.size {s}", ("s", msg.req_trx.ids.size()) );
         close();
         return;
      }
      break;
   default:;
   }
}

void connection::handle_message( const sync_request_message& msg ) {
   peer_dlog( this, "peer requested {start} to {end}", ("start", msg.start_block)("end", msg.end_block) );
   if( msg.end_block == 0 ) {
      peer_requested.reset();
      flush_queues();
   } else {
      if (peer_requested) {
         // This happens when peer already requested some range and sync is still in progress
         // It could be higher in case of peer requested head catchup and current request is lib catchup
         // So to make sure peer will receive all requested blocks we assign end_block to highest value
         peer_requested->end_block = std::max(msg.end_block, peer_requested->end_block);
      }
      else {
         peer_requested = peer_sync_state( msg.start_block, msg.end_block, msg.start_block-1);
      }
      enqueue_sync_block();
   }
}

void connection::handle_message( packed_transaction_ptr trx ) {
   const auto& tid = trx->id();
   peer_dlog( this, "received packed_transaction {id}", ("id", tid) );

   trx_in_progress_size += trx->get_estimated_size();
   net_plugin_impl::get()->chain_plug->accept_transaction( trx,
      [weak = weak_from_this(), trx](const std::variant<fc::exception_ptr, transaction_trace_ptr>& result) mutable {
      // next (this lambda) called from application thread
      if (std::holds_alternative<fc::exception_ptr>(result)) {
         fc_dlog( net_plugin_impl::get_logger(), "bad packed_transaction : {m}", ("m", std::get<fc::exception_ptr>(result)->what()) );
      } else {
         const transaction_trace_ptr& trace = std::get<transaction_trace_ptr>(result);
         if( !trace->except ) {
            fc_dlog( net_plugin_impl::get_logger(), "chain accepted transaction, bcast {id}", ("id", trace->id) );
         } else {
            fc_elog( net_plugin_impl::get_logger(), "bad packed_transaction : {m}", ("m", trace->except->what()));
         }
      }
      ptr conn = weak.lock();
      if( conn ) {
         conn->trx_in_progress_size -= trx->get_estimated_size();
      }
   });
}

// called from connection strand
void connection::handle_message( const block_id_type& id, signed_block_ptr ptr ) {
   peer_dlog( this, "received signed_block {num}, id {id}", ("num", ptr->block_num())("id", id) );
   if( net_plugin_impl::get()->p2p_reject_incomplete_blocks ) {
      if( ptr->prune_state == signed_block::prune_state_type::incomplete ) {
         peer_wlog( this, "Sending go away for incomplete block #{n} {id}...",
                     ("n", ptr->block_num())("id", id.str().substr(8,16)) );
         no_retry = go_away_reason::fatal_other;
         enqueue( go_away_message( fatal_other ) );
         return;
      }
   }

   auto trace = fc_create_trace_with_id_if(net_plugin_impl::get()->telemetry_span_root, "block", id);
   fc_add_tag(trace, "block_num", ptr->block_num());
   fc_add_tag(trace, "block_id", id );

   auto handle_message_span  = fc_create_span_with_id("handle_message", (uint64_t) rand(), id);
   fc_add_tag(handle_message_span, "queue_size", app().get_priority_queue().size());

   app().post(priority::medium, [ptr{std::move(ptr)}, id, c = shared_from_this(),
                                 handle_message_span = std::move(handle_message_span)]() mutable {
      auto       span = fc_create_span(handle_message_span, "processing_singed_block");
      const auto bn   = ptr->block_num();
      c->process_signed_block(id, std::move(ptr));
   });
}

// called from application thread
void connection::process_signed_block( const block_id_type& blk_id, signed_block_ptr msg ) {
   controller& cc = net_plugin_impl::get()->chain_plug->chain();
   uint32_t blk_num = msg->block_num();
   // use c in this method instead of this to highlight that all methods called on c-> must be thread safe
   ptr c = shared_from_this();

   // if we have closed connection then stop processing
   if( !c->socket_is_open() )
      return;

   try {
      if( cc.fetch_block_by_id(blk_id) ) {
         c->strand.post( [dispatcher = net_plugin_impl::get()->dispatcher.get(), c, blk_id, blk_num]() {
            dispatcher->add_peer_block( blk_id, c->connection_id );
            c->sync_recv_block( blk_id, blk_num, false );
         });
         return;
      }
   } catch(...) {
      // should this even be caught?
      fc_elog( net_plugin_impl::get_logger(), "Caught an unknown exception trying to recall block ID" );
   }

   fc::microseconds age( fc::time_point::now() - msg->timestamp);
   fc_dlog( net_plugin_impl::get_logger(), "received signed_block: #{n} block age in secs = {age}, connection {cid}",
            ("n", blk_num)("age", age.to_seconds())("cid", c->connection_id) );

   go_away_reason reason = fatal_other;
   try {
      net_plugin_impl::get()->dispatcher->add_peer_block( blk_id, c->connection_id );
      bool accepted = net_plugin_impl::get()->chain_plug->accept_block(msg, blk_id);
      net_plugin_impl::get()->update_chain_info();
      reason = no_reason;
      if( !accepted ) reason = unlinkable; // false if producing or duplicate, duplicate checked above
   } catch( const unlinkable_block_exception &ex) {
      fc_dlog(net_plugin_impl::get_logger(), "unlinkable_block_exception connection {cid}: #{n} {id}...: {m}",
               ("cid", c->connection_id)("n", blk_num)("id", blk_id.str().substr(8,16))("m",ex.to_string()));
      reason = unlinkable;
   } catch( const block_validate_exception &ex ) {
      fc_elog(net_plugin_impl::get_logger(), "block_validate_exception connection {cid}: #{n} {id}...: {m}",
               ("cid", c->connection_id)("n", blk_num)("id", blk_id.str().substr(8,16))("m",ex.to_string()));
      reason = validation;
   } catch( const assert_exception &ex ) {
      fc_elog(net_plugin_impl::get_logger(), "block assert_exception connection {cid}: #{n} {id}...: {m}",
               ("cid", c->connection_id)("n", blk_num)("id", blk_id.str().substr(8,16))("m",ex.to_string()));
   } catch( const fc::exception &ex ) {
      fc_elog(net_plugin_impl::get_logger(), "bad block exception connection {cid}: #{n} {id}...: {m}",
               ("cid", c->connection_id)("n", blk_num)("id", blk_id.str().substr(8,16))("m",ex.to_string()));
   } catch( ... ) {
      fc_elog(net_plugin_impl::get_logger(), "bad block connection {cid}: #{n} {id}...: unknown exception",
               ("cid", c->connection_id)("n", blk_num)("id", blk_id.str().substr(8,16)));
   }

   if( reason == no_reason ) {
      boost::asio::post( net_plugin_impl::get()->thread_pool->get_executor(), [dispatcher = net_plugin_impl::get()->dispatcher.get(), blk_id, msg]() {
         fc_dlog( net_plugin_impl::get_logger(), "accepted signed_block : #{n} {id}...", ("n", msg->block_num())("id", blk_id.str().substr(8,16)) );
         dispatcher->update_txns_block_num( msg );
      });
      c->strand.post( [dispatcher = net_plugin_impl::get()->dispatcher.get(), c, blk_id, blk_num]() {
         dispatcher->recv_block( c, blk_id, blk_num );
         c->sync_recv_block( blk_id, blk_num, true );
      });
   } else {
      c->strand.post( [c, blk_id, blk_num, reason]() {
         if( reason == unlinkable ) {
            net_plugin_impl::get()->dispatcher->rm_peer_block( blk_id, c->connection_id );
         }
         c->rejected_block( blk_num );
         net_plugin_impl::get()->dispatcher->rejected_block( blk_id );
      });
   }
}

// call from connection strand
void connection::backoff_handshake() {
   const auto now = std::chrono::steady_clock::now();
   if (now > last_handshake_time + last_handshake_backoff) {
      last_handshake_time = now;
      last_handshake_backoff = handshake_backoff_floor;
      peer_ilog(this, "no backoff - sending handshake immediately");
   } else {
      // exponential backoff
      last_handshake_backoff = last_handshake_backoff * 2;
      if (last_handshake_backoff > handshake_backoff_cap) {
         last_handshake_backoff = handshake_backoff_cap;
      }
      peer_ilog(this, "handshake backoff, sleep for {x}ms",
                ("x", last_handshake_backoff.count()));
      std::this_thread::sleep_for(last_handshake_backoff);
      last_handshake_time = std::chrono::steady_clock::now();
   }
}

// call from connection strand
bool connection::populate_handshake( handshake_message& hello ) {
   hello.network_version = net_version_base + net_version;
   uint32_t lib, head;
   std::tie( lib, std::ignore, head,
               hello.last_irreversible_block_id, std::ignore, hello.head_id ) = net_plugin_impl::get()->get_chain_info();
   hello.last_irreversible_block_num = lib;
   hello.head_num = head;
   hello.chain_id = net_plugin_impl::get()->chain_id;
   hello.node_id = net_plugin_impl::get()->node_id;
   hello.key = net_plugin_impl::get()->get_authentication_key();
   hello.time = sc::duration_cast<sc::nanoseconds>(sc::system_clock::now().time_since_epoch()).count();
   hello.token = fc::sha256::hash(hello.time);
   hello.sig = net_plugin_impl::get()->sign_compact(hello.key, hello.token);
   // If we couldn't sign, don't send a token.
   if(hello.sig == chain::signature_type())
      hello.token = sha256();
   hello.p2p_address = net_plugin_impl::get()->p2p_address;
   if( is_transactions_only_connection() ) hello.p2p_address += ":trx";
   if( is_blocks_only_connection() ) hello.p2p_address += ":blk";
   hello.p2p_address += " - " + hello.node_id.str().substr(0,7);
#if defined( __APPLE__ )
   hello.os = "osx";
#elif defined( __linux__ )
   hello.os = "linux";
#elif defined( _WIN32 )
   hello.os = "win32";
#else
   hello.os = "other";
#endif
   hello.agent = net_plugin_impl::get()->user_agent_name;

   return true;
}

void connection::process_handshake(const handshake_message& msg) {
   if( is_transactions_only_connection() )
      return;

   net_plugin_impl::get()->sync_man().sync_reset_lib_num(msg.last_irreversible_block_num);

   uint32_t lib_num = 0;
   uint32_t peer_lib = msg.last_irreversible_block_num;
   uint32_t head = 0;
   block_id_type head_id;
   std::tie( lib_num, std::ignore, head,
               std::ignore, std::ignore, head_id ) = net_plugin_impl::get()->get_chain_info();

   long long current_time_ns = sc::duration_cast<sc::nanoseconds>(sc::system_clock::now().time_since_epoch()).count();
   long long network_latency_ns = std::max(0LL, current_time_ns - msg.time); // net latency in nanoseconds
   // number of blocks syncing node is behind from a peer node
   uint32_t nblk_behind_by_net_latency = static_cast<uint32_t>(network_latency_ns / block_interval_ns);
   // Multiplied by 2 to compensate the time it takes for message to reach peer node, and plus 1 to compensate for integer division truncation
   uint32_t nblk_combined_latency = 2 * nblk_behind_by_net_latency + 1;
   // message in the log below is used in p2p_high_latency_test.py test
   peer_dlog(this, "Network latency is {lat}ms, {num} blocks discrepancy by network latency, {tot_num} blocks discrepancy expected once message received",
            ("lat", network_latency_ns/1000000)("num", nblk_behind_by_net_latency)("tot_num", nblk_combined_latency));

   //--------------------------------
   // sync need checks; (lib == last irreversible block)
   //
   // 0. my head block id == peer head id means we are all caught up block wise
   // 1. my head block num < peer lib - send handshake (if not sent in handle_message) and wait for receipt of notice message to start syncing
   // 2. my lib > peer head num - send an last_irr_catch_up notice if not the first generation
   // 2. my lib > peer head num + nblk_combined_latency - send last_irr_catch_up notice if not the first generation
   //
   // 3  my head block num < peer head block num - update sync state and send a catchup request
   // 4  my head block num >= peer block num send a notice catchup if this is not the first generation
   // 3  my head block num + nblk_combined_latency < peer head block num - update sync state and send a catchup request
   // 4  my head block num >= peer block num + nblk_combined_latency send a notice catchup if this is not the first generation
   //    4.1 if peer appears to be on a different fork ( our_id_for( msg.head_num ) != msg.head_id )
   //        then request peer's blocks
   //
   //-----------------------------

   if (head_id == msg.head_id) {
      peer_ilog( this, "handshake lib {lib}, head {head}, head id {id}.. sync 0",
                  ("lib", msg.last_irreversible_block_num)("head", msg.head_num)("id", msg.head_id.str().substr(8,16)) );
      syncing = false;
      notice_message note;
      note.known_blocks.mode = none;
      note.known_trx.mode = catch_up;
      note.known_trx.pending = 0;
      enqueue( note );
      return;
   }
   if (head < peer_lib) {
      peer_ilog( this, "handshake lib {lib}, head {head}, head id {id}.. sync 1",
                  ("lib", msg.last_irreversible_block_num)("head", msg.head_num)("id", msg.head_id.str().substr(8,16)) );
      syncing = false;
      if (sent_handshake_count > 0) {
         send_handshake();
      }
      return;
   }
   if (lib_num > msg.head_num + nblk_combined_latency ) {
      peer_ilog( this, "handshake lib {lib}, head {head}, head id {id}.. sync 2",
                  ("lib", msg.last_irreversible_block_num)("head", msg.head_num)("id", msg.head_id.str().substr(8,16)) );
      if (msg.generation > 1 || protocol_version > proto_base) {
         notice_message note;
         note.known_trx.pending = lib_num;
         note.known_trx.mode = last_irr_catch_up;
         note.known_blocks.mode = last_irr_catch_up;
         note.known_blocks.pending = head;
         enqueue( note );
      }
      syncing = true;
      return;
   }
   if (head + nblk_combined_latency < msg.head_num ) {
      peer_ilog( this, "handshake lib {lib}, head {head}, head id {id}.. sync 3",
                  ("lib", msg.last_irreversible_block_num)("head", msg.head_num)("id", msg.head_id.str().substr(8,16)) );
      syncing = false;
      verify_catchup(msg.head_num, msg.head_id);
      return;
   } else if(head >= msg.head_num + nblk_combined_latency) {
      peer_ilog( this, "handshake lib {lib}, head {head}, head id {id}.. sync 4",
               ("lib", msg.last_irreversible_block_num)("head", msg.head_num)("id", msg.head_id.str().substr(8,16)) );
      if (msg.generation > 1 ||  protocol_version > proto_base) {
         notice_message note;
         note.known_trx.mode = none;
         note.known_blocks.mode = catch_up;
         note.known_blocks.pending = head;
         note.known_blocks.ids.push_back(head_id);
         enqueue( note );
      }
      syncing = false;
      app().post( priority::medium, [chain_plug = net_plugin_impl::get()->chain_plug, c = shared_from_this(),
                                       msg_head_num = msg.head_num, msg_head_id = msg.head_id]() {
         bool on_fork = true;
         try {
            controller& cc = chain_plug->chain();
            on_fork = cc.get_block_id_for_num( msg_head_num ) != msg_head_id;
         } catch( ... ) {}
         if( on_fork ) {
            c->strand.post( [c]() {
               request_message req;
               req.req_blocks.mode = catch_up;
               req.req_trx.mode = none;
               c->enqueue( req );
            } );
         }
      } );
   } else {
         peer_dlog( this, "Block discrepancy is within network latency range.");
   }
}

void connection::process_notice( const notice_message& msg) {
   peer_dlog( this, "connection got {m} block notice", ("m", modes_str( msg.known_blocks.mode )) );
   EOS_ASSERT( msg.known_blocks.mode == catch_up || msg.known_blocks.mode == last_irr_catch_up, plugin_exception,
               "process_notice only called on catch_up" );
   if (msg.known_blocks.mode == catch_up) {
      if (msg.known_blocks.ids.size() == 0) {
         peer_elog( this, "got a catch up with ids size = 0" );
      } else {
         const block_id_type& id = msg.known_blocks.ids.back();
         peer_ilog( this, "notice_message, pending {p}, blk_num {n}, id {id}...",
                  ("p", msg.known_blocks.pending)("n", block_header::num_from_id(id))("id",id.str().substr(8,16)) );
         if( !net_plugin_impl::get()->dispatcher->have_block( id ) ) {
            verify_catchup(msg.known_blocks.pending, id);
         } else {
            // we already have the block, so update peer with our view of the world
            send_handshake();
         }
      }
   } else if (msg.known_blocks.mode == last_irr_catch_up) {
      {
         std::lock_guard<std::mutex> g_conn( conn_mtx );
         last_handshake_recv.last_irreversible_block_num = msg.known_trx.pending;
      }
      try {
         peer_dlog( this, "target lib = {m}", ("m", msg.known_trx.pending) );
         bool passed = false;
         {
            auto lock = net_plugin_impl::get()->sm_impl().locked_sml_mutex();

            passed = net_plugin_impl::get()->sync_sm->process_event(
               net_plugin_impl::sync_man_sm_impl::lib_catchup{msg.known_trx.pending, shared_from_this()}
            );
         }
         if ( !passed )
            send_handshake();
      } FC_LOG_AND_RETHROW();
   }
}

void connection::send_none_request() {
   request_message req;
   peer_ilog( this, "none notice while in {s}, previous fork head num = {fhn}, id {id}...",
            ("s", net_plugin_impl::get()->get_state_str())("fhn", fork_head_num)("id", fork_head.str().substr(8,16)) );
   {
      std::lock_guard<std::mutex> g_conn( conn_mtx );
      fork_head = block_id_type();
      fork_head_num = 0;
   }
   req.req_blocks.mode = none;
   req.req_trx.mode = none;
   enqueue( req );
}

void connection::verify_catchup(uint32_t num, const chain::block_id_type& id) {
   if (net_plugin_impl::get()->sync_man().fork_head_ge(num, id)) {
      send_none_request();
   } else {
      if (net_plugin_impl::get()->syncing_with_peer())
         return;

      uint32_t lib;
      block_id_type head_id;
      std::tie( lib, std::ignore, std::ignore,
                std::ignore, std::ignore, head_id ) = net_plugin_impl::get()->get_chain_info();
      if (num < lib)
         return;
      {
         std::lock_guard<std::mutex> g_conn( conn_mtx );
         fork_head = id;
         fork_head_num = num;
         peer_dlog(this, "fork head num = {fh} id = {id}", ("fh",fork_head_num)("id",fork_head.str().substr( 8, 16 )));
      }
      {
         auto lock = net_plugin_impl::get()->sm_impl().locked_sml_mutex();
         try {
            net_plugin_impl::get()->sync_sm->process_event( net_plugin_impl::sync_man_sm_impl::head_catchup{} );
         } FC_LOG_AND_RETHROW();
      }

      request_message req;
      req.req_blocks.mode = catch_up;
      req.req_blocks.ids.emplace_back( head_id );
      req.req_trx.mode = none;
      enqueue( req );
   }
}

template <typename Strand>
void verify_strand_in_this_thread(const Strand& strand, const char* func, int line) {
   if( !strand.running_in_this_thread() ) {
      elog( "wrong strand: {f} : line {n}, exiting", ("f", func)("n", line) );
      app().quit();
   }
}

void connection::rejected_block(uint32_t blk_num) {
   block_status_monitor_.rejected();
   net_plugin_impl::get()->sync_man().reset_last_requested_num();
   if( block_status_monitor_.max_events_violated()) {
      peer_wlog( this, "block {bn} not accepted, closing connection", ("bn", blk_num) );
      net_plugin_impl::get()->sync_man().reset_sync_source();
      close();
   } else {
      send_handshake();
   }
}

void connection::sync_recv_block( const chain::block_id_type& blk_id, uint32_t blk_num, bool blk_applied ) {
   if( app().is_quiting() ) {
      close( false, true );
      return;
   }

   block_status_monitor_.accepted();
   bool passed = false;
   {
      try {
         peer_dlog( this, "recv_block event, blk_id = {id} blk_num = {n} applied = {a}", ("id", blk_id)("n", blk_num)("a", blk_applied) );
         auto lock = net_plugin_impl::get()->sm_impl().locked_sml_mutex();
         passed = net_plugin_impl::get()->sync_sm->process_event(
            net_plugin_impl::sync_man_sm_impl::recv_block{blk_id, blk_num, blk_applied}
         );
      } FC_LOG_AND_RETHROW();
   }
   if ( !passed ) {
      peer_dlog( this, "calling sync_wait" );
      sync_wait();
   }
}

fc::logger& connection::get_logger() {
   return net_plugin_impl::get_logger();
}
const std::string& connection::peer_log_format() {
   return net_plugin_impl::get()->peer_log_format;
}

}} //eosio::p2p

#pragma once

#include <boost/asio.hpp>

namespace eosio { namespace p2p {

// thread safe
class queued_buffer : boost::noncopyable {
public:
   void clear_write_queue() {
      std::lock_guard<std::mutex> g( _mtx );
      _write_queue.clear();
      _sync_write_queue.clear();
      _write_queue_size = 0;
   }

   void clear_out_queue() {
      std::lock_guard<std::mutex> g( _mtx );
      while ( _out_queue.size() > 0 ) {
         _out_queue.pop_front();
      }
   }

   uint32_t write_queue_size() const {
      std::lock_guard<std::mutex> g( _mtx );
      return _write_queue_size;
   }

   bool is_out_queue_empty() const {
      std::lock_guard<std::mutex> g( _mtx );
      return _out_queue.empty();
   }

   bool ready_to_send() const {
      std::lock_guard<std::mutex> g( _mtx );
      // if out_queue is not empty then async_write is in progress
      return ((!_sync_write_queue.empty() || !_write_queue.empty()) && _out_queue.empty());
   }

   // @param callback must not callback into queued_buffer
   bool add_write_queue( const std::shared_ptr<std::vector<char>>& buff,
                           std::function<void( boost::system::error_code, std::size_t )> callback,
                           bool to_sync_queue ) {
      std::lock_guard<std::mutex> g( _mtx );
      if( to_sync_queue ) {
         _sync_write_queue.push_back( {buff, callback} );
      } else {
         _write_queue.push_back( {buff, callback} );
      }
      _write_queue_size += buff->size();
      if( _write_queue_size > 2 * def_max_write_queue_size ) {
         return false;
      }
      return true;
   }

   void fill_out_buffer( std::vector<boost::asio::const_buffer>& bufs ) {
      std::lock_guard<std::mutex> g( _mtx );
      if( _sync_write_queue.size() > 0 ) { // always send msgs from sync_write_queue first
         fill_out_buffer( bufs, _sync_write_queue );
      } else { // postpone real_time write_queue if sync queue is not empty
         fill_out_buffer( bufs, _write_queue );
         EOS_ASSERT( _write_queue_size == 0, chain::plugin_exception, "write queue size expected to be zero" );
      }
   }

   void out_callback( boost::system::error_code ec, std::size_t w ) {
      std::lock_guard<std::mutex> g( _mtx );
      for( auto& m : _out_queue ) {
         m.callback( ec, w );
      }
   }

private:
   struct queued_write;
   void fill_out_buffer( std::vector<boost::asio::const_buffer>& bufs,
                         std::deque<queued_write>& w_queue ) {
      while ( w_queue.size() > 0 ) {
         auto& m = w_queue.front();
         bufs.push_back( boost::asio::buffer( *m.buff ));
         _write_queue_size -= m.buff->size();
         _out_queue.emplace_back( m );
         w_queue.pop_front();
      }
   }

private:
   struct queued_write {
      std::shared_ptr<std::vector<char>> buff;
      std::function<void( boost::system::error_code, std::size_t )> callback;
   };

   mutable std::mutex  _mtx;
   uint32_t            _write_queue_size{0};
   std::deque<queued_write> _write_queue;
   std::deque<queued_write> _sync_write_queue; // sync_write_queue will be sent first
   std::deque<queued_write> _out_queue;

}; // queued_buffer

}} //eosio::p2p

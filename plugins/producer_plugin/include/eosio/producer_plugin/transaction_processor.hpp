#pragma once

#include <eosio/producer_plugin/subjective_billing.hpp>
#include <eosio/producer_plugin/produce_block_tracker.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/unapplied_transaction_queue.hpp>

#include <atomic>

namespace eosio {

class producer;

template<typename T>
using next_function = std::function<void(const std::variant<fc::exception_ptr, T>&)>;

/**
 * Main class for transaction processing of the producer_plugin.
 */
class transaction_processor {
public:

   // lifetime managed by producer
   explicit transaction_processor(producer& prod, produce_block_tracker& tracker)
   : _producer( prod )
   , _produce_block_tracker( tracker ) {}

   void disable_persist_until_expired() { _disable_persist_until_expired = true; }
   void disable_subjective_p2p_billing() { _disable_subjective_p2p_billing = true; }
   void disable_subjective_api_billing() { _disable_subjective_api_billing = true; }

   void disable_subjective_billing() { _subjective_billing.disable(); }
   void disable_subjective_billing_account( const account_name& a ) { _subjective_billing.disable_account( a ); }

   void set_max_transaction_queue_size( uint64_t v ) { _unapplied_transactions.set_max_transaction_queue_size( v ); }

   void start( size_t num_threads);
   void stop();
   void handle_sighup();

   // thread safe
   void set_max_transaction_time(const fc::microseconds& max_time ) {
      _max_transaction_time_us = max_time.count() < 0 ? fc::microseconds::maximum().count() : max_time.count();
   }

   // thread safe
   fc::microseconds get_max_transaction_time() const {
      return fc::microseconds( _max_transaction_time_us.load() );
   }

   void on_block( const block_state_ptr& bsp );

   void aborted_block( chain::deque<chain::transaction_metadata_ptr> aborted_trxs ) {
      _unapplied_transactions.add_aborted( std::move( aborted_trxs ) );
      _subjective_billing.abort_block();
   }

   void add_forked( const chain::branch_type& forked_branch ) {
      _unapplied_transactions.add_forked( forked_branch );
   }

   chain::transaction_metadata_ptr get_trx( const transaction_id_type& id ) const {
      return _unapplied_transactions.get_trx( id );
   }

   /// Can be called from any thread. Called from net threads
   void on_incoming_transaction_async( chain::controller& chain,
                                       const chain::packed_transaction_ptr& trx,
                                       bool persist_until_expired,
                                       const bool read_only,
                                       const bool return_failure_trace,
                                       next_function<chain::transaction_trace_ptr> next );

   bool remove_expired_trxs( const chain::controller& chain, const fc::time_point& deadline );

   enum class process_result {
      succeeded,
      failed,
      exhausted
   };

   process_result process_unapplied_trxs_start_block( chain::controller& chain, const fc::time_point& deadline );

   bool process_incoming_trxs( chain::controller& chain, const fc::time_point& deadline, size_t& pending_incoming_process_limit );

   static void log_failed_transaction( const chain::controller& chain,
                                       const chain::transaction_id_type& trx_id,
                                       const chain::packed_transaction_ptr& packed_trx_ptr,
                                       const char* reason );

   /// return variant of trace for logging, trace is modified to minimize log output
   static fc::variant get_log_trx_trace( const chain::controller& chain, const chain::transaction_trace_ptr& trx_trace );

   /// return variant of trx for logging, trace is modified to minimize log output
   static fc::variant get_log_trx( const chain::controller& chain, const chain::transaction& trx );

   bool process_incoming_transaction( chain::controller& chain,
                                      const chain::transaction_metadata_ptr& trx,
                                      bool persist_until_expired,
                                      next_function<chain::transaction_trace_ptr> next,
                                      const bool return_failure_trace = false );

private:
   process_result process_unapplied_trxs( chain::controller& chain, const fc::time_point& deadline );

private:
   producer& _producer;
   produce_block_tracker& _produce_block_tracker;
   chain::unapplied_transaction_queue _unapplied_transactions;
   std::optional<chain::named_thread_pool> _thread_pool;
   std::atomic<int64_t> _max_transaction_time_us{}; // modified by app thread, read by net_plugin thread pool
   subjective_billing _subjective_billing;
   bool _disable_persist_until_expired = false;
   bool _disable_subjective_p2p_billing = false;
   bool _disable_subjective_api_billing = false;
};

} // namespace eosio

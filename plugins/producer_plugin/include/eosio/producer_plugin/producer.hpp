#pragma once

#include <eosio/producer_plugin/pending_snapshot_tracker.hpp>
#include <eosio/producer_plugin/block_producer.hpp>
#include <eosio/producer_plugin/produce_block_tracker.hpp>
#include <eosio/producer_plugin/producer_timer.hpp>
#include <eosio/producer_plugin/transaction_processor.hpp>
#include <eosio/producer_ha_plugin/producer_ha_plugin.hpp>

#include <eosio/chain/controller.hpp>
#include <eosio/chain/unapplied_transaction_queue.hpp>

#include <appbase/application.hpp>

#include <boost/signals2/connection.hpp>
#include <memory>

namespace eosio {

struct integrity_hash_information {
   chain::block_id_type head_block_id;
   chain::digest_type   integrity_hash;
};

enum class pending_block_mode {
   producing,
   speculating
};

template<typename T>
using next_function = std::function<void(const std::variant<fc::exception_ptr, T>&)>;

/**
 * Main class for producer_plugin
 */
class producer : public std::enable_shared_from_this<producer> {
public:

   using transaction_ack_function = std::function<void(const fc::exception_ptr&, const chain::transaction_metadata_ptr&)>;
   using rejected_block_function = std::function<void(const chain::signed_block_ptr&)>;

   producer( std::unique_ptr<producer_timer_base> prod_timer,
             transaction_ack_function transaction_ack,
             rejected_block_function rejected_block_ack )
         : _producer_timer( std::move(prod_timer) )
         , _transaction_ack( std::move(transaction_ack) )
         , _rejected_block_ack( std::move(rejected_block_ack) ) {
   }

   producer( const producer& ) = delete;
   producer& operator=( const producer& ) = delete;

   bool _production_enabled = false;
   bool _pause_production = false;

   using signature_provider_type = std::function<chain::signature_type(chain::digest_type)>;
   std::map<chain::public_key_type, signature_provider_type> _signature_providers;
   std::unique_ptr<producer_timer_base> _producer_timer;
   bool _accept_transactions = true;
   pending_block_mode _pending_block_mode = pending_block_mode::speculating;

   produce_block_tracker _produce_block_tracker;
   transaction_processor _transaction_processor{*this, _produce_block_tracker};
   block_producer _block_producer;

   fc::microseconds _max_irreversible_block_age_us;
   int32_t _produce_time_offset_us = 0;
   int32_t _last_block_time_offset_us = 0;
   uint32_t _max_block_cpu_usage_threshold_us = 0;
   uint32_t _max_block_net_usage_threshold_bytes = 0;
   fc::time_point _irreversible_block_time;

   std::vector<chain::digest_type> _protocol_features_to_activate;
   bool _protocol_features_signaled = false; // to mark whether it has been signaled in start_block

   chain::controller* chain_control = nullptr;

   producer_ha_plugin* producer_ha_plug = nullptr;
   chain_plugin* chain_plug = nullptr;

   transaction_ack_function _transaction_ack;
   rejected_block_function  _rejected_block_ack;

   pending_snapshot_tracker _pending_snapshot_tracker;
   uint32_t background_snapshot_write_period_in_blocks = 7200;
   std::optional<boost::signals2::scoped_connection> _accepted_block_connection;
   std::optional<boost::signals2::scoped_connection> _accepted_block_header_connection;
   std::optional<boost::signals2::scoped_connection> _irreversible_block_connection;

   chain::controller& get_chain() {
      return *chain_control;
   }

   const chain::controller& get_chain() const {
      return *chain_control;
   }

   std::shared_ptr<producer> get_self() {
      return shared_from_this();
   }

   void on_block( const block_state_ptr& bsp ) {
      _transaction_processor.on_block( bsp );
   }

   void on_block_header( const block_state_ptr& bsp ) {
      _block_producer.on_block_header( bsp );
   }

   void on_irreversible_block( const chain::signed_block_ptr& lib ) {
      _irreversible_block_time = lib->timestamp.to_time_point();

      _pending_snapshot_tracker.promote_pending_snapshots( *chain_control, lib->block_num() );
   }

   void abort_block() {
      chain::controller& chain = *chain_control;
      _transaction_processor.aborted_block( chain.abort_block() );
   }

   bool on_incoming_block( const chain::signed_block_ptr& block, const std::optional<chain::block_id_type>& block_id );

   // Can be called from any thread. Called from net threads
   void on_incoming_transaction_async( const chain::packed_transaction_ptr& trx,
                                       bool persist_until_expired,
                                       const bool read_only,
                                       const bool return_failure_trace,
                                       next_function<chain::transaction_trace_ptr> next ) {
      chain::controller& chain = *chain_control;
      _transaction_processor.on_incoming_transaction_async( chain, trx, persist_until_expired, read_only, return_failure_trace, next );
   }

   fc::microseconds get_irreversible_block_age() const {
      auto t = fc::time_point::now();
      if( t < _irreversible_block_time ) {
         return fc::microseconds( 0 );
      } else {
         return t - _irreversible_block_time;
      }
   }

   account_name get_pending_block_producer() const {
      auto& chain = *chain_control;
      if( chain.is_building_block() ) {
         return chain.pending_block_producer();
      } else {
         return {};
      }
   }

   bool production_disabled_by_policy() const {
      return !_production_enabled || _pause_production ||
        (_max_irreversible_block_age_us.count() >= 0 && get_irreversible_block_age() >= _max_irreversible_block_age_us);
   }

   enum class start_block_result {
      succeeded,
      failed,
      waiting_for_block,
      waiting_for_production,
      exhausted
   };

   fc::time_point calculate_block_deadline( const fc::time_point& block_time ) const;

   producer::start_block_result start_block();

   bool block_is_exhausted() const;
   void block_exhausted();
   void restart_speculative_block();

   void schedule_production_loop();

   void schedule_maybe_produce_block( bool exhausted );

   void schedule_delayed_production_loop( std::optional<fc::time_point> wake_up_time );

   bool maybe_produce_block();

   void produce_block();

   // thread safe
   void set_max_transaction_time(const fc::microseconds& max_time ) {
      _transaction_processor.set_max_transaction_time(max_time);
   }

   // thread safe
   fc::microseconds get_max_transaction_time() const {
      return _transaction_processor.get_max_transaction_time();
   }

   void pause();
   void resume();
   bool paused() const {
      auto paused = _pause_production;
      if (producer_ha_plug->enabled() && !producer_ha_plug->is_active_and_leader()) {
         paused = true;
      }
      return paused;
   }

   bool has_producers() const { return _block_producer.has_producers(); }

   auto get_num_producers() const { return _block_producer.get_num_producers(); }

   bool is_production_enabled() const { return _production_enabled; }

   bool is_producing_block() const {
      return _pending_block_mode == pending_block_mode::producing;
   }

   bool is_producer_key(const chain::public_key_type& key) const {
      auto private_key_itr = _signature_providers.find(key);
      if(private_key_itr != _signature_providers.end())
         return true;
      return false;
   }

   chain::signature_type sign_compact(const chain::public_key_type& key, const fc::sha256& digest) const;

   integrity_hash_information get_integrity_hash();

   bool execute_incoming_transaction(const chain::transaction_metadata_ptr& trx,
                                     next_function<chain::transaction_trace_ptr> next )
   {
      chain::controller& chain = *chain_control;
      const bool persist_until_expired = false;
      const bool return_failure_trace = true;
      bool exhausted = !_transaction_processor.process_incoming_transaction( chain, trx, persist_until_expired, std::move(next), return_failure_trace );
      if( exhausted ) {
         block_exhausted();
      }
      return !exhausted;
   }

   void schedule_protocol_feature_activations( const std::vector<chain::digest_type>& protocol_features_to_activate );

   void create_snapshot(next_function<snapshot_information> next);

   void handle_sighup();

   void startup();

   void shutdown();

   void log_failed_transaction(const transaction_id_type& trx_id, const chain::packed_transaction_ptr& packed_trx_ptr, const char* reason) const {
      const chain::controller& chain = *chain_control;
      transaction_processor::log_failed_transaction( chain, trx_id, packed_trx_ptr, reason );
   }

   static fc::logger& get_log();
}; // class producer

template<typename Timer>
class producer_timer : public producer_timer_base {
public:
   explicit producer_timer( boost::asio::io_service& io )
   : _timer( io ) {}

   ~producer_timer() override = default;

   void cancel() override {
      _timer.cancel();
   }

   void schedule_production_later( producer_wptr wptr ) override {
      elog( "Failed to start a pending block, will try again later" );
      _timer.expires_from_now( boost::posix_time::microseconds( config::block_interval_us / 10 ) );

      // we failed to start a block, so try again later.
      _timer.async_wait( appbase::app().get_priority_queue().wrap( appbase::priority::high,
             [this, wptr{std::move(wptr)}, cid = ++_timer_corelation_id]( const boost::system::error_code& ec ) {
                auto ptr = wptr.lock(); // lifetime of producer_timer tied to producer
                if( ptr && ec != boost::asio::error::operation_aborted && cid == _timer_corelation_id ) {
                   ptr->schedule_production_loop();
                }
             } ) );
   }

   void schedule_maybe_produce_block( producer_wptr wptr, bool exhausted, const fc::time_point& deadline, uint32_t block_num ) override {
      if( !exhausted && deadline > fc::time_point::now() ) {
         // ship this block off no later than its deadline
         _timer.expires_at( epoch + boost::posix_time::microseconds( deadline.time_since_epoch().count() ) );
         fc_dlog( producer::get_log(), "Scheduling Block Production on Normal Block #{num} for {time}",
                  ("num", block_num)("time", deadline) );
      } else {
         _timer.expires_from_now( boost::posix_time::microseconds( 0 ) );
         fc_dlog( producer::get_log(), "Scheduling Block Production on {desc} Block #{num} immediately",
                  ("num", block_num)("desc", exhausted ? "Exhausted" : "Deadline exceeded") );
      }

      _timer.async_wait( appbase::app().get_priority_queue().wrap( appbase::priority::high,
             [this, wptr{std::move(wptr)}, cid = ++_timer_corelation_id]( const boost::system::error_code& ec ) {
                auto ptr = wptr.lock(); // lifetime of producer_timer tied to producer
                if( ptr && ec != boost::asio::error::operation_aborted && cid == _timer_corelation_id ) {
                   ptr->maybe_produce_block();
                }
             } ) );
   }

   void schedule_delayed_production_loop( producer_wptr wptr, const fc::time_point& wake_up_time ) override {
      fc_dlog( producer::get_log(), "Scheduling Speculative/Production Change at {time}", ("time", wake_up_time) );
      _timer.expires_at( epoch + boost::posix_time::microseconds( wake_up_time.time_since_epoch().count() ) );
      _timer.async_wait( appbase::app().get_priority_queue().wrap( appbase::priority::high,
             [this, wptr{std::move(wptr)}, cid = ++_timer_corelation_id]( const boost::system::error_code& ec ) {
                auto ptr = wptr.lock(); // lifetime of producer_timer tied to producer
                if( ptr && ec != boost::asio::error::operation_aborted && cid == _timer_corelation_id ) {
                   ptr->schedule_production_loop();
                }
             } ) );
   }

private:
   Timer _timer;

   /*
    * HACK ALERT
    * Boost timers can be in a state where a handler has not yet executed but is not abortable.
    * As this method needs to mutate state handlers depend on for proper functioning to maintain
    * invariants for other code (namely accepting incoming transactions in a nearly full block)
    * the handlers capture a corelation ID at the time they are set.  When they are executed
    * they must check that correlation_id against the global ordinal.  If it does not match that
    * implies that this method has been called with the handler in the state where it should be
    * cancelled but wasn't able to be.
    */
   uint32_t _timer_corelation_id = 0;
};


} // namespace eosio

FC_REFLECT( eosio::integrity_hash_information, (head_block_id)(integrity_hash) )

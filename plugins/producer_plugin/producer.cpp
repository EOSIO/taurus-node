#include <eosio/producer_plugin/producer.hpp>
#include <eosio/producer_plugin/produce_block_tracker.hpp>
#include <eosio/producer_plugin/producer_timer.hpp>
#include <eosio/producer_plugin/transaction_processor.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/unapplied_transaction_queue.hpp>
#include <eosio/chain/to_string.hpp>
#include <eosio/producer_ha_plugin/producer_ha_plugin.hpp>

#include <appbase/application.hpp>

#include <fc/log/logger_config.hpp>
#include <fc/scoped_exit.hpp>

#include <boost/signals2/connection.hpp>
#include <memory>
#include <algorithm>

namespace {

const std::string logger_name("producer_plugin");
fc::logger _log;

using appbase::app;
using appbase::priority;

} // anonymous namespace

namespace eosio {

using namespace eosio::chain;

const boost::posix_time::ptime producer_timer_base::epoch{ boost::gregorian::date( 1970, 1, 1 ) };

fc::logger& producer::get_log() {
   return _log;
}

bool producer::on_incoming_block( const signed_block_ptr& block, const std::optional<block_id_type>& block_id ) {
   if( is_producing_block() ) {
      bool dropping = true;
      // if producer_ha is enabled and loaded, also check whether this
      // node is the leader. If it is not the leader, good to continue
      if( producer_ha_plug->enabled() && !producer_ha_plug->can_produce() ) {
         dropping = false;
      }

      if( dropping ) {
         fc_wlog(_log, "dropped incoming block #{num} id: {id}",
                 ("num", block->block_num())("id", block_id ? (*block_id).str() : "UNKNOWN"));
         return false;
      }
   }

   chain::controller& chain = *chain_control;
   const auto& id = block_id ? *block_id : block->calculate_id();
   auto blk_num = block->block_num();

   // check the block against the producer_ha, if it is enabled
   if( producer_ha_plug->enabled() && producer_ha_plug->is_active_raft_cluster() && producer_ha_plug->can_produce() ) {
      auto raft_head = producer_ha_plug->get_raft_head_block();
      if( raft_head ) {
         // the block is too further beyond producer_ha
         if( raft_head->block_num() < blk_num - 1 ) {
            fc_wlog(_log,
                    "dropped incoming block #{n} {id} which is larger than the Raft head block #{rn} {rid} by more than 1 block",
                    ("n", blk_num)("id", id.str().substr(8, 16))
                    ("rn", raft_head->block_num())("rid", raft_head->calculate_id().str().substr(8, 16)));
            return false;
         }

         // if it is 1 block larger, check whether it is linkable
         auto raft_head_id = raft_head->calculate_id();
         if( raft_head->block_num() == blk_num - 1 && block->previous != raft_head_id ) {
            fc_wlog(_log,
                    "dropped incoming block #{n} {id} which is unlinkable to the Raft head block #{rn} {rid}",
                    ("n", blk_num)("id", id.str().substr(8, 16))
                    ("rn", raft_head->block_num())("rid", raft_head_id.str().substr(8, 16)));
            return false;
         }

         // if it is the raft head, check whether it is the same
         if( raft_head->block_num() == blk_num && raft_head_id != id ) {
            fc_wlog(_log,
                    "dropped incoming block #{n} {id} that has different block ID from the Raft head block #{rn} {rid} ...",
                    ("n", blk_num)("id", id.str().substr(8, 16))
                    ("rn", raft_head->block_num())("rid", raft_head_id.str().substr(8, 16)));
            return false;
         }
      }
   }

   fc_dlog( _log, "received incoming block {n} {id}", ("n", blk_num)( "id", id ) );

   EOS_ASSERT( block->timestamp < (fc::time_point::now() + fc::seconds( 7 )), block_from_the_future,
               "received a block from the future, ignoring it: {id}", ("id", id) );

   /* de-dupe here... no point in aborting block if we already know the block */
   auto existing = chain.fetch_block_by_id( id );
   if( existing ) { return false; }

   // start processing of block
   auto bsf = chain.create_block_state_future( id, block );

   // abort the pending block
   abort_block();

   // exceptions throw out, make sure we restart our loop
   auto ensure = fc::make_scoped_exit( [this]() {
      schedule_production_loop();
   } );

   // push the new block
   auto handle_error = [&]( const auto& e ) {
      elog( "error: {e}", ("e", e.to_detail_string()) );
      _rejected_block_ack( block );
      throw;
   };

   try {
      block_state_ptr blk_state = chain.push_block( bsf, [this]( const branch_type& forked_branch ) {
         _transaction_processor.add_forked( forked_branch );
      }, [this]( const transaction_id_type& id ) {
         return _transaction_processor.get_trx( id );
      } );
   } catch( const guard_exception& e ) {
      log_and_drop_exceptions();
      return false;
   } catch( const std::bad_alloc& ) {
      log_and_drop_exceptions();
   } catch( boost::interprocess::bad_alloc& ) {
      log_and_drop_exceptions();
   } catch( const fork_database_exception& e ) {
      log_and_drop_exceptions();
   } catch( const fc::exception& e ) {
      handle_error( e );
   } catch( const std::exception& e ) {
      handle_error( fc::std_exception_wrapper::from_current_exception( e ) );
   }

   const auto& hbs = chain.head_block_state();
   if( hbs->header.timestamp.next().to_time_point() >= fc::time_point::now() ) {
      _production_enabled = true;
   }

   if( fc::time_point::now() - block->timestamp < fc::minutes( 5 ) || (blk_num % 1000 == 0) ) {
      static uint64_t log_counter = 0;
      if (log_counter++ % 1000 == 0) {
         ilog("Received block {id}... #{n} @ {t} signed by {p} [trxs: {count}, lib: {lib}, conf: {confs}, latency: {latency} ms]",
              ( "p", block->producer.to_string())("id", id.str().substr(8, 16))
                    ("n", blk_num)
                    ("t", block->timestamp.to_time_point())
                    ("count", block->transactions.size())
                    ("lib", chain.last_irreversible_block_num())
                    ("confs", block->confirmed)
                    ("latency", ( fc::time_point::now() - block->timestamp ).count() / 1000));
      } else {
         dlog("Received block {id}... #{n} @ {t} signed by {p} [trxs: {count}, lib: {lib}, conf: {confs}, latency: {latency} ms]",
              ( "p", block->producer.to_string())("id", id.str().substr(8, 16))
                    ("n", blk_num)
                    ("t", block->timestamp.to_time_point())
                    ("count", block->transactions.size())
                    ("lib", chain.last_irreversible_block_num())
                    ("confs", block->confirmed)
                    ("latency", ( fc::time_point::now() - block->timestamp ).count() / 1000));
      }

      if( chain.get_read_mode() != db_read_mode::IRREVERSIBLE && hbs->id != id && hbs->block != nullptr ) { // not applied to head
         ilog( "Block not applied to head {id}... #{n} @ {t} signed by {p} [trxs: {count}, dpos: {dpos}, conf: {confs}, latency: {latency} ms]",
               ("p", hbs->block->producer.to_string())("id", hbs->id.str().substr( 8, 16 ))("n", hbs->block_num)("t", hbs->block->timestamp.to_time_point())
               ("count", hbs->block->transactions.size())("dpos", hbs->dpos_irreversible_blocknum)
               ("confs", hbs->block->confirmed )("latency", (fc::time_point::now() - hbs->block->timestamp).count() / 1000) );
      }
   }

   // trigger background snapshot creation process for non-producer node
   if (chain_plug != nullptr) {
      if(!chain_plug->background_snapshots_disabled()) {
         if (hbs->block_num % background_snapshot_write_period_in_blocks == 0) {
            chain_plug->create_snapshot_background();
         }
      }
   }

   return true;
}

fc::time_point producer::calculate_block_deadline( const fc::time_point& block_time ) const {
   if( is_producing_block() ) {
      bool last_block = ((block_timestamp_type( block_time ).slot % config::producer_repetitions) ==
                         config::producer_repetitions - 1);
      return block_time + fc::microseconds( last_block ? _last_block_time_offset_us : _produce_time_offset_us );
   } else {
      return block_time + fc::microseconds( _produce_time_offset_us );
   }
}

producer::start_block_result producer::start_block() {
   // producer_ha plugin for checking whether producer can produce
   // cached for performance reason
   chain::controller& chain = *chain_control;

   if( !_accept_transactions )
      return start_block_result::waiting_for_block;

   const auto& hbs = chain.head_block_state();

   if( chain.get_terminate_at_block() > 0 && chain.get_terminate_at_block() < chain.head_block_num() ) {
      ilog( "Reached configured maximum block {num}; terminating", ("num", chain.get_terminate_at_block()) );
      app().quit();
      return start_block_result::failed;
   }

   const fc::time_point start_time = fc::time_point::now();
   const fc::time_point block_time = _block_producer.calculate_pending_block_time( chain );

   const pending_block_mode previous_pending_mode = _pending_block_mode;
   _pending_block_mode = pending_block_mode::producing;

   // Not our turn
   const auto& scheduled_producer = hbs->get_scheduled_producer( block_time );
   account_name scheduled_producer_name = scheduled_producer.producer_name;

   size_t num_relevant_signatures = 0;
   scheduled_producer.for_each_key( [&]( const public_key_type& key ) {
      const auto& iter = _signature_providers.find( key );
      if( iter != _signature_providers.end() ) {
         num_relevant_signatures++;
      }
   } );

   auto irreversible_block_age = get_irreversible_block_age();

   // If the next block production opportunity is in the present or future, we're synced.
   if( !_production_enabled ) {
      _pending_block_mode = pending_block_mode::speculating;
   } else if( !_block_producer.is_producer( scheduled_producer_name ) ) {
      _pending_block_mode = pending_block_mode::speculating;
   } else if( num_relevant_signatures == 0 ) {
      elog( "Not producing block because I don't have any private keys relevant to authority: {authority}",
            ("authority", scheduled_producer.authority) );
      _pending_block_mode = pending_block_mode::speculating;
   } else if( _pause_production ) {
      ilog( "Not producing block because production is explicitly paused" );
      _pending_block_mode = pending_block_mode::speculating;
   } else if( _max_irreversible_block_age_us.count() >= 0 && irreversible_block_age >= _max_irreversible_block_age_us ) {
      elog( "Not producing block because the irreversible block is too old [age:{age}s, max:{max}s]",
            ("age", irreversible_block_age.count() / 1'000'000)( "max", _max_irreversible_block_age_us.count() / 1'000'000 ) );
      _pending_block_mode = pending_block_mode::speculating;
   }

   if( _pending_block_mode == pending_block_mode::speculating ) {
      auto head_block_age = start_time - chain.head_block_time();
      if( head_block_age > fc::seconds( 5 ) )
         return start_block_result::waiting_for_block;
   }

   if( _pending_block_mode == pending_block_mode::producing ) {
      const auto start_block_time = block_time - fc::microseconds( config::block_interval_us );
      if( start_time < start_block_time ) {
         fc_dlog( _log, "Not producing block waiting for production window {n} {bt}",
                  ("n", hbs->block_num + 1)( "bt", block_time ) );
         // start_block_time instead of block_time because schedule_delayed_production_loop calculates next block time from given time
         schedule_delayed_production_loop( _block_producer.calculate_producer_wake_up_time( chain, start_block_time ) );
         return start_block_result::waiting_for_production;
      }
   } else if( previous_pending_mode == pending_block_mode::producing ) {
      // just produced our last block of our round
      const auto start_block_time = block_time - fc::microseconds( config::block_interval_us );
      fc_dlog( _log, "Not starting speculative block until {bt}", ("bt", start_block_time) );
      schedule_delayed_production_loop( start_block_time );
      return start_block_result::waiting_for_production;
   }

   // determine whether producer_ha_plugin is enabled and allows production
   if ( producer_ha_plug->enabled() ) {
      if (!producer_ha_plug->is_active_and_leader()) {
         _pending_block_mode = pending_block_mode::speculating;
      } else if (!producer_ha_plug->can_produce(false) ) {
         fc_dlog(_log, ("Not producing block because producer_ha_plugin is not allowing producing."));
         // heuristic wait time before re-checking producer_ha_plug
         // 1/10 of the heartbeat time
         int64_t wait_time_us = producer_ha_plug->get_config().heart_beat_interval_ms * 100;
         const int64_t wait_time_us_min = 1000; // 1ms
         const int64_t wait_time_us_max = 50000; // 50ms
         wait_time_us = std::min(wait_time_us_max, std::max(wait_time_us, wait_time_us_min));
         schedule_delayed_production_loop(start_time + fc::microseconds(wait_time_us));
         return start_block_result::waiting_for_production;
      }
   }

   fc_dlog( _log, "Starting block #{n} at {time} producer {p}",
            ("n", hbs->block_num + 1)( "time", start_time )( "p", scheduled_producer_name.to_string() ) );

   try {
      uint16_t blocks_to_confirm = 0;

      if( _pending_block_mode == pending_block_mode::producing ) {
         // determine how many blocks this producer can confirm
         // 1) if it is not a producer from this node, assume no confirmations (we will discard this block anyway)
         // 2) if it is a producer on this node that has never produced, the conservative approach is to assume no
         //    confirmations to make sure we don't double sign after a crash TODO: make these watermarks durable?
         // 3) if it is a producer on this node where this node knows the last block it produced, safely set it -UNLESS-
         // 4) the producer on this node's last watermark is higher (meaning on a different fork)
         blocks_to_confirm = _block_producer.get_blocks_to_confirm( scheduled_producer_name, hbs->block_num );

         // can not confirm irreversible blocks
         blocks_to_confirm = (uint16_t) (std::min<uint32_t>( blocks_to_confirm, (uint32_t) (hbs->block_num -
                                                                                            hbs->dpos_irreversible_blocknum) ));
      }

      abort_block();

      auto features_to_activate = chain.get_preactivated_protocol_features();
      if( _pending_block_mode == pending_block_mode::producing && _protocol_features_to_activate.size() > 0 ) {
         bool drop_features_to_activate = false;
         try {
            chain.validate_protocol_features( _protocol_features_to_activate );
         } catch( const std::bad_alloc& ) {
            log_and_drop_exceptions();
         } catch( const boost::interprocess::bad_alloc& ) {
            log_and_drop_exceptions();
         } catch( const fc::exception& e ) {
            wlog( "protocol features to activate are no longer all valid: {details}",
                  ("details", e.to_detail_string()) );
            drop_features_to_activate = true;
         } catch( const std::exception& e ) {
            wlog( "protocol features to activate are no longer all valid: {details}",
                  ("details", fc::std_exception_wrapper::from_current_exception( e ).to_detail_string()) );
            drop_features_to_activate = true;
         }

         if( drop_features_to_activate ) {
            _protocol_features_to_activate.clear();
         } else {
            auto protocol_features_to_activate = _protocol_features_to_activate; // do a copy as pending_block might be aborted
            if( features_to_activate.size() > 0 ) {
               protocol_features_to_activate.reserve( protocol_features_to_activate.size()
                                                      + features_to_activate.size() );
               std::set<digest_type> set_of_features_to_activate( protocol_features_to_activate.begin(),
                                                                  protocol_features_to_activate.end() );
               for( const auto& f: features_to_activate ) {
                  auto res = set_of_features_to_activate.insert( f );
                  if( res.second ) {
                     protocol_features_to_activate.push_back( f );
                  }
               }
               features_to_activate.clear();
            }
            std::swap( features_to_activate, protocol_features_to_activate );
            _protocol_features_signaled = true;
            ilog( "signaling activation of the following protocol features in block {num}: {features_to_activate}",
                  ("num", hbs->block_num + 1)("features_to_activate", features_to_activate) );
         }
      }

      chain.start_block( block_time, blocks_to_confirm, features_to_activate );
   } catch( ... ) {
      log_and_drop_exceptions();
   }

   if( chain.is_building_block() ) {
      const auto& pending_block_signing_authority = chain.pending_block_signing_authority();
      const fc::time_point preprocess_deadline = calculate_block_deadline( block_time );

      if( _pending_block_mode == pending_block_mode::producing && pending_block_signing_authority != scheduled_producer.authority ) {
         elog( "Unexpected block signing authority, reverting to speculative mode! [expected: \"{expected}\", actual: \"{actual\"",
               ("expected", scheduled_producer.authority)( "actual", pending_block_signing_authority ) );
         _pending_block_mode = pending_block_mode::speculating;
      }

      try {
         transaction_processor::process_result r =
               _transaction_processor.process_unapplied_trxs_start_block( chain, preprocess_deadline );
         switch (r) {
            case transaction_processor::process_result::exhausted :
               return start_block_result::exhausted;
            case transaction_processor::process_result::failed :
               return start_block_result::failed;
            case transaction_processor::process_result::succeeded :
               return start_block_result::succeeded;
         }

      } catch( const guard_exception& e ) {
         log_and_drop_exceptions();
         return start_block_result::failed;
      } catch( std::bad_alloc& ) {
         log_and_drop_exceptions();
      } catch( boost::interprocess::bad_alloc& ) {
         log_and_drop_exceptions();
      }

   }

   return start_block_result::failed;
}

bool producer::block_is_exhausted() const {
   const chain::controller& chain = *chain_control;
   const auto& rl = chain.get_resource_limits_manager();

   const uint64_t cpu_limit = rl.get_block_cpu_limit();
   if( cpu_limit < _max_block_cpu_usage_threshold_us ) return true;
   const uint64_t net_limit = rl.get_block_net_limit();
   if( net_limit < _max_block_net_usage_threshold_bytes ) return true;
   return false;
}


void producer::block_exhausted() {
   if( is_producing_block() ) {
      schedule_maybe_produce_block( true );
   } else {
      restart_speculative_block();
   }
}

void producer::restart_speculative_block() {
   chain::controller& chain = *chain_control;
   // abort the pending block
   _transaction_processor.aborted_block( chain.abort_block() );

   schedule_production_loop();
}

// Example:
// --> Start block A (block time x.500) at time x.000
// -> start_block()
// --> deadline, produce block x.500 at time x.400 (assuming 80% cpu block effort)
// -> Idle
// --> Start block B (block time y.000) at time x.500
void producer::schedule_production_loop() {
   _producer_timer->cancel();

   auto result = start_block();

   if( result == start_block_result::failed ) {
      _producer_timer->schedule_production_later( this->weak_from_this() );
   } else if( result == start_block_result::waiting_for_block ) {
      if( _block_producer.has_producers() && !production_disabled_by_policy() ) {
         chain::controller& chain = *chain_control;
         fc_dlog( _log, "Waiting till another block is received and scheduling Speculative/Production Change" );
         schedule_delayed_production_loop( _block_producer.calculate_producer_wake_up_time( chain, _block_producer.calculate_pending_block_time( chain ) ) );
      } else {
         fc_dlog( _log, "Waiting till another block is received" );
         // nothing to do until more blocks arrive
      }

   } else if( result == start_block_result::waiting_for_production ) {
      // scheduled in start_block()

   } else if( _pending_block_mode == pending_block_mode::producing ) {
      schedule_maybe_produce_block( result == start_block_result::exhausted );

   } else if( _pending_block_mode == pending_block_mode::speculating && _block_producer.has_producers() && !production_disabled_by_policy() ) {
      chain::controller& chain = *chain_control;
      fc_dlog( _log, "Speculative Block Created; Scheduling Speculative/Production Change" );
      EOS_ASSERT( chain.is_building_block(), missing_pending_block_state, "speculating without pending_block_state" );
      schedule_delayed_production_loop( _block_producer.calculate_producer_wake_up_time( chain, chain.pending_block_time() ) );
   } else {
      fc_dlog( _log, "Speculative Block Created" );
   }
}

void producer::schedule_maybe_produce_block( bool exhausted ) {
   chain::controller& chain = *chain_control;

   EOS_ASSERT( chain.is_building_block(), missing_pending_block_state, "producing without pending_block_state" );

   auto deadline = calculate_block_deadline( chain.pending_block_time() );

   _producer_timer->schedule_maybe_produce_block( this->weak_from_this(), exhausted, deadline, chain.head_block_num() + 1 );
}

void producer::schedule_delayed_production_loop( std::optional<fc::time_point> wake_up_time ) {
   if( wake_up_time ) {
      _producer_timer->schedule_delayed_production_loop( this->weak_from_this(), *wake_up_time );
   }
}

bool producer::maybe_produce_block() {
   chain::controller& chain = *chain_control;

   const auto block_num = chain.is_building_block() ? chain.head_block_num() + 1 : 0;
   fc_dlog( _log, "Produce block timer for {num} running at {time}",
            ("num", block_num)("time", fc::time_point::now()) );

   if(chain_plug != nullptr) {
      if(!chain_plug->background_snapshots_disabled()) {
         if (block_num % background_snapshot_write_period_in_blocks == 0) {
            chain_plug->create_snapshot_background();
         }
      }
   }

   auto reschedule = fc::make_scoped_exit( [this] { schedule_production_loop(); } );

   if( _produce_block_tracker.waiting() ) {
      fc_dlog( _log, "Produced Block #{num} returned: waiting", ("num", block_num) );
      return false;
   }

   try {
      produce_block();
      fc_dlog( _log, "Produced Block #{num} returned: true", ("num", block_num) );
      return true;
   } catch( ... ) {
      log_and_drop_exceptions();
   }

   fc_wlog( _log, "Aborting block due to produce_block error" );
   abort_block();
   fc_dlog( _log, "Produced Block #{num} returned: false", ("num", block_num) );
   return false;
}

static auto make_debug_time_logger() {
   auto start = fc::time_point::now();
   return fc::make_scoped_exit( [=]() {
      fc_dlog( _log, "Signing took {ms}us", ("ms", fc::time_point::now() - start) );
   } );
}

static auto maybe_make_debug_time_logger() -> std::optional<decltype( make_debug_time_logger() )> {
   if( _log.is_enabled( fc::log_level::debug ) ) {
      return make_debug_time_logger();
   } else {
      return {};
   }
}

void producer::produce_block() {
   //ilog("produce_block {t}", ("t", now())); // for testing _produce_time_offset_us
   EOS_ASSERT( is_producing_block(), producer_exception, "called produce_block while not actually producing" );
   chain::controller& chain = *chain_control;
   EOS_ASSERT( chain.is_building_block(), missing_pending_block_state,
               "pending_block_state does not exist but it should, another plugin may have corrupted it" );

   const auto& auth = chain.pending_block_signing_authority();
   std::vector<std::reference_wrapper<const signature_provider_type>> relevant_providers;

   relevant_providers.reserve( _signature_providers.size() );

   producer_authority::for_each_key( auth, [&]( const public_key_type& key ) {
      const auto& iter = _signature_providers.find( key );
      if( iter != _signature_providers.end() ) {
         relevant_providers.emplace_back( iter->second );
      }
   } );

   EOS_ASSERT( relevant_providers.size() > 0, producer_priv_key_not_found,
               "Attempting to produce a block for which we don't have any relevant private keys" );

   if( _protocol_features_signaled ) {
      _protocol_features_to_activate.clear(); // clear _protocol_features_to_activate as it is already set in pending_block
      _protocol_features_signaled = false;
   }

   _produce_block_tracker.set_pending();
   auto f = chain.finalize_block( [relevant_providers = std::move( relevant_providers ),
                                   producer_ha_plug = producer_ha_plug,
                                   self = this->shared_from_this()](
                                         block_state_ptr bsp, bool wtmsig_enabled, const digest_type& d ) {
      /// This lambda is called from a separate thread to sign and complete the block, including committing through
      /// producer_ha if it is enabled
      auto debug_logger = maybe_make_debug_time_logger();
      auto on_exit = fc::make_scoped_exit( [self] {
         /// This lambda will always be called after the signing is finished. The purpose is to signal main thread for the
         /// completion of the block signing regardless the block signing is successful or not. The main thread should
         /// then call `complete_produced_block_fut.get()()` to complete the block. If the block signing fails, calling
         /// `complete_produced_block_fut.get()()` would throw an exception so that the caller can handle the situation.
         self->_produce_block_tracker.set_ready();
         app().post( priority::high, [self]() {
            /// This lambda will be executed in main thread
            /// false: has failure, need to abort the block
            /// true: nothing to do, or have completed the produced block
            bool dont_abort = self->_produce_block_tracker.complete_produced_block_if_ready( *self->chain_control );
            /// abort the block, failed to produce it
            if (!dont_abort) {
               try {
                  self->abort_block();
               } FC_LOG_AND_DROP()
            }
         } );
      } );
      std::vector<signature_type> signatures;
      signatures.reserve( relevant_providers.size() );
      std::transform( relevant_providers.begin(), relevant_providers.end(), std::back_inserter( signatures ),
                      [&d]( const auto& p ) { return p.get()( d ); } );
      bsp->assign_signatures(std::move(signatures), wtmsig_enabled);
      /// Commit the block in Raft by producer_ha plugin
      producer_ha_plug->commit_head_block(bsp->block);
   } );

   block_state_ptr new_bs = chain.head_block_state();

   _produce_block_tracker.set_block_id(new_bs->id);
   _produce_block_tracker.set_completed_block_future( std::move( f ) );

   ilog( "Built block {id}... #{n} @ {t} to be signed by {p} [trxs: {count}, lib: {lib}, confirmed: {confs}]",
         ("p", new_bs->header.producer.to_string())("id", new_bs->id.str().substr( 8, 16 ))
         ("n", new_bs->block_num)("t", new_bs->header.timestamp.to_time_point())
         ("count", new_bs->block->transactions.size())("lib", chain.last_irreversible_block_num())("confs", new_bs->header.confirmed) );
}

void producer::pause() {
   if ( producer_ha_plug->enabled() ) {
      fc_ilog(_log, "pause API not available with producer_ha_plugin enabled. producer_ha_plugin controls the block production status automatically.");
      return;
   }
   fc_ilog(_log, "Producer paused.");
   _pause_production = true;
}

void producer::resume() {
   if ( producer_ha_plug->enabled() ) {
      fc_ilog(_log, "resume API not available with producer_ha_plugin enabled. producer_ha_plugin controls the block production status automatically.");
      return;
   }
   _pause_production = false;
   // it is possible that we are only speculating because of this policy which we have now changed
   // re-evaluate that now
   //
   if (_pending_block_mode == pending_block_mode::speculating) {
      abort_block();
      fc_ilog(_log, "Producer resumed. Scheduling production.");
      schedule_production_loop();
   } else {
      fc_ilog(_log, "Producer resumed.");
   }
}

chain::signature_type producer::sign_compact(const chain::public_key_type& key, const fc::sha256& digest) const {
   if(key != chain::public_key_type()) {
      auto private_key_itr = _signature_providers.find(key);
      EOS_ASSERT(private_key_itr != _signature_providers.end(), producer_priv_key_not_found,
                 "Local producer has no private key in config.ini corresponding to public key {key}", ("key", key));

      return private_key_itr->second(digest);
   } else {
      return chain::signature_type();
   }
}

integrity_hash_information producer::get_integrity_hash() {
   chain::controller& chain = *chain_control;

   auto reschedule = fc::make_scoped_exit([this](){
      schedule_production_loop();
   });

   if (chain.is_building_block()) {
      // abort the pending block
      abort_block();
   } else {
      reschedule.cancel();
   }

   return {chain.head_block_id(), chain.calculate_integrity_hash()};
}

void producer::schedule_protocol_feature_activations( const std::vector<chain::digest_type>& protocol_features_to_activate ) {
   const chain::controller& chain = *chain_control;
   std::set<digest_type> set_of_features_to_activate( protocol_features_to_activate.begin(), protocol_features_to_activate.end() );
   EOS_ASSERT( set_of_features_to_activate.size() == protocol_features_to_activate.size(), invalid_protocol_features_to_activate, "duplicate digests" );
   chain.validate_protocol_features( protocol_features_to_activate );
   const auto& pfs = chain.get_protocol_feature_manager().get_protocol_feature_set();
   for (auto &feature_digest : set_of_features_to_activate) {
      const auto& pf = pfs.get_protocol_feature(feature_digest);
      EOS_ASSERT( !pf.preactivation_required, protocol_feature_exception, "protocol feature requires preactivation: {digest}",
                  ("digest", feature_digest));
   }
   _protocol_features_to_activate = protocol_features_to_activate;
   _protocol_features_signaled = false;
}

void producer::create_snapshot(next_function<snapshot_information> next) {
   const chain::controller& chain = *chain_control;
   auto reschedule = fc::make_scoped_exit([this](){
      schedule_production_loop();
   });

   if (chain.is_building_block()) {
      // abort the pending block
      abort_block();
   } else {
      reschedule.cancel();
   }

   _pending_snapshot_tracker.create_snapshot(chain, next);
}

void producer::handle_sighup() {
   fc::logger::update( logger_name, _log );
   _transaction_processor.handle_sighup();
}

void producer::startup() {
   chain::controller& chain = *chain_control;

   chain_plug = app().find_plugin<chain_plugin>();

   producer_ha_plug = app().find_plugin<producer_ha_plugin>();

   // The producer_ha_plugin struct should be not null, as the object is static. disabled() tells whether
   // it is enabled and loaded
   EOS_ASSERT( producer_ha_plug != nullptr, chain::plugin_exception,
              "producer_ha_plug is nullptr. Should not happen." );

   _accepted_block_connection.emplace( chain.accepted_block.connect( [this]( const auto& bsp ) { on_block( bsp ); } ) );
   _accepted_block_header_connection.emplace( chain.accepted_block_header.connect( [this]( const auto& bsp ) { on_block_header( bsp ); } ) );
   _irreversible_block_connection.emplace( chain.irreversible_block.connect( [this]( const auto& bsp ) { on_irreversible_block( bsp->block ); } ) );

   const auto lib_num = chain.last_irreversible_block_num();
   const auto lib = chain.fetch_block_by_number( lib_num );
   if( lib ) {
      on_irreversible_block( lib );
   } else {
      _irreversible_block_time = fc::time_point::maximum();
   }

   schedule_production_loop();
}

void producer::shutdown() {
   try {
      _producer_timer->cancel();
   } catch( ... ) {
      log_and_drop_exceptions();
   }

   // handle the completing (un-finalized) block
   // if there is a completing block, mark it failed.
   // the producer_plugin::shutdown() called later will abort it.
   // if no producer_ha enabled:
   //    this block is not finalized at all. Fine to discard it.
   // if producer_ha is enabled:
   //    this block may have been signed, but being or have been committed with producer_ha
   //        if the block is not committed yet
   //              the block is not finalized at all, fine to discard it.
   //        if the block has been committed successfully
   //              the block is already accepted by another producer, so discarding this block in this node is also fine
   auto finalizing_block_id = _produce_block_tracker.get_block_id();
   if (finalizing_block_id != chain::block_id_type{}) {
      ilog("Marking the block {id} being completed to be failed during shutdown()", ("id", finalizing_block_id));
      chain_control->mark_completing_failed_blockid(finalizing_block_id);
   }

   _transaction_processor.stop();

   app().post( priority::lowest, [me = this->shared_from_this()](){} ); // keep my pointer alive until queue is drained
}

} // namespace eosio

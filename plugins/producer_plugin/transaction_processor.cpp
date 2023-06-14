#include <eosio/producer_plugin/transaction_processor.hpp>
#include <eosio/producer_plugin/producer.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/unapplied_transaction_queue.hpp>
#include <eosio/chain/to_string.hpp>

#include <appbase/application.hpp>

#include <fc/time.hpp>
#include <fc/log/logger_config.hpp>
#include <fc/log/custom_formatter.hpp>

#include <memory>

namespace {

const std::string logger_name("producer_plugin");
fc::logger _log;

const std::string trx_successful_trace_logger_name("transaction_success_tracing");
fc::logger       _trx_successful_trace_log;

const std::string trx_failed_trace_logger_name("transaction_failure_tracing");
fc::logger       _trx_failed_trace_log;

const std::string trx_trace_success_logger_name("transaction_trace_success");
fc::logger       _trx_trace_success_log;

const std::string trx_trace_failure_logger_name("transaction_trace_failure");
fc::logger       _trx_trace_failure_log;

const std::string trx_logger_name("transaction");
fc::logger       _trx_log;

} // anonymous namespace

namespace eosio {

using namespace eosio::chain;
using namespace appbase;

void log_and_drop_exceptions();

bool exception_is_exhausted(const fc::exception& e) {
   auto code = e.code();
   return (code == block_cpu_usage_exceeded::code_value) ||
          (code == block_net_usage_exceeded::code_value) ||
          (code == deadline_exception::code_value);
}

void transaction_processor::start( size_t num_threads) {
   _thread_pool.emplace( "prod", num_threads );

}

void transaction_processor::stop() {
   if( _thread_pool ) {
      _thread_pool->stop();
   }
}

void transaction_processor::on_block( const block_state_ptr& bsp ) {
   auto before = _unapplied_transactions.size();
   _unapplied_transactions.clear_applied( bsp );
   _subjective_billing.on_block( bsp, fc::time_point::now() );
   fc_dlog( _log, "Removed applied transactions before: {before}, after: {after}",
            ("before", before)("after", _unapplied_transactions.size()) );
}

// Can be called from any thread. Called from net threads
void transaction_processor::on_incoming_transaction_async( chain::controller& chain,
                                                           const packed_transaction_ptr& trx,
                                                           bool persist_until_expired,
                                                           const bool read_only,
                                                           const bool return_failure_trace,
                                                           next_function<transaction_trace_ptr> next )
{
   auto future = transaction_metadata::start_recover_keys( trx, _thread_pool->get_executor(), chain.get_chain_id(),
                                                           get_max_transaction_time(),
                                                           read_only ? transaction_metadata::trx_type::read_only
                                                                     : transaction_metadata::trx_type::input,
                                                           chain.configured_subjective_signature_length_limit() );

   // producer keeps this alive
   boost::asio::post( _thread_pool->get_executor(),
       [prod = _producer.get_self(), self=this, future{std::move( future )}, persist_until_expired, return_failure_trace, next{std::move( next )}, trx]() mutable {
          if( future.valid() ) {
             future.wait();
             app().post( priority::low,
                [prod{std::move(prod)}, self=self, future{std::move( future )}, persist_until_expired, next{std::move( next )},
                 trx{std::move( trx )}, return_failure_trace]() mutable {
                   auto exception_handler = [prod, &next, trx{std::move( trx )}]( fc::exception_ptr ex ) {
                      fc_dlog( _trx_failed_trace_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {txid}, auth: {a} : {why} ",
                               ("txid", trx->id())("a", trx->get_transaction().first_authorizer().to_string())("why", ex->what()) );
                      next( ex );

                      fc_dlog( _trx_trace_failure_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {entire_trx}",
                               ("entire_trx", fc::action_expander<transaction>{trx->get_transaction(), &prod->get_chain()} ) );
                      fc_dlog( _trx_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {trx}",
                               ("trx", fc::action_expander<transaction>{trx->get_transaction(), &prod->get_chain()}) );
                   };
                   try {
                      auto result = future.get();
                      if( !self->process_incoming_transaction( prod->get_chain(), result, persist_until_expired, next, return_failure_trace ) ) {
                         prod->block_exhausted();
                      }
                   } CATCH_AND_CALL( exception_handler );
                } );
          }
       } );
}

// @param trx lifetime of returned lambda can't extend past &trx or &next
auto make_send_response( const producer& prod, const controller& chain, const transaction_metadata_ptr& trx,
                         next_function <transaction_trace_ptr>& next ) {

   return [&trx, &prod=prod, &chain=chain, &next]( const std::variant<fc::exception_ptr, transaction_trace_ptr>& response ) {
      next( response );
      fc::exception_ptr except_ptr; // rejected
      if( std::holds_alternative<fc::exception_ptr>( response ) ) {
         except_ptr = std::get<fc::exception_ptr>( response );
      } else if( std::get<transaction_trace_ptr>( response )->except ) {
         except_ptr = std::get<transaction_trace_ptr>( response )->except->dynamic_copy_exception();
      }

      if( !trx->read_only ) {
         prod._transaction_ack( except_ptr, trx );
      }

      if( except_ptr ) {
         if( prod.is_producing_block() ) {
            fc_dlog(_trx_failed_trace_log, "[TRX_TRACE] Block {block_num} for producer {prod} is REJECTING tx: {txid}, auth: {a} : {why} ",
                    ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                    ("txid", trx->id())
                    ("a", trx->packed_trx()->get_transaction().first_authorizer().to_string())
                    ("why",except_ptr->what()));

            fc_dlog(_trx_log, "[TRX_TRACE] Block {block_num} for producer {prod} is REJECTING tx: {trx}",
                    ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                    ("trx", fc::action_expander<transaction>{trx->packed_trx()->get_transaction(), &chain}));

            if (std::holds_alternative<fc::exception_ptr>(response)) {
               fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Block {block_num} for producer {prod} is REJECTING tx: {entire_trace}",
                       ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                       ("entire_trace", *std::get<fc::exception_ptr>(response)));
            } else {
               fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Block {block_num} for producer {prod} is REJECTING tx: {entire_trace}",
                       ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                       ("entire_trace", fc::action_expander<transaction_trace>{*std::get<transaction_trace_ptr>(response), &chain}));
            }
         } else {
            fc_dlog(_trx_failed_trace_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {txid}, auth: {a} : {why} ",
                    ("txid", trx->id())
                    ("a", trx->packed_trx()->get_transaction().first_authorizer().to_string())
                    ("why",except_ptr->what()));

            fc_dlog(_trx_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {trx} ",
                    ("trx", fc::action_expander<transaction>{trx->packed_trx()->get_transaction(), &chain}));
            if (std::holds_alternative<fc::exception_ptr>(response)) {
               fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {entire_trace} ",
                       ("entire_trace", *std::get<fc::exception_ptr>(response)));
            } else {
               fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {entire_trace} ",
                       ("entire_trace", fc::action_expander<transaction_trace>{*std::get<transaction_trace_ptr>(response), &chain}));
            }
         }
      } else {
         if( prod.is_producing_block() ) {
            fc_dlog(_trx_successful_trace_log, "[TRX_TRACE] Block {block_num} for producer {prod} is ACCEPTING tx: {txid}, auth: {a}",
                    ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                    ("txid", trx->id())
                    ("a", trx->packed_trx()->get_transaction().first_authorizer().to_string()));

            fc_dlog(_trx_log, "[TRX_TRACE] Block {block_num} for producer {prod} is ACCEPTING tx: {trx}",
                    ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                    ("trx", fc::action_expander<transaction>{trx->packed_trx()->get_transaction(), &chain}));
            if (std::holds_alternative<fc::exception_ptr>(response)) {
               fc_dlog(_trx_trace_success_log, "[TRX_TRACE] Block {block_num} for producer {prod} is ACCEPTING tx: {entire_trace}",
                       ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                       ("entire_trace", *std::get<fc::exception_ptr>(response)));
            } else {
               fc_dlog(_trx_trace_success_log, "[TRX_TRACE] Block {block_num} for producer {prod} is ACCEPTING tx: {entire_trace}",
                       ("block_num", chain.head_block_num() + 1)("prod", prod.get_pending_block_producer().to_string())
                       ("entire_trace", fc::action_expander<transaction_trace>{*std::get<transaction_trace_ptr>(response), &chain}));
            }
         } else {
            fc_dlog(_trx_successful_trace_log, "[TRX_TRACE] Speculative execution is ACCEPTING tx: {txid}, auth: {a}",
                    ("txid", trx->id())
                     ("a", trx->packed_trx()->get_transaction().first_authorizer().to_string()));

            fc_dlog(_trx_log, "[TRX_TRACE] Speculative execution is ACCEPTING tx: {trx}",
                    ("trx", fc::action_expander<transaction>{trx->packed_trx()->get_transaction(), &chain}));
            if (std::holds_alternative<fc::exception_ptr>(response)) {
               fc_dlog(_trx_trace_success_log, "[TRX_TRACE] Speculative execution is ACCEPTING tx: {entire_trace}",
                       ("entire_trace", *std::get<fc::exception_ptr>(response)));
            } else {
               fc_dlog(_trx_trace_success_log, "[TRX_TRACE] Speculative execution is ACCEPTING tx: {entire_trace}",
                       ("entire_trace", fc::action_expander<transaction_trace>{*std::get<transaction_trace_ptr>(response), &chain}));
            }
         }
      }
   };
}

bool transaction_processor::process_incoming_transaction( chain::controller& chain,
                                                          const transaction_metadata_ptr& trx,
                                                          bool persist_until_expired,
                                                          next_function<transaction_trace_ptr> next,
                                                          const bool return_failure_trace )
{
   bool exhausted = false;

   auto send_response = make_send_response( _producer, chain, trx, next );

   try {
      const auto& id = trx->id();

      fc::time_point bt = chain.is_building_block() ? chain.pending_block_time() : chain.head_block_time();
      const fc::time_point expire = trx->packed_trx()->expiration();
      if( expire < bt ) {
         send_response( std::static_pointer_cast<fc::exception>(
               std::make_shared<expired_tx_exception>(
                     FC_LOG_MESSAGE( error, "expired transaction {id}, expiration {e}, block time {bt}",
                                     ("id", id)("e", expire)("bt", bt) ) ) ) );
         return true;
      }

      if( chain.is_known_unexpired_transaction( id ) ) {
         send_response( std::static_pointer_cast<fc::exception>( std::make_shared<tx_duplicate>(
               FC_LOG_MESSAGE( error, "duplicate transaction {id}", ("id", id) ) ) ) );
         return true;
      }

      if( !chain.is_building_block() ) {
         _unapplied_transactions.add_incoming( trx, persist_until_expired, return_failure_trace, next );
         return true;
      }

      fc::microseconds max_transaction_time = get_max_transaction_time();
      const auto block_deadline = _producer.calculate_block_deadline( chain.pending_block_time() );
      bool disable_subjective_billing = _producer.is_producing_block()
                                        || (persist_until_expired && _disable_subjective_api_billing)
                                        || (!persist_until_expired && _disable_subjective_p2p_billing);

      auto first_auth = trx->packed_trx()->get_transaction().first_authorizer();
      uint32_t sub_bill = 0;
      if( !disable_subjective_billing )
         sub_bill = _subjective_billing.get_subjective_bill( first_auth, fc::time_point::now() );

      auto trace = chain.push_transaction( trx, block_deadline, max_transaction_time, trx->billed_cpu_time_us, false, sub_bill );
      fc_dlog( _trx_failed_trace_log, "Subjective bill for {a}: {b} elapsed {t}us",
               ("a", first_auth)("b", sub_bill)("t", trace->elapsed) );
      if( trace->except ) {
         if( exception_is_exhausted( *trace->except ) ) {
            _unapplied_transactions.add_incoming( trx, persist_until_expired, return_failure_trace, next );
            if( _producer.is_producing_block() ) {
               fc_dlog( _log, "[TRX_TRACE] Block {block_num} for producer {prod} COULD NOT FIT, tx: {txid} RETRYING, ec: {c} ",
                        ("block_num", chain.head_block_num() + 1)
                        ("prod", _producer.get_pending_block_producer().to_string() )("txid", trx->id())("c", trace->except->code()) );
            } else {
               fc_dlog( _log, "[TRX_TRACE] Speculative execution COULD NOT FIT tx: {txid} RETRYING, ec: {c}",
                        ("txid", trx->id())("c", trace->except->code()) );
            }
            exhausted = _producer.block_is_exhausted();
         } else {
            _subjective_billing.subjective_bill_failure( first_auth, trace->elapsed, fc::time_point::now() );
            if( return_failure_trace ) {
               send_response( trace );
            } else {
               auto e_ptr = trace->except->dynamic_copy_exception();
               send_response( e_ptr );
            }
         }
      } else {
         if( persist_until_expired && !_disable_persist_until_expired ) {
            // if this trx didnt fail/soft-fail and the persist flag is set, store its ID so that we can
            // ensure its applied to all future speculative blocks as well.
            // No need to subjective bill since it will be re-applied
            _unapplied_transactions.add_persisted( trx );
         } else {
            // if db_read_mode SPECULATIVE then trx is in the pending block and not immediately reverted
            _subjective_billing.subjective_bill( trx->id(), expire, first_auth, trace->elapsed,
                                                 chain.get_read_mode() == chain::db_read_mode::SPECULATIVE );
         }
         send_response( trace );
      }

   } catch( const guard_exception& e ) {
      log_and_drop_exceptions();
      send_response(e.dynamic_copy_exception());
   } catch( boost::interprocess::bad_alloc& ) {
      log_and_drop_exceptions();
   } catch( std::bad_alloc& ) {
      log_and_drop_exceptions();
   } CATCH_AND_CALL( send_response );

   return !exhausted;
}

transaction_processor::process_result
transaction_processor::process_unapplied_trxs_start_block( chain::controller& chain, const fc::time_point& deadline ) {
   if( !remove_expired_trxs( chain, deadline ) )
      return process_result::exhausted;

   if( !_produce_block_tracker.complete_produced_block_if_ready( chain ) )
      return process_result::failed;

   if( !_subjective_billing.remove_expired( _log, chain.pending_block_time(), fc::time_point::now(), deadline ) )
      return process_result::exhausted;

   if( !_produce_block_tracker.complete_produced_block_if_ready( chain ) )
      return process_result::failed;

   // limit execution of pending incoming to once per block
   size_t pending_incoming_process_limit = _unapplied_transactions.incoming_size();

   auto process_unapplied_trxs_result = process_unapplied_trxs( chain, deadline );
   if( process_unapplied_trxs_result != process_result::succeeded )
      return process_unapplied_trxs_result;

   if( !_produce_block_tracker.complete_produced_block_if_ready( chain ) )
      return process_result::failed;

   if( app().is_quiting() ) // db guard exception above in log_and_drop_exceptions() could have called app().quit()
      return process_result::failed;

   if( !process_incoming_trxs( chain, deadline, pending_incoming_process_limit ) )
      return process_result::exhausted;

   return process_result::succeeded;
}


bool transaction_processor::remove_expired_trxs( const chain::controller& chain, const fc::time_point& deadline ) {
   auto pending_block_time = chain.pending_block_time();

   // remove all expired transactions
   size_t num_expired_persistent = 0;
   size_t num_expired_other = 0;
   size_t orig_count = _unapplied_transactions.size();
   bool exhausted = !_unapplied_transactions.clear_expired( pending_block_time, deadline,
      [&num_expired_persistent, &num_expired_other, &chain, &prod = _producer]
      (const packed_transaction_ptr& packed_trx_ptr, trx_enum_type trx_type ) {
         if( trx_type == trx_enum_type::persisted ) {
            if( prod.is_producing_block() ) {
               fc_dlog( _trx_failed_trace_log, "[TRX_TRACE] Block {block_num} for producer {prod} is EXPIRING PERSISTED tx: {txid}",
                        ("block_num", chain.head_block_num() + 1)("txid", packed_trx_ptr->id())
                        ("prod", chain.is_building_block() ? chain.pending_block_producer().to_string() : name().to_string()) );
               fc_dlog( _trx_log, "[TRX_TRACE] Block {block_num} for producer {prod} is EXPIRING PERSISTED tx: {trx}",
                        ("block_num", chain.head_block_num() + 1)("prod", chain.is_building_block() ? chain.pending_block_producer().to_string() : name().to_string())
                        ("trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
               fc_dlog( _trx_trace_failure_log, "[TRX_TRACE] Block {block_num} for producer {prod} is EXPIRING PERSISTED tx: {entire_trx}",
                        ("block_num", chain.head_block_num() + 1)("prod", chain.is_building_block() ? chain.pending_block_producer().to_string() : name().to_string())
                        ("entire_trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
            } else {
               fc_dlog( _trx_failed_trace_log, "[TRX_TRACE] Speculative execution is EXPIRING PERSISTED tx: {txid}",
                        ("txid", packed_trx_ptr->id()) );
               fc_dlog( _trx_log, "[TRX_TRACE] Speculative execution is EXPIRING PERSISTED tx: {trx}",
                        ("trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
               fc_dlog( _trx_trace_failure_log, "[TRX_TRACE] Speculative execution is EXPIRING PERSISTED tx: {entire_trx}",
                        ("entire_trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
            }
            ++num_expired_persistent;
         } else {
            if( prod.has_producers() ) {
               fc_dlog( _trx_failed_trace_log, "[TRX_TRACE] Node with producers configured is dropping an EXPIRED transaction that was PREVIOUSLY ACCEPTED : {txid}",
                        ("txid", packed_trx_ptr->id()) );
               fc_dlog( _trx_log, "[TRX_TRACE] Node with producers configured is dropping an EXPIRED transaction that was PREVIOUSLY ACCEPTED: {trx}",
                        ("trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
               fc_dlog( _trx_trace_failure_log, "[TRX_TRACE] Node with producers configured is dropping an EXPIRED transaction that was PREVIOUSLY ACCEPTED: {entire_trx}",
                        ("entire_trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
            }
            ++num_expired_other;
         }
      } );

   if( exhausted ) {
      fc_wlog( _log, "Unable to process all expired transactions in unapplied queue before deadline, "
                     "Persistent expired {persistent_expired}, Other expired {other_expired}",
               ("persistent_expired", num_expired_persistent)("other_expired", num_expired_other) );
   } else {
      fc_dlog( _log, "Processed {m} expired transactions of the {n} transactions in the unapplied queue, "
                     "Persistent expired {persistent_expired}, Other expired {other_expired}",
               ("m", num_expired_persistent + num_expired_other)( "n", orig_count )
               ("persistent_expired", num_expired_persistent)("other_expired", num_expired_other) );
   }

   return !exhausted;
}

transaction_processor::process_result
transaction_processor::process_unapplied_trxs( chain::controller& chain, const fc::time_point& deadline ) {
   process_result result = process_result::succeeded;
   if( !_unapplied_transactions.empty() ) {
      const auto& rl = chain.get_resource_limits_manager();
      int num_applied = 0, num_failed = 0, num_processed = 0;
      auto unapplied_trxs_size = _unapplied_transactions.size();
      // unapplied and persisted do not have a next method to call
      auto itr = _producer.is_producing_block() ?
                 _unapplied_transactions.unapplied_begin() : _unapplied_transactions.persisted_begin();
      auto end_itr = _producer.is_producing_block() ?
                     _unapplied_transactions.unapplied_end() : _unapplied_transactions.persisted_end();
      fc::microseconds max_transaction_time = get_max_transaction_time();
      while( itr != end_itr ) {
         if( deadline <= fc::time_point::now() ) {
            result = process_result::exhausted;
            break;
         }
         // do not complete_produced_block_if_ready() as that can modify the unapplied_transaction queue erasing itr

         const transaction_metadata_ptr trx = itr->trx_meta;
         ++num_processed;
         try {
            auto start = fc::time_point::now();
            auto max_trx_time = max_transaction_time;
            auto first_auth = trx->packed_trx()->get_transaction().first_authorizer();
            auto prev_billed_cpu_time_us = trx->billed_cpu_time_us;
            if( !_subjective_billing.is_disabled() && prev_billed_cpu_time_us > 0 && !rl.is_unlimited_cpu( first_auth ) ) {
               auto prev_billed_plus100 = fc::microseconds(
                     prev_billed_cpu_time_us + EOS_PERCENT( prev_billed_cpu_time_us, 100 * config::percent_1 ) );
               if( prev_billed_plus100 < max_trx_time ) max_trx_time = prev_billed_plus100;
            }
            // no subjective billing since we are producing or processing persisted trxs
            const uint32_t sub_bill = 0;

            auto trace = chain.push_transaction( trx, deadline, max_trx_time, prev_billed_cpu_time_us, false, sub_bill );
            fc_dlog( _trx_failed_trace_log, "Subjective unapplied bill for {a}: {b} prev {t}us",
                     ("a", first_auth)( "b", prev_billed_cpu_time_us )( "t", trace->elapsed ) );
            if( trace->except ) {
               if( exception_is_exhausted( *trace->except ) ) {
                  if( _producer.block_is_exhausted() ) {
                     result = process_result::exhausted;
                     // don't erase, subjective failure so try again next time
                     break;
                  }
                  // don't erase, subjective failure so try again next time
               } else {
                  fc_dlog( _trx_failed_trace_log, "Subjective unapplied bill for failed {a}: {b} prev {t}us",
                           ("a", first_auth.to_string())("b", prev_billed_cpu_time_us)("t", trace->elapsed) );
                  auto failure_code = trace->except->code();
                  if( failure_code != tx_duplicate::code_value ) {
                     // this failed our configured maximum transaction time, we don't want to replay it
                     fc_dlog( _log, "Failed {c} trx, prev billed: {p}us, ran: {r}us, id: {id}",
                              ("c", trace->except->code())("p", prev_billed_cpu_time_us)
                              ("r", fc::time_point::now() - start)("id", trx->id()) );
                     _subjective_billing.subjective_bill_failure( first_auth, trace->elapsed, fc::time_point::now() );
                  }
                  ++num_failed;
                  if( itr->next ) {
                     if( itr->return_failure_trace ) {
                        itr->next( trace );
                     } else {
                        itr->next( trace->except->dynamic_copy_exception() );
                     }
                  }
                  itr = _unapplied_transactions.erase( itr );
                  continue;
               }
            } else {
               fc_dlog( _trx_successful_trace_log, "Subjective unapplied bill for success {a}: {b} prev {t}us",
                        ("a", first_auth.to_string())( "b", prev_billed_cpu_time_us )( "t", trace->elapsed ) );
               // if db_read_mode SPECULATIVE then trx is in the pending block and not immediately reverted
               _subjective_billing.subjective_bill( trx->id(), trx->packed_trx()->expiration(), first_auth,
                                                    trace->elapsed,
                                                    chain.get_read_mode() == chain::db_read_mode::SPECULATIVE );
               ++num_applied;
               if( itr->trx_type != trx_enum_type::persisted ) {
                  if( itr->next ) itr->next( trace );
                  itr = _unapplied_transactions.erase( itr );
                  continue;
               }
            }
         } catch( ... ) {
            log_and_drop_exceptions();
         }
         ++itr;
      }

      fc_dlog( _log,
               "Processed {m} of {n} previously applied transactions, Applied {applied}, Failed/Dropped {failed}",
               ("m", num_processed)( "n", unapplied_trxs_size )( "applied", num_applied )( "failed", num_failed ) );
   }
   return result;
}

bool
transaction_processor::process_incoming_trxs( chain::controller& chain, const fc::time_point& deadline, size_t& pending_incoming_process_limit ) {
   bool exhausted = false;
   if( pending_incoming_process_limit ) {
      size_t processed = 0;
      fc_dlog( _log, "Processing {n} pending transactions", ("n", pending_incoming_process_limit) );
      auto itr = _unapplied_transactions.incoming_begin();
      auto end = _unapplied_transactions.incoming_end();
      while( pending_incoming_process_limit && itr != end ) {
         if( deadline <= fc::time_point::now() ) {
            exhausted = true;
            break;
         }
         --pending_incoming_process_limit;
         auto trx_meta = itr->trx_meta;
         auto next = itr->next;
         bool persist_until_expired = itr->trx_type == trx_enum_type::incoming_persisted;
         bool return_failure_trace = itr->return_failure_trace;
         itr = _unapplied_transactions.erase( itr );
         ++processed;
         if( !process_incoming_transaction( chain, trx_meta, persist_until_expired, next, return_failure_trace ) ) {
            exhausted = true;
            break;
         }
      }
      fc_dlog( _log, "Processed {n} pending transactions, {p} left", ("n", processed)( "p", _unapplied_transactions.incoming_size() ) );
   }
   return !exhausted;
}

void transaction_processor::handle_sighup() {
   fc::logger::update( logger_name, _log );
   fc::logger::update( trx_successful_trace_logger_name, _trx_successful_trace_log );
   fc::logger::update( trx_failed_trace_logger_name, _trx_failed_trace_log );
   fc::logger::update( trx_trace_success_logger_name, _trx_trace_success_log );
   fc::logger::update( trx_trace_failure_logger_name, _trx_trace_failure_log );
   fc::logger::update( trx_logger_name, _trx_log );
}

void transaction_processor::log_failed_transaction( const chain::controller& chain, const transaction_id_type& trx_id,
                                                    const packed_transaction_ptr& packed_trx_ptr,
                                                    const char* reason ) {
   fc_dlog( _trx_failed_trace_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {txid} : {why}",
            ("txid", trx_id)( "why", reason ) );

   if (packed_trx_ptr) {
      fc_dlog(_trx_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {trx}",
              ("entire_trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
      fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {entire_trx}",
              ("entire_trx", fc::action_expander<transaction>{packed_trx_ptr->get_transaction(), &chain}));
   } else {
      fc_dlog(_trx_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {trx}",
              ("entire_trx", trx_id));
      fc_dlog(_trx_trace_failure_log, "[TRX_TRACE] Speculative execution is REJECTING tx: {entire_trx}",
              ("entire_trx", trx_id));
   }
}

// return variant of trace for logging, trace is modified to minimize log output
fc::variant transaction_processor::get_log_trx_trace( const chain::controller& chain,
                                                      const transaction_trace_ptr& trx_trace ) {
   fc::variant pretty_output;
   try {
      abi_serializer::to_log_variant( trx_trace, pretty_output,
                                      make_resolver( chain, abi_serializer::create_yield_function(chain.get_abi_serializer_max_time() ) ),
                                      abi_serializer::create_yield_function( chain.get_abi_serializer_max_time() ) );
   } catch( ... ) {
      pretty_output = trx_trace;
   }
   return pretty_output;
}

// return variant of trx for logging, trace is modified to minimize log output
fc::variant transaction_processor::get_log_trx( const chain::controller& chain, const transaction& trx ) {
   fc::variant pretty_output;
   try {
      abi_serializer::to_log_variant( trx, pretty_output,
                                      make_resolver( chain, abi_serializer::create_yield_function(chain.get_abi_serializer_max_time() ) ),
                                      abi_serializer::create_yield_function( chain.get_abi_serializer_max_time() ) );
   } catch( ... ) {
      pretty_output = trx;
   }
   return pretty_output;
}

} // namespace eosio

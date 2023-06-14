#pragma once

#include <eosio/chain/types.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/block_state.hpp>

namespace eosio {

void log_and_drop_exceptions();

/**
 * Wrapper around future for tracking signing of produced block.
 */
class produce_block_tracker {
public:

   /// Call only from main thread
   /// @return false only if the previous block signing failed.
   bool complete_produced_block_if_ready(const chain::controller& chain) {
      if( block_finalizing_status.load() == block_finalizing_status_type::ready ) {
         return complete_produced_block(chain);
      }
      return true;
   }

   /// @return true if previous block has not been signed/completed
   bool waiting() {
      if( block_finalizing_status.load() != block_finalizing_status_type::none ) {
         // If the condition is true, it means the previous block is either waiting for
         // its signatures/finalizing or waiting to be completed, the pending block cannot be produced
         // immediately to ensure that no more than one block is signed at any time.
         return true;
      }
      return false;
   }

   /// wait until ready and then call complete_produced_block
   bool wait_to_complete_block(const chain::controller& chain) {
      while (block_finalizing_status.load() == block_finalizing_status_type::pending) {
         ilog("Waiting for the pending produce_block_tracker to complete");
         // sleep a while for the async signing/committing thread to complete
         std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      return complete_produced_block_if_ready(chain);
   }

   /// Track given completed block future
   void set_completed_block_future( std::future<std::function<void()>> f ) {
      complete_produced_block_fut = std::move( f );
   }

   /// Called when block is being finalized and signed
   void set_pending() {
      block_finalizing_status = block_finalizing_status_type::pending;
   }

   /// Called when siging/finalizing are done, and future is ready
   void set_ready() {
      block_finalizing_status = block_finalizing_status_type::ready;
   }

   /// Set the status of the tracker to none
   void set_none() {
      block_finalizing_status = block_finalizing_status_type::none;
      id = {};
   }

   /// Set/get the block ID being completed
   void set_block_id(const chain::block_id_type& id_) {
      id = id_;
   }

   /// Get the block ID being completed
   chain::block_id_type get_block_id() {
      return id;
   }

private:

   bool complete_produced_block(const chain::controller& chain) {
      bool result = false;
      try {
         complete_produced_block_fut.get()();
         result = true;

         // the head block is produced now
         auto new_bs = chain.head_block_state();
         ilog("Produced block {id}... #{n} @ {t} signed by {p} [trxs: {count}, lib: {lib}, confirmed: {confs}]",
              ("p", new_bs->header.producer.to_string())("id", new_bs->id.str().substr(8, 16))
              ("n", new_bs->block_num)("t", new_bs->header.timestamp.to_time_point())
              ("count", new_bs->block->transactions.size())("lib", chain.last_irreversible_block_num())
              ("confs", new_bs->header.confirmed));
      } catch( ... ) {
         auto new_bs = chain.head_block_state();
         ilog("Failed to complete block {id}... #{n} @ {t} signed by {p} [trxs: {count}, lib: {lib}, confirmed: {confs}]. Discarding it.",
              ("p", new_bs->header.producer.to_string())("id", new_bs->id.str().substr(8, 16))
              ("n", new_bs->block_num)("t", new_bs->header.timestamp.to_time_point())
              ("count", new_bs->block->transactions.size())("lib", chain.last_irreversible_block_num())
              ("confs", new_bs->header.confirmed));

         log_and_drop_exceptions();
      }

      // set status back to none
      set_none();

      return result;
   }

private:
   enum class block_finalizing_status_type {
      none,
      pending,
      ready
   };

   std::future<std::function<void()>> complete_produced_block_fut;
   // id of the block being completed
   chain::block_id_type id = {};
   std::atomic<block_finalizing_status_type> block_finalizing_status = block_finalizing_status_type::none;
};

} // namespace eosio

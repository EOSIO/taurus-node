#pragma once

#include <eosio/chain/controller.hpp>

namespace eosio {

/**
 * Transient state for block production, used by producer.
 * Keeps configured producer accounts, tracks producer_watermarks.
 * Also has calculations for pending block time, producer wake up time, and number of blocks to confirm.
 */
class block_producer {
public:
   block_producer() = default;

   void add_producer( const chain::account_name& p ) {
      _producers.emplace( p );
   }

   // Any producers configured on this node
   bool has_producers() const { return !_producers.empty(); }

   // How many producers configured on this node
   auto get_num_producers() const { return _producers.size(); }

   // Is the account producer_name configured as a producer on this node
   bool is_producer( const chain::account_name& producer_name ) const {
      return _producers.find( producer_name ) != _producers.end();
   }

   void on_block_header( const chain::block_state_ptr& bsp ) {
      consider_new_watermark( bsp->header.producer, bsp->block_num, bsp->block->timestamp );
   }

   fc::time_point calculate_pending_block_time( const chain::controller& chain ) const;

   std::optional<fc::time_point>
   calculate_producer_wake_up_time( const chain::controller& chain, const chain::block_timestamp_type& ref_block_time ) const;

   uint16_t get_blocks_to_confirm( const chain::account_name& producer_name, uint32_t head_block_num ) const;

private:

   void consider_new_watermark( const chain::account_name& producer, uint32_t block_num, chain::block_timestamp_type timestamp );

   using producer_watermark = std::pair<uint32_t, chain::block_timestamp_type>;
   std::optional<producer_watermark> get_watermark( const chain::account_name& producer ) const;

   std::optional<fc::time_point> calculate_next_block_time( const chain::controller& chain,
                                                            const chain::account_name& producer_name,
                                                            const chain::block_timestamp_type& current_block_time ) const;

private:
   std::set<chain::account_name> _producers;
   std::map<chain::account_name, producer_watermark> _producer_watermarks;

}; // class block_producer

} // namespace eosio

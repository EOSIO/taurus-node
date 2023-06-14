#include <eosio/producer_plugin/block_producer.hpp>

namespace eosio {

using namespace eosio::chain;

fc::time_point block_producer::calculate_pending_block_time( const chain::controller& chain ) const {
   const fc::time_point base = std::max<fc::time_point>( fc::time_point::now(), chain.head_block_time() );
   const int64_t min_time_to_next_block =
         (config::block_interval_us) - (base.time_since_epoch().count() % (config::block_interval_us));
   fc::time_point block_time = base + fc::microseconds( min_time_to_next_block );
   return block_time;
}

std::optional<fc::time_point>
block_producer::calculate_producer_wake_up_time( const chain::controller& chain, const chain::block_timestamp_type& ref_block_time ) const {
   // if we have any producers then we should at least set a timer for our next available slot
   std::optional<fc::time_point> wake_up_time;
   for( const auto& p: _producers ) {
      auto next_producer_block_time = calculate_next_block_time( chain, p, ref_block_time );
      if( next_producer_block_time ) {
         auto producer_wake_up_time = *next_producer_block_time - fc::microseconds( config::block_interval_us );
         if( wake_up_time ) {
            // wake up with a full block interval to the deadline
            if( producer_wake_up_time < *wake_up_time ) {
               wake_up_time = producer_wake_up_time;
            }
         } else {
            wake_up_time = producer_wake_up_time;
         }
      }
   }
   if( !wake_up_time ) {
      dlog( "Not Scheduling Speculative/Production, no local producers had valid wake up times" );
   }

   return wake_up_time;
}

uint16_t block_producer::get_blocks_to_confirm( const account_name& producer_name, uint32_t head_block_num ) const {
   uint16_t blocks_to_confirm = 0;
   const auto current_watermark = get_watermark( producer_name );
   if( current_watermark ) {
      auto watermark_bn = current_watermark->first;
      if( watermark_bn < head_block_num ) {
         blocks_to_confirm = (uint16_t) (std::min<uint32_t>( std::numeric_limits<uint16_t>::max(),
                                                             (uint32_t) (head_block_num - watermark_bn) ));
      }
   }
   return blocks_to_confirm;
}

void block_producer::consider_new_watermark( const account_name& producer, uint32_t block_num, chain::block_timestamp_type timestamp ) {
   auto itr = _producer_watermarks.find( producer );
   if( itr != _producer_watermarks.end() ) {
      itr->second.first = std::max( itr->second.first, block_num );
      itr->second.second = std::max( itr->second.second, timestamp );
   } else if( is_producer( producer ) ) {
      _producer_watermarks.emplace( producer, std::make_pair( block_num, timestamp ) );
   }
}

std::optional<block_producer::producer_watermark>
block_producer::get_watermark( const account_name& producer ) const {
   auto itr = _producer_watermarks.find( producer );
   if( itr == _producer_watermarks.end() ) return {};
   return itr->second;
}

std::optional<fc::time_point>
block_producer::calculate_next_block_time( const chain::controller& chain,
                                           const account_name& producer_name,
                                           const chain::block_timestamp_type& current_block_time ) const {
   const auto& hbs = chain.head_block_state();
   const auto& active_schedule = hbs->active_schedule.producers;

   std::optional<fc::time_point> result;
   // determine if this producer is in the active schedule and if so, where
   auto itr = std::find_if( active_schedule.begin(), active_schedule.end(),
                            [&]( const auto& asp ) { return asp.producer_name == producer_name; } );
   if( itr == active_schedule.end() ) {
      // this producer is not in the active producer set
      return result;
   }

   size_t producer_index = itr - active_schedule.begin();
   uint32_t minimum_offset = 1; // must at least be the "next" block

   // account for a watermark in the future which is disqualifying this producer for now
   // this is conservative assuming no blocks are dropped.  If blocks are dropped the watermark will
   // disqualify this producer for longer but it is assumed they will wake up, determine that they
   // are disqualified for longer due to skipped blocks and re-caculate their next block with better
   // information then
   auto current_watermark = get_watermark( producer_name );
   if( current_watermark ) {
      const auto watermark = *current_watermark;
      auto block_num = chain.head_block_state()->block_num;
      if( chain.is_building_block() ) {
         ++block_num;
      }
      if( watermark.first > block_num ) {
         // if I have a watermark block number then I need to wait until after that watermark
         minimum_offset = watermark.first - block_num + 1;
      }
      if( watermark.second > current_block_time ) {
         // if I have a watermark block timestamp then I need to wait until after that watermark timestamp
         minimum_offset = std::max( minimum_offset, watermark.second.slot - current_block_time.slot + 1 );
      }
   }

   // this producers next opportuity to produce is the next time its slot arrives after or at the calculated minimum
   uint32_t minimum_slot = current_block_time.slot + minimum_offset;
   size_t minimum_slot_producer_index =
         (minimum_slot % (active_schedule.size() * config::producer_repetitions)) / config::producer_repetitions;
   if( producer_index == minimum_slot_producer_index ) {
      // this is the producer for the minimum slot, go with that
      result = chain::block_timestamp_type( minimum_slot ).to_time_point();
   } else {
      // calculate how many rounds are between the minimum producer and the producer in question
      size_t producer_distance = producer_index - minimum_slot_producer_index;
      // check for unsigned underflow
      if( producer_distance > producer_index ) {
         producer_distance += active_schedule.size();
      }

      // align the minimum slot to the first of its set of reps
      uint32_t first_minimum_producer_slot = minimum_slot - (minimum_slot % config::producer_repetitions);

      // offset the aligned minimum to the *earliest* next set of slots for this producer
      uint32_t next_block_slot = first_minimum_producer_slot + (producer_distance * config::producer_repetitions);
      result = chain::block_timestamp_type( next_block_slot ).to_time_point();
   }

   return result;
}

} // namespace eosio

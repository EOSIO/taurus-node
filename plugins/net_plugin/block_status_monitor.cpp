#include <eosio/net_plugin/block_status_monitor.hpp>

namespace eosio {

void block_status_monitor::reset() {
   in_accepted_state_ = true;
   events_ = 0;
}

void block_status_monitor::rejected() {
   const auto now = fc::time_point::now();

   // in rejected state
   if(!in_accepted_state_) {
      const auto elapsed = now - window_start_;
      if( elapsed < window_size_ ) {
         return;
      }
      ++events_;
      window_start_ = now;
      return;
   }

   // switching to rejected state
   in_accepted_state_ = false;
   window_start_ = now;
   events_ = 0;
}

} //eosio

#pragma once

#include <fc/time.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <memory>

namespace eosio {

class producer;
using producer_wptr = std::weak_ptr<producer>;

/**
 * Interface for timer used in producer.
 * This is used because producer_timer is a template and we want the producer not to have all the implementation in the
 * header. Implementation of producer_timer template is in producer.hpp which is a template so that it can be
 * instantiated with a mock_time_traits timer in tests.
 */
class producer_timer_base {
public:
   virtual ~producer_timer_base() = default;
   virtual void cancel() = 0;
   virtual void schedule_production_later( producer_wptr wptr ) = 0;
   virtual void schedule_maybe_produce_block( producer_wptr wptr, bool exhausted, const fc::time_point& deadline, uint32_t block_num ) = 0;
   virtual void schedule_delayed_production_loop( producer_wptr wptr, const fc::time_point& wake_up_time ) = 0;

   // used for converting from fc time and boost ptime
   static const boost::posix_time::ptime epoch;
};

} // namespace eosio

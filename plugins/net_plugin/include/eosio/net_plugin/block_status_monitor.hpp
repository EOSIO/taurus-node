#pragma once

#include <fc/time.hpp>

namespace eosio {

/// monitors the status of blocks as to whether a block is accepted (sync'd) or
/// rejected. It groups consecutive rejected blocks in a (configurable) time
/// window (rbw) and maintains a metric of the number of consecutive rejected block
/// time windows (rbws).
class block_status_monitor {
private:
   bool in_accepted_state_ {true};              ///< indicates of accepted(true) or rejected(false) state
   fc::microseconds window_size_{2*1000};       ///< rbw time interval (2ms)
   fc::time_point   window_start_;              ///< The start of the recent rbw (0 implies not started)
   uint32_t         events_{0};                 ///< The number of consecutive rbws
   const uint32_t   max_consecutive_rejected_windows_{13};

public:
   /// ctor
   ///
   /// @param[in] window_size          The time, in microseconds, of the rejected block window
   /// @param[in] max_rejected_windows The max consecutive number of rejected block windows
   /// @note   Copy ctor is not allowed
   explicit block_status_monitor(fc::microseconds window_size = fc::microseconds(2*1000),
         [[maybe_unused]] uint32_t max_rejected_windows = 13) :
      window_size_(window_size) {}
   block_status_monitor( const block_status_monitor& ) = delete;
   block_status_monitor( block_status_monitor&& ) = delete;
   ~block_status_monitor() = default;
   /// reset to initial state
   void reset();
   /// called when a block is accepted (sync_recv_block)
   void accepted() { reset(); }
   /// called when a block is rejected
   void rejected();
   /// returns number of consecutive rbws
   auto events() const { return events_; }
   /// indicates if the max number of consecutive rbws has been reached or exceeded
   bool max_events_violated() const { return events_ >= max_consecutive_rejected_windows_; }
   /// assignment not allowed
   block_status_monitor& operator=( const block_status_monitor& ) = delete;
   block_status_monitor& operator=( block_status_monitor&& ) = delete;
};

} //eosio

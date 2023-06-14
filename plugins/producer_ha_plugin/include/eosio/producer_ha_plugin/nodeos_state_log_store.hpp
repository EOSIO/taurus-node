#pragma once

#include <libnuraft/log_store.hxx>
#include <libnuraft/raft_server.hxx>
#include <libnuraft/../../src/event_awaiter.h>
#include <libnuraft/internal_timer.hxx>

#include <eosio/producer_ha_plugin/nodeos_state_db.hpp>

#include <atomic>
#include <map>
#include <mutex>

namespace eosio {

/*
 * The Raft log store implementation for the nodeos_state_machine.
 */
class nodeos_state_log_store : public nuraft::log_store {
public:
   inline static const std::string start_idx_key = "start_idx";
   inline static const std::string last_idx_key = "last_idx";

public:
   inline static std::string index_to_key(nuraft::ulong index) {
      return std::to_string(index);
   }

   inline static nuraft::ulong key_to_index(const std::string& str) {
      return std::stoul(str);
   }

   inline static nuraft::ptr<nuraft::log_entry> make_clone(const nuraft::ptr<nuraft::log_entry>& entry) {
      return nuraft::cs_new<nuraft::log_entry>(
            entry->get_term(),
            nuraft::buffer::clone(entry->get_buf()),
            entry->get_val_type());
   }

public:
   nodeos_state_log_store(std::shared_ptr<nodeos_state_db> db);

   ~nodeos_state_log_store() = default;

__nocopy__(nodeos_state_log_store);

public:
   nuraft::ulong next_slot() const override;

   nuraft::ulong start_index() const override;

   nuraft::ptr<nuraft::log_entry> last_entry() const override;

   nuraft::ulong append(nuraft::ptr<nuraft::log_entry>& entry) override;

   void write_at(nuraft::ulong index, nuraft::ptr<nuraft::log_entry>& entry) override;

   nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>>
   log_entries(nuraft::ulong start, nuraft::ulong end) override;

   nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>> log_entries_ext(
         nuraft::ulong start, nuraft::ulong end, nuraft::int64 batch_size_hint_in_bytes = 0) override;

   nuraft::ptr<nuraft::log_entry> entry_at(nuraft::ulong index) override;

   nuraft::ulong term_at(nuraft::ulong index) override;

   nuraft::ptr<nuraft::buffer> pack(nuraft::ulong index, nuraft::int32 cnt) override;

   void apply_pack(nuraft::ulong index, nuraft::buffer& pack) override;

   bool compact(nuraft::ulong last_log_index) override;

   bool flush() override;

   nuraft::ulong last_durable_index() override;

private:
   // no lock protected version of entry_at
   nuraft::ptr<nuraft::log_entry> entry_at_(nuraft::ulong index) const;

   // Log store operations can be called by different threads in parallel, thus they need to be thread-safe.
   mutable std::mutex log_store_lock_;

   // current index for the start and last log_idx
   nuraft::ulong start_idx_;
   nuraft::ulong last_idx_;

   // the producer_ha db for storing logs
   std::shared_ptr<nodeos_state_db> db_;

   // initial log entry, the very initial log entry as a placeholder
   nuraft::ptr<nuraft::log_entry> log_init_;
};

}


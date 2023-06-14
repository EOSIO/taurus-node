#include <eosio/producer_ha_plugin/nodeos_state_log_store.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_machine.hpp>
#include <eosio/chain/block.hpp>

namespace eosio {

nodeos_state_log_store::nodeos_state_log_store(std::shared_ptr<nodeos_state_db> db)
      : db_(db) {
   // log[0] in db as the init block as a placeholder
   // if it does not exist, the db was not initialized before, and we initialize it for the log_store
   auto log_init_buf = db_->read(nodeos_state_db::log, index_to_key(0));
   if (!log_init_buf) {
      ilog("producer_ha db does not contain any raft logs. Initializing it ...");

      // construct one
      log_init_ = nuraft::cs_new<nuraft::log_entry>(0, nodeos_state_machine::get_init_block());

      // initialize the db for entry 0 as a placeholder
      db_->write(nodeos_state_db::log, index_to_key(0), log_init_->serialize());

      // initialize start_idx_
      start_idx_ = 1;
      db_->write(nodeos_state_db::log, start_idx_key, index_to_key(start_idx_));

      // initialize last_idx_
      last_idx_ = 0;
      db_->write(nodeos_state_db::log, last_idx_key, index_to_key(last_idx_));

      db_->flush();
   } else {
      // load values from the db
      // deserialize log_init_buf to log_init_
      log_init_ = nuraft::log_entry::deserialize(*log_init_buf);

      auto start_idx_value = db_->read_value(nodeos_state_db::log, start_idx_key);
      start_idx_ = key_to_index(*start_idx_value);
      auto last_idx_value = db_->read_value(nodeos_state_db::log, last_idx_key);
      last_idx_ = key_to_index(*last_idx_value);
   }
}

nuraft::ulong nodeos_state_log_store::next_slot() const {
   std::lock_guard<std::mutex> l(log_store_lock_);
   return last_idx_ + 1;
}

nuraft::ulong nodeos_state_log_store::start_index() const {
   std::lock_guard<std::mutex> l(log_store_lock_);
   return start_idx_;
}

nuraft::ulong nodeos_state_log_store::last_durable_index() {
   std::lock_guard<std::mutex> l(log_store_lock_);
   return last_idx_;
}

nuraft::ulong nodeos_state_log_store::append(nuraft::ptr<nuraft::log_entry>& entry) {
   std::lock_guard<std::mutex> l(log_store_lock_);
   ++last_idx_;
   db_->write(nodeos_state_db::log, index_to_key(last_idx_), entry->serialize());
   db_->write(nodeos_state_db::log, last_idx_key, index_to_key(last_idx_));
   db_->flush();

   return last_idx_;
}

void nodeos_state_log_store::write_at(nuraft::ulong index, nuraft::ptr<nuraft::log_entry>& entry) {
   std::lock_guard<std::mutex> l(log_store_lock_);
   db_->write(nodeos_state_db::log, index_to_key(index), entry->serialize());
   // discard all logs greater than index
   while (last_idx_ > index) {
      db_->erase(nodeos_state_db::log, index_to_key(last_idx_));
      --last_idx_;
   }
   // bring last_idx_ to index if last_idx_ is older
   if (last_idx_ < index) {
      last_idx_ = index;
   }
   db_->write(nodeos_state_db::log, last_idx_key, index_to_key(last_idx_));
   db_->flush();
}

nuraft::ptr<nuraft::log_entry> nodeos_state_log_store::entry_at_(nuraft::ulong index) const {
   // this function does not acquire lock by design, caller should acquire lock if it is necessary
   auto buf = db_->read(nodeos_state_db::log, index_to_key(index));
   if (buf) {
      return nuraft::log_entry::deserialize(*buf);
   } else {
      dlog("entry_at_({i}) -> nullptr", ("i", index));
      return nullptr;
   }
}

nuraft::ptr<nuraft::log_entry> nodeos_state_log_store::entry_at(nuraft::ulong index) {
   std::lock_guard<std::mutex> l(log_store_lock_);
   return entry_at_(index);
}

nuraft::ulong nodeos_state_log_store::term_at(nuraft::ulong index) {
   std::lock_guard<std::mutex> l(log_store_lock_);

   if (index > last_idx_) {
      nuraft::ulong idx = last_idx_;
      elog("term_at({i}) called while last_idx_ = {l}. Should not happen.", ("i", index)("l", idx));
      EOS_THROW(
            chain::producer_ha_log_store_exception,
            "term_at({i}) called while last_idx_ = {l}. Should not happen.",
            ("i", index)("l", idx)
      );
   }

   auto entry = entry_at_(index);
   if (entry) {
      // dlog("term_at({i}) => {t}", ("i", index)("t", entry->get_term()));
      return entry->get_term();
   } else {
      return 0;
   }
}

nuraft::ptr<nuraft::log_entry> nodeos_state_log_store::last_entry() const {
   std::lock_guard<std::mutex> l(log_store_lock_);
   auto entry = entry_at_(last_idx_);
   if (!entry) {
      entry = log_init_;
   }
   return entry;
}

nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>>
nodeos_state_log_store::log_entries_ext(nuraft::ulong start,
                                        nuraft::ulong end,
                                        nuraft::int64 batch_size_hint_in_bytes) {
   std::lock_guard<std::mutex> l(log_store_lock_);
   nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>> ret =
         nuraft::cs_new<std::vector<nuraft::ptr<nuraft::log_entry>>>();

   if (batch_size_hint_in_bytes < 0) {
      return ret;
   }

   size_t accum_size = 0;
   for (nuraft::ulong ii = start; ii < end; ++ii) {
      auto entry = entry_at_(ii);
      if (entry) {
         ret->push_back(entry);
         if (batch_size_hint_in_bytes) {
            accum_size += entry->get_buf().size();
            if (accum_size >= (nuraft::ulong) batch_size_hint_in_bytes) {
               break;
            }
         }
      } else {
         return nullptr;
      }
   }
   return ret;
}

nuraft::ptr<std::vector<nuraft::ptr<nuraft::log_entry>>>
nodeos_state_log_store::log_entries(nuraft::ulong start, nuraft::ulong end) {
   return log_entries_ext(start, end, 0);
}

nuraft::ptr<nuraft::buffer> nodeos_state_log_store::pack(nuraft::ulong index, nuraft::int32 cnt) {
   auto entries = log_entries(index, index + cnt);

   size_t size_total = 0;
   std::vector<nuraft::ptr<nuraft::buffer>> logs;
   for (const auto& entry: *entries) {
      nuraft::ptr<nuraft::buffer> buf = entry->serialize();
      size_total += buf->size();
      logs.push_back(buf);
   }

   nuraft::ptr<nuraft::buffer> buf_out = nuraft::buffer::alloc(
         sizeof(nuraft::int32) +
         cnt * sizeof(nuraft::int32) +
         size_total);

   buf_out->pos(0);
   buf_out->put(static_cast<nuraft::int32>(cnt));

   for (const auto& entry: logs) {
      buf_out->put(static_cast<nuraft::int32>(entry->size()));
      buf_out->put(*entry);
   }
   return buf_out;
}

void nodeos_state_log_store::apply_pack(nuraft::ulong index, nuraft::buffer& pack) {
   std::lock_guard<std::mutex> l(log_store_lock_);

   pack.pos(0);
   nuraft::int32 num_logs = pack.get_int();
   for (nuraft::int32 ii = 0; ii < num_logs; ++ii) {
      nuraft::ulong cur_idx = index + ii;
      nuraft::int32 buf_size = pack.get_int();

      nuraft::ptr<nuraft::buffer> buf = nuraft::buffer::alloc(buf_size);
      pack.get(buf);

      db_->write(nodeos_state_db::log, index_to_key(cur_idx), buf);
      if (last_idx_ < cur_idx) {
         last_idx_ = cur_idx;
      }
   }
   db_->write(nodeos_state_db::log, last_idx_key, index_to_key(last_idx_));
   db_->flush();
}

bool nodeos_state_log_store::compact(nuraft::ulong last_log_index) {
   dlog("log_store::compact(last_log_index={i})", ("i", last_log_index));
   std::lock_guard<std::mutex> l(log_store_lock_);
   while (start_idx_ <= last_log_index) {
      db_->erase(nodeos_state_db::log, index_to_key(start_idx_));
      ++start_idx_;
   }
   db_->write(nodeos_state_db::log, start_idx_key, index_to_key(start_idx_));

   if (last_idx_ < last_log_index) {
      last_idx_ = last_log_index;
      db_->write(nodeos_state_db::log, last_idx_key, index_to_key(last_idx_));
   }

   db_->flush();

   return true;
}

bool nodeos_state_log_store::flush() {
   std::lock_guard<std::mutex> l(log_store_lock_);

   db_->flush();

   return true;
}

}

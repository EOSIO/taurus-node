#pragma once

#include <libnuraft/nuraft.hxx>

#include <rocksdb/db.h>
#include <rocksdb/table.h>
#include <rocksdb/utilities/options_util.h>

#include <eosio/chain/exceptions.hpp>

namespace eosio {

struct nodeos_state_db {
   // known prefix's
   inline static const std::string manager = "mgr";
   inline static const std::string log = "log";
   inline static const std::string state_machine = "sm";

   static std::string get_db_key(const std::string& prefix, const std::string& key) {
      return prefix + "/" + key;
   }

   static rocksdb::Slice to_slice(const std::string& db_key) {
      return rocksdb::Slice(db_key);
   }

   static rocksdb::Slice to_slice(const nuraft::ptr<nuraft::buffer> buf) {
      auto data = buf->data_begin();
      return rocksdb::Slice(reinterpret_cast<const char*>(data), buf->size());
   }

   static rocksdb::Slice to_slice(const nuraft::buffer& buf) {
      auto data = buf.data_begin();
      return rocksdb::Slice(reinterpret_cast<const char*>(data), buf.size());
   }

   nodeos_state_db(const char* db_path) {
      rocksdb::DB* p;

      rocksdb::Options options;
      options.create_if_missing = true;

      // Configuration tested for rodeos
      // Producer_ha expects less operations to the RDB
      options.IncreaseParallelism(20);  // number of background threads
      options.max_open_files = 765; // max number of files in open

      // Those are from RocksDB Performance Tuning Guide for a typical
      // setting. Applications are encuroage to experiment different settings
      // and use options file instead.
      options.max_write_buffer_number = 10;
      options.compaction_style = rocksdb::kCompactionStyleLevel; // level style compaction
      options.level0_file_num_compaction_trigger = 10; // number of L0 files to trigger L0 to L1 compaction.
      options.level0_slowdown_writes_trigger = 20;     // number of L0 files that will slow down writes
      options.level0_stop_writes_trigger = 40;         // number of L0 files that will stop writes
      options.write_buffer_size = 256 * 1024 * 1024;   // memtable size
      options.target_file_size_base = 256 * 1024 * 1024; // size of files in L1
      options.max_bytes_for_level_base = options.target_file_size_base;  // total size of L1, recommended to be 10 * target_file_size_base but to match the number used in testing.

      // open the database now
      auto status = rocksdb::DB::Open(options, db_path, &p);
      if (!status.ok()) {
         EOS_THROW(
               chain::producer_ha_config_exception,
               "Failed to open producer_ha db, error: {e}",
               ("e", status.ToString())
         );
      }

      rdb.reset(p);
   }

   nodeos_state_db(nodeos_state_db&&) = default;

   nodeos_state_db& operator=(nodeos_state_db&&) = default;

   void flush() {
      rocksdb::FlushOptions op;

      // wait till WAL flushed and synced
      op.allow_write_stall = true;
      op.wait = true;

      // flush WAL and sync the WAL file
      // This is safe to do because all write through write() and write*() functions write WAL first.
      rdb->FlushWAL(true);
   }

   void write(const rocksdb::Slice& key, const rocksdb::Slice& value) {
      rocksdb::WriteOptions opt;
      // make sure to write the WAL first
      // so that WAL flushing is safe in flush()
      opt.disableWAL = false;

      // write to the database now
      auto status = rdb->Put(opt, key, value);
      if (!status.ok()) {
         EOS_THROW(
               chain::producer_ha_persist_exception,
               "Failed to write a key to producer_ha db: {k}",
               ("k", key.ToString())
         );
      }
   }

   void write(const std::string& prefix, const std::string& key, const nuraft::ptr<nuraft::buffer> buf) {
      auto db_key = get_db_key(prefix, key);
      write(to_slice(db_key), to_slice(buf));
   }

   void write(const std::string& prefix, const std::string& key, const nuraft::buffer& buf) {
      auto db_key = get_db_key(prefix, key);
      write(to_slice(db_key), to_slice(buf));
   }

   void write(const std::string& prefix, const std::string& key, const std::string& str) {
      auto db_key = get_db_key(prefix, key);
      write(to_slice(db_key), to_slice(str));
   }

   void erase(const std::string& prefix, const std::string& key) {
      auto db_key = get_db_key(prefix, key);
      auto status = rdb->Delete(rocksdb::WriteOptions(), to_slice(db_key));
      if (!status.ok()) {
         EOS_THROW(
               chain::producer_ha_persist_exception,
               "Failed to delete a single key {k}",
               ("k", prefix + "/" + key)
         );
      }
   }

   // nullptr: not found
   // !nullptr: the value in a buffer
   nuraft::ptr<nuraft::buffer> read(const std::string& prefix, const std::string& key) {
      std::string v;
      auto db_key = get_db_key(prefix, key);
      auto stat = rdb->Get(rocksdb::ReadOptions(), to_slice(db_key), &v);

      if (stat.IsNotFound()) {
         dlog("db::read({s}, {k}) -> nullptr", ("s", prefix)("k", key));
         return nullptr;
      } else if (stat.ok()) {
         nuraft::ptr<nuraft::buffer> ret = nuraft::buffer::alloc(v.size());
         auto data = v.data();
         ret->put_raw(reinterpret_cast<const nuraft::byte*>(data), v.size());
         // reset position to 0 for receiver
         ret->pos(0);
         return ret;
      } else {
         EOS_THROW(
               chain::producer_ha_persist_exception,
               "Failed to read a single key {k}",
               ("k", prefix + "/" + key)
         );
      }
   }

   // nullptr: not found
   // !nullptr: the value in str::string
   std::shared_ptr<std::string> read_value(const std::string& prefix, const std::string& key) {
      std::string v;
      auto db_key = get_db_key(prefix, key);
      auto stat = rdb->Get(rocksdb::ReadOptions(), to_slice(db_key), &v);

      if (stat.IsNotFound()) {
         dlog("db::read_value({s}, {k}) -> nullptr", ("s", prefix)("k", key));
         return nullptr;
      } else if (stat.ok()) {
         return std::make_shared<std::string>(std::move(v));
      } else {
         EOS_THROW(
               chain::producer_ha_persist_exception,
               "Failed to read a single key {k}",
               ("k", prefix + "/" + key)
         );
      }
   }

private:
   // rocksdb instance
   std::unique_ptr<rocksdb::DB> rdb;
};

}

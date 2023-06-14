#pragma once

#include <libnuraft/nuraft.hxx>

#include <eosio/producer_ha_plugin/nodeos_state_db.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_log_store.hpp>

#include <eosio/chain/block.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>

#include <eosio/chain/thread_utils.hpp>

#include <appbase/application.hpp>

#include <atomic>
#include <cassert>
#include <iostream>
#include <mutex>
#include <memory>
#include <string.h>


namespace eosio {

// declare the function, implementation is in producer_plugin.cpp
void log_and_drop_exceptions();

class nodeos_state_machine : public nuraft::state_machine {
public:
   // keys for db addresses
   inline static const std::string head_block_key = "head";
   inline static const std::string cluster_config_key = "cfg";
   inline static const std::string last_commit_idx_key = "last";
   inline static const std::string snapshots_key = "snapshots";
   inline static const std::string last_snapshot_idx_key = "snapshot_last";
   inline static const std::string log_idx_ss_idx_map_key = "log_idx_ss_idx_map";

public:
   nodeos_state_machine(const std::shared_ptr<nodeos_state_db> db) {
      chain_plug_ = appbase::app().find_plugin<eosio::chain_plugin>();
      EOS_ASSERT(
            chain_plug_ != nullptr,
            chain::producer_ha_state_machine_exception,
            "nodeos_state_machine cannot get chain_plugin. Should not happen."
      );

      std::lock_guard<std::mutex> l(lock_);

      db_ = db;

      // guarantee the head_block entry exists
      auto buf = db_->read(nodeos_state_db::state_machine, last_commit_idx_key);
      auto block_buf = db_->read(nodeos_state_db::state_machine, head_block_key);

      if (buf && block_buf) {
         last_commit_idx_ = buf->get_ulong();
         nodeos_raft_log log_s;
         decode_log(*block_buf, log_s);
         head_block_ = log_s.block_;
         ilog("nodeos_state loaded -> (log_idx: {l})", ("l", last_commit_idx_));
      } else {
         ilog("producer_ha db does not contain Raft state machine state yet.");
         head_block_ = nullptr;
         last_commit_idx_ = 0;
      }
   }

   ~nodeos_state_machine() = default;

   struct nodeos_raft_log {
      chain::signed_block_ptr block_;

      nodeos_raft_log() :
            block_(new chain::signed_block()) {}
   };

   static const nuraft::ptr<nuraft::buffer> get_init_block() {
      static nuraft::ptr<nuraft::buffer> init_block_buf = nullptr;
      if (!init_block_buf) {
         // readers that read out the log entry can find out whether this entry's block is the very initial one
         // by checking:
         //    the log_entry block's timestamp == taurus-node's epoch block_timestamp_epoch (year 2000)
         // no block should have its timestamp the same as block_timestamp_epoch
         chain::signed_block_ptr init_block(new chain::signed_block());
         init_block_buf = encode_block(init_block);
      }
      return init_block_buf;
   }

   static nuraft::ptr<nuraft::buffer> encode_block(const chain::signed_block_ptr block) {
      size_t padded_size = fc::raw::pack_size(*block);
      std::vector<char> buff(padded_size);
      fc::datastream<char*> stream(buff.data(), buff.size());
      fc::raw::pack(stream, *block);
      nuraft::ptr<nuraft::buffer> ret = nuraft::buffer::alloc(sizeof(nuraft::int32) + buff.size());
      nuraft::buffer_serializer bs(ret);
      bs.put_bytes(buff.data(), buff.size());
      return ret;
   }

   static nuraft::ptr<nuraft::buffer> encode_log(const nodeos_raft_log& log_s) {
      return encode_block(log_s.block_);
   }

   // Assumption: block should not be nullptr. The caller should ensure this.
   static void decode_block(nuraft::buffer& log_b, chain::signed_block_ptr block) {
      nuraft::buffer_serializer bs(log_b);
      size_t len = 0;
      char* pdata = static_cast<char*>(bs.get_bytes(len));
      fc::datastream<char*> stream(pdata, len);
      fc::raw::unpack(stream, *block);
   }

   static void decode_log(nuraft::buffer& log_b, nodeos_raft_log& log_s_out) {
      decode_block(log_b, log_s_out.block_);
   }

   const chain::signed_block_ptr get_head_block() {
      std::lock_guard<std::mutex> l(lock_);
      // the constructor ensures it exists
      return head_block_;
   }

   nuraft::ptr<nuraft::buffer> commit(const nuraft::ulong log_idx, nuraft::buffer& data) override {
      dlog("state_machine::commit(log_idx={i})", ("i", log_idx));

      {
         std::lock_guard<std::mutex> l(lock_);

         commit_raft_log(log_idx, data);

         db_->flush();
      }

      // Return Raft log number as a return result.
      nuraft::ptr<nuraft::buffer> ret = nuraft::buffer::alloc(sizeof(log_idx));
      nuraft::buffer_serializer bs(ret);
      bs.put_u64(log_idx);
      return ret;
   }

   void commit_config(const nuraft::ulong log_idx, nuraft::ptr<nuraft::cluster_config>& new_conf) override {
      dlog("state_machine::commit_config(log_idx={i})", ("i", log_idx));

      std::lock_guard<std::mutex> l(lock_);

      auto cfg_buf = new_conf->serialize();
      db_->write(nodeos_state_db::state_machine, cluster_config_key, cfg_buf);

      update_last_commit_index(log_idx);

      db_->flush();
   }

   nuraft::ptr<nuraft::buffer> pre_commit(const nuraft::ulong log_idx, nuraft::buffer& data) override {
      // pre_commit is not used, do not add any logic here
      return nullptr;
   }

   void rollback(const nuraft::ulong log_idx, nuraft::buffer& data) override {
      // Nothing to do with rollback,
      // as nothing done by pre-commit.
   }

   // the snapshot related functions provide snapshot support based on NuRaft snapshot functions
   // https://github.com/eBay/NuRaft/blob/master/docs/snapshot_transmission.md
   void create_snapshot(nuraft::snapshot& ss,
                        nuraft::async_result<bool>::handler_type& when_done) override {
      dlog("state_machine::create_snapshot()");

      {
         std::lock_guard<std::mutex> l( lock_ );

         // next idx to write to
         nuraft::ulong last_ss_idx = get_last_snapshot_idx();
         if ( last_ss_idx == 0 ) {
            ilog( "producer_ha db does not contain any snapshot yet." );
         }
         // next idx
         last_ss_idx += 1;

         // snapshot_data: snapshot + values
         auto ss_buf = ss.serialize();
         auto head_block_buf = encode_block( head_block_ );

         auto ss_data_buf = nuraft::buffer::alloc(
               sizeof( nuraft::ulong ) + ss_buf->size() + sizeof( nuraft::ulong ) + head_block_buf->size());
         ss_data_buf->put( static_cast<nuraft::ulong>(ss_buf->size()));
         ss_data_buf->put( *ss_buf );
         ss_data_buf->put( static_cast<nuraft::ulong>(head_block_buf->size()));
         ss_data_buf->put( *head_block_buf );

         // store snapshot_data
         store_last_snapshot_data( ss, *ss_data_buf, last_ss_idx );

         ilog("producer_ha created snapshot: last_log_idx: {l}, last_log_term: {t}, last_config->log_idx: {ci}",
              ("l", ss.get_last_log_idx())
              ("t", ss.get_last_log_term())
              ("ci", ss.get_last_config()->get_log_idx()));

         // TODO: garbage collect older snapshots? Only needed if the DB size is too large to store, in the future.

         db_->flush();
      }

      // call when_done
      nuraft::ptr<std::exception> except(nullptr);
      bool ret = true;
      when_done(ret, except);
   }

   nuraft::ptr<nuraft::snapshot> last_snapshot() override {
      dlog("state_machine::last_snapshot()");

      std::lock_guard<std::mutex> l(lock_);

      auto ss = get_last_snapshot();

      if ( ss ) {
         dlog( "last_snapshot: last_log_idx: {l}, last_log_term: {t}, last_config->log_idx: {ci}",
               ( "l", ss->get_last_log_idx())
               ( "t", ss->get_last_log_term())
               ( "ci", ss->get_last_config()->get_log_idx()));
      }
      return ss;
   }

   void save_logical_snp_obj( nuraft::snapshot& s,
                              nuraft::ulong& obj_id,
                              nuraft::buffer& data,
                              bool is_first_obj,
                              bool is_last_obj ) override {
      dlog( "state_machine::save_logical_snp_obj(obj_id={i})", ( "i", obj_id ));

      std::lock_guard<std::mutex> l( lock_ );

      if ( obj_id == 0 ) {
         ++obj_id;
         // Object ID == 0: it contains dummy value
         return;
      }

      // next idx to write to
      nuraft::ulong last_ss_idx = get_last_snapshot_idx();
      if ( last_ss_idx == 0 ) {
         ilog( "producer_ha db does not contain any snapshot yet." );
      }
      // next idx
      last_ss_idx += 1;

      // store snapshot_data in data
      store_last_snapshot_data( s, data, last_ss_idx );

      db_->flush();
   }

   int read_logical_snp_obj( nuraft::snapshot& s,
                             void*& user_snp_ctx,
                             nuraft::ulong obj_id,
                             nuraft::ptr<nuraft::buffer>& data_out,
                             bool& is_last_obj ) override {
      std::lock_guard<std::mutex> l( lock_ );

      auto last_snapshot = get_last_snapshot();
      nuraft::ulong last_snapshot_log_idx = 0;
      if ( last_snapshot ) {
         last_snapshot_log_idx = last_snapshot->get_last_log_idx();
      }

      dlog( "state_machine::read_logical_snp_obj(obj_id={i}, s: log_idx {l}, last_log_term: {t}, last_config->log_idx: {ci}); current last_snapshot_log_idx: {cl}",
            ( "i", obj_id )
            ( "l", s.get_last_log_idx())
            ( "t", s.get_last_log_term())
            ( "ci", s.get_last_config()->get_log_idx())
            ( "cl", last_snapshot_log_idx ));

      if ( last_snapshot_log_idx < s.get_last_log_idx()) {
         data_out = nullptr;
         is_last_obj = true;
         return 0;
      }

      if ( obj_id == 0 ) {
         // Object ID == 0: first object, put dummy data.
         data_out = nuraft::buffer::alloc( sizeof( nuraft::int32 ));
         nuraft::buffer_serializer bs( data_out );
         bs.put_i32( 0 );
         is_last_obj = false;
         return 0;
      }

      is_last_obj = true;

      // find ss idx for the log_idx from s
      nuraft::ulong ss_idx = 0;
      auto buf = db_->read( nodeos_state_db::state_machine,
                            log_idx_ss_idx_map_key + std::to_string( s.get_last_log_idx()));
      if ( !buf ) {
         ilog( "producer_ha db does not contain the requested snapshot yet." );
         data_out = nullptr;
         return 0;
      }
      ss_idx = buf->get_ulong();

      // read ss_data
      auto ss_data_buf = db_->read( nodeos_state_db::state_machine, snapshots_key + std::to_string( ss_idx ));

      if ( !ss_data_buf ) {
         elog( "snapshots at idx {i} does not exist!", ( "i", ss_idx ));
         data_out = nullptr;
         return -1;
      }

      data_out = nuraft::buffer::alloc( ss_data_buf->size());
      data_out->put( *ss_data_buf );
      if ( last_snapshot_log_idx > s.get_last_log_idx()) {
         is_last_obj = false;
      }

      return 0;
   }

   bool apply_snapshot(nuraft::snapshot& s) override {
      ilog( "state_machine::apply_snapshot(s: log_idx {l}, last_log_term: {t}, last_config->log_idx: {ci})",
            ( "l", s.get_last_log_idx())
            ( "t", s.get_last_log_term())
            ( "ci", s.get_last_config()->get_log_idx()));

      std::lock_guard<std::mutex> l(lock_);

      // find ss idx for the log_idx from s
      nuraft::ulong ss_idx = 0;
      auto buf = db_->read(nodeos_state_db::state_machine, log_idx_ss_idx_map_key + std::to_string(s.get_last_log_idx()));
      if (!buf) {
         ilog("producer_ha db does not contain the requested snapshot yet.");
         return false;
      }
      ss_idx = buf->get_ulong();

      // read ss_data
      auto ss_data_buf = db_->read(nodeos_state_db::state_machine, snapshots_key + std::to_string(ss_idx));

      if (!ss_data_buf) {
         elog("snapshots at idx {i} does not exist!", ("i", ss_idx));
         return false;
      }

      auto len = ss_data_buf->get_ulong();
      ss_data_buf->pos(ss_data_buf->pos() + len);
      len = ss_data_buf->get_ulong();

      auto head_block_buf = nuraft::buffer::alloc(len);
      ss_data_buf->get(head_block_buf);

      // content of log_buf and head_block_buf are actually the same. But this is just an implementation coincidence.
      // We don't rely on that and still decode and encode it, paying the tiny performance overhead here.
      // apply_snapshot is not a common operation. The performance cost is acceptable.
      nodeos_raft_log log_s;
      decode_block(*head_block_buf, log_s.block_);
      auto log_buf = encode_log(log_s);

      commit_raft_log(s.get_last_log_idx(), *log_buf);

      db_->flush();

      return true;
   }

   void free_user_snp_ctx(void*& user_snp_ctx) override {
      // nothing to do here
   }

   nuraft::ulong last_commit_index() override {
      dlog("state_machine::last_commit_index()");
      std::lock_guard<std::mutex> l(lock_);

      return last_commit_idx_;
   }

private:
   // get the last snapshot index stored, starting from 1
   // returns 0 if no last snapshot index ever stored.
   // caller should acquire the lock_
   nuraft::ulong get_last_snapshot_idx() {
      nuraft::ulong last_ss_idx = 0;
      auto buf = db_->read(nodeos_state_db::state_machine, last_snapshot_idx_key);
      if (buf) {
         last_ss_idx = buf->get_ulong();
      }
      return last_ss_idx;
   }

   // store the snapshot_data for snapshot s into index last_ss_idx
   // also update last_log_idx -> ss_idx map and last_snapshot_idx in DB
   // caller should acquire the lock_
   // caller should flush the db
   void store_last_snapshot_data(
         const nuraft::snapshot& s,
         const nuraft::buffer& snapshot_data,
         nuraft::ulong last_ss_idx) {
      // new last_ss_idx
      auto last_ss_idx_buf = nuraft::buffer::alloc(sizeof(nuraft::ulong));
      last_ss_idx_buf->put(last_ss_idx);

      // store the ss_idx -> snapshot_data
      db_->write(nodeos_state_db::state_machine, snapshots_key + std::to_string(last_ss_idx), snapshot_data);
      // store the last_log_idx -> ss_idx map
      db_->write(nodeos_state_db::state_machine, log_idx_ss_idx_map_key + std::to_string(s.get_last_log_idx()), last_ss_idx_buf);
      // store the last snapshot idx
      db_->write(nodeos_state_db::state_machine, last_snapshot_idx_key, last_ss_idx_buf);
   }

   // get the last snapshot
   // caller should acquire the lock_
   nuraft::ptr<nuraft::snapshot> get_last_snapshot() {
      // last idx to read from
      nuraft::ulong last_ss_idx = get_last_snapshot_idx();
      if ( last_ss_idx == 0 ) {
         ilog( "producer_ha db does not contain any snapshot yet." );
         return nullptr;
      }

      // read ss_data
      auto ss_data_buf = db_->read( nodeos_state_db::state_machine, snapshots_key + std::to_string( last_ss_idx ));

      if ( !ss_data_buf ) {
         elog( "snapshots at idx {i} does not exist!", ( "i", last_ss_idx ));
         return nullptr;
      }

      nuraft::ulong ss_buf_size = ss_data_buf->get_ulong();
      auto ss_buf = nuraft::buffer::alloc( ss_buf_size );
      ss_data_buf->get( ss_buf );

      return nuraft::snapshot::deserialize( *ss_buf );
   }

   // commit and store the raft log containing the new head block
   // caller should acquire the lock_
   // caller should flush the db
   void commit_raft_log(const nuraft::ulong log_idx, nuraft::buffer& data) {
      nodeos_raft_log log_s;
      decode_log(data, log_s);

      // Post the new block to the main thread

      // producer_ha handles the possibility of a very small forking (a single block long forking which
      // only exists within one BP).
      appbase::app().post(appbase::priority::medium, [
            id = log_s.block_->calculate_id(),
            num = log_s.block_->block_num(),
            block = log_s.block_,
            chain_plug = this->chain_plug_]() mutable {
         // whether to quit the whole process
         bool quit = false;
         // whether to accept the block
         bool accept_block = true;
         auto head_num = chain_plug->chain().head_block_num();
         auto head_id = chain_plug->chain().head_block_id();
         if (num < head_num) {
            // the producer_ha is processing historical blocks, no need to post it
            accept_block = false;

            dlog("Block ({n}, ID: {i}) is already in chain. Skipping accepting it again.",
                 ("n", num)("i", id));
         } else if (num == head_num) {
            if (id == head_id) {
               // no need to post it again
               accept_block = false;

               // mark the block valid, and should not be aborted later
               chain_plug->chain().mark_completing_succeeded_blockid(id);

               dlog("Committed a block ({n}, ID: {i}) which is already the current head. Skipped accepting again.",
                    ("n", num)("i", id));

            } else {
               // the current head block needs to be discarded, e.g. previously failed to be committed
               // post the block.
               //
               // One example situation: say we have BP1, BP2, BP3. BP1 is the leader.
               // Say a sequence of events happen as this (should be rare or never happen, but possible).
               //
               //  BP1 constructs a new head block at number N.
               //  BP1 is trying to commit it through Raft in the separate thread. Fails to commit it because of
               //     temporary network connectivity issues. BP1 gives away the leadership - but this message
               //     passed through the network successfully.
               //  BP2 and BP3 elect a new leader BP2.
               //  BP2 constructs a new head block at number N.
               //  BP2 connects back to BP1.
               //  BP2 commits the new head block.
               //
               // Now, BP1 receives a new block from BP2 at number N. But BP1 hasn't got the chance to remove the
               // previous head it constructed from its fork DB (e.g. BP1's CPU turns to be very slow dynamically
               // for some threads ...).
               //
               // BP1 should accept the new block from BP2. And eventually discard the head block it constructed.

               ilog("Committed a block ({n}, ID: {i}) at the same level as the current head ({h}, ID: {d}). Discarding the current head.",
                    ("n", num)("i", id)("h", head_num)("d", head_id));
            }
         } else if (num == head_num + 1) {
            // post the new block that is one block forward from the head
         } else {
            // num > head_num + 1
            // this happens means the chain is old and is still syncing up through p2p
            // in this case, we do not apply this block from Raft.
            // in can_produce() function, we should avoid allowing this node to produce in such status
            accept_block = false;
            elog("Received a block ({n}, ID: {i}), however, the head is only at ({h}, ID: {d}). Skip applying this block from producer_ha. Waiting for the chain to sync up first ...",
                 ("n", num)("i", id)("h", head_num)("d", head_id));
         }

         if (accept_block) {
            try {
               // apply this block to chain plugin
               bool accepted = chain_plug->accept_block(block, id);
               if (!accepted) {
                  quit = true;
                  elog("Chain plugin did not accept block ({n}, ID: {i}). Should not happen.",
                       ("n", num)("i", id));
               } else {
                  // mark the block valid, and should not be aborted later
                  chain_plug->chain().mark_completing_succeeded_blockid(id);

                  dlog("Accepted block ({n}, ID: {i})",
                       ("n", num)("i", id));
               }
            } catch (...) {
               quit = true;
               log_and_drop_exceptions();
            }
         }

         // quit the whole process, we don't want to move forward under unexpected situations
         if (quit) {
            appbase::app().quit();
         }
      });

      // store the new head
      db_->write(nodeos_state_db::state_machine, head_block_key, data);
      head_block_ = log_s.block_;

      update_last_commit_index(log_idx);
   }

   void update_last_commit_index(nuraft::ulong log_idx) {
      nuraft::ptr<nuraft::buffer> idx_buf = nuraft::buffer::alloc(sizeof(nuraft::ulong));
      idx_buf->put(log_idx);
      db_->write(nodeos_state_db::state_machine, last_commit_idx_key, idx_buf);
      last_commit_idx_ = log_idx;
   }

private:
   // lock_ should be acquired before updating fields
   std::mutex lock_;

   // State machine's current block(s), accessed by string key.
   chain::signed_block_ptr head_block_;
   nuraft::ulong last_commit_idx_;

   // rocksdb for persisting states
   std::shared_ptr<nodeos_state_db> db_;

   // log store
   nuraft::ptr<nodeos_state_log_store> log_store_;

   // chain plugin
   eosio::chain_plugin* chain_plug_ = nullptr;
};

}

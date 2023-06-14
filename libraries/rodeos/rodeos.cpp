#include <b1/rodeos/rodeos.hpp>

#include <b1/rodeos/callbacks/kv.hpp>
#include <b1/rodeos/rodeos_tables.hpp>
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
#   include <b1/rodeos/native_module_context_type.hpp>
#endif
#include <fc/log/trace.hpp>

#include <dlfcn.h>
#include <eosio/state_history/types.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/webassembly/dynamic_loaded_function.hpp>
#include <fc/scoped_exit.hpp>

namespace b1::rodeos {

namespace ship_protocol = eosio::ship_protocol;

using ship_protocol::get_blocks_result_base;
using ship_protocol::get_blocks_result_v0;
using ship_protocol::get_blocks_result_v1;
using ship_protocol::signed_block_header;
using ship_protocol::signed_block_variant;

rodeos_db_snapshot::rodeos_db_snapshot(std::shared_ptr<rodeos_db_partition> partition, bool persistent, bool undo_stack_enabled)
    : partition{ std::move(partition) }, db{ this->partition->db }, undo_stack_enabled{ undo_stack_enabled } {
   if (persistent) {
      undo_stack.emplace(*db, this->partition->undo_prefix);
      write_session.emplace(*db);
   } else {
      snap.emplace(db->rdb.get());
      write_session.emplace(*db, snap->snapshot());
   }

   db_view_state    view_state{ state_account, *db, *write_session, this->partition->contract_kv_prefix };
   fill_status_sing sing{ state_account, view_state, false };
   if (sing.exists()) {
      auto status     = std::get<0>(sing.get());
      chain_id        = status.chain_id;
      head            = status.head;
      head_id         = status.head_id;
      irreversible    = status.irreversible;
      irreversible_id = status.irreversible_id;
      first           = status.first;
   }
}

void rodeos_db_snapshot::refresh() {
   if (undo_stack)
      throw std::runtime_error("can not refresh a persistent snapshot");
   snap.emplace(db->rdb.get());
   write_session->snapshot = snap->snapshot();
   write_session->wipe_cache();
}

void rodeos_db_snapshot::write_fill_status() {
   if (!undo_stack)
      throw std::runtime_error("Can only write to persistent snapshots");
   fill_status status;
   if (irreversible < head)
      status = fill_status_v0{ .chain_id        = chain_id,
                               .head            = head,
                               .head_id         = head_id,
                               .irreversible    = irreversible,
                               .irreversible_id = irreversible_id,
                               .first           = first };
   else
      status = fill_status_v0{ .chain_id        = chain_id,
                               .head            = head,
                               .head_id         = head_id,
                               .irreversible    = head,
                               .irreversible_id = head_id,
                               .first           = first };

   db_view_state view_state{ state_account, *db, *write_session, partition->contract_kv_prefix };
   view_state.kv_state.enable_write = true;
   fill_status_sing sing{ state_account, view_state, false };
   sing.set(status);
   sing.store();
}

void rodeos_db_snapshot::end_write(bool write_fill) {
   if (!undo_stack)
      throw std::runtime_error("Can only write to persistent snapshots");
   if (write_fill)
      write_fill_status();
   write_session->write_changes(*undo_stack);
}

void rodeos_db_snapshot::start_block(const get_blocks_result_base& result) {
   if (!undo_stack)
      throw std::runtime_error("Can only write to persistent snapshots");
   if (!result.this_block)
      throw std::runtime_error("get_blocks_result this_block is empty");

   if (result.this_block->block_num <= head) {
      if (!undo_stack_enabled) {
           wlog("can't switch forks at {b} since undo stack is disabled. head: {h}", ("b", result.this_block->block_num) ("h", head));
           EOS_ASSERT(false, eosio::chain::unsupported_feature, "can't switch forks at {b} since undo stack is disabled. head: {h}", ("b", result.this_block->block_num) ("h", head));
      } else {
        ilog("switch forks at block {b}; database contains revisions {f} - {h}",
             ("b", result.this_block->block_num)("f", undo_stack->first_revision())("h", undo_stack->revision()));
        if (undo_stack->first_revision() >= result.this_block->block_num)
           throw std::runtime_error("can't switch forks since database doesn't contain revision " +
                                    std::to_string(result.this_block->block_num - 1));
        write_session->wipe_cache();
        while (undo_stack->revision() >= result.this_block->block_num) //
           undo_stack->undo(true);
      }
   }

   if (head_id != eosio::checksum256{} && (!result.prev_block || result.prev_block->block_id != head_id))
      throw std::runtime_error("prev_block does not match");

   if (!undo_stack_enabled) {
     end_write(false);
   } else {
     if (result.this_block->block_num <= result.last_irreversible.block_num) {
        undo_stack->commit(std::min(result.last_irreversible.block_num, head));
        undo_stack->set_revision(result.this_block->block_num, false);
     } else {
        end_write(false);
        undo_stack->commit(std::min(result.last_irreversible.block_num, head));
        undo_stack->push(false);
     }
   }

   writing_block = result.this_block->block_num;
}

void rodeos_db_snapshot::end_block(const get_blocks_result_base& result, bool force_write,
                                   bool dont_flush /* with default argument = false */) {
   if (!undo_stack)
      throw std::runtime_error("Can only write to persistent snapshots");
   if (!result.this_block)
      throw std::runtime_error("get_blocks_result this_block is empty");
   if (!writing_block || result.this_block->block_num != *writing_block)
      throw std::runtime_error("call start_block first");

   bool near       = result.this_block->block_num + 4 >= result.last_irreversible.block_num;
   bool write_now  = !(result.this_block->block_num % force_write_stride) || force_write;
   head            = result.this_block->block_num;
   head_id         = result.this_block->block_id;
   irreversible    = result.last_irreversible.block_num;
   irreversible_id = result.last_irreversible.block_id;
   if (!first || head < first)
      first = head;
   if (write_now || near)
      end_write(write_now || near);
   if (write_now && !dont_flush) {
      db->flush(false, false);
   }
}

void rodeos_db_snapshot::check_write(const ship_protocol::get_blocks_result_base& result) {
   if (!undo_stack)
      throw std::runtime_error("Can only write to persistent snapshots");
   if (!result.this_block)
      throw std::runtime_error("get_blocks_result this_block is empty");
   if (!writing_block || result.this_block->block_num != *writing_block)
      throw std::runtime_error("call start_block first");
}

void rodeos_db_snapshot::write_block_info(uint32_t block_num, const eosio::checksum256& id,
                                          const eosio::ship_protocol::signed_block_header& block) {
   db_view_state view_state{ state_account, *db, *write_session, partition->contract_kv_prefix };
   view_state.kv_state.enable_write = true;

   block_info_v0 info;
   info.num                = block_num;
   info.id                 = id;
   info.timestamp          = block.timestamp;
   info.producer           = block.producer;
   info.confirmed          = block.confirmed;
   info.previous           = block.previous;
   info.transaction_mroot  = block.transaction_mroot;
   info.action_mroot       = block.action_mroot;
   info.schedule_version   = block.schedule_version;
   info.new_producers      = block.new_producers;
   info.producer_signature = block.producer_signature;

   block_info_kv table{ kv_environment{ view_state } };
   table.put(info);
}

void rodeos_db_snapshot::write_block_info(const ship_protocol::get_blocks_result_v0& result) {
   check_write(result);
   if (!result.block)
      return;

   uint32_t            block_num = result.this_block->block_num;
   eosio::input_stream bin       = *result.block;
   signed_block_header block;
   from_bin(block, bin);
   write_block_info(block_num, result.this_block->block_id, block);
}

void rodeos_db_snapshot::write_block_info(const ship_protocol::get_blocks_result_v1& result) {
   check_write(result);
   if (!result.block)
      return;

   uint32_t block_num = result.this_block->block_num;

   const signed_block_header& header =
         std::visit([](const auto& blk) { return static_cast<const signed_block_header&>(blk); }, *result.block);

   write_block_info(block_num, result.this_block->block_id, header);
}

void rodeos_db_snapshot::write_block_info(const ship_protocol::get_blocks_result_v2& result) {
   check_write(result);
   signed_block_header header;
   if (!result.block_header.empty()) {
      eosio::unpack( result.block_header, header );
   } else if (!result.block.empty()) {
      signed_block_variant sbv;
      eosio::unpack( result.block, sbv );
      header = std::visit([](const auto& blk) { return static_cast<const signed_block_header&>(blk); }, sbv);
   } else {
      return;
   }

   uint32_t block_num = result.this_block->block_num;
   write_block_info(block_num, result.this_block->block_id, header);
}

void rodeos_db_snapshot::write_deltas(uint32_t block_num, eosio::opaque<std::vector<ship_protocol::table_delta>> deltas,
                                      std::function<bool()> shutdown) {
   db_view_state view_state{ state_account, *db, *write_session, partition->contract_kv_prefix };
   view_state.kv_state.bypass_receiver_check = true; // TODO: can we enable receiver check in the future
   view_state.kv_state.enable_write          = true;
   eosio::for_each(deltas, [this, &view_state, block_num](auto&& delta) {
      size_t num_processed = 0;
      std::visit(
         [this, &num_processed, &view_state, block_num](auto&& delta_any_v) {
         store_delta({ view_state }, delta_any_v, head == 0, [this, &num_processed, &view_state, &delta_any_v, block_num]() mutable{
            if (delta_any_v.rows.size() > 10000 && !(num_processed % 10000)) {
               ilog("block {b} {t} {n} of {r}",
                    ("b", block_num)("t", delta_any_v.name)("n", num_processed)("r", delta_any_v.rows.size()));
               if (head == 0) {
                  end_write(false);
                  view_state.reset();
               }
            }
            ++num_processed;
            dlog("block {b} {t} {n} of {r}",
                 ("b", block_num)("t", delta_any_v.name)("n", num_processed)("r", delta_any_v.rows.size()));

         });
      }, std::move(delta));
   });
}

void rodeos_db_snapshot::write_deltas(uint32_t block_num, std::vector<eosio::state_history::table_delta>&& deltas,
                                      std::function<bool()> shutdown) {
   db_view_state view_state{ state_account, *db, *write_session, partition->contract_kv_prefix };
   view_state.kv_state.bypass_receiver_check = true; // TODO: can we enable receiver check in the future
   view_state.kv_state.enable_write          = true;
   for( auto& delta : deltas ) {
      size_t num_processed = 0;
      store_delta({ view_state }, delta, head == 0, [this, &num_processed, &view_state, &delta, block_num]() mutable{
         if (delta.rows.obj.size() > 10000 && !(num_processed % 10000)) {
            ilog("block {b} {t} {n} of {r}",
                 ("b", block_num)("t", delta.name)("n", num_processed)("r", delta.rows.obj.size()));
            if (head == 0) {
               end_write(false);
               view_state.reset();
            }
         }
         ++num_processed;
         dlog("block {b} {t} {n} of {r}",
              ("b", block_num)("t", delta.name)("n", num_processed)("r", delta.rows.obj.size()));

      });
   }
}

void rodeos_db_snapshot::write_deltas(const ship_protocol::get_blocks_result_v0& result,
                                      std::function<bool()>                      shutdown) {
   check_write(result);
   if (!result.deltas)
      return;

   uint32_t block_num = result.this_block->block_num;
   write_deltas(block_num, eosio::as_opaque<std::vector<ship_protocol::table_delta>>(*result.deltas), shutdown);
}

void rodeos_db_snapshot::write_deltas(const ship_protocol::get_blocks_result_v1& result,
                                      std::function<bool()>                      shutdown) {
   check_write(result);
   if (result.deltas.empty())
      return;

   uint32_t block_num = result.this_block->block_num;
   write_deltas(block_num, result.deltas, shutdown);
}

void rodeos_db_snapshot::write_deltas(const ship_protocol::get_blocks_result_v2& result,
                                      std::function<bool()>                      shutdown) {
   check_write(result);
   if (result.deltas.empty()) {
      return;
   }
   dlog( "deltas size {s}", ("s", result.deltas.num_bytes()) );

   uint32_t block_num = result.this_block->block_num;
   write_deltas(block_num, result.deltas, shutdown);
}

filter::filter_state::~filter_state() {
   // wasm allocator must be explicitly freed
   wa.free();
}

std::once_flag registered_filter_callbacks;

#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
struct eos_vm_instantiated_module : instantiated_module_interface {
   std::unique_ptr<filter::backend_t>       backend = {};
   std::unique_ptr<eosio::vm::profile_data> prof    = {};

   template <typename Extrasetup>
   eos_vm_instantiated_module(
         const std::string& wasm_filename, bool profile, Extrasetup&& setup) {
      std::call_once(registered_filter_callbacks, filter::register_callbacks);
      std::ifstream wasm_file(wasm_filename, std::ios::binary);
      if (!wasm_file.is_open())
         throw std::runtime_error("can not open " + wasm_filename);
      ilog("compiling {f}", ("f", wasm_filename));
      wasm_file.seekg(0, std::ios::end);
      int len = wasm_file.tellg();
      if (len < 0)
         throw std::runtime_error("unable to get wasm file length");
      std::vector<uint8_t> code(len);
      wasm_file.seekg(0, std::ios::beg);
      wasm_file.read((char*)code.data(), code.size());
      wasm_file.close();
      backend = std::make_unique<filter::backend_t>(code, nullptr);
      filter::rhf_t::resolve(backend->get_module());
      if (profile) {
         prof = std::make_unique<eosio::vm::profile_data>(wasm_filename + ".profile", *backend);
      }
      setup(code);
   }

   void apply(filter::callbacks& cb) override {
      backend->set_wasm_allocator(&cb.filter_state.wa);
      backend->initialize(&cb);
      eosio::vm::scoped_profile profile_runner(prof.get());
      (*backend)(cb, "env", "apply", uint64_t(0), uint64_t(0), uint64_t(0));
   }
};

#   ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
struct eos_vm_oc_instantiated_module : eos_vm_instantiated_module {
   eos_vm_oc_instantiated_module(const std::string& wasm_filename, bool profile,
                                 const boost::filesystem::path&       eosvmoc_path,
                                 const eosio::chain::eosvmoc::config& eosvmoc_config,
                                 filter::filter_state&                filter_state)
       : eos_vm_instantiated_module(wasm_filename, profile,
                                    [&eosvmoc_path, &eosvmoc_config, &filter_state](const std::vector<uint8_t>& code) {
                                       if (eosvmoc_config.tierup) {
                                          try {
                                             auto cache_path = eosvmoc_path / "rodeos_eosvmoc_cc";
                                             try {
                                                filter_state.eosvmoc_tierup.emplace(
                                                      cache_path, eosvmoc_config, code,
                                                      eosio::chain::digest_type::hash(
                                                            reinterpret_cast<const char*>(code.data()), code.size()));
                                             } catch (const eosio::chain::database_exception& e) {
                                                wlog("eosvmoc cache exception {e} removing cache {c}",
                                                     ("e", e.to_string())("c", cache_path.generic_string()));
                                                // destroy cache and try again
                                                boost::filesystem::remove_all(cache_path);
                                                filter_state.eosvmoc_tierup.emplace(
                                                      cache_path, eosvmoc_config, code,
                                                      eosio::chain::digest_type::hash(
                                                            reinterpret_cast<const char*>(code.data()), code.size()));
                                             }
                                          }
                                          FC_LOG_AND_RETHROW();
                                       }
                                    }) {}

   void apply(filter::callbacks& cb) override {
      auto filter_state = &cb.filter_state;
      if (filter_state->eosvmoc_tierup) {
         const auto* code =
               filter_state->eosvmoc_tierup->cc.get_descriptor_for_code(filter_state->eosvmoc_tierup->hash, 0);
         if (code) {
            eosio::chain::eosvmoc::timer_base timer;
            filter_state->eosvmoc_tierup->exec.execute(*code, filter_state->eosvmoc_tierup->mem, &cb, 251, 65536,
                                                       &timer, 0, 0, 0);
            return;
         }
      }
      eos_vm_instantiated_module::apply(cb);
   }
};
#   endif // EOSIO_EOS_VM_OC_RUNTIME_ENABLED
#endif    // EOSIO_EOS_VM_JIT_RUNTIME_ENABLED

#if EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
struct native_instantiated_module : instantiated_module_interface {
   eosio::chain::dynamic_loaded_function apply_fun;
   native_module_context_type*           native_context;

   native_instantiated_module(const std::string& module_file, native_module_context_type* native_module_context)
       : apply_fun(module_file.c_str(), "apply"), native_context(native_module_context) {}

   void apply(filter::callbacks& cb) override {
      native_context->push(&cb);
      auto on_exit = fc::make_scoped_exit([this]() { native_context->pop(); });
      apply_fun.exec<void (*)(uint64_t, uint64_t, uint64_t)>(0, 0, 0);
   }
};
#endif

#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
rodeos_filter::rodeos_filter(eosio::name name, const std::string& wasm_filename, bool profile
#   ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
                             ,
                             const boost::filesystem::path&       eosvmoc_path,
                             const eosio::chain::eosvmoc::config& eosvmoc_config
#   endif
                             )
    : name{ name } {
#   ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
   instantiated = std::make_unique<eos_vm_oc_instantiated_module>(wasm_filename, profile, eosvmoc_path, eosvmoc_config,
                                                                  *filter_state);
#   else
   instantiated = std::make_unique<eos_vm_instantiated_module>(wasm_filename, profile, [](const std::vector<uint8_t>&){});
#   endif
}
#endif // EOSIO_EOS_VM_JIT_RUNTIME_ENABLED

#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
rodeos_filter::rodeos_filter(eosio::name name, const std::string& filename,
                             native_module_context_type* native_module_context)
    : name(name), instantiated(std::make_unique<native_instantiated_module>(filename, native_module_context)) {}
#endif

void rodeos_filter::process(rodeos_db_snapshot& snapshot, const ship_protocol::get_blocks_result_base& result,
                            eosio::input_stream                                         bin,
                            const std::function<void(const char* data, uint64_t size)>& push_data) {
   // todo: timeout
   snapshot.check_write(result);
   chaindb_state  chaindb_state;
   db_view_state  view_state{ name, *snapshot.db, *snapshot.write_session, snapshot.partition->contract_kv_prefix };
   coverage_state coverage_state;
   view_state.kv_state.enable_write = true;
   filter::callbacks cb{ *filter_state, chaindb_state, view_state, coverage_state };
   filter_state->max_console_size = 10000;
   filter_state->console.clear();
   filter_state->input_data = bin;
   filter_state->push_data  = push_data;
   try {
      auto on_exit = fc::make_scoped_exit([this]() {
         if (!filter_state->console.empty())
            ilog("filter {n} console output: <<<\n{c}>>>", ("n", name.to_string())("c", filter_state->console));
      });
      instantiated->apply(cb);
   } FC_CAPTURE_LOG_AND_RETHROW(("exception thrown while processing filter wasm"))
}

rodeos_query_handler::rodeos_query_handler(std::shared_ptr<rodeos_db_partition>         partition,
                                           std::shared_ptr<const wasm_ql::shared_state> shared_state)
    : partition{ partition }, shared_state{ std::move(shared_state) }, state_cache{
         std::make_shared<wasm_ql::thread_state_cache>(this->shared_state)
      } {}

} // namespace b1::rodeos

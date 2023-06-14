#pragma once
#include <b1/chain_kv/chain_kv.hpp>
#include <b1/rodeos/filter.hpp>
#include <b1/rodeos/wasm_ql.hpp>
#include <eosio/ship_protocol.hpp>
#include <eosio/vm/profile.hpp>
#include <functional>

namespace eosio::state_history {
struct table_delta;
}

namespace b1::rodeos {

static constexpr char undo_prefix_byte        = 0x01;
static constexpr char contract_kv_prefix_byte = 0x02;

struct rodeos_context {
   std::shared_ptr<chain_kv::database> db;
};

struct rodeos_db_partition {
   const std::shared_ptr<chain_kv::database> db;
   const std::vector<char>                   undo_prefix;
   const std::vector<char>                   contract_kv_prefix;

   // todo: move rocksdb::ManagedSnapshot to here to prevent optimization in cloner from
   //       defeating non-persistent snapshots.

   rodeos_db_partition(std::shared_ptr<chain_kv::database> db, const std::vector<char>& prefix)
       : db{ std::move(db) }, //
         undo_prefix{ [&] {
            auto x = prefix;
            x.push_back(undo_prefix_byte);
            return x;
         }() },
         contract_kv_prefix{ [&] {
            auto x = prefix;
            x.push_back(contract_kv_prefix_byte);
            return x;
         }() } {}
};

struct rodeos_db_snapshot {
   std::shared_ptr<rodeos_db_partition>    partition       = {};
   std::shared_ptr<chain_kv::database>     db              = {};
   bool                                    undo_stack_enabled = false;
   std::optional<chain_kv::undo_stack>     undo_stack      = {}; // only if persistent
   std::optional<rocksdb::ManagedSnapshot> snap            = {}; // only if !persistent
   std::optional<chain_kv::write_session>  write_session   = {};
   eosio::checksum256                      chain_id        = {};
   uint32_t                                head            = 0;
   eosio::checksum256                      head_id         = {};
   uint32_t                                irreversible    = 0;
   eosio::checksum256                      irreversible_id = {};
   uint32_t                                first           = 0;
   std::optional<uint32_t>                 writing_block   = {};
   uint32_t                                force_write_stride = 1; // used in modulus so init to 1 for eosio-tester

   rodeos_db_snapshot(std::shared_ptr<rodeos_db_partition> partition, bool persistent, bool undo_stack_disabled = false);

   void refresh();
   void end_write(bool write_fill);
   void start_block(const eosio::ship_protocol::get_blocks_result_base& result);
   // For end_block(), parameter dont_flush with default argument = false is an interim solution during the period when
   // we support both standalone rodeos program and rodeos-plugin. Accepting the default value of dont_flush (= false)
   // shall not change any existing behavior in standalone rodeos program. In the meanwhile, setting dont_flush = true
   // allows rodeos-plugin to skip flushing to its local RocksDB files during processing a block. We aim to make
   // rodeos-plugin a stateless plugin, so its local RocksDB files will be discarded anyway during a new startup.
   void end_block(const eosio::ship_protocol::get_blocks_result_base& result, bool force_write, bool dont_flush = false);
   void check_write(const eosio::ship_protocol::get_blocks_result_base& result);
   void write_block_info(const eosio::ship_protocol::get_blocks_result_v0& result);
   void write_block_info(const eosio::ship_protocol::get_blocks_result_v1& result);
   void write_block_info(const eosio::ship_protocol::get_blocks_result_v2& result);
   void write_deltas(const eosio::ship_protocol::get_blocks_result_v0& result, std::function<bool()> shutdown);
   void write_deltas(const eosio::ship_protocol::get_blocks_result_v1& result, std::function<bool()> shutdown);
   void write_deltas(const eosio::ship_protocol::get_blocks_result_v2& result, std::function<bool()> shutdown);
   void write_deltas(uint32_t block_num, std::vector<eosio::state_history::table_delta>&& deltas, std::function<bool()> shutdown);

 private:
   void write_block_info(uint32_t block_num, const eosio::checksum256& id,
                         const eosio::ship_protocol::signed_block_header& block);
   void write_deltas(uint32_t block_num, eosio::opaque<std::vector<eosio::ship_protocol::table_delta>> deltas,
                     std::function<bool()> shutdown);
   void write_fill_status();
};

struct native_module_context_type;

struct instantiated_module_interface {
   virtual void apply(filter::callbacks& cb) = 0;
   virtual ~instantiated_module_interface() {}
};

struct rodeos_filter {
   eosio::name                           name         = {};
   std::unique_ptr<filter::filter_state> filter_state = std::make_unique<filter::filter_state>();
   std::unique_ptr<instantiated_module_interface>  instantiated = {};

#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
   rodeos_filter(eosio::name name, const std::string& wasm_filename, bool profile
#ifdef EOSIO_EOS_VM_OC_RUNTIME_ENABLED
                 ,
                 const boost::filesystem::path&       eosvmoc_path   = "",
                 const eosio::chain::eosvmoc::config& eosvmoc_config = {}
#endif // EOSIO_EOS_VM_OC_RUNTIME_ENABLED
   );
#endif // WASM_RUNTIME_ENABLED

#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
   rodeos_filter(eosio::name name, const std::string& wasm_filename, native_module_context_type* native_module_context);
#endif // EOSIO_NATIVE_MODULE_RUNTIME_ENABLED

   void process(rodeos_db_snapshot& snapshot, const eosio::ship_protocol::get_blocks_result_base& result,
                eosio::input_stream bin, const std::function<void(const char* data, uint64_t size)>& push_data);
};

struct rodeos_query_handler {
   std::shared_ptr<rodeos_db_partition>               partition;
   const std::shared_ptr<const wasm_ql::shared_state> shared_state;
   const std::shared_ptr<wasm_ql::thread_state_cache> state_cache;

   rodeos_query_handler(std::shared_ptr<rodeos_db_partition>         partition,
                        std::shared_ptr<const wasm_ql::shared_state> shared_state);
   rodeos_query_handler(const rodeos_query_handler&) = delete;
};

} // namespace b1::rodeos

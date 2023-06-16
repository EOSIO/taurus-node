#include "test_chain.hpp"
#include <algorithm>
#include <b1/rodeos/filter.hpp>
#include <b1/rodeos/native_module_context_type.hpp>
#include <b1/rodeos/wasm_ql.hpp>
#include <eosio/chain/webassembly/dynamic_loaded_function.hpp>
#include <eosio/chain/webassembly/native-module-config.hpp>
#include <fc/scoped_exit.hpp>
#include <setjmp.h>

struct native_state;
native_state* ptr_state;

struct native_state : state, eosio::chain::native_module_context_type, b1::rodeos::native_module_context_type {
   using cb_alloc_data_type = void*;
   using cb_alloc_type      = void* (*)(void* cb_alloc_data, size_t size);

   b1::tester::callbacks<native_state> cb;
   std::exception_ptr                  eptr_;

   fc::temp_directory code_dir_;
   using callbacks_t = std::variant<eosio::chain::webassembly::interface*, b1::rodeos::filter::callbacks*,
                                    b1::rodeos::wasm_ql::callbacks*, b1::tester::callbacks<native_state>*>;
   std::vector<callbacks_t> callbacks_stack_;

   boost::filesystem::path code_dir() override { return code_dir_.path(); }
   void                    push(eosio::chain::webassembly::interface* interface) override { push_interface(interface); }
   void                    push(b1::rodeos::filter::callbacks* interface) override { push_interface(interface); }
   void                    push(b1::rodeos::wasm_ql::callbacks* interface) override { push_interface(interface); }
   void                    pop() override { callbacks_stack_.pop_back(); }

   template <typename Interface>
   void push_interface(Interface* interface) {
      callbacks_stack_.emplace_back(interface);
   }

   native_state(const std::vector<char>& args) : state(args), cb(*this) {
      this->files.emplace_back(stdin, false);
      this->files.emplace_back(stdout, false);
      this->files.emplace_back(stderr, false);
      callbacks_stack_.emplace_back(&cb);
   }

   void check_bounds(const void* data, size_t size) {}

   char* alloc(void*, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc, uint32_t size) {
      return reinterpret_cast<char*>(cb_alloc(cb_alloc_data, size));
   }

   void config_chain(eosio::chain::controller::config& cfg) {
      cfg.wasm_runtime                        = eosio::chain::wasm_interface::vm_type::native_module;
      cfg.native_config.native_module_context = this;
   }

   template <typename T>
   auto exec(T&& visitor) {
      return std::visit(std::forward<T&&>(visitor), callbacks_stack_.back());
   }
};

// helper type for the visitor #4
template <class... Ts>
struct overloaded : Ts... {
   using Ts::operator()...;
};
// explicit deduction guide (not needed as of C++20)
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

#define INTRINSIC_EXPORT extern "C" __attribute__((visibility("default")))
using cb_alloc_type = void* (*)(void* cb_alloc_data, size_t size);

INTRINSIC_EXPORT void eosio_assert_message(uint32_t test, const char* msg, uint32_t msg_len) {
   ptr_state->exec([&](auto arg) { arg->eosio_assert_message(test, { (char*)msg, msg_len }); });
}

INTRINSIC_EXPORT void prints_l(const char* msg, uint32_t len) { 
   ptr_state->exec([&](auto arg) { arg->prints_l({ (void*)msg, len }); });
}

INTRINSIC_EXPORT void prints(const char* msg) { prints_l(msg, strlen(msg)); }
INTRINSIC_EXPORT void printi(int64_t value) { prints(std::to_string(value).c_str()); }
INTRINSIC_EXPORT void printui(uint64_t value) { prints(std::to_string(value).c_str()); }
INTRINSIC_EXPORT void printn(uint64_t value) { prints( eosio::name(value).to_string().c_str());}

INTRINSIC_EXPORT void connect_rodeos(uint32_t rodeos, uint32_t chain) {
   ptr_state->exec(overloaded{
         [](auto arg) { throw std::runtime_error("connect_rodeos not implemented"); },
         [rodeos, chain](b1::tester::callbacks<native_state>* arg) { arg->connect_rodeos(rodeos, chain); } });
}

INTRINSIC_EXPORT uint32_t create_chain(const char* snapshot, uint32_t snapshot_size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("create_chain not implemented"); },
                     [snapshot, snapshot_size](b1::tester::callbacks<native_state>* arg) {
                        return arg->create_chain({ snapshot, snapshot_size });
                     } });
}

INTRINSIC_EXPORT uint32_t create_rodeos() {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("create_rodeos not implemented"); },
                     [](b1::tester::callbacks<native_state>* arg) { return arg->create_rodeos(); } });
}

INTRINSIC_EXPORT void destroy_chain(uint32_t chain) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("destroy_chain not implemented"); },
                               [chain](b1::tester::callbacks<native_state>* arg) { arg->destroy_chain(chain); } });
}

INTRINSIC_EXPORT void destroy_rodeos(uint32_t rodeos) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("destroy_rodeos not implemented"); },
                               [rodeos](b1::tester::callbacks<native_state>* arg) { arg->destroy_rodeos(rodeos); } });
}

INTRINSIC_EXPORT bool exec_deferred(uint32_t chain_index, void* cb_alloc_data, cb_alloc_type cb_alloc) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> bool { throw std::runtime_error("exec_deferred not implemented"); },
                     [chain_index, cb_alloc_data, cb_alloc](b1::tester::callbacks<native_state>* arg) {
                        return arg->exec_deferred(chain_index, cb_alloc_data, cb_alloc);
                     } });
}

INTRINSIC_EXPORT int32_t execute(const char* command, uint32_t command_size) {
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("execute not implemented"); },
                                      [command, command_size](b1::tester::callbacks<native_state>* arg) {
                                         return arg->execute({ command, command_size });
                                      } });
}

INTRINSIC_EXPORT void finish_block(uint32_t chain_index) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("finish_block not implemented"); },
                     [chain_index](b1::tester::callbacks<native_state>* arg) { arg->finish_block(chain_index); } });
}

INTRINSIC_EXPORT uint32_t get_args(char* dest, uint32_t dest_size) {
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("get_args not implemented"); },
                                      [dest, dest_size](b1::tester::callbacks<native_state>* arg) -> int32_t {
                                         return arg->get_args({ dest, dest_size });
                                      } });
}

INTRINSIC_EXPORT int32_t open_file(const char* filename, uint32_t filename_size, const char* mode, uint32_t mode_size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("open_file not implemented"); },
                     [filename, filename_size, mode, mode_size](b1::tester::callbacks<native_state>* arg) {
                        return arg->open_file({ filename, filename_size }, { mode, mode_size });
                     } });
}

INTRINSIC_EXPORT void close_file(int32_t file_index) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("close_file not implemented"); },
                     [file_index](b1::tester::callbacks<native_state>* arg) { arg->close_file(file_index); } });
}

INTRINSIC_EXPORT bool write_file(int32_t file_index, const char* content, uint32_t content_size) {
   return ptr_state->exec(overloaded{ [](auto arg) -> bool { throw std::runtime_error("write_file not implemented"); },
                                      [file_index, content, content_size](b1::tester::callbacks<native_state>* arg) {
                                         return arg->write_file(file_index, { content, content_size });
                                      } });
}

INTRINSIC_EXPORT uint32_t get_chain_path(uint32_t chain, char* dest, uint32_t dest_size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("get_chain_path not implemented"); },
                     [chain, dest, dest_size](b1::tester::callbacks<native_state>* arg) -> int32_t {
                        return arg->get_chain_path(chain, { dest, dest_size });
                     } });
}

INTRINSIC_EXPORT void get_head_block_info(uint32_t chain_index, void* cb_alloc_data, cb_alloc_type cb_alloc) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("get_head_block_info not implemented"); },
                               [chain_index, cb_alloc_data, cb_alloc](b1::tester::callbacks<native_state>* arg) {
                                  arg->get_head_block_info(chain_index, cb_alloc_data, cb_alloc);
                               } });
}

INTRINSIC_EXPORT uint32_t get_history(uint32_t chain_index, uint32_t block_num, char* dest, uint32_t dest_size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("get_history not implemented"); },
                     [chain_index, block_num, dest, dest_size](b1::tester::callbacks<native_state>* arg) -> int32_t {
                        return arg->get_history(chain_index, block_num, { dest, dest_size });
                     } });
}

INTRINSIC_EXPORT void push_transaction(uint32_t chain_index, const char* args_packed, uint32_t args_packed_size,
                                       void* cb_alloc_data, cb_alloc_type cb_alloc) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("push_transaction not implemented"); },
                     [chain_index, args_packed, args_packed_size, cb_alloc_data,
                      cb_alloc](b1::tester::callbacks<native_state>* arg) {
                        arg->push_transaction(chain_index, { args_packed, args_packed_size }, cb_alloc_data, cb_alloc);
                     } });
}

INTRINSIC_EXPORT void replace_account_keys(uint32_t chain_index, uint64_t account, uint64_t permission, const char* key,
                                           uint32_t key_size) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("replace_account_keys not implemented"); },
                     [chain_index, account, permission, key, key_size](b1::tester::callbacks<native_state>* arg) {
                        arg->replace_account_keys(chain_index, account, permission, { key, key_size });
                     } });
}

INTRINSIC_EXPORT void replace_producer_keys(uint32_t chain_index, const char* key, uint32_t key_size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("replace_producer_keys not implemented"); },
                               [chain_index, key, key_size](b1::tester::callbacks<native_state>* arg) {
                                  arg->replace_producer_keys(chain_index, { key, key_size });
                               } });
}

INTRINSIC_EXPORT void rodeos_add_filter(uint32_t rodeos, uint64_t name, const char* wasm_filename,
                                        uint32_t wasm_filename_size) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("rodeos_add_filter not implemented"); },
                     [rodeos, name, wasm_filename, wasm_filename_size](b1::tester::callbacks<native_state>* arg) {
                        boost::filesystem::path p(wasm_filename, wasm_filename+wasm_filename_size);
                        p.replace_extension(".so");
                        auto& r = arg->assert_rodeos(rodeos);
                        r.filters.emplace_back(name, p.c_str(), ptr_state);
                     } });
}

INTRINSIC_EXPORT void rodeos_enable_queries(uint32_t rodeos, uint32_t max_console_size, uint32_t wasm_cache_size,
                                            uint64_t max_exec_time_ms, const char* contract_dir,
                                            uint32_t contract_dir_size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("rodeos_enable_queries not implemented"); },
                               [rodeos, max_console_size, wasm_cache_size, max_exec_time_ms, contract_dir,
                                contract_dir_size](b1::tester::callbacks<native_state>* arg) {
                                  auto&       r = arg->assert_rodeos(rodeos);
                                  std::string contract_directory(contract_dir, contract_dir_size);
                                  r.query_handler.emplace(*r.partition, max_console_size, wasm_cache_size,
                                                          max_exec_time_ms, contract_directory.c_str(), ptr_state);
                               } });
}

INTRINSIC_EXPORT uint32_t rodeos_get_num_pushed_data(uint32_t rodeos) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> int32_t { throw std::runtime_error("rodeos_get_num_pushed_data not implemented"); },
         [rodeos](b1::tester::callbacks<native_state>* arg) -> int32_t {
            return arg->rodeos_get_num_pushed_data(rodeos);
         } });
}

INTRINSIC_EXPORT uint32_t rodeos_get_pushed_data(uint32_t rodeos, uint32_t index, char* dest, uint32_t dest_size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("rodeos_get_pushed_data not implemented"); },
                     [rodeos, index, dest, dest_size](b1::tester::callbacks<native_state>* arg) -> int32_t {
                        return arg->rodeos_get_pushed_data(rodeos, index, { dest, dest_size });
                     } });
}

INTRINSIC_EXPORT void rodeos_push_transaction(uint32_t rodeos, const char* packed_args, uint32_t packed_args_size,
                                              void* cb_alloc_data, cb_alloc_type cb_alloc) {
   ptr_state->exec(overloaded{
         [](auto arg) { throw std::runtime_error("rodeos_push_transaction not implemented"); },
         [rodeos, packed_args, packed_args_size, cb_alloc_data, cb_alloc](b1::tester::callbacks<native_state>* arg) {
            arg->rodeos_push_transaction(rodeos, { packed_args, packed_args_size }, cb_alloc_data, cb_alloc);
         } });
}

INTRINSIC_EXPORT bool rodeos_sync_block(uint32_t rodeos) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> bool { throw std::runtime_error("rodeos_sync_block not implemented"); },
         [rodeos](b1::tester::callbacks<native_state>* arg) -> bool { return arg->rodeos_sync_block(rodeos); } });
}

INTRINSIC_EXPORT void select_chain_for_db(uint32_t chain_index) {
   ptr_state->exec(overloaded{
         [](auto arg) { throw std::runtime_error("select_chain_for_db not implemented"); },
         [chain_index](b1::tester::callbacks<native_state>* arg) { arg->select_chain_for_db(chain_index); } });
}

INTRINSIC_EXPORT void shutdown_chain(uint32_t chain) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("shutdown_chain not implemented"); },
                               [chain](b1::tester::callbacks<native_state>* arg) { arg->shutdown_chain(chain); } });
}

INTRINSIC_EXPORT void start_block(uint32_t chain_index, int64_t skip_miliseconds) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("start_block not implemented"); },
                               [chain_index, skip_miliseconds](b1::tester::callbacks<native_state>* arg) {
                                  arg->start_block(chain_index, skip_miliseconds);
                               } });
}
INTRINSIC_EXPORT uint32_t sign(const char* key, uint32_t keylen, const void* digest, char* sig, uint32_t siglen) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("sign not implemented"); },
                     [key, keylen, digest, sig, siglen](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->sign({ key, keylen }, digest, { sig, siglen });
                     } });
}

INTRINSIC_EXPORT int32_t db_store_i64(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id, const void* data,
                                      uint32_t len) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_store_i64 not implemented"); },
                     [scope, table, payer, id, data, len](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_store_i64(scope, table, payer, id, { (char*)data, len });
                     } });
}

INTRINSIC_EXPORT void db_update_i64(int32_t iterator, uint64_t payer, const void* data, uint32_t len) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("db_update_i64 not implemented"); },
                               [iterator, payer, data, len](eosio::chain::webassembly::interface* arg) {
                                  arg->db_update_i64(iterator, payer, { (char*)data, len });
                               } });
}

INTRINSIC_EXPORT void db_remove_i64(int32_t iterator) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("db_remove_i64 not implemented"); },
                     [iterator](eosio::chain::webassembly::interface* arg) { arg->db_remove_i64(iterator); } });
}

INTRINSIC_EXPORT int32_t db_get_i64(int32_t iterator, char* data, uint32_t len) {
   return ptr_state->exec([iterator, data, len](auto arg) { return arg->db_get_i64(iterator, { data, len }); });
}

INTRINSIC_EXPORT int32_t db_next_i64(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec([iterator, primary](auto arg) { return arg->db_next_i64(iterator, primary); });
}

INTRINSIC_EXPORT int32_t db_previous_i64(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec([iterator, primary](auto arg) { return arg->db_previous_i64(iterator, primary); });
}

INTRINSIC_EXPORT int32_t db_find_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id) {
   return ptr_state->exec([code, scope, table, id](auto arg) { return arg->db_find_i64(code, scope, table, id); });
}

INTRINSIC_EXPORT int32_t db_lowerbound_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id) {
   return ptr_state->exec(
         [code, scope, table, id](auto arg) { return arg->db_lowerbound_i64(code, scope, table, id); });
}

INTRINSIC_EXPORT int32_t db_upperbound_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id) {
   return ptr_state->exec(
         [code, scope, table, id](auto arg) { return arg->db_upperbound_i64(code, scope, table, id); });
}
INTRINSIC_EXPORT int32_t db_end_i64(uint64_t code, uint64_t scope, uint64_t table) {
   return ptr_state->exec([code, scope, table](auto arg) { return arg->db_end_i64(code, scope, table); });
}

INTRINSIC_EXPORT int32_t db_idx64_store(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id,
                                        const uint64_t* secondary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_store not implemented"); },
                     [scope, table, payer, id, secondary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_store(scope, table, payer, id, (void*)secondary);
                     } });
}

INTRINSIC_EXPORT void db_idx64_update(int32_t iterator, uint64_t payer, const uint64_t* secondary) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("db_idx64_update not implemented"); },
                               [iterator, payer, secondary](eosio::chain::webassembly::interface* arg) {
                                  arg->db_idx64_update(iterator, payer, (void*)secondary);
                               } });
}

INTRINSIC_EXPORT void db_idx64_remove(int32_t iterator) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("db_idx64_remove not implemented"); },
                     [iterator](eosio::chain::webassembly::interface* arg) { arg->db_idx64_remove(iterator); } });
}

INTRINSIC_EXPORT int32_t db_idx64_find_secondary(uint64_t code, uint64_t scope, uint64_t table,
                                                 const uint64_t* secondary, uint64_t* primary) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_find_secondary not implemented"); },
         [&](eosio::chain::webassembly::interface* arg) -> uint32_t {
            return arg->db_idx64_find_secondary(code, scope, table, const_cast<uint64_t*>(secondary), primary);
         },
         [&](b1::tester::callbacks<native_state>* arg) -> uint32_t {
            return arg->db_idx64_find_secondary(code, scope, table, const_cast<uint64_t*>(secondary), primary);
         } });
}

INTRINSIC_EXPORT int32_t db_idx64_find_primary(uint64_t code, uint64_t scope, uint64_t table, uint64_t* secondary,
                                               uint64_t primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_find_primary not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_find_primary(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx64_find_primary(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx64_lowerbound(uint64_t code, uint64_t scope, uint64_t table, uint64_t* secondary,
                                             uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_lowerbound not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_lowerbound(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx64_lowerbound(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx64_upperbound(uint64_t code, uint64_t scope, uint64_t table, uint64_t* secondary,
                                             uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_upperbound not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_upperbound(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx64_upperbound(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx64_end(uint64_t code, uint64_t scope, uint64_t table) {
   return ptr_state->exec(
         overloaded{ [](b1::rodeos::filter::callbacks* arg) -> uint32_t {
                       throw std::runtime_error("db_idx64_end not implemented");
                    },
                     [code, scope, table](auto arg) -> uint32_t { return arg->db_idx64_end(code, scope, table); } });
}

INTRINSIC_EXPORT int32_t db_idx64_next(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_next not implemented"); },
                     [iterator, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_next(iterator, primary);
                     },
                     [iterator, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx64_next(iterator, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx64_previous(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx64_previous not implemented"); },
                     [iterator, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx64_previous(iterator, primary);
                     },
                     [iterator, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx64_previous(iterator, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_find_secondary(uint64_t code, uint64_t scope, uint64_t table,
                                                  const unsigned __int128* secondary, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_find_secondary not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_find_secondary(code, scope, table,
                                                             const_cast<unsigned __int128*>(secondary), primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_find_secondary(code, scope, table,
                                                             const_cast<unsigned __int128*>(secondary), primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_find_primary(uint64_t code, uint64_t scope, uint64_t table,
                                                unsigned __int128* secondary, uint64_t primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_find_primary not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_find_primary(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_find_primary(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_lowerbound(uint64_t code, uint64_t scope, uint64_t table,
                                              unsigned __int128* secondary, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_lowerbound not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_lowerbound(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_lowerbound(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_upperbound(uint64_t code, uint64_t scope, uint64_t table,
                                              unsigned __int128* secondary, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_upperbound not implemented"); },
                     [code, scope, table, secondary, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_upperbound(code, scope, table, secondary, primary);
                     },
                     [code, scope, table, secondary, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_upperbound(code, scope, table, secondary, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_end(uint64_t code, uint64_t scope, uint64_t table) {
   return ptr_state->exec(
         overloaded{ [](b1::rodeos::filter::callbacks* arg) -> uint32_t {
                       throw std::runtime_error("db_idx128_end not implemented");
                    },
                     [code, scope, table](auto arg) -> uint32_t { return arg->db_idx128_end(code, scope, table); } });
}

INTRINSIC_EXPORT int32_t db_idx128_store(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id,
                                         const unsigned __int128* secondary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_store not implemented"); },
                     [scope, table, payer, id, secondary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_store(scope, table, payer, id, const_cast<unsigned __int128*>(secondary));
                     } });
}

INTRINSIC_EXPORT void db_idx128_update(int32_t iterator, uint64_t payer, const unsigned __int128* secondary) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("db_idx128_update not implemented"); },
                               [iterator, payer, secondary](eosio::chain::webassembly::interface* arg) {
                                  arg->db_idx128_update(iterator, payer, (void*)secondary);
                               } });
}

INTRINSIC_EXPORT void db_idx128_remove(int32_t iterator) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("db_idx128_remove not implemented"); },
                     [iterator](eosio::chain::webassembly::interface* arg) { arg->db_idx128_remove(iterator); } });
}

INTRINSIC_EXPORT int32_t db_idx128_next(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_next not implemented"); },
                     [iterator, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_next(iterator, primary);
                     },
                     [iterator, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_next(iterator, primary);
                     } });
}

INTRINSIC_EXPORT int32_t db_idx128_previous(int32_t iterator, uint64_t* primary) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("db_idx128_previous not implemented"); },
                     [iterator, primary](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->db_idx128_previous(iterator, primary);
                     },
                     [iterator, primary](b1::tester::callbacks<native_state>* arg) -> uint32_t {
                        return arg->db_idx128_previous(iterator, primary);
                     } });
}

INTRINSIC_EXPORT int64_t kv_erase(uint64_t contract, const char* key, uint32_t key_size) {
   return ptr_state->exec([contract, key, key_size](auto arg) { return arg->kv_erase(contract, { key, key_size }); });
}

INTRINSIC_EXPORT int64_t kv_set(uint64_t contract, const char* key, uint32_t key_size, const char* value,
                                uint32_t value_size, uint64_t payer) {
   return ptr_state->exec([contract, key, key_size, value, value_size, payer](auto arg) {
      return arg->kv_set(contract, { key, key_size }, { value, value_size }, payer);
   });
}

INTRINSIC_EXPORT bool kv_get(uint64_t contract, const char* key, uint32_t key_size, uint32_t& value_size) {
   return ptr_state->exec([contract, key, key_size, &value_size](auto arg) {
      return arg->kv_get(contract, { key, key_size }, &value_size);
   });
}

INTRINSIC_EXPORT uint32_t kv_get_data(uint32_t offset, char* data, uint32_t data_size) {
   return ptr_state->exec([offset, data, data_size](auto arg) {
      return arg->kv_get_data(offset, { data, data_size });
   });
}

INTRINSIC_EXPORT uint32_t kv_it_create(uint64_t contract, const char* prefix, uint32_t size) {
   return ptr_state->exec([contract, prefix, size](auto arg) { return arg->kv_it_create(contract, { prefix, size }); });
}

INTRINSIC_EXPORT void kv_it_destroy(uint32_t itr) {
   ptr_state->exec([itr](auto arg) { arg->kv_it_destroy(itr); });
}

INTRINSIC_EXPORT int32_t kv_it_status(uint32_t itr) {
   return ptr_state->exec([itr](auto arg) { return arg->kv_it_status(itr); });
}

INTRINSIC_EXPORT int32_t kv_it_compare(uint32_t itr_a, uint32_t itr_b) {
   return ptr_state->exec([itr_a, itr_b](auto arg) { return arg->kv_it_compare(itr_a, itr_b); });
}

INTRINSIC_EXPORT int32_t kv_it_key_compare(uint32_t itr, const char* key, uint32_t size) {
   return ptr_state->exec([itr, key, size](auto arg) { return arg->kv_it_key_compare(itr, { key, size }); });
}

INTRINSIC_EXPORT int32_t kv_it_move_to_end(uint32_t itr) {
   return ptr_state->exec([itr](auto arg) { return arg->kv_it_move_to_end(itr); });
}

INTRINSIC_EXPORT int32_t kv_it_next(uint32_t itr, uint32_t* found_key_size, uint32_t* found_value_size) {
   return ptr_state->exec([itr, found_key_size, found_value_size](auto arg) {
      return arg->kv_it_next(itr, found_key_size, found_value_size);
   });
}

INTRINSIC_EXPORT int32_t kv_it_prev(uint32_t itr, uint32_t* found_key_size, uint32_t* found_value_size) {
   return ptr_state->exec([itr, found_key_size, found_value_size](auto arg) {
      return arg->kv_it_prev(itr, found_key_size, found_value_size);
   });
}

INTRINSIC_EXPORT int32_t kv_it_lower_bound(uint32_t itr, const char* key, uint32_t size, uint32_t& found_key_size,
                                           uint32_t& found_value_size) {
   return ptr_state->exec([itr, key, size, &found_key_size, &found_value_size](auto arg) {
      return arg->kv_it_lower_bound(itr, { key, size }, &found_key_size, &found_value_size);
   });
}

INTRINSIC_EXPORT int32_t kv_it_key(uint32_t itr, uint32_t offset, char* dest, uint32_t size, uint32_t& actual_size) {
   return ptr_state->exec([itr, offset, dest, size, &actual_size](auto arg) {
      return arg->kv_it_key(itr, offset, { dest, size }, &actual_size);
   });
}

INTRINSIC_EXPORT int32_t kv_it_value(uint32_t itr, uint32_t offset, char* dest, uint32_t size, uint32_t& actual_size) {
   return ptr_state->exec([itr, offset, dest, size, &actual_size](auto arg) {
      return arg->kv_it_value(itr, offset, { dest, size }, &actual_size);
   });
}

INTRINSIC_EXPORT void kv_check_iterator(uint32_t itr) {
   ptr_state->exec(overloaded{ [](eosio::chain::webassembly::interface* arg) {
                                 throw std::runtime_error("kv_check_iterator not implemented");
                              },
                               [itr](auto arg) { return arg->kv_check_iterator(itr); } });
}

struct capi_checksum160;
struct capi_checksum256;
struct capi_checksum512;

INTRINSIC_EXPORT void assert_sha256(const char* data, uint32_t length, const capi_checksum256* hash) {
   ptr_state->cb.assert_sha256({ data, length }, hash);
}
INTRINSIC_EXPORT void assert_sha1(const char* data, uint32_t length, const capi_checksum160* hash) {
   ptr_state->cb.assert_sha1({ data, length }, hash);
}
INTRINSIC_EXPORT void assert_sha512(const char* data, uint32_t length, const capi_checksum512* hash) {
   ptr_state->cb.assert_sha512({ data, length }, hash);
}
INTRINSIC_EXPORT void assert_ripemd160(const char* data, uint32_t length, const capi_checksum160* hash) {
   ptr_state->cb.assert_ripemd160({ data, length }, hash);
}
INTRINSIC_EXPORT void sha256(const char* data, uint32_t length, capi_checksum256* hash) {
   ptr_state->cb.sha256({ data, length }, hash);
}
INTRINSIC_EXPORT void sha1(const char* data, uint32_t length, capi_checksum160* hash) {
   ptr_state->cb.sha1({ data, length }, hash);
}
INTRINSIC_EXPORT void sha512(const char* data, uint32_t length, capi_checksum512* hash) {
   ptr_state->cb.sha512({ data, length }, hash);
}

INTRINSIC_EXPORT void ripemd160(const char* data, uint32_t length, capi_checksum160* hash) {
   ptr_state->cb.ripemd160({ data, length }, hash);
}

INTRINSIC_EXPORT int32_t recover_key(const capi_checksum256* digest, const char* sig, uint32_t siglen, char* pub,
                                     uint32_t publen) {                                     
   return ptr_state->exec(
      [&](auto arg) -> uint32_t {
      return arg->recover_key((void*)digest, { (void*)sig, siglen }, {(void*) pub, publen });
   });

}

INTRINSIC_EXPORT bool read_whole_file(const char* filename, uint32_t filename_size, void* cb_alloc_data,
                                      cb_alloc_type cb_alloc) {
   namespace bfs = boost::filesystem;
   bfs::path fn{ filename, filename + filename_size };
   if (fn.extension() == ".wasm") {
      fn.replace_extension(".so");
      if (bfs::exists(fn)) {
         bfs::path code_dir  = ptr_state->code_dir();
         auto      abs_fn    = bfs::absolute(fn);
         auto      from_path = code_dir / (fc::sha256::hash(abs_fn.c_str(), abs_fn.size()).str() + ".so");
         boost::system::error_code ec;
         create_symlink(abs_fn, from_path, ec);
         ilog("setup symlink {from} --> {to}", ("from", from_path.c_str())("to", abs_fn.c_str()));
         ptr_state->cb.set_data(cb_alloc_data, cb_alloc, std::string_view{ abs_fn.c_str(), abs_fn.size() });
         return true;
      }
      return false;
   }

   return ptr_state->cb.read_whole_file({ filename, filename_size }, cb_alloc_data, cb_alloc);
}

INTRINSIC_EXPORT bool read_abi_file(const char* filename, uint32_t filename_size, void* cb_alloc_data,
                                      cb_alloc_type cb_alloc) {
   return ptr_state->cb.read_abi_file({ filename, filename_size }, cb_alloc_data, cb_alloc);
}

INTRINSIC_EXPORT void assert_recover_key(const struct capi_checksum256* digest, const char* sig, uint32_t siglen,
                                         const char* pub, uint32_t publen) {
   ptr_state->exec([digest, sig, siglen, pub, publen](auto arg) {
      arg->assert_recover_key(const_cast<capi_checksum256*>(digest), { (void*)sig, siglen }, { (void*)pub, publen });
   });
}

INTRINSIC_EXPORT void eosio_assert(uint32_t test, const char* msg) { eosio_assert_message(test, msg, strlen(msg)); }

INTRINSIC_EXPORT void eosio_assert_code(uint32_t test, uint64_t code) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("eosio_assert_code not implemented"); },
                     [test, code](eosio::chain::webassembly::interface* arg) { arg->eosio_assert_code(test, code); } });
}

INTRINSIC_EXPORT uint64_t current_time() {
   return ptr_state->exec([](auto arg) { return arg->current_time(); });
}

INTRINSIC_EXPORT void load_block_info() {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("load_block_info not implemented"); },
                               [](b1::rodeos::filter::callbacks* arg) { arg->load_block_info(); },
                               [](b1::rodeos::wasm_ql::callbacks* arg) { arg->load_block_info(); } });
}

INTRINSIC_EXPORT bool is_privileged(uint64_t account) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> bool { throw std::runtime_error("is_privileged not implemented"); },
         [account](eosio::chain::webassembly::interface* arg) -> bool { return arg->is_privileged(account); } });
}

INTRINSIC_EXPORT void get_resource_limits(uint64_t account, int64_t* ram_bytes, int64_t* net_weight,
                                          int64_t* cpu_weight) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("get_resource_limits not implemented"); },
                               [account, ram_bytes, net_weight, cpu_weight](eosio::chain::webassembly::interface* arg) {
                                  arg->get_resource_limits(eosio::chain::account_name{ account }, ram_bytes, net_weight,
                                                           cpu_weight);
                               } });
}

INTRINSIC_EXPORT void set_resource_limits(uint64_t account, int64_t ram_bytes, int64_t net_weight, int64_t cpu_weight) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_resource_limits not implemented"); },
                               [account, ram_bytes, net_weight, cpu_weight](eosio::chain::webassembly::interface* arg) {
                                  arg->set_resource_limits(eosio::chain::account_name{ account }, ram_bytes, net_weight,
                                                           cpu_weight);
                               } });
}

INTRINSIC_EXPORT void set_privileged(uint64_t account, bool is_priv) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_privileged not implemented"); },
                               [account, is_priv](eosio::chain::webassembly::interface* arg) {
                                  arg->set_privileged(eosio::chain::account_name{ account }, is_priv);
                               } });
}

INTRINSIC_EXPORT void set_blockchain_parameters_packed(char* data, uint32_t datalen) {
   ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("set_blockchain_parameters_packed not implemented"); },
                     [data, datalen](eosio::chain::webassembly::interface* arg) {
                        arg->set_blockchain_parameters_packed({ data, datalen });
                     } });
}

INTRINSIC_EXPORT uint32_t get_blockchain_parameters_packed(char* data, uint32_t datalen) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> uint32_t { throw std::runtime_error("get_blockchain_parameters_packed not implemented"); },
         [data, datalen](eosio::chain::webassembly::interface* arg) -> uint32_t {
            return arg->get_blockchain_parameters_packed({ data, datalen });
         } });
}

INTRINSIC_EXPORT int64_t set_proposed_producers(char* data, uint32_t datalen) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int64_t { throw std::runtime_error("set_proposed_producers not implemented"); },
                     [data, datalen](eosio::chain::webassembly::interface* arg) -> int64_t {
                        return arg->set_proposed_producers({ data, datalen });
                     } });
}

INTRINSIC_EXPORT uint32_t get_active_producers(uint64_t* data, uint32_t datalen) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("get_active_producers not implemented"); },
                     [data, datalen](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->get_active_producers({ data, datalen });
                     } });
}

INTRINSIC_EXPORT bool is_feature_activated(void* feature_digest) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> bool { throw std::runtime_error("is_feature_activated not implemented"); },
                     [feature_digest](eosio::chain::webassembly::interface* arg) -> bool {
                        return arg->is_feature_activated(feature_digest);
                     } });
}

INTRINSIC_EXPORT uint64_t get_sender() {
   return ptr_state->exec(overloaded{
         [](auto arg) -> uint64_t { throw std::runtime_error("get_sender not implemented"); },
         [](eosio::chain::webassembly::interface* arg) -> uint64_t { return arg->get_sender().to_uint64_t(); } });
}

INTRINSIC_EXPORT void push_event(const char* data, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("push_event not implemented"); },
                               [data, size](eosio::chain::webassembly::interface* arg) {
                                  arg->push_event({ data, size });
                               } });
}

INTRINSIC_EXPORT void set_push_event_alloc(uint32_t chain_index, void* cb_alloc_data, cb_alloc_type cb_alloc) {
   ptr_state->exec(
           overloaded{ [](auto arg) { throw std::runtime_error("set_push_event_alloc not implemented"); },
                       [chain_index, cb_alloc_data, cb_alloc](b1::tester::callbacks<native_state>* arg) {
                          arg->set_push_event_alloc(chain_index, cb_alloc_data, cb_alloc);
                       } });
}

INTRINSIC_EXPORT void preactivate_feature(const void* feature_digest) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("preactivate_feature not implemented"); },
                               [feature_digest](eosio::chain::webassembly::interface* arg) {
                                  return arg->preactivate_feature(const_cast<void*>(feature_digest));
                               } });
}

INTRINSIC_EXPORT int64_t set_proposed_producers_ex(uint64_t producer_data_format, char* producer_data,
                                                   uint32_t producer_data_size) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> int64_t { throw std::runtime_error("set_proposed_producers_ex not implemented"); },
         [producer_data_format, producer_data,
          producer_data_size](eosio::chain::webassembly::interface* arg) -> int64_t {
            return arg->set_proposed_producers_ex(producer_data_format, { producer_data, producer_data_size });
         } });
}
///
INTRINSIC_EXPORT uint32_t read_action_data(char* msg, uint32_t len) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("read_action_data not implemented"); },
                     [msg, len](eosio::chain::webassembly::interface* arg) -> uint32_t {
                        return arg->read_action_data({ msg, len });
                     },
                     [msg, len](b1::rodeos::wasm_ql::callbacks* arg) -> uint32_t {
                        return arg->read_action_data({ msg, len });
                     } });
}

INTRINSIC_EXPORT uint32_t action_data_size() {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("action_data_size not implemented"); },
                     [](eosio::chain::webassembly::interface* arg) -> uint32_t { return arg->action_data_size(); },
                     [](b1::rodeos::wasm_ql::callbacks* arg) -> uint32_t { return arg->action_data_size(); } });
}

INTRINSIC_EXPORT void require_recipient(uint64_t name) {
   return ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("require_recipient not implemented"); },
                                      [name](eosio::chain::webassembly::interface* arg) {
                                         return arg->require_recipient(eosio::chain::account_name{ name });
                                      } });
}

INTRINSIC_EXPORT void require_auth(uint64_t name) {
   return ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("require_auth not implemented"); },
                                      [name](eosio::chain::webassembly::interface* arg) {
                                         return arg->require_auth(eosio::chain::account_name{ name });
                                      } });
}

INTRINSIC_EXPORT bool has_auth(uint64_t name) {
   return ptr_state->exec(overloaded{ [](auto arg) -> bool { throw std::runtime_error("has_auth not implemented"); },
                                      [name](eosio::chain::webassembly::interface* arg) -> bool {
                                         return arg->has_auth(eosio::chain::account_name{ name });
                                      } });
}

INTRINSIC_EXPORT void require_auth2(uint64_t name, uint64_t permission) {
   return ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("require_auth2 not implemented"); },
                                      [name, permission](eosio::chain::webassembly::interface* arg) {
                                         return arg->require_auth2(eosio::chain::account_name{ name },
                                                                   eosio::chain::account_name{ permission });
                                      } });
}

INTRINSIC_EXPORT bool is_account(uint64_t name) {
   return ptr_state->exec(overloaded{ [](auto arg) -> bool { throw std::runtime_error("is_account not implemented"); },
                                      [name](eosio::chain::webassembly::interface* arg) -> bool {
                                         return arg->is_account(eosio::chain::account_name{ name });
                                      } });
}

INTRINSIC_EXPORT void send_inline(char* serialized_action, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("send_inline not implemented"); },
                               [serialized_action, size](eosio::chain::webassembly::interface* arg) {
                                  arg->send_inline({ serialized_action, (uint32_t)size });
                               } });
}

INTRINSIC_EXPORT void send_context_free_inline(char* serialized_action, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("send_context_free_inline not implemented"); },
                               [serialized_action, size](eosio::chain::webassembly::interface* arg) {
                                  arg->send_context_free_inline({ serialized_action, (uint32_t)size });
                               } });
}

INTRINSIC_EXPORT uint64_t publication_time() {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint64_t { throw std::runtime_error("publication_time not implemented"); },
                     [](eosio::chain::webassembly::interface* arg) -> uint64_t { return arg->publication_time(); } });
}

INTRINSIC_EXPORT uint64_t current_receiver() {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> uint64_t { throw std::runtime_error("current_receiver not implemented"); },
                     [](eosio::chain::webassembly::interface* arg) -> uint64_t { return arg->current_receiver(); },
                     [](b1::rodeos::wasm_ql::callbacks* arg) -> uint64_t { return arg->current_receiver(); } });
}

INTRINSIC_EXPORT void set_action_return_value(void* return_value, uint32_t size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) { throw std::runtime_error("set_action_return_value not implemented"); },
                     [return_value, size](eosio::chain::webassembly::interface* arg) {
                        return arg->set_action_return_value({ (const char*)return_value, (uint32_t)size });
                     },
                     [return_value, size](b1::rodeos::wasm_ql::callbacks* arg) {
                        return arg->set_action_return_value({ (const char*)return_value, (uint32_t)size });
                     } });
}

INTRINSIC_EXPORT int32_t check_transaction_authorization(const char* trx_data, uint32_t trx_size,
                                                         const char* pubkeys_data, uint32_t pubkeys_size,
                                                         const char* perms_data, uint32_t perms_size) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> int32_t { throw std::runtime_error("check_transaction_authorization not implemented"); },
         [trx_data, trx_size, pubkeys_data, pubkeys_size, perms_data,
          perms_size](eosio::chain::webassembly::interface* arg) -> int32_t {
            return arg->check_transaction_authorization({ (void*)trx_data, (uint32_t)trx_size },
                                                        { (void*)pubkeys_data, (uint32_t)pubkeys_size },
                                                        { (void*)perms_data, (uint32_t)perms_size });
         } });
}

INTRINSIC_EXPORT int32_t check_permission_authorization(uint64_t account, uint64_t permission, const char* pubkeys_data,
                                                        uint32_t pubkeys_size, const char* perms_data,
                                                        uint32_t perms_size, uint64_t delay_us) {
   return ptr_state->exec(overloaded{
         [](auto arg) -> int32_t { throw std::runtime_error("check_permission_authorization not implemented"); },
         [account, permission, pubkeys_data, pubkeys_size, perms_data, perms_size,
          delay_us](eosio::chain::webassembly::interface* arg) -> int32_t {
            return arg->check_permission_authorization(eosio::chain::account_name{ account },
                                                       eosio::chain::account_name{ permission },
                                                       { (void*)pubkeys_data, (uint32_t)pubkeys_size },
                                                       { (void*)perms_data, perms_size }, (uint32_t)delay_us);
         } });
}

INTRINSIC_EXPORT int64_t get_permission_last_used(uint64_t account, uint64_t permission) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int64_t { throw std::runtime_error("get_permission_last_used not implemented"); },
                     [account, permission](eosio::chain::webassembly::interface* arg) -> int64_t {
                        return arg->get_permission_last_used(eosio::chain::account_name{ account },
                                                             eosio::chain::account_name{ permission });
                     } });
}

INTRINSIC_EXPORT int64_t get_account_creation_time(uint64_t account) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int64_t { throw std::runtime_error("get_account_creation_time not implemented"); },
                     [account](eosio::chain::webassembly::interface* arg) -> int64_t {
                        return arg->get_account_creation_time(eosio::chain::account_name{ account });
                     } });
}

INTRINSIC_EXPORT int32_t get_action(uint32_t type, uint32_t index, char* buff, uint32_t size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("get_action not implemented"); },
                     [type, index, buff, size](eosio::chain::webassembly::interface* arg) -> int32_t {
                        return arg->get_action(type, index, { buff, (uint32_t)size });
                     } });
}

INTRINSIC_EXPORT void set_kv_parameters_packed(const char* params, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_kv_parameters_packed not implemented"); },
                               [params, size](eosio::chain::webassembly::interface* arg) {
                                  arg->set_kv_parameters_packed({ params, size });
                               } });
}

INTRINSIC_EXPORT uint32_t get_kv_parameters_packed(void* params, uint32_t size, uint32_t max_version) {
   return ptr_state->exec(overloaded{ [](auto arg) -> uint32_t { throw std::runtime_error("get_kv_parameters_packed not implemented"); },
                               [params, size, max_version](eosio::chain::webassembly::interface* arg) {
                                  return arg->get_kv_parameters_packed({ (char*)params, size }, max_version);
                               } });
}

INTRINSIC_EXPORT void set_wasm_parameters_packed(const char* params, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_wasm_parameters_packed not implemented"); },
                               [params, size](eosio::chain::webassembly::interface* arg) {
                                  arg->set_wasm_parameters_packed({ params, size });
                               } });
}

INTRINSIC_EXPORT void set_parameters_packed(const char* params, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_parameters_packed not implemented"); },
                               [params, size](eosio::chain::webassembly::interface* arg) {
                                  arg->set_parameters_packed({ params, size });
                               } });
}

INTRINSIC_EXPORT uint32_t get_input_data(char* dest, uint32_t size) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("get_input_data not implemented"); },
                     [dest, size](b1::rodeos::filter::callbacks* arg) -> int32_t {
                        return arg->get_input_data({ dest, size });
                     } });
}

INTRINSIC_EXPORT void set_output_data(const char* data, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_output_data not implemented"); },
                               [data, size](b1::rodeos::filter::callbacks* arg) {
                                  return arg->set_output_data({ data, size });
                               } });
}

INTRINSIC_EXPORT void push_data(const char* data, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("push_data not implemented"); },
                               [data, size](b1::rodeos::filter::callbacks* arg) {
                                  arg->push_data({ data, size });
                               } });
}

INTRINSIC_EXPORT void print_time_us() {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("print_time_us not implemented"); },
                               [](b1::rodeos::filter::callbacks* arg) { arg->print_time_us(); } });
}

INTRINSIC_EXPORT void write_snapshot(uint32_t chain, const char* filename, uint32_t size) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("write_snapshot not implemented"); },
                               [&](b1::tester::callbacks<native_state>* arg) { arg->write_snapshot(chain, {filename, size}); } });
}


INTRINSIC_EXPORT void set_resource_limit( uint64_t account, uint64_t resource, int64_t limit ) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("set_resource_limit not implemented"); },
                               [account, resource, limit](eosio::chain::webassembly::interface* arg) {
                                  arg->set_resource_limit(eosio::chain::account_name{ account }, eosio::chain::account_name{resource}, limit);
                               } });
}

INTRINSIC_EXPORT void printi128( const void* value ){
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("printi128 not implemented"); },
                               [value](eosio::chain::webassembly::interface* arg) {
                                  arg->printi128((void*)value);
                               } });
}

INTRINSIC_EXPORT void printui128( const void* value ) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("printui128 not implemented"); },
                               [value](eosio::chain::webassembly::interface* arg) {
                                  arg->printui128((void*)value);
                               } });
}

INTRINSIC_EXPORT void printhex( const void* data, uint32_t datalen ){
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("printhex not implemented"); },
                               [data, datalen](eosio::chain::webassembly::interface* arg) {
                                  arg->printhex({ (void*)data, datalen});
                               } });
}

using uint128_t           = unsigned __int128;

INTRINSIC_EXPORT int32_t db_idx256_store(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id, const uint128_t* data, uint32_t data_len ){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_store not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_store( scope, table, payer, id, {(void*)data, data_len});
                               } });
}

INTRINSIC_EXPORT void db_idx256_update(int32_t iterator, uint64_t payer, const uint128_t* data, uint32_t data_len){
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("db_idx256_update not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  arg->db_idx256_update(iterator, payer, { (void*)data, data_len});
                               } });

}

INTRINSIC_EXPORT void db_idx256_remove(int32_t iterator) {
   ptr_state->exec(overloaded{ [](auto arg) { throw std::runtime_error("db_idx256_remove not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  arg->db_idx256_remove(iterator);
                               } });
}

INTRINSIC_EXPORT int32_t db_idx256_next(int32_t iterator, uint64_t* primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_next not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_next( iterator, primary);
                               } });
}

INTRINSIC_EXPORT int32_t db_idx256_previous(int32_t iterator, uint64_t* primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_previous not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_previous( iterator, primary);
                               } });
}


INTRINSIC_EXPORT int32_t db_idx256_find_primary(uint64_t code, uint64_t scope, uint64_t table, uint128_t* data, uint32_t data_len, uint64_t primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_find_primary not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_find_primary( code, scope, table, {(void*)data, data_len}, primary);
                               } });
}

INTRINSIC_EXPORT int32_t db_idx256_find_secondary(uint64_t code, uint64_t scope, uint64_t table, const uint128_t* data, uint32_t data_len, uint64_t* primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_find_secondary not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_find_secondary( code, scope, table, {(void*)data, data_len}, primary);
                               } });
}

INTRINSIC_EXPORT int32_t db_idx256_lowerbound(uint64_t code, uint64_t scope, uint64_t table, uint128_t* data, uint32_t data_len, uint64_t* primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_lowerbound not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_lowerbound( code, scope, table, {(void*)data, data_len}, primary);
                               } });
}


INTRINSIC_EXPORT int32_t db_idx256_upperbound(uint64_t code, uint64_t scope, uint64_t table, uint128_t* data, uint32_t data_len, uint64_t* primary){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_upperbound not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_upperbound( code, scope, table, {(void*)data, data_len}, primary);
                               } });
}

INTRINSIC_EXPORT int32_t db_idx256_end(uint64_t code, uint64_t scope, uint64_t table){
   return ptr_state->exec(overloaded{ [](auto arg) -> int32_t { throw std::runtime_error("db_idx256_end not implemented"); },
                               [&](eosio::chain::webassembly::interface* arg) {
                                  return arg->db_idx256_end( code, scope, table);
                               } });
}

INTRINSIC_EXPORT bool verify_rsa_sha256_sig(const char* msg, uint32_t msg_len,
                                            const char* sig, uint32_t sig_len,
                                            const char* exp, uint32_t exp_len,
                                            const char* mod, uint32_t mod_len){
   return ptr_state->exec(
         overloaded{ [](auto arg) -> bool { throw std::runtime_error("verify_rsa_sha256_sig not implemented"); },
                     [&](eosio::chain::webassembly::interface* arg) -> bool {
                        return arg->verify_rsa_sha256_sig({ (void*)msg, msg_len },
                                                          { (void*)sig, sig_len },
                                                          { (void*)exp, exp_len },
                                                          { (void*)mod, mod_len });
                     } });
}

INTRINSIC_EXPORT bool verify_ecdsa_sig(const char* msg, uint32_t msg_len,
                                       const char* sig, uint32_t sig_len,
                                       const char* pubkey, uint32_t pubkey_len) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> bool { throw std::runtime_error("verify_ecdsa_sig not implemented"); },
                     [&](eosio::chain::webassembly::interface* arg) -> bool {
                        return arg->verify_ecdsa_sig({ (void*)msg, msg_len },
                                                     { (void*)sig, sig_len },
                                                     { (void*)pubkey, pubkey_len });
                     } });
}

INTRINSIC_EXPORT bool is_supported_ecdsa_pubkey(const char* pubkey, uint32_t pubkey_len) {
   return ptr_state->exec(
         overloaded{ [](auto arg) -> bool { throw std::runtime_error("is_supported_ecdsa_pubkey not implemented"); },
                     [&](eosio::chain::webassembly::interface* arg) -> bool {
                        return arg->is_supported_ecdsa_pubkey({ (void*)pubkey, pubkey_len });
                     } });
}

int run(const char* filename, const std::vector<std::string>& args) {
   native_state state{ eosio::convert_to_bin(args) };
   ptr_state = &state;

   boost::filesystem::path fn = filename;
   if (!fn.has_parent_path()) {
      fn = boost::filesystem::current_path() / fn;
   }

   eosio::chain::dynamic_loaded_function start_fun(fn.c_str(), "start");
   return start_fun.exec<int (*)(void (*f)())>(nullptr);
}

const char* usage = "usage: native-tester [-h or --help] [-v or --verbose] file.so [args for loadable module]\n";
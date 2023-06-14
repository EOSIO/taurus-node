#include "test_chain.hpp"
#include <eosio/vm/backend.hpp>

struct wasm_state;
using callbacks = b1::tester::callbacks<wasm_state>;
using rhf_t     = eosio::vm::registered_host_functions<callbacks>;
using backend_t = eosio::vm::backend<rhf_t, eosio::vm::jit>;

struct wasm_state : state {
   using cb_alloc_data_type = uint32_t;
   using cb_alloc_type      = uint32_t;

   const char*                               wasm;
   eosio::vm::wasm_allocator&                wa;
   backend_t&                                backend;
   wasm_state(const char* wasm, eosio::vm::wasm_allocator& wa,  backend_t& backend, const std::vector<char>& args)
      : state(args), wasm(wasm), wa(wa), backend(backend) {}

   void check_bounds(const void* data, size_t size) {
      volatile auto check = *((const char*)data + size - 1);
      eosio::vm::ignore_unused_variable_warning(check);
   }

   char* alloc(callbacks* cb, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc, uint32_t size) {
            // todo: verify cb_alloc isn't in imports
      if (backend.get_module().tables.size() < 0 || backend.get_module().tables[0].table.size() < cb_alloc)
         throw std::runtime_error("cb_alloc is out of range");
      auto result = backend.get_context().execute( //
            cb, eosio::vm::jit_visitor(42), backend.get_module().tables[0].table[cb_alloc], cb_alloc_data,
            size);
      if (!result || !result->is_a<eosio::vm::i32_const_t>())
         throw std::runtime_error("cb_alloc returned incorrect type");
      char* begin = wa.get_base_ptr<char>() + result->to_ui32();
      check_bounds(begin, size);
      return begin;
   }

   void config_chain(eosio::chain::controller::config& cfg) {
      cfg.wasm_runtime = eosio::chain::wasm_interface::vm_type::eos_vm_jit;
   }
};


#define DB_REGISTER_SECONDARY(IDX)                                                                                     \
   rhf_t::add<&callbacks::db_##IDX##_find_secondary>("env", "db_" #IDX "_find_secondary");                             \
   rhf_t::add<&callbacks::db_##IDX##_find_primary>("env", "db_" #IDX "_find_primary");                                 \
   rhf_t::add<&callbacks::db_##IDX##_lowerbound>("env", "db_" #IDX "_lowerbound");                                     \
   rhf_t::add<&callbacks::db_##IDX##_upperbound>("env", "db_" #IDX "_upperbound");                                     \
   rhf_t::add<&callbacks::db_##IDX##_end>("env", "db_" #IDX "_end");                                                   \
   rhf_t::add<&callbacks::db_##IDX##_next>("env", "db_" #IDX "_next");                                                 \
   rhf_t::add<&callbacks::db_##IDX##_previous>("env", "db_" #IDX "_previous");

void register_callbacks() {
   rhf_t::add<&callbacks::abort>("env", "abort");
   rhf_t::add<&callbacks::eosio_assert_message>("env", "eosio_assert_message");
   rhf_t::add<&callbacks::prints_l>("env", "prints_l");
   rhf_t::add<&callbacks::get_args>("env", "get_args");
   rhf_t::add<&callbacks::clock_gettime>("env", "clock_gettime");
   rhf_t::add<&callbacks::open_file>("env", "open_file");
   rhf_t::add<&callbacks::isatty>("env", "isatty");
   rhf_t::add<&callbacks::close_file>("env", "close_file");
   rhf_t::add<&callbacks::write_file>("env", "write_file");
   rhf_t::add<&callbacks::read_file>("env", "read_file");
   rhf_t::add<&callbacks::read_whole_file>("env", "read_whole_file");
   rhf_t::add<&callbacks::read_abi_file>("env", "read_abi_file");
   rhf_t::add<&callbacks::execute>("env", "execute");
   rhf_t::add<&callbacks::create_chain>("env", "create_chain");
   rhf_t::add<&callbacks::destroy_chain>("env", "destroy_chain");
   rhf_t::add<&callbacks::shutdown_chain>("env", "shutdown_chain");
   rhf_t::add<&callbacks::write_snapshot>("env", "write_snapshot");
   rhf_t::add<&callbacks::get_chain_path>("env", "get_chain_path");
   rhf_t::add<&callbacks::replace_producer_keys>("env", "replace_producer_keys");
   rhf_t::add<&callbacks::replace_account_keys>("env", "replace_account_keys");
   rhf_t::add<&callbacks::start_block>("env", "start_block");
   rhf_t::add<&callbacks::finish_block>("env", "finish_block");
   rhf_t::add<&callbacks::get_head_block_info>("env", "get_head_block_info");
   rhf_t::add<&callbacks::push_transaction>("env", "push_transaction");
   rhf_t::add<&callbacks::exec_deferred>("env", "exec_deferred");
   rhf_t::add<&callbacks::get_history>("env", "get_history");
   rhf_t::add<&callbacks::select_chain_for_db>("env", "select_chain_for_db");
   rhf_t::add<&callbacks::set_push_event_alloc>("env", "set_push_event_alloc");

   rhf_t::add<&callbacks::create_rodeos>("env", "create_rodeos");
   rhf_t::add<&callbacks::destroy_rodeos>("env", "destroy_rodeos");
   rhf_t::add<&callbacks::rodeos_add_filter>("env", "rodeos_add_filter");
   rhf_t::add<&callbacks::rodeos_enable_queries>("env", "rodeos_enable_queries");
   rhf_t::add<&callbacks::connect_rodeos>("env", "connect_rodeos");
   rhf_t::add<&callbacks::rodeos_sync_block>("env", "rodeos_sync_block");
   rhf_t::add<&callbacks::rodeos_push_transaction>("env", "rodeos_push_transaction");
   rhf_t::add<&callbacks::rodeos_get_num_pushed_data>("env", "rodeos_get_num_pushed_data");
   rhf_t::add<&callbacks::rodeos_get_pushed_data>("env", "rodeos_get_pushed_data");

   rhf_t::add<&callbacks::db_get_i64>("env", "db_get_i64");
   rhf_t::add<&callbacks::db_next_i64>("env", "db_next_i64");
   rhf_t::add<&callbacks::db_previous_i64>("env", "db_previous_i64");
   rhf_t::add<&callbacks::db_find_i64>("env", "db_find_i64");
   rhf_t::add<&callbacks::db_lowerbound_i64>("env", "db_lowerbound_i64");
   rhf_t::add<&callbacks::db_upperbound_i64>("env", "db_upperbound_i64");
   rhf_t::add<&callbacks::db_end_i64>("env", "db_end_i64");
   DB_REGISTER_SECONDARY(idx64)
   DB_REGISTER_SECONDARY(idx128)
   // DB_REGISTER_SECONDARY(idx256)
   // DB_REGISTER_SECONDARY(idx_double)
   // DB_REGISTER_SECONDARY(idx_long_double)
   rhf_t::add<&callbacks::kv_erase>("env", "kv_erase");
   rhf_t::add<&callbacks::kv_set>("env", "kv_set");
   rhf_t::add<&callbacks::kv_get>("env", "kv_get");
   rhf_t::add<&callbacks::kv_get_data>("env", "kv_get_data");
   rhf_t::add<&callbacks::kv_it_create>("env", "kv_it_create");
   rhf_t::add<&callbacks::kv_it_destroy>("env", "kv_it_destroy");
   rhf_t::add<&callbacks::kv_it_status>("env", "kv_it_status");
   rhf_t::add<&callbacks::kv_it_compare>("env", "kv_it_compare");
   rhf_t::add<&callbacks::kv_it_key_compare>("env", "kv_it_key_compare");
   rhf_t::add<&callbacks::kv_it_move_to_end>("env", "kv_it_move_to_end");
   rhf_t::add<&callbacks::kv_it_next>("env", "kv_it_next");
   rhf_t::add<&callbacks::kv_it_prev>("env", "kv_it_prev");
   rhf_t::add<&callbacks::kv_it_lower_bound>("env", "kv_it_lower_bound");
   rhf_t::add<&callbacks::kv_it_key>("env", "kv_it_key");
   rhf_t::add<&callbacks::kv_it_value>("env", "kv_it_value");
   rhf_t::add<&callbacks::sign>("env", "sign");

   rhf_t::add<&callbacks::assert_sha1>("env", "assert_sha1");
   rhf_t::add<&callbacks::assert_sha256>("env", "assert_sha256");
   rhf_t::add<&callbacks::assert_sha512>("env", "assert_sha512");
   rhf_t::add<&callbacks::assert_ripemd160>("env", "assert_ripemd160");

   rhf_t::add<&callbacks::sha1>("env", "sha1");
   rhf_t::add<&callbacks::sha256>("env", "sha256");
   rhf_t::add<&callbacks::sha512>("env", "sha512");
   rhf_t::add<&callbacks::ripemd160>("env", "ripemd160");
   rhf_t::add<&callbacks::recover_key>("env", "recover_key");
   rhf_t::add<&callbacks::has_auth>("env", "has_auth");
}

int run(const char* wasm, const std::vector<std::string>& args) {
   register_callbacks();

   eosio::vm::wasm_allocator wa;
   auto                      code = eosio::vm::read_wasm(wasm);
   backend_t                 backend(code, nullptr);
   ::wasm_state              state{ wasm, wa, backend, eosio::convert_to_bin(args) };
   callbacks                 cb{ state };
   state.files.emplace_back(stdin, false);
   state.files.emplace_back(stdout, false);
   state.files.emplace_back(stderr, false);
   backend.set_wasm_allocator(&wa);

   rhf_t::resolve(backend.get_module());
   backend.initialize(&cb);
   auto returned_stack_elem = backend.call_with_return(cb, "env", "start", 0);
   if (returned_stack_elem.has_value()) {
      return returned_stack_elem->to_i32();
   }
   return 0;
}

const char* usage = "usage: eosio-tester [-h or --help] [-v or --verbose] file.wasm [args for wasm]\n";


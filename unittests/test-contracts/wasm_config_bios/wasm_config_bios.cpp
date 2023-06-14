#include <eosio/contract.hpp>
#include <eosio/privileged.hpp>

#if !__has_include(<eosio/table.hpp>)
extern "C" __attribute__((eosio_wasm_import)) void set_wasm_parameters_packed(const char*, uint32_t);
extern "C" __attribute__((eosio_wasm_import)) uint32_t read_action_data( void* msg, uint32_t len );
extern "C" __attribute__((eosio_wasm_import))    uint32_t action_data_size();
#else
using namespace eosio::internal_use_do_not_use;
#endif

struct wasm_config {
   std::uint32_t max_mutable_global_bytes;
   std::uint32_t max_table_elements;
   std::uint32_t max_section_elements;
   std::uint32_t max_linear_memory_init;
   std::uint32_t max_func_local_bytes;
   std::uint32_t max_nested_structures;
   std::uint32_t max_symbol_bytes;
   std::uint32_t max_module_bytes;
   std::uint32_t max_code_bytes;
   std::uint32_t max_pages;
   std::uint32_t max_call_depth;
};

struct internal_config {
   uint32_t version;
   wasm_config config;
};

class [[eosio::contract]] wasm_config_bios : public eosio::contract {
 public:
   using contract::contract;
   [[eosio::action]] void setwparams(const wasm_config& cfg) {
      internal_config config{0, cfg};
      set_wasm_parameters_packed(reinterpret_cast<const char*>(&config), sizeof(config));
   }
};

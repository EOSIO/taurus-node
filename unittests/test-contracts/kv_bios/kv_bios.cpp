#include <eosio/contract.hpp>
#include <eosio/name.hpp>
#include <eosio/privileged.hpp>

#if defined( __eosio_cdt_major__) &&  __eosio_cdt_major__ <= 2
extern "C" __attribute__((import_name("set_resource_limit"))) void set_resource_limit(int64_t, int64_t, int64_t);
extern "C" __attribute__((import_name("get_kv_parameters_packed"))) uint32_t get_kv_parameters_packed(void* params, uint32_t size, uint32_t max_version);
extern "C" __attribute__((import_name("set_kv_parameters_packed"))) void set_kv_parameters_packed(const char* params, uint32_t size);
#else
using eosio::internal_use_do_not_use::set_resource_limit;
using eosio::internal_use_do_not_use::get_kv_parameters_packed;
using eosio::internal_use_do_not_use::set_kv_parameters_packed; 
#endif

using namespace eosio;

// Manages resources used by the kv-store
class [[eosio::contract]] kv_bios : eosio::contract {
 public:
   using contract::contract;
   [[eosio::action]] void setramlimit(name account, int64_t limit) {
      set_resource_limit(account.value, "ram"_n.value, limit);
   }
   [[eosio::action]] void ramkvlimits(uint32_t k, uint32_t v, uint32_t i) {
      kvlimits_impl(k, v, i);
   }
   void kvlimits_impl(uint32_t k, uint32_t v, uint32_t i) {
      uint32_t limits[4];
      limits[0] = 0;
      limits[1] = k;
      limits[2] = v;
      limits[3] = i;
      char limits_buf[sizeof(limits)];
      memcpy(limits_buf, limits, sizeof(limits));
      set_kv_parameters_packed(limits_buf, sizeof(limits));
      int sz = get_kv_parameters_packed(nullptr, 0, 0);
      std::fill_n(limits, sizeof(limits)/sizeof(limits[0]), 0xFFFFFFFFu);
      check(sz == 16, "wrong kv parameters size");
      sz = get_kv_parameters_packed(limits, sizeof(limits), 0);
      check(sz == 16, "wrong kv parameters result");
      check(limits[0] == 0, "wrong version");
      check(limits[1] == k, "wrong key");
      check(limits[2] == v, "wrong value");
      check(limits[3] == i, "wrong iter limit");
   }
};

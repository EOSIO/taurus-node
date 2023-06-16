
#include <eosio/chain/webassembly/interface.hpp>
#include <eosio/chain/webassembly/native-module-config.hpp>

namespace {
   static eosio::chain::webassembly::interface *interface_;
   static boost::filesystem::path code_path_;
}

namespace eosio::chain {

struct native_module_runtime : native_module_context_type {
  native_module_runtime(boost::filesystem::path p) { code_path_ = p; }
  boost::filesystem::path code_dir() override { return code_path_; }
  void push(webassembly::interface *ifs) override { interface_ = ifs; };
  void pop() override{};
};

void configure_native_module(native_module_config &config,
                             const boost::filesystem::path &p) {
  static native_module_runtime runtime{p};
  config.native_module_context = &runtime;
}
} // namespace eosio::chain

#define INTRINSIC_EXPORT extern "C" __attribute__((visibility("default")))
using cb_alloc_type = void *(*)(void *cb_alloc_data, size_t size);

INTRINSIC_EXPORT void eosio_assert_message(uint32_t test, const char *msg,
                                           uint32_t msg_len) {
  if (interface_)
    interface_->eosio_assert_message(test, {(char *)msg, msg_len});
}

INTRINSIC_EXPORT void prints_l(const char *msg, uint32_t len) {
  if (interface_)
    interface_->prints_l({(char *)msg, len});
}

INTRINSIC_EXPORT void prints(const char *msg) { prints_l(msg, strlen(msg)); }
INTRINSIC_EXPORT void printi(int64_t value) {
  prints(std::to_string(value).c_str());
}
INTRINSIC_EXPORT void printui(uint64_t value) {
  prints(std::to_string(value).c_str());
}
INTRINSIC_EXPORT void printn(uint64_t value) {
  prints(eosio::chain::name(value).to_string().c_str());
}

INTRINSIC_EXPORT int32_t db_store_i64(uint64_t scope, uint64_t table,
                                      uint64_t payer, uint64_t id,
                                      const void *data, uint32_t len) {
  return interface_ ? interface_->db_store_i64(scope, table, payer, id,
                                               {(char *)data, len})
                    : 0;
}

INTRINSIC_EXPORT void db_update_i64(int32_t iterator, uint64_t payer,
                                    const void *data, uint32_t len) {
  if (interface_)
    interface_->db_update_i64(iterator, payer, {(char *)data, len});
}

INTRINSIC_EXPORT void db_remove_i64(int32_t iterator) {
  if (interface_)
    interface_->db_remove_i64(iterator);
}

INTRINSIC_EXPORT int32_t db_get_i64(int32_t iterator, char *data,
                                    uint32_t len) {
  return interface_ ? interface_->db_get_i64(iterator, {data, len}) : 0;
}

INTRINSIC_EXPORT int32_t db_next_i64(int32_t iterator, uint64_t *primary) {
  return interface_ ? interface_->db_next_i64(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_previous_i64(int32_t iterator, uint64_t *primary) {
  return interface_ ? interface_->db_previous_i64(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_find_i64(uint64_t code, uint64_t scope,
                                     uint64_t table, uint64_t id) {
  return interface_ ? interface_->db_find_i64(code, scope, table, id) : 0;
}

INTRINSIC_EXPORT int32_t db_lowerbound_i64(uint64_t code, uint64_t scope,
                                           uint64_t table, uint64_t id) {
  return interface_ ? interface_->db_lowerbound_i64(code, scope, table, id) : 0;
}

INTRINSIC_EXPORT int32_t db_upperbound_i64(uint64_t code, uint64_t scope,
                                           uint64_t table, uint64_t id) {
  return interface_ ? interface_->db_upperbound_i64(code, scope, table, id) : 0;
}
INTRINSIC_EXPORT int32_t db_end_i64(uint64_t code, uint64_t scope,
                                    uint64_t table) {
  return interface_ ? interface_->db_end_i64(code, scope, table) : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_store(uint64_t scope, uint64_t table,
                                        uint64_t payer, uint64_t id,
                                        const uint64_t *secondary) {
  return interface_ ? interface_->db_idx64_store(scope, table, payer, id,
                                                 (void *)secondary)
                    : 0;
}

INTRINSIC_EXPORT void db_idx64_update(int32_t iterator, uint64_t payer,
                                      const uint64_t *secondary) {
  if (interface_)
    interface_->db_idx64_update(iterator, payer, (void *)secondary);
}

INTRINSIC_EXPORT void db_idx64_remove(int32_t iterator) {
  if (interface_)
    interface_->db_idx64_remove(iterator);
}

INTRINSIC_EXPORT int32_t db_idx64_find_secondary(uint64_t code, uint64_t scope,
                                                 uint64_t table,
                                                 const uint64_t *secondary,
                                                 uint64_t *primary) {
  return interface_ ? interface_->db_idx64_find_secondary(
                          code, scope, table, const_cast<uint64_t *>(secondary),
                          primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_find_primary(uint64_t code, uint64_t scope,
                                               uint64_t table,
                                               uint64_t *secondary,
                                               uint64_t primary) {
  return interface_ ? interface_->db_idx64_find_primary(code, scope, table,
                                                        secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_lowerbound(uint64_t code, uint64_t scope,
                                             uint64_t table,
                                             uint64_t *secondary,
                                             uint64_t *primary) {
  return interface_ ? interface_->db_idx64_lowerbound(code, scope, table,
                                                      secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_upperbound(uint64_t code, uint64_t scope,
                                             uint64_t table,
                                             uint64_t *secondary,
                                             uint64_t *primary) {
  return interface_ ? interface_->db_idx64_upperbound(code, scope, table,
                                                      secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_end(uint64_t code, uint64_t scope,
                                      uint64_t table) {
  return interface_ ? interface_->db_idx64_end(code, scope, table) : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_next(int32_t iterator, uint64_t *primary) {
  return interface_ ? interface_->db_idx64_next(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_idx64_previous(int32_t iterator,
                                           uint64_t *primary) {
  return interface_ ? interface_->db_idx64_previous(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_find_secondary(
    uint64_t code, uint64_t scope, uint64_t table,
    const unsigned __int128 *secondary, uint64_t *primary) {
  return interface_ ? interface_->db_idx128_find_secondary(
                          code, scope, table,
                          const_cast<unsigned __int128 *>(secondary), primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_find_primary(uint64_t code, uint64_t scope,
                                                uint64_t table,
                                                unsigned __int128 *secondary,
                                                uint64_t primary) {
  return interface_ ? interface_->db_idx128_find_primary(code, scope, table,
                                                         secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_lowerbound(uint64_t code, uint64_t scope,
                                              uint64_t table,
                                              unsigned __int128 *secondary,
                                              uint64_t *primary) {
  return interface_ ? interface_->db_idx128_lowerbound(code, scope, table,
                                                       secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_upperbound(uint64_t code, uint64_t scope,
                                              uint64_t table,
                                              unsigned __int128 *secondary,
                                              uint64_t *primary) {
  return interface_ ? interface_->db_idx128_upperbound(code, scope, table,
                                                       secondary, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_end(uint64_t code, uint64_t scope,
                                       uint64_t table) {
  return interface_ ? interface_->db_idx128_end(code, scope, table) : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_store(uint64_t scope, uint64_t table,
                                         uint64_t payer, uint64_t id,
                                         const unsigned __int128 *secondary) {
  return interface_ ? interface_->db_idx128_store(
                          scope, table, payer, id,
                          const_cast<unsigned __int128 *>(secondary))
                    : 0;
}

INTRINSIC_EXPORT void db_idx128_update(int32_t iterator, uint64_t payer,
                                       const unsigned __int128 *secondary) {
  if (interface_)
    interface_->db_idx128_update(iterator, payer, (void *)secondary);
}

INTRINSIC_EXPORT void db_idx128_remove(int32_t iterator) {
  if (interface_)
    interface_->db_idx128_remove(iterator);
}

INTRINSIC_EXPORT int32_t db_idx128_next(int32_t iterator, uint64_t *primary) {
  return interface_ ? interface_->db_idx128_next(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_idx128_previous(int32_t iterator,
                                            uint64_t *primary) {
  return interface_ ? interface_->db_idx128_previous(iterator, primary) : 0;
}

INTRINSIC_EXPORT int64_t kv_erase(uint64_t contract, const char *key,
                                  uint32_t key_size) {
  return interface_ ? interface_->kv_erase(contract, {key, key_size}) : 0;
}

INTRINSIC_EXPORT int64_t kv_set(uint64_t contract, const char *key,
                                uint32_t key_size, const char *value,
                                uint32_t value_size, uint64_t payer) {
  return interface_ ? interface_->kv_set(contract, {key, key_size},
                                         {value, value_size}, payer)
                    : 0;
}

INTRINSIC_EXPORT bool kv_get(uint64_t contract, const char *key,
                             uint32_t key_size, uint32_t &value_size) {
  return interface_ ? interface_->kv_get(contract, {key, key_size}, &value_size)
                    : 0;
}

INTRINSIC_EXPORT uint32_t kv_get_data(uint32_t offset, char *data,
                                      uint32_t data_size) {
  return interface_ ? interface_->kv_get_data(offset, {data, data_size}) : 0;
}

INTRINSIC_EXPORT uint32_t kv_it_create(uint64_t contract, const char *prefix,
                                       uint32_t size) {
  return interface_ ? interface_->kv_it_create(contract, {prefix, size}) : 0;
}

INTRINSIC_EXPORT void kv_it_destroy(uint32_t itr) {
  if (interface_)
    interface_->kv_it_destroy(itr);
}

INTRINSIC_EXPORT int32_t kv_it_status(uint32_t itr) {
  return interface_ ? interface_->kv_it_status(itr) : 0;
}

INTRINSIC_EXPORT int32_t kv_it_compare(uint32_t itr_a, uint32_t itr_b) {
  return interface_ ? interface_->kv_it_compare(itr_a, itr_b) : 0;
}

INTRINSIC_EXPORT int32_t kv_it_key_compare(uint32_t itr, const char *key,
                                           uint32_t size) {
  return interface_ ? interface_->kv_it_key_compare(itr, {key, size}) : 0;
}

INTRINSIC_EXPORT int32_t kv_it_move_to_end(uint32_t itr) {
  return interface_ ? interface_->kv_it_move_to_end(itr) : 0;
}

INTRINSIC_EXPORT int32_t kv_it_next(uint32_t itr, uint32_t *found_key_size,
                                    uint32_t *found_value_size) {
  return interface_
             ? interface_->kv_it_next(itr, found_key_size, found_value_size)
             : 0;
}

INTRINSIC_EXPORT int32_t kv_it_prev(uint32_t itr, uint32_t *found_key_size,
                                    uint32_t *found_value_size) {
  return interface_
             ? interface_->kv_it_prev(itr, found_key_size, found_value_size)
             : 0;
}

INTRINSIC_EXPORT int32_t kv_it_lower_bound(uint32_t itr, const char *key,
                                           uint32_t size,
                                           uint32_t &found_key_size,
                                           uint32_t &found_value_size) {
  return interface_ ? interface_->kv_it_lower_bound(
                          itr, {key, size}, &found_key_size, &found_value_size)
                    : 0;
}

INTRINSIC_EXPORT int32_t kv_it_key(uint32_t itr, uint32_t offset, char *dest,
                                   uint32_t size, uint32_t &actual_size) {
  return interface_
             ? interface_->kv_it_key(itr, offset, {dest, size}, &actual_size)
             : 0;
}

INTRINSIC_EXPORT int32_t kv_it_value(uint32_t itr, uint32_t offset, char *dest,
                                     uint32_t size, uint32_t &actual_size) {
  return interface_
             ? interface_->kv_it_value(itr, offset, {dest, size}, &actual_size)
             : 0;
}

INTRINSIC_EXPORT void assert_sha256(const char *data, uint32_t length,
                                    const void *hash) {
  if (interface_)
    interface_->assert_sha256({(void *)data, length}, (void *)hash);
}
INTRINSIC_EXPORT void assert_sha1(const char *data, uint32_t length,
                                  const void *hash) {
  if (interface_)
    interface_->assert_sha1({(void *)data, length}, (void *)hash);
}
INTRINSIC_EXPORT void assert_sha512(const char *data, uint32_t length,
                                    const void *hash) {
  if (interface_)
    interface_->assert_sha512({(void *)data, length}, (void *)hash);
}
INTRINSIC_EXPORT void assert_ripemd160(const char *data, uint32_t length,
                                       const void *hash) {
  if (interface_)
    interface_->assert_ripemd160({(void *)data, length}, (void *)hash);
}
INTRINSIC_EXPORT void sha256(const char *data, uint32_t length, void *hash) {
  if (interface_)
    interface_->sha256({(void *)data, length}, hash);
}
INTRINSIC_EXPORT void sha1(const char *data, uint32_t length, void *hash) {
  if (interface_)
    interface_->sha1({(void *)data, length}, hash);
}
INTRINSIC_EXPORT void sha512(const char *data, uint32_t length, void *hash) {
  if (interface_)
    interface_->sha512({(void *)data, length}, hash);
}

INTRINSIC_EXPORT void ripemd160(const char *data, uint32_t length, void *hash) {
  if (interface_)
    interface_->ripemd160({(void *)data, length}, hash);
}

INTRINSIC_EXPORT int32_t recover_key(const void *digest, const char *sig,
                                     uint32_t siglen, char *pub,
                                     uint32_t publen) {
  return interface_
             ? interface_->recover_key((void *)digest, {(void *)sig, siglen},
                                       {(void *)pub, publen})
             : 0;
}

INTRINSIC_EXPORT void assert_recover_key(const void *digest, const char *sig,
                                         uint32_t siglen, const char *pub,
                                         uint32_t publen) {
  if (interface_)
    interface_->assert_recover_key(const_cast<void *>(digest),
                                   {(void *)sig, siglen},
                                   {(void *)pub, publen});
}

INTRINSIC_EXPORT void eosio_assert(uint32_t test, const char *msg) {
  eosio_assert_message(test, msg, strlen(msg));
}

INTRINSIC_EXPORT void eosio_assert_code(uint32_t test, uint64_t code) {
  if (interface_)
    interface_->eosio_assert_code(test, code);
}

INTRINSIC_EXPORT uint64_t current_time() {
  return interface_ ? interface_->current_time() : 0;
}

INTRINSIC_EXPORT bool is_privileged(uint64_t account) {
  return interface_ ? interface_->is_privileged(account) : 0;
}

INTRINSIC_EXPORT void get_resource_limits(uint64_t account, int64_t *ram_bytes,
                                          int64_t *net_weight,
                                          int64_t *cpu_weight) {
  if (interface_)
    interface_->get_resource_limits(eosio::chain::account_name{account},
                                    ram_bytes, net_weight, cpu_weight);
}

INTRINSIC_EXPORT void set_resource_limits(uint64_t account, int64_t ram_bytes,
                                          int64_t net_weight,
                                          int64_t cpu_weight) {
  if (interface_)
    interface_->set_resource_limits(eosio::chain::account_name{account},
                                    ram_bytes, net_weight, cpu_weight);
}

INTRINSIC_EXPORT void set_privileged(uint64_t account, bool is_priv) {
  if (interface_)
    interface_->set_privileged(eosio::chain::account_name{account}, is_priv);
}

INTRINSIC_EXPORT void set_blockchain_parameters_packed(char *data,
                                                       uint32_t datalen) {
  if (interface_)
    interface_->set_blockchain_parameters_packed({data, datalen});
}

INTRINSIC_EXPORT uint32_t get_blockchain_parameters_packed(char *data,
                                                           uint32_t datalen) {
  return interface_
             ? interface_->get_blockchain_parameters_packed({data, datalen})
             : 0;
}

INTRINSIC_EXPORT int64_t set_proposed_producers(char *data, uint32_t datalen) {
  return interface_ ? interface_->set_proposed_producers({data, datalen}) : 0;
}

INTRINSIC_EXPORT uint32_t get_active_producers(uint64_t *data,
                                               uint32_t datalen) {
  return interface_ ? interface_->get_active_producers({data, datalen}) : 0;
}

INTRINSIC_EXPORT bool is_feature_activated(void *feature_digest) {
  return interface_ ? interface_->is_feature_activated(feature_digest) : 0;
}

INTRINSIC_EXPORT uint64_t get_sender() {
  return interface_ ? interface_->get_sender().to_uint64_t() : 0;
}

INTRINSIC_EXPORT void push_event(const char* data, uint32_t size) {
   if (interface_)
      interface_->push_event({data, size});
}

INTRINSIC_EXPORT void preactivate_feature(const void *feature_digest) {
  if (interface_)
    interface_->preactivate_feature(const_cast<void *>(feature_digest));
}

INTRINSIC_EXPORT int64_t set_proposed_producers_ex(uint64_t producer_data_format, char *producer_data,
                          uint32_t producer_data_size) {
  return interface_
             ? interface_->set_proposed_producers_ex(
                   producer_data_format, {producer_data, producer_data_size})
             : 0;
}
///
INTRINSIC_EXPORT uint32_t read_action_data(char *msg, uint32_t len) {
  return interface_ ? interface_->read_action_data({msg, len}) : 0;
}

INTRINSIC_EXPORT uint32_t action_data_size() {
  return interface_ ? interface_->action_data_size() : 0;
}

INTRINSIC_EXPORT void require_recipient(uint64_t name) {
  if (interface_)
    interface_->require_recipient(eosio::chain::account_name{name});
}

INTRINSIC_EXPORT void require_auth(uint64_t name) {
  if (interface_)
    interface_->require_auth(eosio::chain::account_name{name});
}

INTRINSIC_EXPORT bool has_auth(uint64_t name) {
  return interface_ ? interface_->has_auth(eosio::chain::account_name{name})
                    : 0;
}

INTRINSIC_EXPORT void require_auth2(uint64_t name, uint64_t permission) {
  if (interface_)
    interface_->require_auth2(eosio::chain::account_name{name},
                              eosio::chain::account_name{permission});
}

INTRINSIC_EXPORT bool is_account(uint64_t name) {
  return interface_ ? interface_->is_account(eosio::chain::account_name{name})
                    : 0;
}

INTRINSIC_EXPORT void send_inline(char *serialized_action, uint32_t size) {
  if (interface_)
    interface_->send_inline({serialized_action, (uint32_t)size});
}

INTRINSIC_EXPORT void send_context_free_inline(char *serialized_action,
                                               uint32_t size) {
  if (interface_)
    interface_->send_context_free_inline({serialized_action, (uint32_t)size});
}

INTRINSIC_EXPORT uint64_t publication_time() {
  return interface_ ? interface_->publication_time() : 0;
}

INTRINSIC_EXPORT uint64_t current_receiver() {
  return interface_ ? interface_->current_receiver() : 0;
}

INTRINSIC_EXPORT void set_action_return_value(void *return_value,
                                              uint32_t size) {
  if (interface_)
    interface_->set_action_return_value(
        {(const char *)return_value, (uint32_t)size});
}

INTRINSIC_EXPORT int32_t check_transaction_authorization(
    const char *trx_data, uint32_t trx_size, const char *pubkeys_data,
    uint32_t pubkeys_size, const char *perms_data, uint32_t perms_size) {
  return interface_ ? interface_->check_transaction_authorization(
                          {(void *)trx_data, (uint32_t)trx_size},
                          {(void *)pubkeys_data, (uint32_t)pubkeys_size},
                          {(void *)perms_data, (uint32_t)perms_size})
                    : 0;
}

INTRINSIC_EXPORT int32_t check_permission_authorization(
    uint64_t account, uint64_t permission, const char *pubkeys_data,
    uint32_t pubkeys_size, const char *perms_data, uint32_t perms_size,
    uint64_t delay_us) {
  return interface_ ? interface_->check_permission_authorization(
                          eosio::chain::account_name{account},
                          eosio::chain::account_name{permission},
                          {(void *)pubkeys_data, (uint32_t)pubkeys_size},
                          {(void *)perms_data, perms_size}, (uint32_t)delay_us)
                    : 0;
}

INTRINSIC_EXPORT int64_t get_permission_last_used(uint64_t account,
                                                  uint64_t permission) {
  return interface_ ? interface_->get_permission_last_used(
                          eosio::chain::account_name{account},
                          eosio::chain::account_name{permission})
                    : 0;
}

INTRINSIC_EXPORT int64_t get_account_creation_time(uint64_t account) {
  return interface_ ? interface_->get_account_creation_time(
                          eosio::chain::account_name{account})
                    : 0;
}

INTRINSIC_EXPORT int32_t get_action(uint32_t type, uint32_t index, char *buff,
                                    uint32_t size) {
  return interface_
             ? interface_->get_action(type, index, {buff, (uint32_t)size})
             : 0;
}

INTRINSIC_EXPORT void set_kv_parameters_packed(const char *params,
                                               uint32_t size) {
  if (interface_)
    interface_->set_kv_parameters_packed({params, size});
}

INTRINSIC_EXPORT uint32_t get_kv_parameters_packed(void *params, uint32_t size,
                                                   uint32_t max_version) {
  return interface_ ? interface_->get_kv_parameters_packed(
                          {(char *)params, size}, max_version)
                    : 0;
}

INTRINSIC_EXPORT void set_wasm_parameters_packed(const char *params,
                                                 uint32_t size) {
  if (interface_)
    interface_->set_wasm_parameters_packed({params, size});
}

INTRINSIC_EXPORT void set_parameters_packed(const char *params, uint32_t size) {
  if (interface_)
    interface_->set_parameters_packed({params, size});
}

INTRINSIC_EXPORT void set_resource_limit(uint64_t account, uint64_t resource,
                                         int64_t limit) {
  if (interface_)
    interface_->set_resource_limit(eosio::chain::account_name{account},
                                   eosio::chain::account_name{resource}, limit);
}

INTRINSIC_EXPORT void printi128(const void *value) {
  if (interface_)
    interface_->printi128((void *)value);
}

INTRINSIC_EXPORT void printui128(const void *value) {
  if (interface_)
    interface_->printui128((void *)value);
}

INTRINSIC_EXPORT void printhex(const void *data, uint32_t datalen) {
  if (interface_)
    interface_->printhex({(void *)data, datalen});
}

using uint128_t = unsigned __int128;

INTRINSIC_EXPORT int32_t db_idx256_store(uint64_t scope, uint64_t table,
                                         uint64_t payer, uint64_t id,
                                         const uint128_t *data,
                                         uint32_t data_len) {
  return interface_ ? interface_->db_idx256_store(scope, table, payer, id,
                                                  {(void *)data, data_len})
                    : 0;
}

INTRINSIC_EXPORT void db_idx256_update(int32_t iterator, uint64_t payer,
                                       const uint128_t *data,
                                       uint32_t data_len) {
  if (interface_)
    interface_->db_idx256_update(iterator, payer, {(void *)data, data_len});
}

INTRINSIC_EXPORT void db_idx256_remove(int32_t iterator) {
  if (interface_)
    interface_->db_idx256_remove(iterator);
}

INTRINSIC_EXPORT int32_t db_idx256_next(int32_t iterator, uint64_t *primary) {
  return interface_ ? interface_->db_idx256_next(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_previous(int32_t iterator,
                                            uint64_t *primary) {
  return interface_ ? interface_->db_idx256_previous(iterator, primary) : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_find_primary(uint64_t code, uint64_t scope,
                                                uint64_t table, uint128_t *data,
                                                uint32_t data_len,
                                                uint64_t primary) {
  return interface_ ? interface_->db_idx256_find_primary(
                          code, scope, table, {(void *)data, data_len}, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_find_secondary(uint64_t code, uint64_t scope,
                                                  uint64_t table,
                                                  const uint128_t *data,
                                                  uint32_t data_len,
                                                  uint64_t *primary) {
  return interface_ ? interface_->db_idx256_find_secondary(
                          code, scope, table, {(void *)data, data_len}, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_lowerbound(uint64_t code, uint64_t scope,
                                              uint64_t table, uint128_t *data,
                                              uint32_t data_len,
                                              uint64_t *primary) {
  return interface_ ? interface_->db_idx256_lowerbound(
                          code, scope, table, {(void *)data, data_len}, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_upperbound(uint64_t code, uint64_t scope,
                                              uint64_t table, uint128_t *data,
                                              uint32_t data_len,
                                              uint64_t *primary) {
  return interface_ ? interface_->db_idx256_upperbound(
                          code, scope, table, {(void *)data, data_len}, primary)
                    : 0;
}

INTRINSIC_EXPORT int32_t db_idx256_end(uint64_t code, uint64_t scope,
                                       uint64_t table) {
  return interface_ ? interface_->db_idx256_end(code, scope, table) : 0;
}

INTRINSIC_EXPORT bool verify_rsa_sha256_sig(const char* msg, uint32_t msg_len,
                                            const char* sig, uint32_t sig_len,
                                            const char* exp, uint32_t exp_len,
                                            const char* mod, uint32_t mod_len) {
  return interface_ ? interface_->verify_rsa_sha256_sig({ (void *)msg, msg_len },
                                                        { (void *)sig, sig_len },
                                                        { (void *)exp, exp_len },
                                                        { (void *)mod, mod_len })
                    : 0;
}

INTRINSIC_EXPORT bool verify_ecdsa_sig(const char *msg, uint32_t msg_len,
                                       const char *sig, uint32_t sig_len,
                                       const char *pubkey, uint32_t pubkey_len) {
  return interface_ ? interface_->verify_ecdsa_sig({ (void *)msg, msg_len },
                                                   { (void *)sig, sig_len},
                                                   { (void *)pubkey, pubkey_len})
                    : 0;
}

INTRINSIC_EXPORT bool is_supported_ecdsa_pubkey(const char *pubkey, uint32_t pubkey_len) {
  return interface_ ? interface_->is_supported_ecdsa_pubkey({ (void *)pubkey, pubkey_len})
                    : 0;
}

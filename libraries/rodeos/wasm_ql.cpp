#include <b1/rodeos/wasm_ql.hpp>


#include <b1/rodeos/rodeos.hpp>
#include <boost/filesystem.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index_container.hpp>
#include <chrono>
#include <eosio/abi.hpp>
#include <eosio/bytes.hpp>
#include <eosio/vm/watchdog.hpp>
#include <fc/log/logger.hpp>
#include <fc/scoped_exit.hpp>
#include <mutex>
#include <rocksdb/utilities/checkpoint.h>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
#   include <b1/rodeos/native_module_context_type.hpp>
#   include <eosio/chain/webassembly/dynamic_loaded_function.hpp>
#endif

using namespace std::literals;
namespace ship_protocol = eosio::ship_protocol;

using boost::multi_index::indexed_by;
using boost::multi_index::member;
using boost::multi_index::multi_index_container;
using boost::multi_index::ordered_non_unique;
using boost::multi_index::sequenced;
using boost::multi_index::tag;

using eosio::ship_protocol::action_receipt_v0;
using eosio::ship_protocol::action_trace_v1;
using eosio::ship_protocol::transaction_trace_v0;

namespace eosio {

// todo: abieos support for pair. Used by extensions_type.
template <typename S>
void to_json(const std::pair<uint16_t, std::vector<char>>&, S& stream) {
   eosio::check(false, eosio::convert_stream_error(stream_error::bad_variant_index));
}

} // namespace eosio

namespace b1::rodeos::wasm_ql {

template <class... Ts>
struct overloaded : Ts... {
   using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...)->overloaded<Ts...>;

struct wasm_ql_backend_options {
   std::uint32_t                  max_pages      = 528; // 33 MiB
   static constexpr std::uint32_t max_call_depth = 251;
};

struct callbacks;
using rhf_t     = registered_host_functions<callbacks>;



#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
using backend_t = eosio::vm::backend<rhf_t, eosio::vm::jit, wasm_ql_backend_options>;
#endif


std::once_flag registered_callbacks;

void register_callbacks() {
   action_callbacks<callbacks>::register_callbacks<rhf_t>();
   chaindb_callbacks<callbacks>::register_callbacks<rhf_t>();
   compiler_builtins_callbacks<callbacks>::register_callbacks<rhf_t>();
   console_callbacks<callbacks>::register_callbacks<rhf_t>();
   context_free_system_callbacks<callbacks>::register_callbacks<rhf_t>();
   crypto_callbacks<callbacks>::register_callbacks<rhf_t>();
   db_callbacks<callbacks>::register_callbacks<rhf_t>();
   memory_callbacks<callbacks>::register_callbacks<rhf_t>();
   query_callbacks<callbacks>::register_callbacks<rhf_t>();
   unimplemented_callbacks<callbacks>::register_callbacks<rhf_t>();
   coverage_callbacks<callbacks>::register_callbacks<rhf_t>();
}


struct backend_entry {
   eosio::name                name; // only for wasms loaded from disk
   eosio::checksum256         hash; // only for wasms loaded from chain
#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
   std::unique_ptr<backend_t> backend;
#endif
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
   std::optional<eosio::chain::dynamic_loaded_function> apply_fun;
#endif
};

struct by_age;
struct by_name;
struct by_hash;

using backend_container = multi_index_container<
      backend_entry,
      indexed_by<sequenced<tag<by_age>>, //
                 ordered_non_unique<tag<by_name>, member<backend_entry, eosio::name, &backend_entry::name>>,
                 ordered_non_unique<tag<by_hash>, member<backend_entry, eosio::checksum256, &backend_entry::hash>>>>;

class backend_cache {
 private:
   std::mutex                   mutex;
   const wasm_ql::shared_state& shared_state;
   backend_container            backends;

 public:
   backend_cache(const wasm_ql::shared_state& shared_state) : shared_state{ shared_state } {}

   void add(backend_entry&& entry) {
      std::lock_guard<std::mutex> lock{ mutex };
      auto&                       ind = backends.get<by_age>();
      ind.push_back(std::move(entry));
      while (ind.size() > shared_state.wasm_cache_size) ind.pop_front();
   }

   std::optional<backend_entry> get(eosio::name name) {
      std::optional<backend_entry> result;
      std::lock_guard<std::mutex>  lock{ mutex };
      auto&                        ind = backends.get<by_name>();
      auto                         it  = ind.find(name);
      if (it == ind.end())
         return result;
      ind.modify(it, [&](auto& x) { result = std::move(x); });
      ind.erase(it);
      return result;
   }

   std::optional<backend_entry> get(const eosio::checksum256& hash) {
      std::optional<backend_entry> result;
      std::lock_guard<std::mutex>  lock{ mutex };
      auto&                        ind = backends.get<by_hash>();
      auto                         it  = ind.find(hash);
      if (it == ind.end())
         return result;
      ind.modify(it, [&](auto& x) { result = std::move(x); });
      ind.erase(it);
      return result;
   }
};

shared_state::shared_state(std::shared_ptr<chain_kv::database> db)
    : backend_cache(std::make_shared<wasm_ql::backend_cache>(*this)), db(std::move(db)) {}

shared_state::~shared_state() {}

thread_state::~thread_state() {
   // wasm allocator must be explicitly freed
   wa.free();
}

std::optional<std::vector<uint8_t>> read_code(wasm_ql::thread_state& thread_state, eosio::name account) {
   std::optional<std::vector<uint8_t>> code;
   if (!thread_state.shared->contract_dir.empty()) {
      auto          filename = thread_state.shared->contract_dir + "/" + (std::string)account + ".wasm";
      std::ifstream wasm_file(filename, std::ios::binary);
      if (wasm_file.is_open()) {
         ilog("compiling {f}", ("f", filename));
         wasm_file.seekg(0, std::ios::end);
         int len = wasm_file.tellg();
         if (len < 0)
            throw std::runtime_error("wasm file length is -1");
         code.emplace(len);
         wasm_file.seekg(0, std::ios::beg);
         wasm_file.read((char*)code->data(), code->size());
         wasm_file.close();
      }
   }
   return code;
}

std::optional<eosio::checksum256> get_contract_hash(db_view_state& db_view_state, eosio::name account) {
   std::optional<eosio::checksum256> result;
   auto                              meta = get_state_row<ship_protocol::account_metadata>(
         db_view_state.kv_state.view,
         std::make_tuple(eosio::name{ "account.meta" }, eosio::name{ "primary" }, account));
   if (!meta)
      return result;
   auto& meta0 = std::get<ship_protocol::account_metadata_v0>(meta->second);
   if (!meta0.code->vm_type && !meta0.code->vm_version)
      result = meta0.code->code_hash;
   return result;
}

std::optional<std::vector<uint8_t>> read_contract(db_view_state& db_view_state, const eosio::checksum256& hash,
                                                  eosio::name account) {
   std::optional<std::vector<uint8_t>> result;
   auto                                code_row = get_state_row<ship_protocol::code>(
         db_view_state.kv_state.view,
         std::make_tuple(eosio::name{ "code" }, eosio::name{ "primary" }, uint8_t(0), uint8_t(0), hash));
   if (!code_row)
      return result;
   auto& code0 = std::get<ship_protocol::code_v0>(code_row->second);

   // todo: avoid copy
   result.emplace(code0.code.pos, code0.code.end);
   ilog("compiling {h}: {a}", ("h", eosio::convert_to_json(hash))("a", (std::string)account));
   return result;
}

void run_action(wasm_ql::thread_state& thread_state, const std::vector<char>& contract_kv_prefix,
                ship_protocol::action& action, action_trace_v1& atrace, const rocksdb::Snapshot* snapshot,
                const std::chrono::steady_clock::time_point& stop_time, std::vector<std::vector<char>>& memory) {
   if (std::chrono::steady_clock::now() >= stop_time)
      throw eosio::vm::timeout_exception("execution timed out");

   chain_kv::write_session write_session{ *thread_state.shared->db, snapshot };
   db_view_state           db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   std::optional<backend_entry>        entry = thread_state.shared->backend_cache->get(action.account);
   std::optional<std::vector<uint8_t>> code;
   if (!entry)
      code = read_code(thread_state, action.account);
   std::optional<eosio::checksum256> hash;
   if (!entry && !code) {
      hash = get_contract_hash(db_view_state, action.account);
      if (hash) {
         entry = thread_state.shared->backend_cache->get(*hash);
         if (!entry)
            code = read_contract(db_view_state, *hash, action.account);
      }
   }

   // todo: fail? silent success like normal transactions?
   if (!entry && !code)
      throw std::runtime_error("account " + (std::string)action.account + " has no code");

   if (!entry) {
      entry.emplace();
      if (hash)
         entry->hash = *hash;
      else
         entry->name = action.account;
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
      if (thread_state.shared->native_context) {
         auto bytes = hash->extract_as_byte_array();
         auto code_path = thread_state.shared->native_context->code_dir() / ( fc::to_hex((const char*)bytes.data(), bytes.size()) + ".so");
         entry->apply_fun.emplace(code_path.c_str(), "apply");
      } else
#endif
      {
#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
         std::call_once(registered_callbacks, register_callbacks);
         entry->backend = std::make_unique<backend_t>(
               *code, nullptr, wasm_ql_backend_options{ .max_pages = thread_state.shared->max_pages });
         rhf_t::resolve(entry->backend->get_module());
#endif
      }
   }
   auto se = fc::make_scoped_exit([&] { thread_state.shared->backend_cache->add(std::move(*entry)); });

   fill_status_sing sing{ state_account, db_view_state, false };
   if (!sing.exists())
      throw std::runtime_error("No fill_status records found; is filler running?");
   auto& fill_status = sing.get();

   // todo: move these out of thread_state since future enhancements could cause state to accidentally leak between
   // queries
   thread_state.max_console_size = thread_state.shared->max_console_size;
   thread_state.receiver         = action.account;
   thread_state.action_data      = action.data;
   thread_state.action_return_value.clear();
   std::visit([&](auto& stat) { thread_state.block_num = stat.head; }, fill_status);
   thread_state.block_info.reset();

   chaindb_state chaindb_state;
   coverage_state coverage_state;
   callbacks     cb{ thread_state, chaindb_state, db_view_state, coverage_state };

   try {
#ifdef EOSIO_NATIVE_MODULE_RUNTIME_ENABLED
      if (entry->apply_fun) {
         auto native_context = thread_state.shared->native_context;
         native_context->push(&cb);
         auto on_exit = fc::make_scoped_exit([native_context] { native_context->pop(); });
         entry->apply_fun->exec<void (*)(uint64_t, uint64_t, uint64_t)>(action.account.value, action.account.value,
                                                                       action.name.value);
      } else
#endif
      {
#ifdef EOSIO_EOS_VM_JIT_RUNTIME_ENABLED
         entry->backend->set_wasm_allocator(&thread_state.wa);
         eosio::vm::watchdog wd{ stop_time - std::chrono::steady_clock::now() };
         entry->backend->timed_run(wd, [&] {
            entry->backend->initialize(&cb);
            (*entry->backend)(cb, "env", "apply", action.account.value, action.account.value, action.name.value);
         });
#endif
      }
   } catch (...) {
      atrace.console = std::move(thread_state.console);
      throw;
   }

   atrace.console = std::move(thread_state.console);
   memory.push_back(std::move(thread_state.action_return_value));
   atrace.return_value = memory.back();
} // run_action

template<typename I>
std::string itoh(I n, size_t hlen = sizeof(I)<<1) {
   static const char* digits = "0123456789abcdef";
   std::string r(hlen, '0');
   for(size_t i = 0, j = (hlen - 1) * 4 ; i < hlen; ++i, j -= 4)
      r[i] = digits[(n>>j) & 0x0f];
   return r;
}

const std::vector<char>& query_get_info(wasm_ql::thread_state&   thread_state,
                                        uint64_t                 version,
                                        const std::string&       version_str,
                                        const std::string&       full_version_str,
                                        const std::vector<char>& contract_kv_prefix) {
   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };
   chain_kv::write_session  write_session{ *thread_state.shared->db, snapshot.snapshot() };
   db_view_state            db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   std::string result = "{\"server_type\":\"wasm-ql\"";
   result += ",\"server_version\":\"" + itoh(static_cast<uint32_t>(version)) + "\"";
   result += ",\"server_version_string\":\"" + version_str + "\"";
   result += ",\"server_full_version_string\":\"" + full_version_str + "\"";

   {
      global_property_kv table{ { db_view_state } };
      bool               found = false;
      if (table.primary_index.begin() != table.primary_index.end()) {
         auto record = table.primary_index.begin().value();
         if (auto* obj = std::get_if<ship_protocol::global_property_v1>(&record)) {
            found = true;
            result += ",\"chain_id\":" + eosio::convert_to_json(obj->chain_id);
         }
      }
      if (!found)
         throw std::runtime_error("No global_property_v1 records found; is filler running?");
   }

   {
      fill_status_sing sing{ state_account, db_view_state, false };
      if (sing.exists()) {
         std::visit(
               [&](auto& obj) {
                  result += ",\"head_block_num\":\"" + std::to_string(obj.head) + "\"";
                  result += ",\"head_block_id\":" + eosio::convert_to_json(obj.head_id);
                  result += ",\"last_irreversible_block_num\":\"" + std::to_string(obj.irreversible) + "\"";
                  result += ",\"last_irreversible_block_id\":" + eosio::convert_to_json(obj.irreversible_id);
               },
               sing.get());
      } else
         throw std::runtime_error("No fill_status records found; is filler running?");
   }

   result += "}";

   thread_state.action_return_value.assign(result.data(), result.data() + result.size());
   return thread_state.action_return_value;
}

struct get_block_params {
   std::string block_num_or_id = {};
};

EOSIO_REFLECT(get_block_params, block_num_or_id)

const std::vector<char>& query_get_block(wasm_ql::thread_state&   thread_state,
                                         const std::vector<char>& contract_kv_prefix, std::string_view body) {
   get_block_params         params;
   std::string              s{ body.begin(), body.end() };
   eosio::json_token_stream stream{ s.data() };
   try {
      from_json(params, stream);
   } catch (std::exception& e) {
      throw std::runtime_error("An error occurred deserializing get_block_params: "s + e.what());
   }

   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };
   chain_kv::write_session  write_session{ *thread_state.shared->db, snapshot.snapshot() };
   db_view_state            db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   std::string              bn_json = "\"" + params.block_num_or_id + "\"";
   eosio::json_token_stream bn_stream{ bn_json.data() };

   std::optional<std::pair<std::shared_ptr<const chain_kv::bytes>, block_info>> info;
   if (params.block_num_or_id.size() == 64) {
      eosio::checksum256 id;
      try {
         from_json(id, bn_stream);
      } catch (std::exception& e) {
         throw std::runtime_error("An error occurred deserializing block_num_or_id: "s + e.what());
      }
      info = get_state_row_secondary<block_info>(db_view_state.kv_state.view,
                                                 std::make_tuple(eosio::name{ "block.info" }, eosio::name{ "id" }, id));
   } else {
      uint32_t num;
      try {
         from_json(num, bn_stream);
      } catch (std::exception& e) {
         throw std::runtime_error("An error occurred deserializing block_num_or_id: "s + e.what());
      }
      info = get_state_row<block_info>(db_view_state.kv_state.view,
                                       std::make_tuple(eosio::name{ "block.info" }, eosio::name{ "primary" }, num));
   }

   if (info) {
      auto&    obj = std::get<block_info_v0>(info->second);
      const uint32_t ref_block_prefix =
            fc::sha256{ reinterpret_cast<const char*>(obj.id.extract_as_byte_array().data()), 32 }._hash[1];

      std::string result = "{";
      result += "\"block_num\":" + eosio::convert_to_json(obj.num);
      result += ",\"id\":" + eosio::convert_to_json(obj.id);
      result += ",\"timestamp\":" + eosio::convert_to_json(obj.timestamp);
      result += ",\"producer\":" + eosio::convert_to_json(obj.producer);
      result += ",\"confirmed\":" + eosio::convert_to_json(obj.confirmed);
      result += ",\"previous\":" + eosio::convert_to_json(obj.previous);
      result += ",\"transaction_mroot\":" + eosio::convert_to_json(obj.transaction_mroot);
      result += ",\"action_mroot\":" + eosio::convert_to_json(obj.action_mroot);
      result += ",\"schedule_version\":" + eosio::convert_to_json(obj.schedule_version);
      result += ",\"producer_signature\":" + eosio::convert_to_json(obj.producer_signature);
      result += ",\"ref_block_prefix\":" + eosio::convert_to_json(ref_block_prefix);
      result += "}";

      thread_state.action_return_value.assign(result.data(), result.data() + result.size());
      return thread_state.action_return_value;
   }

   throw std::runtime_error("block " + params.block_num_or_id + " not found");
} // query_get_block

struct get_account_results {
   eosio::name                                  account_name = {};
   uint32_t                                     head_block_num = {};
   eosio::block_timestamp                       created = {};
   std::vector<ship_protocol::permission_v0>    permissions = {};
};
EOSIO_REFLECT(get_account_results, account_name, head_block_num, created, permissions)

struct get_account_params {
   eosio::name                               account_name = {};
};
EOSIO_REFLECT(get_account_params, account_name)

const std::vector<char>& query_get_account(wasm_ql::thread_state& thread_state, const std::vector<char>& contract_kv_prefix,
                                           std::string_view body) {
   get_account_params       params;
   std::string              s{ body.begin(), body.end() };
   eosio::json_token_stream stream{ s.data() };
   try {
      from_json(params, stream);
   } catch (std::exception& e) {
      throw std::runtime_error("An error occurred deserializing get_account_params: "s + e.what());
   }

   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };
   chain_kv::write_session  write_session{ *thread_state.shared->db, snapshot.snapshot() };
   db_view_state            db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   auto acc = get_state_row<ship_protocol::account>(
           db_view_state.kv_state.view,
           std::make_tuple(eosio::name{ "account" }, eosio::name{ "primary" }, params.account_name));
   if (!acc)
      throw std::runtime_error("account " + (std::string)params.account_name + " not found");
   auto& acc0 = std::get<ship_protocol::account_v0>(acc->second);

   get_account_results result;
   result.account_name = acc0.name;
   result.created = acc0.creation_date;

   // permissions
   {
      auto t = std::make_tuple(eosio::name{"account.perm"}, eosio::name{"primary"}, params.account_name);
      auto key = eosio::convert_to_key(std::make_tuple((uint8_t) 0x01, t));
      b1::chain_kv::view::iterator view_it(db_view_state.kv_state.view, state_account.value, chain_kv::to_slice(key));
      view_it.lower_bound(key);
      while (!view_it.is_end() ){
         const auto key_value = view_it.get_kv();
         if (key_value) {
            eosio::input_stream in((*key_value).value.data(), (*key_value).value.size());
            ship_protocol::permission perm;
            try {
               from_bin(perm, in);
            } catch (std::exception &e) {
               throw std::runtime_error("An error occurred deserializing state: " + std::string(e.what()));
            }
            auto &perm0 = std::get<ship_protocol::permission_v0>(perm);
            result.permissions.push_back(std::move(perm0));
         }
         ++view_it;
      }
   }

   // head_block_num
   {
      fill_status_sing sing{ state_account, db_view_state, false };
      if (sing.exists()) {
         std::visit( [&](auto& obj) { result.head_block_num = obj.head;}, sing.get());
      } else
         throw std::runtime_error("No fill_status records found; is filler running?");
   }

   auto json = eosio::convert_to_json(result);

   rapidjson::Document doc;
   doc.Parse(json.c_str());
   for (auto& perm : doc["permissions"].GetArray()) {
      auto name_value = perm.FindMember("name");
      perm.AddMember("perm_name", name_value->value, doc.GetAllocator());
      perm.EraseMember("name");

      auto auth_value = perm.FindMember("auth");
      perm.AddMember("required_auth", auth_value->value, doc.GetAllocator());
      perm.EraseMember("auth");
   }
   rapidjson::StringBuffer sb;
   rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
   doc.Accept(writer);

   thread_state.action_return_value.assign(sb.GetString(), sb.GetString() + sb.GetSize());
   return thread_state.action_return_value;
} // query_get_account

struct get_abi_params {
   eosio::name account_name = {};
};

EOSIO_REFLECT(get_abi_params, account_name)

struct get_abi_result {
   eosio::name                   account_name;
   std::optional<eosio::abi_def> abi;
};

EOSIO_REFLECT(get_abi_result, account_name, abi)

const std::vector<char>& query_get_abi(wasm_ql::thread_state& thread_state, const std::vector<char>& contract_kv_prefix,
                                       std::string_view body) {
   get_abi_params           params;
   std::string              s{ body.begin(), body.end() };
   eosio::json_token_stream stream{ s.data() };
   try {
      from_json(params, stream);
   } catch (std::exception& e) {
      throw std::runtime_error("An error occurred deserializing get_abi_params: "s + e.what());
   }

   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };
   chain_kv::write_session  write_session{ *thread_state.shared->db, snapshot.snapshot() };
   db_view_state            db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   auto acc = get_state_row<ship_protocol::account>(
         db_view_state.kv_state.view,
         std::make_tuple(eosio::name{ "account" }, eosio::name{ "primary" }, params.account_name));
   if (!acc)
      throw std::runtime_error("account " + (std::string)params.account_name + " not found");
   auto& acc0 = std::get<ship_protocol::account_v0>(acc->second);

   get_abi_result result;
   result.account_name = acc0.name;
   if (acc0.abi.pos != acc0.abi.end) {
      result.abi.emplace();
      eosio::from_bin(*result.abi, acc0.abi);
   }

   // todo: avoid the extra copy
   auto json = eosio::convert_to_json(result);
   thread_state.action_return_value.assign(json.begin(), json.end());
   return thread_state.action_return_value;
} // query_get_abi

struct get_raw_abi_params {
   eosio::name account_name = {};
   std::optional<eosio::checksum256> abi_hash;
};

EOSIO_REFLECT(get_raw_abi_params, account_name, abi_hash)

struct get_raw_abi_result {
   eosio::name                account_name;
   eosio::checksum256         code_hash;
   eosio::checksum256         abi_hash;
   std::optional<std::string> abi;
};

EOSIO_REFLECT(get_raw_abi_result, account_name, code_hash, abi_hash, abi)

const std::vector<char>& query_get_raw_abi(wasm_ql::thread_state& thread_state, const std::vector<char>& contract_kv_prefix,
                                       std::string_view body) {
   get_raw_abi_params       params;
   std::string              s{ body.begin(), body.end() };
   eosio::json_token_stream stream{ s.data() };
   try {
      from_json(params, stream);
   } catch (std::exception& e) {
      throw std::runtime_error("An error occurred deserializing get_abi_params: "s + e.what());
   }

   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };
   chain_kv::write_session  write_session{ *thread_state.shared->db, snapshot.snapshot() };
   db_view_state            db_view_state{ state_account, *thread_state.shared->db, write_session, contract_kv_prefix };

   get_raw_abi_result result = {};

   auto                              meta = get_state_row<ship_protocol::account_metadata>(
         db_view_state.kv_state.view,
         std::make_tuple(eosio::name{ "account.meta" }, eosio::name{ "primary" }, params.account_name));
   if (meta) {
      auto& meta0 = std::get<ship_protocol::account_metadata_v0>(meta->second);
      if (!meta0.code->vm_type && !meta0.code->vm_version)
         result.code_hash = meta0.code->code_hash;
   }

   auto acc = get_state_row<ship_protocol::account>(
         db_view_state.kv_state.view,
         std::make_tuple(eosio::name{ "account" }, eosio::name{ "primary" }, params.account_name));
   if (!acc)
      throw std::runtime_error("account " + (std::string)params.account_name + " not found");
   auto& acc0 = std::get<ship_protocol::account_v0>(acc->second);

   result.account_name = acc0.name;
   if (acc0.abi.pos != acc0.abi.end) {
      auto fc_abi_hash = fc::sha256::hash(acc0.abi.pos, acc0.abi.remaining());
      auto abi_hash_stream = eosio::input_stream(fc_abi_hash.data(), fc_abi_hash.data_size());
      eosio::from_bin(result.abi_hash, abi_hash_stream);
      if(!params.abi_hash || *params.abi_hash != result.abi_hash) {
        result.abi = fc::base64_encode(reinterpret_cast<const unsigned char*>(acc0.abi.pos), acc0.abi.remaining()) + "=";
      }
   }

   // todo: avoid the extra copy
   auto json = eosio::convert_to_json(result);
   thread_state.action_return_value.assign(json.begin(), json.end());
   return thread_state.action_return_value;
} // query_get_raw_abi

// Ignores data field
struct action_no_data {
   eosio::name                                  account       = {};
   eosio::name                                  name          = {};
   std::vector<ship_protocol::permission_level> authorization = {};
};

struct extension_hex_data {
   uint16_t     type = {};
   eosio::bytes data = {};
};

EOSIO_REFLECT(extension_hex_data, type, data)

EOSIO_REFLECT(action_no_data, account, name, authorization)

struct transaction_for_get_keys : ship_protocol::transaction_header {
   std::vector<action_no_data>     context_free_actions   = {};
   std::vector<action_no_data>     actions                = {};
   std::vector<extension_hex_data> transaction_extensions = {};
};

EOSIO_REFLECT(transaction_for_get_keys, base ship_protocol::transaction_header, context_free_actions, actions,
              transaction_extensions)

struct get_required_keys_params {
   transaction_for_get_keys       transaction    = {};
   std::vector<eosio::public_key> available_keys = {};
};

EOSIO_REFLECT(get_required_keys_params, transaction, available_keys)

struct get_required_keys_result {
   std::vector<eosio::public_key> required_keys = {};
};

EOSIO_REFLECT(get_required_keys_result, required_keys)

const std::vector<char>& query_get_required_keys(wasm_ql::thread_state& thread_state, std::string_view body) {
   get_required_keys_params params;
   std::string              s{ body.begin(), body.end() };
   eosio::json_token_stream stream{ s.data() };
   try {
      from_json(params, stream);
   } catch (std::exception& e) {
      throw std::runtime_error("An error occurred deserializing get_required_keys_params: "s + e.what());
   }

   get_required_keys_result result;
   for (auto& action : params.transaction.context_free_actions)
      if (!action.authorization.empty())
         throw std::runtime_error("Context-free actions may not have authorizations");
   for (auto& action : params.transaction.actions)
      if (!action.authorization.empty())
         throw std::runtime_error("Actions may not have authorizations"); // todo

   // todo: avoid the extra copy
   auto json = eosio::convert_to_json(result);
   thread_state.action_return_value.assign(json.begin(), json.end());
   return thread_state.action_return_value;
} // query_get_required_keys

struct send_transaction_params {
   std::vector<eosio::signature> signatures               = {};
   std::string                   compression              = {};
   eosio::bytes                  packed_context_free_data = {};
   eosio::bytes                  packed_trx               = {};
};

EOSIO_REFLECT(send_transaction_params, signatures, compression, packed_context_free_data, packed_trx)

eosio::ship_protocol::transaction_trace_v0
query_send_transaction(wasm_ql::thread_state&   thread_state,
                       const std::vector<char>& contract_kv_prefix, std::string_view body, std::vector<std::vector<char>>& memory) {
   send_transaction_params params;
   {
      std::string              s{ body.begin(), body.end() };
      eosio::json_token_stream stream{ s.data() };
      try {
         from_json(params, stream);
      } catch (std::exception& e) {
         throw std::runtime_error("An error occurred deserializing send_transaction_params: "s + e.what());
      }
   }
   if (params.compression != "0" && params.compression != "none")
      throw std::runtime_error("Compression must be 0 or none"); // todo
   ship_protocol::packed_transaction trx{ 0,
                                          { ship_protocol::prunable_data_full_legacy{
                                                std::move(params.signatures), params.packed_context_free_data.data } },
                                          params.packed_trx.data };

   rocksdb::ManagedSnapshot snapshot{ thread_state.shared->db->rdb.get() };

   return query_send_transaction(thread_state, contract_kv_prefix, trx, snapshot.snapshot(), memory, true);
} // query_send_transaction

bool is_signatures_empty(const ship_protocol::prunable_data_type& data) {
   return std::visit(overloaded{ [](const ship_protocol::prunable_data_none&) { return true; },
                                 [](const auto& v) { return v.signatures.empty(); } },
                     data.prunable_data);
}

bool is_context_free_data_empty(const ship_protocol::prunable_data_type& data) {
   return std::visit(overloaded{ [](const ship_protocol::prunable_data_none&) { return true; },
                                 [](const ship_protocol::prunable_data_full_legacy& v) {
                                    return v.packed_context_free_data.pos == v.packed_context_free_data.end;
                                 },
                                 [](const auto& v) { return v.context_free_segments.empty(); } },
                     data.prunable_data);
}

transaction_trace_v0 query_send_transaction(wasm_ql::thread_state&                   thread_state,       //
                                            const std::vector<char>&                 contract_kv_prefix, //
                                            const ship_protocol::packed_transaction& trx,                //
                                            const rocksdb::Snapshot*                 snapshot,           //
                                            std::vector<std::vector<char>>&          memory,             //
                                            bool                                     return_trace_on_except) {
   eosio::input_stream        s{ trx.packed_trx };
   ship_protocol::transaction unpacked;
   try {
      eosio::from_bin(unpacked, s);
   } catch (std::exception& e) { throw std::runtime_error("An error occurred deserializing packed_trx: "s + e.what()); }
   if (s.end != s.pos)
      throw std::runtime_error("Extra data in packed_trx");

   if (!is_signatures_empty(trx.prunable_data))
      throw std::runtime_error("Signatures must be empty"); // todo

   if (trx.compression)
      throw std::runtime_error("Compression must be 0 or none"); // todo

   if (!is_context_free_data_empty(trx.prunable_data))
      throw std::runtime_error("packed_context_free_data must be empty");

   // todo: verify query transaction extension is present, but no others
   // todo: redirect if transaction extension not present?
   if (!unpacked.transaction_extensions.empty())
      throw std::runtime_error("transaction_extensions must be empty");
   // todo: check expiration, ref_block_num, ref_block_prefix
   if (unpacked.delay_sec.value)
      throw std::runtime_error("delay_sec must be 0"); // queries can't be deferred
   if (!unpacked.context_free_actions.empty())
      throw std::runtime_error("context_free_actions must be empty"); // todo: is there a case where CFA makes sense?
   for (auto& action : unpacked.actions)
      if (!action.authorization.empty())
         throw std::runtime_error("authorization must be empty"); // todo

   // todo: fill transaction_id
   transaction_trace_v0 tt;
   tt.action_traces.reserve(unpacked.actions.size());

   auto start_time = std::chrono::steady_clock::now();
   auto stop_time  = start_time + std::chrono::milliseconds{ thread_state.shared->max_exec_time_ms };

   for (auto& action : unpacked.actions) {
      tt.action_traces.emplace_back();
      auto& at                = tt.action_traces.back().emplace<action_trace_v1>();
      at.action_ordinal.value = tt.action_traces.size(); // starts at 1
      at.receiver             = action.account;
      at.act                  = action;

      try {
         run_action(thread_state, contract_kv_prefix, action, at, snapshot, stop_time, memory);
      } catch (eosio::vm::timeout_exception&) { //
         throw std::runtime_error(
               "timeout after " +
               std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(stop_time - start_time).count()) +
               " ms");
      } catch (std::exception& e) {
         if (!return_trace_on_except)
            throw;
         // todo: errorcode
         at.except = tt.except = e.what();
         tt.status             = ship_protocol::transaction_status::soft_fail;
         break;
      }

      at.receipt.emplace();
      auto& r    = at.receipt->emplace<action_receipt_v0>();
      r.receiver = action.account;
   }

   return tt;
} // query_send_transaction

struct create_checkpoint_result {
   std::string        path{};
   eosio::checksum256 chain_id{};
   uint32_t           head{};
   eosio::checksum256 head_id{};
   uint32_t           irreversible{};
   eosio::checksum256 irreversible_id{};
};

EOSIO_REFLECT(create_checkpoint_result, path, chain_id, head, head_id, irreversible, irreversible_id)

const std::vector<char>& query_create_checkpoint(wasm_ql::thread_state&         thread_state,
                                                 const boost::filesystem::path& dir) {
   try {
      std::time_t t       = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
      char        buf[30] = "temp";
      strftime(buf, 30, "%FT%H-%M-%S", localtime(&t));
      auto tmp_path = dir / buf;
      ilog("creating checkpoint {p}", ("p", tmp_path.string()));

      rocksdb::Checkpoint* p;
      b1::chain_kv::check(rocksdb::Checkpoint::Create(thread_state.shared->db->rdb.get(), &p),
                          "query_create_checkpoint: rocksdb::Checkpoint::Create: ");
      std::unique_ptr<rocksdb::Checkpoint> checkpoint{ p };
      b1::chain_kv::check(checkpoint->CreateCheckpoint(tmp_path.string()),
                          "query_create_checkpoint: rocksdb::Checkpoint::CreateCheckpoint: ");

      create_checkpoint_result result;
      {
         ilog("examining checkpoint {p}", ("p", tmp_path.string()));
         auto                       db        = std::make_shared<chain_kv::database>(tmp_path.c_str(), false);
         auto                       partition = std::make_shared<rodeos::rodeos_db_partition>(db, std::vector<char>{});
         rodeos::rodeos_db_snapshot snap{ partition, true };

         result.chain_id        = snap.chain_id;
         result.head            = snap.head;
         result.head_id         = snap.head_id;
         result.irreversible    = snap.irreversible;
         result.irreversible_id = snap.irreversible_id;
         auto head_id_json      = eosio::convert_to_json(result.head_id);
         result.path            = tmp_path.string() +
                       ("-head-" + std::to_string(result.head) + "-" + head_id_json.substr(1, head_id_json.size() - 2));

         ilog("checkpoint contains:");
         ilog("    revisions:    {f} - {r}",
              ("f", snap.undo_stack->first_revision())("r", snap.undo_stack->revision()));
         ilog("    chain:        {a}", ("a", eosio::convert_to_json(snap.chain_id)));
         ilog("    head:         {a} {b}", ("a", snap.head)("b", eosio::convert_to_json(snap.head_id)));
         ilog("    irreversible: {a} {b}",
              ("a", snap.irreversible)("b", eosio::convert_to_json(snap.irreversible_id)));
      }

      ilog("rename {a} to {b}", ("a", tmp_path.string())("b", result.path));
      boost::filesystem::rename(tmp_path, result.path);

      auto json = eosio::convert_to_json(result);
      thread_state.action_return_value.assign(json.begin(), json.end());

      ilog("checkpoint finished");
      return thread_state.action_return_value;
   } catch (const fc::exception& e) {
      elog("fc::exception creating snapshot: {e}", ("e", e.to_detail_string()));
      throw;
   } catch (const std::exception& e) {
      elog("std::exception creating snapshot: {e}", ("e", e.what()));
      throw;
   }
   catch (...) {
      elog("unknown exception creating snapshot");
      throw;
   }
}

} // namespace b1::rodeos::wasm_ql

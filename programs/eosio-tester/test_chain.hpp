#pragma once
// clang-format off
#include <eosio/chain/apply_context.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/snapshot.hpp>
#include <eosio/chain/transaction_context.hpp>
#include <eosio/chain/whitelisted_intrinsics.hpp>
#include <eosio/chain/webassembly/common.hpp>
#include <eosio/chain/webassembly/interface.hpp>
#include <eosio/chain/webassembly/preconditions.hpp>
#include <eosio/state_history/create_deltas.hpp>
#include <eosio/state_history/serialization.hpp>
#include <eosio/state_history/trace_converter.hpp>
#include <eosio/state_history/transaction_trace_cache.hpp>
#include <fc/crypto/ripemd160.hpp>
#include <fc/crypto/sha1.hpp>
#include <fc/crypto/sha256.hpp>
#include <fc/crypto/sha512.hpp>
#include <fc/exception/exception.hpp>
#include <boost/hana/string.hpp>

#include <b1/rodeos/embedded_rodeos.hpp>
#include <eosio/state_history/type_convert.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/chain_types.hpp>
#include <eosio/to_bin.hpp>
#include <eosio/abi.hpp>

#include <chrono>
#include <stdio.h>

// clang-format on
using namespace eosio::literals;
using namespace std::literals;

using std::optional;

using boost::signals2::scoped_connection;
using eosio::check;
using eosio::convert_to_bin;
using eosio::chain::block_state_ptr;
using eosio::chain::builtin_protocol_feature_t;
using eosio::chain::digest_type;
using eosio::chain::kv_bad_db_id;
using eosio::chain::kv_bad_iter;
using eosio::chain::kv_context;
using eosio::chain::name;
using eosio::chain::packed_transaction_ptr;
using eosio::chain::protocol_feature_exception;
using eosio::chain::protocol_feature_set;
using eosio::chain::signed_transaction;
using eosio::chain::transaction_trace_ptr;
using eosio::state_history::block_position;
using eosio::state_history::create_deltas;
using eosio::state_history::get_blocks_result_v1;
using eosio::state_history::state_result;
using eosio::vm::span;
template <typename T, std::size_t Align = alignof(T)>
using legacy_ptr = eosio::vm::argument_proxy<T*, Align>;

template <typename T, std::size_t Align = alignof(T)>
using legacy_span = eosio::vm::argument_proxy<eosio::vm::span<T>, Align>;

inline constexpr int      block_interval_ms   = 500;
inline constexpr int      block_interval_us   = block_interval_ms * 1000;
inline constexpr uint32_t billed_cpu_time_use = 2000;

// Handle eosio version differences
namespace {
template <typename C, typename F0, typename F1, typename G>
auto do_startup(C&& control, F0&&, F1&& f1, G&&)
      -> std::enable_if_t<std::is_constructible_v<std::decay_t<decltype(*control)>, eosio::chain::controller::config,
                                                  protocol_feature_set>> {
   return control->startup([]() { return false; }, nullptr);
}
template <typename C, typename F0, typename F1, typename G>
auto do_startup(C&& control, F0&&, F1&& f1, G&& genesis) -> decltype(control->startup(f1, genesis)) {
   return control->startup([]() { return false; }, genesis);
}
template <typename C, typename F0, typename F1, typename G>
auto do_startup(C&& control, F0&& f0, F1&& f1, G&& genesis) -> decltype(control->startup(f0, f1, genesis)) {
   return control->startup(f0, f1, genesis);
}
} // namespace

struct assert_exception : std::exception {
   std::string msg;

   assert_exception(std::string&& msg) : msg(std::move(msg)) {}

   const char* what() const noexcept override { return msg.c_str(); }
};

namespace {
struct __attribute__((__may_alias__)) xxx_transaction_checktime_timer {
   std::atomic_bool&             expired;
   eosio::chain::platform_timer& _timer;
};
struct transaction_checktime_factory {
   eosio::chain::platform_timer              timer;
   std::atomic_bool                          expired;
   eosio::chain::transaction_checktime_timer get() { return { expired, timer }; }
};
}; // namespace

struct intrinsic_context {
   eosio::chain::controller&                           control;
   eosio::chain::packed_transaction                    trx;
   std::unique_ptr<eosio::chain::transaction_context>  trx_ctx;
   std::unique_ptr<eosio::chain::apply_context>        apply_context;

   intrinsic_context(eosio::chain::controller& control) : control{ control } {
      static transaction_checktime_factory xxx_timer;

      eosio::chain::signed_transaction strx;
      strx.actions.emplace_back();
      strx.actions.back().account = eosio::chain::name{ "eosio.null" };
      strx.actions.back().authorization.push_back({ eosio::chain::name{ "eosio" }, eosio::chain::name{ "active" } });
      trx = eosio::chain::packed_transaction(std::move(strx), true);
      trx_ctx =
            std::make_unique<eosio::chain::transaction_context>(control, trx, xxx_timer.get(), fc::time_point::now());
      trx_ctx->init_for_implicit_trx(0);
      trx_ctx->exec();
      apply_context = std::make_unique<eosio::chain::apply_context>(control, *trx_ctx, 1, 0);
      apply_context->exec_one();
   }
};

protocol_feature_set make_protocol_feature_set() {
   protocol_feature_set                                             pfs;
   std::map<builtin_protocol_feature_t, std::optional<digest_type>> visited_builtins;

   std::function<digest_type(builtin_protocol_feature_t)> add_builtins =
         [&pfs, &visited_builtins, &add_builtins](builtin_protocol_feature_t codename) -> digest_type {
      auto res = visited_builtins.emplace(codename, std::optional<digest_type>());
      if (!res.second) {
         EOS_ASSERT(res.first->second, protocol_feature_exception,
                    "invariant failure: cycle found in builtin protocol feature dependencies");
         return *res.first->second;
      }

      auto f = protocol_feature_set::make_default_builtin_protocol_feature(
            codename, [&add_builtins](builtin_protocol_feature_t d) { return add_builtins(d); });

      const auto& pf    = pfs.add_feature(f);
      res.first->second = pf.feature_digest;

      return pf.feature_digest;
   };

   for (const auto& p : eosio::chain::builtin_protocol_feature_codenames) { add_builtins(p.first); }

   return pfs;
}

template <typename T>
using wasm_ptr = eosio::vm::argument_proxy<T*>;

struct test_chain;
struct test_chain_ref {
   test_chain* chain = {};

   test_chain_ref() = default;
   test_chain_ref(test_chain&);
   test_chain_ref(const test_chain_ref&);
   ~test_chain_ref();

   test_chain_ref& operator=(const test_chain_ref&);
};

struct test_chain {
   eosio::chain::private_key_type producer_key{ "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"s };

   fc::temp_directory                                dir;
   std::unique_ptr<eosio::chain::controller::config> cfg;
   std::unique_ptr<eosio::chain::controller>         control;
   std::optional<scoped_connection>                  applied_transaction_connection;
   std::optional<scoped_connection>                  accepted_block_connection;
   eosio::state_history::transaction_trace_cache     trace_cache;
   std::optional<block_position>                     prev_block;
   std::map<uint32_t, std::vector<char>>             history;
   std::unique_ptr<intrinsic_context>                intr_ctx;
   std::set<test_chain_ref*>                         refs;

   test_chain(const char* snapshot, std::function<void(eosio::chain::controller::config&)> config_chain) {
      eosio::chain::genesis_state genesis;
      // increase default limits to allow for code coverage
      genesis.initial_configuration.max_transaction_net_usage *= 2;
      genesis.initial_configuration.max_block_net_usage *= 2;
      genesis.initial_configuration.max_block_cpu_usage *= 2;
      genesis.initial_configuration.max_transaction_cpu_usage *= 2;

      genesis.initial_timestamp                 = fc::time_point::from_iso_string("2020-01-01T00:00:00.000");
      cfg                                       = std::make_unique<eosio::chain::controller::config>();
      cfg->max_nonprivileged_inline_action_size = 0xffff'ffff;
      cfg->blog.log_dir                         = dir.path() / "blocks";
      cfg->state_dir                            = dir.path() / "state";
      cfg->contracts_console                    = true;
      config_chain(*cfg);

      std::optional<std::ifstream>                           snapshot_file;
      std::shared_ptr<eosio::chain::istream_snapshot_reader> snapshot_reader;
      if (snapshot && *snapshot) {
         std::optional<eosio::chain::chain_id_type> chain_id;
         {
            std::ifstream temp_file(snapshot, (std::ios::in | std::ios::binary));
            if (!temp_file.is_open())
               throw std::runtime_error("can not open " + std::string{ snapshot });
            eosio::chain::istream_snapshot_reader tmp_reader(temp_file);
            tmp_reader.validate();
            chain_id = eosio::chain::controller::extract_chain_id(tmp_reader);
         }
         snapshot_file.emplace(snapshot, std::ios::in | std::ios::binary);
         snapshot_reader = std::make_shared<eosio::chain::istream_snapshot_reader>(*snapshot_file);
         control         = std::make_unique<eosio::chain::controller>(*cfg, make_protocol_feature_set(), *chain_id);
      } else {
         control = std::make_unique<eosio::chain::controller>(*cfg, make_protocol_feature_set(),
                                                              genesis.compute_chain_id());
      }

      control->add_indices();

      applied_transaction_connection.emplace(control->applied_transaction.connect(
            [&](std::tuple<const transaction_trace_ptr&, const packed_transaction_ptr&> t) {
               on_applied_transaction(std::get<0>(t), std::get<1>(t));
            }));
      accepted_block_connection.emplace(
            control->accepted_block.connect([&](const block_state_ptr& p) { on_accepted_block(p); }));

      if (snapshot_reader) {
         control->startup([] {}, [] { return false; }, snapshot_reader);
      } else {
         do_startup(
               control, [] {}, [] { return false; }, genesis);
         control->start_block(control->head_block_time() + fc::microseconds(block_interval_us), 0,
                              { *control->get_protocol_feature_manager().get_builtin_digest(
                                    eosio::chain::builtin_protocol_feature_t::preactivate_feature) });
      }
   }

   test_chain(const test_chain&) = delete;
   test_chain& operator=(const test_chain&) = delete;

   ~test_chain() {
      for (auto* ref : refs) ref->chain = nullptr;
   }

   void on_applied_transaction(const transaction_trace_ptr& p, const packed_transaction_ptr& t) {
      trace_cache.add_transaction(p, t);
   }

   void on_accepted_block(const block_state_ptr& block_state) {
      using namespace eosio;
      fc::datastream<std::vector<char>> strm;
      state_history::trace_converter::pack(strm, control->db(), false, trace_cache.prepare_traces(block_state),
                                           state_history::compression_type::none);
      strm.seekp(0);

      get_blocks_result_v1 message;
      message.head = block_position{ control->head_block_num(), control->head_block_id() };
      message.last_irreversible =
            block_position{ control->last_irreversible_block_num(), control->last_irreversible_block_id() };
      message.this_block = block_position{ block_state->block->block_num(), block_state->id };
      message.prev_block = prev_block;
      message.block      = block_state->block;
      std::vector<state_history::transaction_trace> traces;
      state_history::trace_converter::unpack(strm, traces);
      message.traces = traces;
      message.deltas = fc::raw::pack(create_deltas(control->db(), !prev_block, false));

      prev_block                         = message.this_block;
      history[control->head_block_num()] = fc::raw::pack(state_result{ message });
   }

   void mutating() { intr_ctx.reset(); }

   auto& get_intrisic_context() {
      if (!intr_ctx) {
         start_if_needed();
         intr_ctx = std::make_unique<intrinsic_context>(*control);
      }
      return *intr_ctx;
   }

   auto& get_apply_context() { return *get_intrisic_context().apply_context; }

   void start_block(int64_t skip_miliseconds = 0) {
      mutating();
      if (control->is_building_block())
         finish_block();
      control->start_block(control->head_block_time() + fc::microseconds(skip_miliseconds * 1000ll + block_interval_us),
                           0);
   }

   void start_if_needed() {
      mutating();
      if (!control->is_building_block())
         control->start_block(control->head_block_time() + fc::microseconds(block_interval_us), 0);
   }

   void finish_block() {
      start_if_needed();
      ilog("finish block {n}", ("n", control->head_block_num()));

      control->finalize_block(
            [&](eosio::chain::block_state_ptr bsp, bool wtmsig_enabled, eosio::chain::digest_type d) {
               auto signatures = std::vector{ producer_key.sign(d) };
               bsp->assign_signatures(std::move(signatures), wtmsig_enabled);
            }).get()();
   }
};

test_chain_ref::test_chain_ref(test_chain& chain) {
   chain.refs.insert(this);
   this->chain = &chain;
}

test_chain_ref::test_chain_ref(const test_chain_ref& src) {
   chain = src.chain;
   if (chain)
      chain->refs.insert(this);
}

test_chain_ref::~test_chain_ref() {
   if (chain)
      chain->refs.erase(this);
}

test_chain_ref& test_chain_ref::operator=(const test_chain_ref& src) {
   if (chain)
      chain->refs.erase(this);
   chain = nullptr;
   if (src.chain)
      src.chain->refs.insert(this);
   chain = src.chain;
   return *this;
}

struct test_rodeos {
   fc::temp_directory                                dir;
   b1::embedded_rodeos::context                      context;
   std::optional<b1::embedded_rodeos::partition>     partition;
   std::optional<b1::embedded_rodeos::snapshot>      write_snapshot;
   std::list<b1::embedded_rodeos::filter>            filters;
   std::optional<b1::embedded_rodeos::query_handler> query_handler;
   test_chain_ref                                    chain;
   uint32_t                                          next_block = 0;
   std::vector<std::vector<char>>                    pushed_data;

   test_rodeos() {
      context.open_db(dir.path().string().c_str(), true);
      partition.emplace(context, "", 0);
      write_snapshot.emplace(partition->obj, true);
   }
};

struct contract_row {
   uint32_t            block_num   = {};
   bool                present     = {};
   eosio::name         code        = {};
   eosio::name         scope       = {};
   eosio::name         table       = {};
   uint64_t            primary_key = {};
   eosio::name         payer       = {};
   eosio::input_stream value       = {};
};

EOSIO_REFLECT(contract_row, block_num, present, code, scope, table, primary_key, payer, value);

struct file {
   FILE* f    = nullptr;
   bool  owns = false;

   file(FILE* f = nullptr, bool owns = true) : f(f), owns(owns) {}

   file(const file&) = delete;
   file(file&& src) { *this = std::move(src); }

   ~file() { close(); }

   file& operator=(const file&) = delete;

   file& operator=(file&& src) {
      close();
      this->f    = src.f;
      this->owns = src.owns;
      src.f      = nullptr;
      src.owns   = false;
      return *this;
   }

   void close() {
      if (owns && f)
         fclose(f);
      f    = nullptr;
      owns = false;
   }
};

struct state {
   state(const std::vector<char>& args) : args(args) {}

   std::vector<char>                         args;
   std::vector<file>                         files;
   std::vector<std::unique_ptr<test_chain>>  chains;
   std::vector<std::unique_ptr<test_rodeos>> rodeoses;
   std::optional<uint32_t>                   selected_chain_index;
};

struct push_trx_args {
   eosio::chain::bytes                         transaction;
   std::vector<eosio::chain::bytes>            context_free_data;
   std::vector<eosio::chain::signature_type>   signatures;
   std::vector<eosio::chain::private_key_type> keys;
};
FC_REFLECT(push_trx_args, (transaction)(context_free_data)(signatures)(keys))

namespace b1::tester {
template <typename State>
struct callbacks {
   State& state;

   using cb_alloc_data_type = typename State::cb_alloc_data_type;
   using cb_alloc_type      = typename State::cb_alloc_type;

   callbacks(State& s) : state(s) {}

   void check_bounds(const void* data, size_t size) { state.check_bounds(data, size); }

   template <typename T>
   T unpack(const char* begin, size_t size) {
      fc::datastream<const char*> ds(begin, size);
      T                           args;
      fc::raw::unpack(ds, args);
      return args;
   }

   template <typename T>
   T unpack(span<const char> data) {
      return unpack<T>(data.begin(), data.size());
   }

   template <typename T>
   T unpack(const eosio::input_stream& data) {
      return unpack<T>(data.pos, data.end - data.pos);
   }

   std::string span_str(span<const char> str) { return { str.data(), str.size() }; }

   template <typename T>
   void set_data(cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc, const T& data) {
      memcpy(state.alloc(this, cb_alloc_data, cb_alloc, data.size()), data.data(), data.size());
   }

   void set_data(cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc, const b1::embedded_rodeos::result& data) {
      memcpy(state.alloc(this, cb_alloc_data, cb_alloc, data.size), data.data, data.size);
   }

   void abort() { throw std::runtime_error("called abort"); }

   void eosio_assert_message(bool condition, span<const char> msg) {
      if (!condition)
         throw ::assert_exception(span_str(msg));
   }

   void prints_l(legacy_span<const char> str) { std::cerr.write(str.data(), str.size()); }

   uint32_t get_args(span<char> dest) {
      memcpy(dest.data(), state.args.data(), std::min(dest.size(), state.args.size()));
      return state.args.size();
   }

   int32_t clock_gettime(int32_t id, void* data) {
      check_bounds((char*)data, 8);
      std::chrono::nanoseconds result;
      if (id == 0) { // CLOCK_REALTIME
         result = std::chrono::system_clock::now().time_since_epoch();
      } else if (id == 1) { // CLOCK_MONOTONIC
         result = std::chrono::steady_clock::now().time_since_epoch();
      } else {
         return -1;
      }
      int32_t               sec  = result.count() / 1000000000;
      int32_t               nsec = result.count() % 1000000000;
      fc::datastream<char*> ds((char*)data, 8);
      fc::raw::pack(ds, sec);
      fc::raw::pack(ds, nsec);
      return 0;
   }

   int32_t open_file(span<const char> filename, span<const char> mode) {
      file f = fopen(span_str(filename).c_str(), span_str(mode).c_str());
      if (!f.f)
         return -1;
      state.files.push_back(std::move(f));
      return state.files.size() - 1;
   }

   file& assert_file(int32_t file_index) {
      if (file_index < 0 || static_cast<uint32_t>(file_index) >= state.files.size() || !state.files[file_index].f)
         throw std::runtime_error("file is not opened");
      return state.files[file_index];
   }

   bool isatty(int32_t file_index) { return !assert_file(file_index).owns; }

   void close_file(int32_t file_index) { assert_file(file_index).close(); }

   bool write_file(int32_t file_index, span<const char> content) {
      auto& f = assert_file(file_index);
      return fwrite(content.data(), content.size(), 1, f.f) == 1;
   }

   int32_t read_file(int32_t file_index, span<char> content) {
      auto& f = assert_file(file_index);
      return fread(content.data(), 1, content.size(), f.f);
   }
   
   template <typename Transform>
   bool read_file_content(span<const char> filename, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc, Transform&& fn) {
      file f = fopen(span_str(filename).c_str(), "r");
      if (!f.f)
         return false;
      if (fseek(f.f, 0, SEEK_END))
         return false;
      auto size = ftell(f.f);
      if (size < 0 || (long)(uint32_t)size != size)
         return false;
      if (fseek(f.f, 0, SEEK_SET))
         return false;
      std::string buf(size, '\0');
      if (fread(buf.data(), size, 1, f.f) != 1)
         return false;
      set_data(cb_alloc_data, cb_alloc, fn(buf));
      return true;
   }

   bool read_whole_file(span<const char> filename, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc) {
      return read_file_content( filename, cb_alloc_data, cb_alloc, [](const std::string& s) { return s;});
   }


   bool read_abi_file(span<const char> filename, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc) {
      return read_file_content( filename, cb_alloc_data, cb_alloc, [](std::string s) { return eosio::abi_def::json_to_bin(s);});
   }

   int32_t execute(span<const char> command) { return system(span_str(command).c_str()); }

   test_chain& assert_chain(uint32_t chain, bool require_control = true) {
      if (chain >= state.chains.size() || !state.chains[chain])
         throw std::runtime_error("chain does not exist or was destroyed");
      auto& result = *state.chains[chain];
      if (require_control && !result.control)
         throw std::runtime_error("chain was shut down");
      return result;
   }

   uint32_t create_chain(span<const char> snapshot) {
      uint32_t chain_index = state.chains.size();
      state.chains.push_back(std::make_unique<test_chain>(
            span_str(snapshot).c_str(), [this](eosio::chain::controller::config& cfg) { state.config_chain(cfg); }));
      if (state.chains.size() == 1)
         state.selected_chain_index = 0;
      return chain_index;
   }

   void destroy_chain(uint32_t chain) {
      assert_chain(chain, false);
      if (state.selected_chain_index && *state.selected_chain_index == chain)
         state.selected_chain_index.reset();
      state.chains[chain].reset();
      while (!state.chains.empty() && !state.chains.back()) { state.chains.pop_back(); }
   }

   void shutdown_chain(uint32_t chain) {
      auto& c = assert_chain(chain);
      c.control.reset();
   }

   void write_snapshot(uint32_t chain, span<const char> filename) {
      auto& c = assert_chain(chain);
      if (c.control->is_building_block())
         c.finish_block();
      auto snap_out = std::ofstream(span_str(filename).c_str(), (std::ios::out | std::ios::binary));
      if (!snap_out.good()) {
         throw std::runtime_error("unable to open file: " + span_str(filename));
      }
      auto writer = std::make_shared<eosio::chain::ostream_snapshot_writer>(snap_out);
      c.control->write_snapshot(writer);
      writer->finalize();
      snap_out.flush();
      snap_out.close();
   }

   uint32_t get_chain_path(uint32_t chain, span<char> dest) {
      auto& c = assert_chain(chain, false);
      auto  s = c.dir.path().string();
      memcpy(dest.data(), s.c_str(), std::min(dest.size(), s.size()));
      return s.size();
   }

   void replace_producer_keys(uint32_t chain_index, span<const char> key) {
      auto& chain = assert_chain(chain_index);
      auto  k     = unpack<eosio::chain::public_key_type>(key);
      chain.control->replace_producer_keys(k);
   }

   void replace_account_keys(uint32_t chain_index, uint64_t account, uint64_t permission, span<const char> key) {
      auto& chain = assert_chain(chain_index);
      auto  k     = unpack<eosio::chain::public_key_type>(key);
      chain.control->replace_account_keys(eosio::chain::name{ account }, eosio::chain::name{ permission }, k);
   }

   void start_block(uint32_t chain_index, int64_t skip_miliseconds) {
      assert_chain(chain_index).start_block(skip_miliseconds);
   }

   void finish_block(uint32_t chain_index) { assert_chain(chain_index).finish_block(); }

   void get_head_block_info(uint32_t chain_index, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc) {
      auto&                   chain = assert_chain(chain_index);
      chain_types::block_info info;
      info.block_num      = chain.control->head_block_num();
      info.block_id       = eosio::state_history::convert(chain.control->head_block_id());
      info.timestamp.slot = chain.control->head_block_state()->header.timestamp.slot;
      set_data(cb_alloc_data, cb_alloc, convert_to_bin(info));
   }

   void push_transaction(uint32_t chain_index, span<const char> args_packed, cb_alloc_data_type cb_alloc_data,
                         cb_alloc_type cb_alloc) {
      auto                             args        = unpack<push_trx_args>(args_packed);
      auto                             transaction = unpack<eosio::chain::transaction>(args.transaction);
      eosio::chain::signed_transaction signed_trx{ std::move(transaction), std::move(args.signatures),
                                                   std::move(args.context_free_data) };
      auto&                            chain = assert_chain(chain_index);
      chain.start_if_needed();
      for (auto& key : args.keys) signed_trx.sign(key, chain.control->get_chain_id());
      auto ptrx = std::make_shared<eosio::chain::packed_transaction>(
            std::move(signed_trx), true, eosio::chain::packed_transaction::compression_type::none);
      auto fut = eosio::chain::transaction_metadata::start_recover_keys(
            ptrx, chain.control->get_thread_pool(), chain.control->get_chain_id(), fc::microseconds::maximum(),
            eosio::chain::transaction_metadata::trx_type::input);
      auto start_time = std::chrono::steady_clock::now();
      auto result     = chain.control->push_transaction(fut.get(), fc::time_point::maximum(), fc::microseconds::maximum(), 2000, true, 0);
      auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time);
      ilog("chainlib transaction took {u} us", ("u", us.count()));
      // ilog("{r}", ("r", fc::json::to_pretty_string(result)));
      set_data(cb_alloc_data, cb_alloc,
               convert_to_bin(chain_types::transaction_trace{ eosio::state_history::convert(*result) }));
   }

   void set_push_event_alloc(uint32_t chain_index, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc) {
      auto& chain = assert_chain(chain_index);
      chain.start_if_needed();
      chain.control->set_push_event_function([this, cb_alloc_data, cb_alloc](const char* data, size_t size){
         memcpy(state.alloc(this, cb_alloc_data, cb_alloc, size), data, size);
      });
   }

   bool exec_deferred(uint32_t chain_index, cb_alloc_data_type cb_alloc_data, cb_alloc_type cb_alloc) {
      EOS_ASSERT(false, eosio::chain::unsupported_feature, "exec_deferred deprecated");
   }

   uint32_t get_history(uint32_t chain_index, uint32_t block_num, span<char> dest) {
      auto&                                           chain = assert_chain(chain_index);
      std::map<uint32_t, std::vector<char>>::iterator it;
      if (block_num == 0xffff'ffff && !chain.history.empty())
         it = --chain.history.end();
      else {
         it = chain.history.find(block_num);
         if (it == chain.history.end())
            return 0;
      }
      memcpy(dest.data(), it->second.data(), std::min(dest.size(), it->second.size()));
      return it->second.size();
   }

   void select_chain_for_db(uint32_t chain_index) {
      assert_chain(chain_index);
      state.selected_chain_index = chain_index;
   }

   auto& selected_chain() {
      if (!state.selected_chain_index || *state.selected_chain_index >= state.chains.size() ||
          !state.chains[*state.selected_chain_index] || !state.chains[*state.selected_chain_index]->control)
         throw std::runtime_error("select_chain_for_db() must be called before using multi_index");
      return *state.chains[*state.selected_chain_index];
   }

   auto& selected() { return selected_chain().get_apply_context(); }

   test_rodeos& assert_rodeos(uint32_t rodeos) {
      if (rodeos >= state.rodeoses.size() || !state.rodeoses[rodeos])
         throw std::runtime_error("rodeos does not exist or was destroyed");
      return *state.rodeoses[rodeos];
   }

   uint32_t create_rodeos() {
      state.rodeoses.push_back(std::make_unique<test_rodeos>());
      return state.rodeoses.size() - 1;
   }

   void destroy_rodeos(uint32_t rodeos) {
      assert_rodeos(rodeos);
      state.rodeoses[rodeos].reset();
      while (!state.rodeoses.empty() && !state.rodeoses.back()) { state.rodeoses.pop_back(); }
   }

   void rodeos_add_filter(uint32_t rodeos, uint64_t name, span<const char> wasm_filename) {
      auto& r = assert_rodeos(rodeos);
      r.filters.emplace_back(name, span_str(wasm_filename).c_str());
   }

   void rodeos_enable_queries(uint32_t rodeos, uint32_t max_console_size, uint32_t wasm_cache_size,
                              uint64_t max_exec_time_ms, span<const char> contract_dir) {
      auto& r = assert_rodeos(rodeos);
      r.query_handler.emplace(*r.partition, max_console_size, wasm_cache_size, max_exec_time_ms,
                              span_str(contract_dir).c_str(), nullptr);
   }

   void connect_rodeos(uint32_t rodeos, uint32_t chain) {
      auto& r = assert_rodeos(rodeos);
      auto& c = assert_chain(chain);
      if (r.chain.chain)
         throw std::runtime_error("rodeos is already connected");
      r.chain = test_chain_ref{ c };
   }

   bool rodeos_sync_block(uint32_t rodeos) {
      auto& r = assert_rodeos(rodeos);
      if (!r.chain.chain)
         throw std::runtime_error("rodeos is not connected to a chain");
      auto it = r.chain.chain->history.lower_bound(r.next_block);
      if (it == r.chain.chain->history.end())
         return false;
      r.write_snapshot->start_block(it->second.data(), it->second.size());
      r.write_snapshot->write_block_info(it->second.data(), it->second.size());
      r.write_snapshot->write_deltas(it->second.data(), it->second.size(), [] { return false; });
      for (auto& filter : r.filters) {
         try {
            filter.run(*r.write_snapshot, it->second.data(), it->second.size(), [&](const char* data, uint64_t size) {
               r.pushed_data.emplace_back(data, data + size);
               return true;
            });
         } catch (std::exception& e) { throw std::runtime_error("filter failed: " + std::string{ e.what() }); }
      }
      r.write_snapshot->end_block(it->second.data(), it->second.size(), true);
      r.next_block = it->first + 1;
      return true;
   }

   void rodeos_push_transaction(uint32_t rodeos, span<const char> packed_args, cb_alloc_data_type cb_alloc_data,
                                cb_alloc_type cb_alloc) {
      auto& r = assert_rodeos(rodeos);
      if (!r.chain.chain)
         throw std::runtime_error("rodeos is not connected to a chain");
      if (!r.query_handler)
         throw std::runtime_error("call rodeos_enable_queries before rodeos_push_transaction");
      auto& chain = *r.chain.chain;
      chain.start_if_needed();

      auto                             args        = unpack<push_trx_args>(packed_args);
      auto                             transaction = unpack<eosio::chain::transaction>(args.transaction);
      eosio::chain::signed_transaction signed_trx{ std::move(transaction), std::move(args.signatures),
                                                   std::move(args.context_free_data) };
      for (auto& key : args.keys) signed_trx.sign(key, chain.control->get_chain_id());
      eosio::chain::packed_transaction ptrx{ std::move(signed_trx), true,
                                             eosio::chain::packed_transaction::compression_type::none };
      auto                             data       = fc::raw::pack(ptrx);
      auto                             start_time = std::chrono::steady_clock::now();
      auto result = r.query_handler->query_transaction(*r.write_snapshot, data.data(), data.size());
      auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start_time);
      ilog("rodeos transaction took {u} us", ("u", us.count()));
      auto tt = eosio::convert_from_bin<eosio::ship_protocol::transaction_trace>(
            { result.data, result.data + result.size });
      auto& tt0 = std::get<eosio::ship_protocol::transaction_trace_v0>(tt);
      for (auto& at : tt0.action_traces) {
         auto& at1 = std::get<eosio::ship_protocol::action_trace_v1>(at);
         if (!at1.console.empty())
            ilog("rodeos query console: <<<\n{c}>>>", ("c", at1.console));
      }
      set_data(cb_alloc_data, cb_alloc, result);
   }

   uint32_t rodeos_get_num_pushed_data(uint32_t rodeos) {
      auto& r = assert_rodeos(rodeos);
      return r.pushed_data.size();
   }

   uint32_t rodeos_get_pushed_data(uint32_t rodeos, uint32_t index, span<char> dest) {
      auto& r = assert_rodeos(rodeos);
      if (index >= r.pushed_data.size())
         throw std::runtime_error("rodeos_get_pushed_data: index is out of range");
      memcpy(dest.data(), r.pushed_data[index].data(), std::min(dest.size(), r.pushed_data[index].size()));
      return r.pushed_data[index].size();
   }

   // clang-format off

   int32_t db_get_i64(int32_t iterator, span<char> buffer)                                {return selected().db_get_i64(iterator, buffer.data(), buffer.size());}
   int32_t db_next_i64(int32_t iterator, wasm_ptr<uint64_t> primary)                      {return selected().db_next_i64(iterator, *primary);}
   int32_t db_previous_i64(int32_t iterator, wasm_ptr<uint64_t> primary)                  {return selected().db_previous_i64(iterator, *primary);}
   int32_t db_find_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id)        {return selected().db_find_i64(name(code), name(scope), name(table), id);}
   int32_t db_lowerbound_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id)  {return selected().db_lowerbound_i64(name(code), name(scope), name(table), id);}
   int32_t db_upperbound_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id)  {return selected().db_upperbound_i64(name(code), name(scope), name(table), id);}
   int32_t db_end_i64(uint64_t code, uint64_t scope, uint64_t table)                      {return selected().db_end_i64(name(code), name(scope), name(table));}

   int32_t db_idx64_find_secondary(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<const uint64_t> secondary,
                                     wasm_ptr<uint64_t> primary) {
      return selected().idx64.find_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx64_find_primary(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<uint64_t> secondary,
                                   uint64_t primary) {
      return selected().idx64.find_primary(code, scope, table, *secondary, primary);
   }
   int32_t db_idx64_lowerbound(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<uint64_t> secondary,
                                 wasm_ptr<uint64_t> primary) {
      return selected().idx64.lowerbound_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx64_upperbound(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<uint64_t> secondary,
                                 wasm_ptr<uint64_t> primary) {
      return selected().idx64.upperbound_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx64_end(uint64_t code, uint64_t scope, uint64_t table) {
      return selected().idx64.end_secondary(code, scope, table);
   }
   int32_t db_idx64_next(int32_t iterator, wasm_ptr<uint64_t> primary) {
      return selected().idx64.next_secondary(iterator, *primary);
   }
   int32_t db_idx64_previous(int32_t iterator, wasm_ptr<uint64_t> primary) {
      return selected().idx64.previous_secondary(iterator, *primary);
   }

   int32_t db_idx128_find_secondary(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<const unsigned __int128> secondary,
                                   wasm_ptr<uint64_t> primary) {
      return selected().idx128.find_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx128_find_primary(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<unsigned __int128> secondary,
                                 uint64_t primary) {
      return selected().idx128.find_primary(code, scope, table, *secondary, primary);
   }
   int32_t db_idx128_lowerbound(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<unsigned __int128> secondary,
                               wasm_ptr<uint64_t> primary) {
      return selected().idx128.lowerbound_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx128_upperbound(uint64_t code, uint64_t scope, uint64_t table, wasm_ptr<unsigned __int128> secondary,
                               wasm_ptr<uint64_t> primary) {
      return selected().idx128.upperbound_secondary(code, scope, table, *secondary, *primary);
   }
   int32_t db_idx128_end(uint64_t code, uint64_t scope, uint64_t table) {
      return selected().idx128.end_secondary(code, scope, table);
   }
   int32_t db_idx128_next(int32_t iterator, wasm_ptr<uint64_t> primary) {
      return selected().idx128.next_secondary(iterator, *primary);
   }
   int32_t db_idx128_previous(int32_t iterator, wasm_ptr<uint64_t> primary) {
      return selected().idx128.previous_secondary(iterator, *primary);
   }

   // clang-format on

   int64_t kv_erase(uint64_t contract, span<const char> key) {
      throw std::runtime_error("kv_erase not implemented in tester");
   }

   int64_t kv_set(uint64_t contract, span<const char> key, span<const char> value, uint64_t payer) {
      throw std::runtime_error("kv_set not implemented in tester");
   }

   bool kv_get(uint64_t contract, span<const char> key, wasm_ptr<uint32_t> value_size) {
      return kv_get_db().kv_get(contract, key.data(), key.size(), *value_size);
   }

   uint32_t kv_get_data(uint32_t offset, span<char> data) {
      return kv_get_db().kv_get_data(offset, data.data(), data.size());
   }

   uint32_t kv_it_create(uint64_t contract, span<const char> prefix) {
      auto&    kdb = kv_get_db();
      uint32_t itr;
      if (!selected().kv_destroyed_iterators.empty()) {
         itr = selected().kv_destroyed_iterators.back();
         selected().kv_destroyed_iterators.pop_back();
      } else {
         // Sanity check in case the per-database limits are set poorly
         EOS_ASSERT(selected().kv_iterators.size() <= 0xFFFFFFFFu, kv_bad_iter, "Too many iterators");
         itr = selected().kv_iterators.size();
         selected().kv_iterators.emplace_back();
      }
      selected().kv_iterators[itr] = kdb.kv_it_create(contract, prefix.data(), prefix.size());
      return itr;
   }

   void kv_it_destroy(uint32_t itr) {
      kv_check_iterator(itr);
      selected().kv_destroyed_iterators.push_back(itr);
      selected().kv_iterators[itr].reset();
   }

   int32_t kv_it_status(uint32_t itr) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(selected().kv_iterators[itr]->kv_it_status());
   }

   int32_t kv_it_compare(uint32_t itr_a, uint32_t itr_b) {
      kv_check_iterator(itr_a);
      kv_check_iterator(itr_b);
      return selected().kv_iterators[itr_a]->kv_it_compare(*selected().kv_iterators[itr_b]);
   }

   int32_t kv_it_key_compare(uint32_t itr, span<const char> key) {
      kv_check_iterator(itr);
      return selected().kv_iterators[itr]->kv_it_key_compare(key.data(), key.size());
   }

   int32_t kv_it_move_to_end(uint32_t itr) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(selected().kv_iterators[itr]->kv_it_move_to_end());
   }

   int32_t kv_it_next(uint32_t itr, wasm_ptr<uint32_t> found_key_size, wasm_ptr<uint32_t> found_value_size) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(selected().kv_iterators[itr]->kv_it_next(found_key_size, found_value_size));
   }

   int32_t kv_it_prev(uint32_t itr, wasm_ptr<uint32_t> found_key_size, wasm_ptr<uint32_t> found_value_size) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(selected().kv_iterators[itr]->kv_it_prev(found_key_size, found_value_size));
   }

   int32_t kv_it_lower_bound(uint32_t itr, span<const char> key, wasm_ptr<uint32_t> found_key_size,
                             wasm_ptr<uint32_t> found_value_size) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(
            selected().kv_iterators[itr]->kv_it_lower_bound(key.data(), key.size(), found_key_size, found_value_size));
   }

   int32_t kv_it_key(uint32_t itr, uint32_t offset, span<char> dest, wasm_ptr<uint32_t> actual_size) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(
            selected().kv_iterators[itr]->kv_it_key(offset, dest.data(), dest.size(), *actual_size));
   }

   int32_t kv_it_value(uint32_t itr, uint32_t offset, span<char> dest, wasm_ptr<uint32_t> actual_size) {
      kv_check_iterator(itr);
      return static_cast<int32_t>(
            selected().kv_iterators[itr]->kv_it_value(offset, dest.data(), dest.size(), *actual_size));
   }

   kv_context& kv_get_db() { return selected().get_kv_context(); }

   void kv_check_iterator(uint32_t itr) {
      EOS_ASSERT(itr < selected().kv_iterators.size() && selected().kv_iterators[itr], kv_bad_iter,
                 "Bad key-value iterator");
   }

   uint32_t sign(span<const char> private_key, const void* hash_val, span<char> signature) {
      auto       k = unpack<fc::crypto::private_key>(private_key);
      fc::sha256 hash;
      std::memcpy(hash.data(), hash_val, hash.data_size());
      auto sig  = k.sign(hash);
      auto data = fc::raw::pack(sig);
      std::memcpy(signature.data(), data.data(), std::min(signature.size(), data.size()));
      return data.size();
   }

   void assert_sha1(span<const char> data, const void* hash_val) {
      auto hash = fc::sha1::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      EOS_ASSERT(std::memcmp(hash_val, hash.data(), hash.data_size()) == 0, eosio::chain::crypto_api_exception,
                 "hash mismatch");
   }

   void assert_sha256(span<const char> data, const void* hash_val) {
      auto hash = fc::sha256::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      EOS_ASSERT(std::memcmp(hash_val, hash.data(), hash.data_size()) == 0, eosio::chain::crypto_api_exception,
                 "hash mismatch");
   }

   void assert_sha512(span<const char> data, const void* hash_val) {
      auto hash = fc::sha512::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      EOS_ASSERT(std::memcmp(hash_val, hash.data(), hash.data_size()) == 0, eosio::chain::crypto_api_exception,
                 "hash mismatch");
   }

   void assert_ripemd160(span<const char> data, const void* hash_val) {
      auto hash = fc::ripemd160::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      EOS_ASSERT(std::memcmp(hash_val, hash.data(), hash.data_size()) == 0, eosio::chain::crypto_api_exception,
                 "hash mismatch");
   }

   void sha1(span<const char> data, void* hash_val) {
      auto hash = fc::sha1::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      std::memcpy(hash_val, hash.data(), hash.data_size());
   }

   void sha256(span<const char> data, void* hash_val) {
      auto hash = fc::sha256::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      std::memcpy(hash_val, hash.data(), hash.data_size());
   }

   void sha512(span<const char> data, void* hash_val) {
      auto hash = fc::sha512::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      std::memcpy(hash_val, hash.data(), hash.data_size());
   }

   void ripemd160(span<const char> data, void* hash_val) {
      auto hash = fc::ripemd160::hash(data.data(), data.size());
      check_bounds(hash_val, hash.data_size());
      std::memcpy(hash_val, hash.data(), hash.data_size());
   }

   int32_t recover_key(legacy_ptr<const fc::sha256> digest, legacy_span<const char> sig, legacy_span<char> pub) {

      // fc::sha256 digest((const char*)digest_val, fc::sha256().data_size());

      fc::crypto::signature       s;
      fc::datastream<const char*> ds(sig.data(), sig.size());
      fc::raw::unpack(ds, s);

      // EOS_ASSERT(static_cast<unsigned>(s.which()) < db.get<protocol_state_object>().num_supported_key_types,
      //            eosio::chain::unactivated_signature_type,
      //            "Unactivated signature type used during assert_recover_key");

      // TODO: enforce subjective signature length limit maximum-variable-signature-length in queries. tester does not need this protection.
      //   EOS_ASSERT(s.variable_size() <= configured_subjective_signature_length_limit(),
      //              eosio::chain::sig_variable_size_limit_exception, "signature variable length component size greater than subjective maximum");

      auto recovered = fc::crypto::public_key(s, *digest, false);

      // the key types newer than the first 2 may be varible in length
      if (static_cast<unsigned>(s.which()) >= eosio::chain::config::genesis_num_supported_key_types) {
         EOS_ASSERT(pub.size() >= 33, eosio::chain::wasm_execution_error,
                    "destination buffer must at least be able to hold an ECC public key");

         auto packed_pubkey = fc::raw::pack(recovered);
         auto copy_size     = std::min<size_t>(pub.size(), packed_pubkey.size());
         std::memcpy(pub.data(), packed_pubkey.data(), copy_size);
         return packed_pubkey.size();
      } else {
         // legacy behavior, key types 0 and 1 always pack to 33 bytes.
         // this will do one less copy for those keys while maintaining the rules of
         //    [0..33) dest sizes: assert (asserts in fc::raw::pack)
         //    [33..inf) dest sizes: return packed size (always 33)
         fc::datastream<char*> out_ds((char*)pub.data(), pub.size());
         fc::raw::pack(out_ds, recovered);
         return out_ds.tellp();
      }
   }
   void assert_recover_key(legacy_ptr<const fc::sha256> digest, legacy_span<const char> sig,
                           legacy_span<const char> pub) const {
      throw std::runtime_error("assert_recover_key not implemented in tester");
   }

   uint64_t current_time() { throw std::runtime_error("current_time not implemented in tester"); }

   bool has_auth(uint64_t account) {
      return selected().has_authorization(name(account));
   }

}; 
}

extern const char* usage;
int                run(const char* filename, const std::vector<std::string>& args);

int main(int argc, char* argv[]) {
   fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::off);

   bool show_usage = false;
   bool error      = false;
   int  next_arg   = 1;
   while (next_arg < argc && argv[next_arg][0] == '-') {
      if (!strcmp(argv[next_arg], "-h") || !strcmp(argv[next_arg], "--help"))
         show_usage = true;
      else if (!strcmp(argv[next_arg], "-v") || !strcmp(argv[next_arg], "--verbose"))
         fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::debug);
      else {
         std::cerr << "unknown option: " << argv[next_arg] << "\n";
         error = true;
      }
      ++next_arg;
   }
   if (next_arg >= argc)
      error = true;
   if (show_usage || error) {
      std::cerr << usage;
      return error;
   }
   try {
      std::vector<std::string> args{ argv + next_arg + 1, argv + argc };
      return run(argv[next_arg], args);
   } catch (::assert_exception& e) {
      std::cerr << "tester wasm asserted: " << e.what() << "\n";
   } catch (eosio::vm::exception& e) {
      std::cerr << "vm::exception: " << e.detail() << "\n";
   } catch (fc::exception& e) { std::cerr << "fc::exception: " << e.to_string() << "\n"; } catch (std::exception& e) {
      std::cerr << "std::exception: " << e.what() << "\n";
   }
   return 1;
}

#include <eosio/rodeos_plugin/rodeos_plugin.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>

#include <eosio/chain/block_state.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/state_history/create_deltas.hpp>
#include <eosio/state_history/trace_converter.hpp>
#include <eosio/state_history/type_convert.hpp>
#include <eosio/rodeos_plugin/wasm_ql_plugin.hpp>

#include <fc/log/trace.hpp>
#include <fc/exception/exception.hpp>
#include <fc/reflect/variant.hpp>

#include <boost/signals2/connection.hpp>

#include <chrono>
#include <unordered_map>
#include <algorithm>

namespace b1 {

using namespace appbase;
using boost::signals2::scoped_connection;
using namespace eosio;

static appbase::abstract_plugin& _rodeos_plugin = app().register_plugin<rodeos_plugin>();

struct transaction_trace_cache {
   std::map<chain::transaction_id_type, chain::transaction_trace_ptr> cached_traces;
   chain::transaction_trace_ptr                                       onblock_trace;

   void add_transaction(const chain::transaction_trace_ptr& trace) {
      if (trace->receipt) {
         if (chain::is_onblock(*trace)) {
            onblock_trace = trace;
         } else if (trace->failed_dtrx_trace) {
            cached_traces[trace->failed_dtrx_trace->id] = trace;
         } else {
            cached_traces[trace->id] = trace;
         }
      }
   }

   void clear() {
      cached_traces.clear();
      onblock_trace.reset();
   }
};

class rodeos_plugin_impl {
public:
   std::optional<scoped_connection>             applied_transaction_connection;
   std::optional<scoped_connection>             block_start_connection;
   std::optional<scoped_connection>             accepted_block_connection;
   eosio::chain_plugin*                         chain_plug = nullptr;
   std::map<uint32_t, transaction_trace_cache>  trace_caches;
   bool                                         trace_debug_mode = false;
   b1::cloner_plugin*                           cloner = nullptr;
   eosio::chain::named_thread_pool              cloner_process_pool {"cloner", 1};
   std::future<std::exception_ptr>              cloner_process_fut;
   bool                                         fresh_rocksdb = true;

   void startup();
   void shutdown();

   void on_applied_transaction(const chain::transaction_trace_ptr& trace,
                               const chain::packed_transaction_ptr& transaction) {
      trace_caches[trace->block_num].add_transaction(trace);
   }

   std::vector<ship_protocol::transaction_trace>
   prepare_ship_traces(transaction_trace_cache& cache, const chain::block_state_ptr& block_state) {
      std::vector<ship_protocol::transaction_trace> traces;
      if (cache.onblock_trace)
         traces.push_back(eosio::state_history::convert(*cache.onblock_trace));
      for (auto& r : block_state->block->transactions) {
         chain::transaction_id_type id;
         if (std::holds_alternative<chain::transaction_id_type>(r.trx))
            id = std::get<chain::transaction_id_type>(r.trx);
         else
            id = std::get<chain::packed_transaction>(r.trx).id();
         auto it = cache.cached_traces.find(id);
         EOS_ASSERT(it != cache.cached_traces.end() && it->second->receipt, chain::state_history_exception,
                    "missing trace for transaction {id}", ("id", id));
         traces.push_back(eosio::state_history::convert(*it->second));
      }
      cache.clear();
      return traces;
   }

   void store(const chain::block_state_ptr& block_state, const ::std::optional<::fc::zipkin_span>& accept_span) {
      try {
         // CDT 2 only supports get_blocks_result_v1, this can be changed to get_blocks_result_v2 when we no longer
         // need to support filter contracts compiled with CDT 2.
         eosio::state_history::get_blocks_result_v1 result;
         auto& control = chain_plug->chain();

         const uint32_t block_num = block_state->block_num;

         result.head.block_num = block_num;
         result.head.block_id = block_state->id;
         result.last_irreversible.block_num = control.last_irreversible_block_num();
         result.last_irreversible.block_id = control.last_irreversible_block_id();
         result.this_block = result.head;
         std::optional<chain::block_id_type> prev_block_id;
         try {
            prev_block_id = control.get_block_id_for_num( block_num - 1 );
         } catch(...) {}
         if (prev_block_id)
            result.prev_block = state_history::block_position{ block_num - 1, *prev_block_id };
         // copy block_header to avoid having to serialize the entire block, only the block_header is needed.
         // get_blocks_result_v2 has support for providing only the block_header.
         result.block = std::make_shared<chain::signed_block>(static_cast<chain::signed_block_header&>(*block_state->block));


         { // traces
            auto trace_span = fc_create_span( accept_span, "store_traces" );
            std::vector<ship_protocol::transaction_trace> traces = prepare_ship_traces(trace_caches[block_num], block_state);
            result.traces = std::make_shared<std::vector<char>>(eosio::convert_to_bin(traces));
            trace_caches.erase( block_num );
         }

         // deltas
         auto delta_span = fc_create_span(accept_span, "store_deltas");
         std::vector<state_history::table_delta> deltas = state_history::create_deltas(control.db(), fresh_rocksdb, true);
         if( fresh_rocksdb ) {
            ilog( "Placing initial state of {d} deltas in block {n}", ("d", deltas.size())( "n", block_num ) );
            for( auto& a: deltas ) {
               dlog( "  table_delta: {t}, rows {r}", ("t", a.name)( "r", a.rows.obj.size() ) );
            }
         }

         // cloner process for the previous block should have finished here
         if (cloner_process_fut.valid()) {
            std::exception_ptr except_to_throw = cloner_process_fut.get();
            if (except_to_throw) {
               cloner->handle_exception();
               std::rethrow_exception(except_to_throw);
            }
         }
         // create a separate thread to write block data to RocksDB via cloner
         cloner_process_fut = eosio::chain::async_thread_pool(
                                 cloner_process_pool.get_executor(),
                                 [&cloner = cloner,
                                  result = std::move(result),
                                  deltas = std::move(deltas),
                                  enable_wasm_ql = fresh_rocksdb]()
                                  mutable -> std::exception_ptr {
            std::exception_ptr except_to_throw;
            try {
               auto packed = fc::raw::pack(state_history::state_result{std::move(result)});
               cloner->process(packed, std::move(deltas));
               if (enable_wasm_ql) {
                  // now start the wasm_ql http server
                  auto* wasm_ql_plug = app().find_plugin<wasm_ql_plugin>();
                  if (wasm_ql_plug) {
                     ilog("Starting wasm_ql plugin http server now after the loading of the full state");
                     wasm_ql_plug->start_http();
                  }
               }
            } catch(...) {
               except_to_throw = std::current_exception();
            }
            return except_to_throw; });
         if (fresh_rocksdb) {
            fresh_rocksdb = false;
         }
         return;
      }
      FC_LOG_AND_DROP()

      // Both app().quit() and exception throwing are required. Without app().quit(),
      // the exception would be caught and drop before reaching main(). The exception is
      // to ensure the block won't be committed.
      appbase::app().quit();
      EOS_THROW(
            // state_history_write_exception is a controller_emit_signal_exception which leaks out of emit
            chain::state_history_write_exception,
            "Rodeos plugin encountered an error which it cannot recover from. Please resolve the error and relaunch "
            "the process");
   }

   void on_accepted_block(const chain::block_state_ptr& block_state) {
      // currently filter contracts expect data in eosio::ship_protocol::result format
      auto accept_span = fc_create_span_with_id("Rodeos-Accepted", chain::name("rodeos").to_uint64_t(), block_state->id);

      fc_add_tag(accept_span, "block_id", block_state->id);
      fc_add_tag(accept_span, "block_num", block_state->block_num);
      fc_add_tag(accept_span, "block_time", block_state->block->timestamp.to_time_point());

      this->store(block_state, accept_span);
   }

   void on_block_start(uint32_t block_num) {
      trace_caches[block_num].clear();
   }

};

void rodeos_plugin_impl::startup() {
   cloner = app().find_plugin<cloner_plugin>();
   EOS_ASSERT(cloner, eosio::chain::missing_cloner_plugin_exception, "");
   fresh_rocksdb = cloner->get_snapshot_head() == 0;
}

void rodeos_plugin_impl::shutdown() {
}

rodeos_plugin::rodeos_plugin() : my(new rodeos_plugin_impl()) {
}

rodeos_plugin::~rodeos_plugin() = default;

void rodeos_plugin::set_program_options(appbase::options_description& cli, appbase::options_description& cfg) {
}

void rodeos_plugin::plugin_initialize(const appbase::variables_map &options) {
   try {

      if (options.at("trace-history-debug-mode").as<bool>())
         my->trace_debug_mode = true;

      my->chain_plug = app().find_plugin<eosio::chain_plugin>();
      EOS_ASSERT(my->chain_plug, eosio::chain::missing_chain_plugin_exception, "");
      auto& chain = my->chain_plug->chain();

      my->applied_transaction_connection.emplace(
            chain.applied_transaction.connect([&](std::tuple<const chain::transaction_trace_ptr&,
                                                  const chain::packed_transaction_ptr&> t) {
               my->on_applied_transaction(std::get<0>(t), std::get<1>(t));
            }));
      my->accepted_block_connection.emplace(
            chain.accepted_block.connect([&](const chain::block_state_ptr& p) {
               my->on_accepted_block(p);
            }));
      my->block_start_connection.emplace(
            chain.block_start.connect([&](uint32_t block_num) {
               my->on_block_start(block_num);
            }));

   } FC_LOG_AND_RETHROW()
}

void rodeos_plugin::plugin_startup() {
   ilog("startup..");
   my->startup();
}

void rodeos_plugin::plugin_shutdown() {
   ilog("shutdown..");
   my->shutdown();
}

} // namespace b1

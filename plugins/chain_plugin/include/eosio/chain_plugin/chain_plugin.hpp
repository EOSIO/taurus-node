#pragma once
#include <appbase/application.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain/types.hpp>
#include <b1/session/shared_bytes.hpp>

#include <eosio/chain_plugin/read_write.hpp>

namespace fc { class variant; }
namespace eosio {
   class chain_plugin : public appbase::plugin<chain_plugin> {
   public:
      APPBASE_PLUGIN_REQUIRES()

      chain_plugin();
      virtual ~chain_plugin();

      virtual void set_program_options(appbase::options_description& cli, appbase::options_description& cfg) override;

      void plugin_initialize(const appbase::variables_map& options);
      void plugin_startup();
      void plugin_shutdown();
      void handle_sighup() override;

      chain_apis::read_write get_read_write_api() { return chain_apis::read_write(chain(), get_abi_serializer_max_time(), api_accept_transactions()); }
      chain_apis::read_only get_read_only_api() const;
      chain_apis::table_query get_table_query_api() const;

      void create_snapshot_background();

      bool accept_block( const chain::signed_block_ptr& block, const chain::block_id_type& id );
      void accept_transaction(const chain::packed_transaction_ptr& trx, chain::plugin_interface::next_function<chain::transaction_trace_ptr> next);

      // Only call this after plugin_initialize()!
      chain::controller& chain();
      // Only call this after plugin_initialize()!
      const chain::controller& chain() const;

      chain::chain_id_type get_chain_id() const;
      fc::microseconds get_abi_serializer_max_time() const;
      bool api_accept_transactions() const;
      // set true by other plugins if any plugin allows transactions
      bool accept_transactions() const;
      void enable_accept_transactions();

      static void handle_guard_exception(const chain::guard_exception& e);
      void do_hard_replay(const appbase::variables_map& options);
      
      bool account_queries_enabled() const;
      bool background_snapshots_disabled() const;

   private:
      static void log_guard_exception(const chain::guard_exception& e);

      std::unique_ptr<class chain_plugin_impl> my;
   };
}


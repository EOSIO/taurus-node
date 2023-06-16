#pragma once
#include <eosio/rodeos_plugin/rocksdb_plugin.hpp>

namespace eosio::state_history {
struct table_delta;
}

namespace b1 {

class cloner_plugin : public appbase::plugin<cloner_plugin> {
 public:
   APPBASE_PLUGIN_REQUIRES((rocksdb_plugin))

   cloner_plugin();
   virtual ~cloner_plugin();

   virtual void set_program_options(appbase::options_description& cli, appbase::options_description& cfg) override;
   void         plugin_initialize(const appbase::variables_map& options);
   void         plugin_startup();
   void         plugin_shutdown();
   void         handle_sighup() override;

   void set_streamer(std::shared_ptr<struct streamer_t> streamer);
   void validate_filter_ids(std::set<int>&& filter_ids);

   uint32_t get_snapshot_head() const;

   void process(const std::vector<char>& packed_ship_state_result, std::vector<eosio::state_history::table_delta>&& deltas);
   void handle_exception();

 private:
   std::shared_ptr<struct cloner_plugin_impl> my;
};

} // namespace b1

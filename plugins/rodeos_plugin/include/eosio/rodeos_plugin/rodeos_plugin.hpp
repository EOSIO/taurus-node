#pragma once

#include <eosio/chain_plugin/chain_plugin.hpp>
#include <eosio/rodeos_plugin/cloner_plugin.hpp>
#include <eosio/rodeos_plugin/rocksdb_plugin.hpp>
#include <eosio/rodeos_plugin/streamer_plugin.hpp>
#include <eosio/rodeos_plugin/wasm_ql_plugin.hpp>
#include <appbase/application.hpp>


namespace b1 {

/**
 *  rodeos implementation as a plugin to nodeos.
 */
class rodeos_plugin : public appbase::plugin<rodeos_plugin> {
public:
   rodeos_plugin();

   virtual ~rodeos_plugin();

   APPBASE_PLUGIN_REQUIRES((eosio::chain_plugin)(cloner_plugin)(rocksdb_plugin)(streamer_plugin)(wasm_ql_plugin))

   virtual void set_program_options(appbase::options_description& cli, appbase::options_description& cfg) override;

   void plugin_initialize(const appbase::variables_map &options);

   void plugin_startup();

   void plugin_shutdown();

private:
   std::unique_ptr<class rodeos_plugin_impl> my;
};

} // b1 namespace

// copyright defined in LICENSE.txt

#pragma once
#include <eosio/chain_plugin/chain_plugin.hpp>
#include <appbase/application.hpp>

#define TAURUS_STREAM_RABBITS_ENV_VAR "TAURUS_STREAM_RABBITS"
#define TAURUS_STREAM_RABBITS_EXCHANGE_ENV_VAR "TAURUS_STREAM_RABBITS_EXCHANGE"

namespace eosio {

class event_streamer_plugin : public appbase::plugin<event_streamer_plugin> {

 public:
   APPBASE_PLUGIN_REQUIRES((chain_plugin))

   event_streamer_plugin();
   virtual ~event_streamer_plugin();

   virtual void set_program_options(appbase::options_description& cli, appbase::options_description& cfg) override;
   void         plugin_initialize(const appbase::variables_map& options);
   void         plugin_startup();
   void         plugin_shutdown();

 private:
   std::shared_ptr<struct event_streamer_plugin_impl> my;
};

} // namespace eosio

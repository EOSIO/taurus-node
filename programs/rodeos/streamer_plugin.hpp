// copyright defined in LICENSE.txt

#pragma once
#include <appbase/application.hpp>
#include <eosio/abi.hpp>

#include "cloner_plugin.hpp"

#define EOSIO_STREAM_RABBITS_ENV_VAR "EOSIO_STREAM_RABBITS"
#define EOSIO_STREAM_RABBITS_EXCHANGE_ENV_VAR "EOSIO_STREAM_RABBITS_EXCHANGE"

namespace b1 {

struct stream_wrapper_v0 {
   eosio::name       route;
   std::vector<char> data;
};
EOSIO_REFLECT(stream_wrapper_v0, route, data);
struct stream_wrapper_v1 {
   std::string       route;
   std::vector<char> data;
};
EOSIO_REFLECT(stream_wrapper_v1, route, data);
using stream_wrapper = std::variant<stream_wrapper_v0, stream_wrapper_v1>;

class streamer_plugin : public appbase::plugin<streamer_plugin> {

 public:
   APPBASE_PLUGIN_REQUIRES((cloner_plugin))

   streamer_plugin();
   virtual ~streamer_plugin();

   virtual void set_program_options(appbase::options_description& cli, appbase::options_description& cfg) override;
   void         plugin_initialize(const appbase::variables_map& options);
   void         plugin_startup();
   void         plugin_shutdown();

 private:
   std::shared_ptr<struct streamer_plugin_impl> my;
};

} // namespace b1

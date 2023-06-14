#pragma once

#include <eosio/amqp_trx_plugin/amqp_trx_plugin.hpp>
#include <eosio/http_plugin/http_plugin.hpp>

#include <appbase/application.hpp>

namespace eosio {

using namespace appbase;

class amqp_trx_api_plugin : public plugin<amqp_trx_api_plugin> {
   public:
      APPBASE_PLUGIN_REQUIRES((amqp_trx_plugin) (http_plugin))

      amqp_trx_api_plugin() = default;
      amqp_trx_api_plugin(const amqp_trx_api_plugin&) = delete;
      amqp_trx_api_plugin(amqp_trx_api_plugin&&) = delete;
      amqp_trx_api_plugin& operator=(const amqp_trx_api_plugin&) = delete;
      amqp_trx_api_plugin& operator=(amqp_trx_api_plugin&&) = delete;
      virtual ~amqp_trx_api_plugin() override = default;

      virtual void set_program_options(options_description& cli, options_description& cfg) override {}
      void plugin_initialize(const variables_map& vm);
      void plugin_startup();
      void plugin_shutdown() {}

   private:
};

}

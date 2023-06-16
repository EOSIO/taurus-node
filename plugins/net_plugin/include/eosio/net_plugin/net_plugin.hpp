#pragma once

#include <eosio/net_plugin/protocol.hpp>
#include <eosio/net_plugin/connection.hpp>

#include <appbase/application.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>

namespace eosio {
   using namespace appbase;

   class net_plugin : public appbase::plugin<net_plugin>
   {
      public:
        net_plugin();
        virtual ~net_plugin();

        APPBASE_PLUGIN_REQUIRES((chain_plugin))
        virtual void set_program_options(options_description& cli, options_description& cfg) override;
        void handle_sighup() override;

        void plugin_initialize(const variables_map& options);
        void plugin_startup();
        void plugin_shutdown();

        std::string                            connect( const std::string& endpoint );
        std::string                            disconnect( const std::string& endpoint );
        std::optional<p2p::connection_status>  status( const std::string& endpoint )const;
        vector<p2p::connection_status>         connections()const;

      private:
        std::shared_ptr<class p2p::net_plugin_impl> my;
   };
}

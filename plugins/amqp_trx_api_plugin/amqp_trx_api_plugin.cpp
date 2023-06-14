#include <eosio/amqp_trx_api_plugin/amqp_trx_api_plugin.hpp>
#include <eosio/chain/exceptions.hpp>

#include <fc/variant.hpp>
#include <fc/io/json.hpp>

#include <chrono>

namespace eosio { namespace detail {
  struct amqp_trx_api_plugin_response {
     std::string result;
  };
}}

FC_REFLECT(eosio::detail::amqp_trx_api_plugin_response, (result));

namespace eosio {

static appbase::abstract_plugin& _amqp_trx_api_plugin = app().register_plugin<amqp_trx_api_plugin>();

using namespace eosio;

struct async_result_visitor : public fc::visitor<fc::variant> {
   template<typename T>
   fc::variant operator()(const T& v) const {
      return fc::variant(v);
   }
};

#define CALL_WITH_400(api_name, api_handle, call_name, INVOKE, http_response_code) \
{std::string("/v1/" #api_name "/" #call_name), \
   [&api_handle](string, string body, url_response_callback cb) mutable { \
          try { \
             INVOKE \
             cb(http_response_code, fc::variant(result)); \
          } catch (...) { \
             http_plugin::handle_exception(#api_name, #call_name, body, cb); \
          } \
       }}


#define INVOKE_V_V(api_handle, call_name) \
     body = parse_params<std::string, http_params_types::no_params_required>(body); \
     api_handle.call_name(); \
     eosio::detail::amqp_trx_api_plugin_response result{"ok"};


void amqp_trx_api_plugin::plugin_startup() {
     ilog("starting amqp_trx_api_plugin");
     // lifetime of plugin is lifetime of application
     auto& amqp_trx = app().get_plugin<amqp_trx_plugin>();

     app().get_plugin<http_plugin>().add_api({
          CALL_WITH_400(amqp_trx, amqp_trx, start,
               INVOKE_V_V(amqp_trx, start), 201),
          CALL_WITH_400(amqp_trx, amqp_trx, stop,
               INVOKE_V_V(amqp_trx, stop), 201)
     }, appbase::priority::medium_high);
}

void amqp_trx_api_plugin::plugin_initialize(const variables_map& options) {
   try {
      const auto& _http_plugin = app().get_plugin<http_plugin>();
      if( !_http_plugin.is_on_loopback()) {
         wlog( "\n"
               "**********SECURITY WARNING**********\n"
               "*                                  *\n"
               "* --        AMQP TRX API        -- *\n"
               "* - EXPOSED to the LOCAL NETWORK - *\n"
               "* - USE ONLY ON SECURE NETWORKS! - *\n"
               "*                                  *\n"
               "************************************\n" );

      }
   } FC_LOG_AND_RETHROW()
}


#undef INVOKE_V_V
#undef CALL_WITH_400

}

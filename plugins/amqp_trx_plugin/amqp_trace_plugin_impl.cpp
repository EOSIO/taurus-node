#include <eosio/amqp_trx_plugin/amqp_trace_types.hpp>
#include <eosio/amqp_trx_plugin/amqp_trace_plugin_impl.hpp>
#include <eosio/state_history/type_convert.hpp>
#include <eosio/for_each_field.hpp>
#include <eosio/to_bin.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/transaction.hpp>
#include <appbase/application.hpp>

namespace eosio {
namespace amqp_trace_plugin_impl {

void publish_error( eosio::amqp_handler& amqp, std::string routing_key, std::string correlation_id, int64_t error_code, std::string error_message ) {
   using namespace eosio;
   try {
      transaction_trace_msg msg{transaction_trace_exception{error_code}};
      std::get<transaction_trace_exception>( msg ).error_message = std::move( error_message );

      std::vector<char> buf = convert_to_bin( msg );

      amqp.publish( {}, routing_key, correlation_id, {}, std::move(buf) );
   } FC_LOG_AND_DROP()
}

// called from application thread
void publish_result( eosio::amqp_handler& amqp,
                     std::string routing_key,
                     std::string correlation_id,
                     std::string block_uuid,
                     const eosio::chain::packed_transaction_ptr& trx,
                     const eosio::chain::transaction_trace_ptr& trace ) {
   using namespace eosio;
   try {

      amqp.publish( {}, routing_key, correlation_id, {},
                    [trace, rk=std::move(routing_key), cid=std::move(correlation_id), uuid=std::move(block_uuid)]() {
                       if( !trace->except ) {
                          dlog( "chain accepted transaction, bcast {id}", ("id", trace->id) );
                       } else {
                          dlog( "trace except : {m}", ("m", trace->except->to_string()) );
                       }
                       transaction_trace_msg msg{ transaction_trace_message{ std::move(uuid), eosio::state_history::convert( *trace ) } };
                       std::vector<char> buf = convert_to_bin( msg );
                       return buf;
                    }
      );
   } FC_LOG_AND_DROP()
}

void publish_block_uuid( eosio::amqp_handler& amqp,
                         std::string routing_key,
                         std::string block_uuid,
                         const eosio::chain::block_id_type& block_id ) {
   using namespace eosio;
   try {
      transaction_trace_msg msg{ block_uuid_message{ std::move(block_uuid), eosio::state_history::convert( block_id ) } };
      std::vector<char> buf = convert_to_bin( msg );

      amqp.publish( {}, routing_key, {}, "", std::move(buf) );
   } FC_LOG_AND_DROP()
}

} // namespace amqp_trace_plugin_impl
} // namespace eosio

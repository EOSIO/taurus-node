#pragma once
#include <eosio/chain/trace.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/amqp/amqp_handler.hpp>

namespace eosio {

namespace amqp_trace_plugin_impl {
   // called from any thread
   void publish_error( amqp_handler& amqp, std::string routing_key, std::string correlation_id, int64_t error_code, std::string error_message );

   // called from any thread
   void publish_result( amqp_handler& amqp, std::string routing_key, std::string correlation_id, std::string block_uuid,
                        const chain::packed_transaction_ptr& trx, const chain::transaction_trace_ptr& trace );

   // called from any thread
   void publish_block_uuid( amqp_handler& amqp, std::string routing_key, std::string block_uuid, const chain::block_id_type& block_id );
};

} // namespace eosio

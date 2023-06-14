#pragma once
#include <eosio/chain_plugin/read_only.hpp>

namespace eosio {
namespace chain_apis
{
    class read_write
    {
        chain::controller &db;
        const fc::microseconds abi_serializer_max_time;
        const bool api_accept_transactions;

    public:
        read_write(chain::controller &db, const fc::microseconds &abi_serializer_max_time, bool api_accept_transactions);
        
        struct push_transaction_results
        {
            chain::transaction_id_type transaction_id;
            fc::variant processed;
        };
        using push_block_params_v1 = chain::signed_block_v0;
        using push_block_results = chain_apis::empty;
        using push_transaction_params_v1 = fc::variant_object;
        using push_transactions_params_v1 = vector<push_transaction_params_v1>;
        using push_transactions_results = vector<push_transaction_results>;
        using send_transaction_params_v1 = push_transaction_params_v1;
        using send_transaction_results = push_transaction_results;
        struct send_transaction_params_v2
        {
            bool return_failure_traces = true;
            fc::variant transaction;
        };

        void validate() const;
        void push_block(push_block_params_v1 &&params, chain::plugin_interface::next_function<push_block_results> next);

        void push_transaction(const push_transaction_params_v1 &params, chain::plugin_interface::next_function<push_transaction_results> next);
        void push_transactions(const push_transactions_params_v1 &params, chain::plugin_interface::next_function<push_transactions_results> next);
        void send_transaction(const send_transaction_params_v1 &params, chain::plugin_interface::next_function<send_transaction_results> next);
        void send_transaction(const send_transaction_params_v2 &params, chain::plugin_interface::next_function<send_transaction_results> next);
        void send_transaction(chain::packed_transaction_ptr input_trx, const std::string method, bool return_failure_traces,
                                chain::plugin_interface::next_function<send_transaction_results> next);
    };
}} // namespace eosio::chain_apis
FC_REFLECT( eosio::chain_apis::read_write::send_transaction_params_v2, (return_failure_traces)(transaction) )
FC_REFLECT( eosio::chain_apis::read_write::push_transaction_results, (transaction_id)(processed) )


#pragma once
#include <eosio/chain/block.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/chain/plugin_interface.hpp>
#include <eosio/chain/backing_store/kv_context.hpp>
#include <eosio/chain/config.hpp>
#include <eosio/chain/authority.hpp>
#include <eosio/chain/block_state.hpp>
#include <eosio/chain/genesis_state.hpp>
#include <eosio/chain_plugin/table_query.hpp>
#include <eosio/chain_plugin/account_query_db.hpp>
#include <boost/container/flat_set.hpp>

namespace eosio {
namespace chain_apis {
    struct empty{};
    struct linked_action {
        chain::name                account;
        std::optional<chain::name> action;
    };

    struct permission {
        chain::name                                perm_name;
        chain::name                                parent;
        chain::authority                           required_auth;
        std::optional<std::vector<linked_action>>  linked_actions;
    };
    class read_only {
        const chain::controller &db;
        const std::optional<account_query_db> &aqdb;
        const fc::microseconds abi_serializer_max_time;
        bool shorten_abi_errors = true;
        table_query _table_query;
        std::optional<chain::genesis_state> genesis;

    public:
        read_only(const chain::controller& db, const std::optional<account_query_db>& aqdb, const fc::microseconds& abi_serializer_max_time, std::optional<chain::genesis_state> genesis);
        
        void validate() const {}

        void set_shorten_abi_errors( bool f ) { shorten_abi_errors = f; }
        using get_info_params = chain_apis::empty;

        struct get_info_results {
            string                               server_version;
            chain::chain_id_type                 chain_id;
            uint32_t                             head_block_num = 0;
            uint32_t                             last_irreversible_block_num = 0;
            chain::block_id_type                 last_irreversible_block_id;
            chain::block_id_type                 head_block_id;
            fc::time_point                       head_block_time;
            chain::account_name                  head_block_producer;

            uint64_t                             virtual_block_cpu_limit = 0;
            uint64_t                             virtual_block_net_limit = 0;

            uint64_t                             block_cpu_limit = 0;
            uint64_t                             block_net_limit = 0;
            std::optional<string>                server_version_string;
            std::optional<uint32_t>              fork_db_head_block_num;
            std::optional<chain::block_id_type>  fork_db_head_block_id;
            std::optional<string>                server_full_version_string;
            std::optional<fc::time_point>        last_irreversible_block_time;
            std::optional<uint64_t>              total_cpu_weight;
            std::optional<uint64_t>              total_net_weight;
            std::optional<uint32_t>              first_block_num;
        };

        struct get_activated_protocol_features_params {
            std::optional<uint32_t>  lower_bound;
            std::optional<uint32_t>  upper_bound;
            uint32_t                 limit = 10;
            bool                     search_by_block_num = false;
            bool                     reverse = false;
        };

        struct get_activated_protocol_features_results {
            fc::variants             activated_protocol_features;
            std::optional<uint32_t>  more;
        };

        struct producer_info {
            chain::name              producer_name;
        };

        // account_resource_info holds similar data members as in account_resource_limit, but decoupling making them independently to be refactored in future
        struct account_resource_info {
            int64_t used = 0;
            int64_t available = 0;
            int64_t max = 0;
            std::optional<chain::block_timestamp_type> last_usage_update_time;    // optional for backward nodeos support
            std::optional<int64_t> current_used;  // optional for backward nodeos support
            void set( const chain::resource_limits::account_resource_limit& arl)
            {
                used = arl.used;
                available = arl.available;
                max = arl.max;
                last_usage_update_time = arl.last_usage_update_time;
                current_used = arl.current_used;
            }
        };

        struct get_account_results {
            chain::name                account_name;
            uint32_t                   head_block_num = 0;
            fc::time_point             head_block_time;

            bool                       privileged = false;
            fc::time_point             last_code_update;
            fc::time_point             created;

            std::optional<chain::asset>       core_liquid_balance;

            int64_t                    ram_quota  = 0;
            int64_t                    net_weight = 0;
            int64_t                    cpu_weight = 0;

            account_resource_info      net_limit;
            account_resource_info      cpu_limit;
            int64_t                    ram_usage = 0;

            vector<chain_apis::permission>         permissions;

            fc::variant                total_resources;
            fc::variant                self_delegated_bandwidth;
            fc::variant                refund_request;
            fc::variant                voter_info;
            fc::variant                rex_info;

            // linked actions for eosio_any
            std::vector<chain_apis::linked_action> eosio_any_linked_actions;
        };

        struct get_account_params {
            chain::name                  account_name;
            std::optional<chain::symbol> expected_core_symbol;
        };

        struct get_code_results {
            chain::name            account_name;
            string                 wast;
            string                 wasm;
            fc::sha256             code_hash;
            std::optional<chain::abi_def> abi;
        };

        struct get_code_params {
            chain::name account_name;
            bool code_as_wasm = true;
        };

        struct get_code_hash_results {
            chain::name            account_name;
            fc::sha256             code_hash;
        };

        struct get_code_hash_params {
            chain::name account_name;
        };

        struct get_abi_results {
            chain::name                   account_name;
            std::optional<chain::abi_def> abi;
        };

        struct get_abi_params {
            chain::name account_name;
        };

        struct get_raw_code_and_abi_results {
            chain::name            account_name;
            chain::blob            wasm;
            chain::blob            abi;
        };

        struct get_raw_code_and_abi_params {
            chain::name            account_name;
        };

        struct get_raw_abi_params {
            chain::name               account_name;
            std::optional<fc::sha256> abi_hash;
        };

        struct get_raw_abi_results {
            chain::name                account_name;
            fc::sha256                 code_hash;
            fc::sha256                 abi_hash;
            std::optional<chain::blob> abi;
        };

        struct abi_json_to_bin_params {
            chain::name  code;
            chain::name  action;
            fc::variant  args;
        };
        struct abi_json_to_bin_result {
            vector<char>   binargs;
        };

        struct abi_bin_to_json_params {
            chain::name  code;
            chain::name  action;
            vector<char> binargs;
        };
        struct abi_bin_to_json_result {
            fc::variant    args;
        };

        struct get_required_keys_params {
            fc::variant transaction;
            boost::container::flat_set<chain::public_key_type> available_keys;
        };
        struct get_required_keys_result {
            boost::container::flat_set<chain::public_key_type> required_keys;
        };

        using get_transaction_id_params = chain::transaction;
        using get_transaction_id_result = chain::transaction_id_type;

        struct get_block_params {
            string block_num_or_id;
        };

        struct get_block_info_params {
            uint32_t block_num;
        };

        struct get_block_header_state_params {
            string block_num_or_id;
        };

        struct get_currency_balance_params {
            chain::name           code;
            chain::name           account;
            std::optional<string> symbol;
        };

        struct get_currency_stats_params {
            chain::name    code;
            string         symbol;
        };


        struct get_currency_stats_result {
            chain::asset          supply;
            chain::asset          max_supply;
            chain::account_name   issuer;
        };

        struct get_producers_params {
            bool        json = false;
            string      lower_bound;
            uint32_t    limit = 50;
        };

        struct get_producers_result {
            vector<fc::variant> rows; ///< one row per item, either encoded as hex string or JSON object
            double              total_producer_vote_weight;
            string              more; ///< fill lower_bound with this value to fetch more rows
        };

        struct get_producer_schedule_params {};

        struct get_producer_schedule_result {
            fc::variant active;
            fc::variant pending;
            fc::variant proposed;
        };

        struct get_all_accounts_result {
            struct account_result {
                chain::name                          name;
                chain::block_timestamp_type          creation_date;
            };

            std::vector<account_result> accounts;

            std::optional<chain::name> more;
        };

        struct get_all_accounts_params {
            uint32_t                    limit = 10;
            std::optional<chain::name>  lower_bound;
            std::optional<chain::name>  upper_bound;
            bool                        reverse = false;
        };

        using get_consensus_parameters_params = chain_apis::empty;
        struct get_consensus_parameters_results {
            chain::chain_config        chain_config;
            chain::kv_database_config  kv_database_config;
            chain::wasm_config         wasm_config;
        };

        using get_genesis_params = chain_apis::empty;
        using get_genesis_result = chain::genesis_state;

        struct send_ro_transaction_params_v1 {
            bool return_failure_traces = true;
            fc::variant transaction;
        };

        struct send_ro_transaction_results {
            uint32_t                     head_block_num = 0;
            chain::block_id_type         head_block_id;
            uint32_t                     last_irreversible_block_num = 0;
            chain::block_id_type         last_irreversible_block_id;
            chain::digest_type           code_hash;
            vector<chain::transaction_id_type>  pending_transactions;
            fc::variant                  result;
        };

        get_info_results get_info(const get_info_params&) const;
        get_activated_protocol_features_results get_activated_protocol_features( const get_activated_protocol_features_params& params )const;
        get_account_results get_account(const get_account_params &params) const;
        get_code_results get_code(const get_code_params &params) const;
        get_code_hash_results get_code_hash(const get_code_hash_params &params) const;
        get_abi_results get_abi(const get_abi_params &params) const;
        get_raw_code_and_abi_results get_raw_code_and_abi(const get_raw_code_and_abi_params &params) const;
        get_raw_abi_results get_raw_abi(const get_raw_abi_params &params) const;   
        abi_json_to_bin_result abi_json_to_bin( const abi_json_to_bin_params& params )const;
        abi_bin_to_json_result abi_bin_to_json(const abi_bin_to_json_params &params) const;
        get_required_keys_result get_required_keys( const get_required_keys_params& params ) const;
        get_transaction_id_result get_transaction_id(const get_transaction_id_params &params) const;
        fc::variant get_block(const get_block_params &params) const;
        fc::variant get_block_info(const get_block_info_params& params) const;
        fc::variant get_block_header_state(const get_block_header_state_params& params) const;

        vector<chain::asset> get_currency_balance(const get_currency_balance_params &p) const;
        fc::variant get_currency_stats(const get_currency_stats_params &p) const;
        get_producers_result get_producers(const get_producers_params &p) const;
        get_producer_schedule_result get_producer_schedule( const get_producer_schedule_params& p ) const;

        void send_ro_transaction(const send_ro_transaction_params_v1& params, chain::plugin_interface::next_function<send_ro_transaction_results> next) const;

        using get_accounts_by_authorizers_result = account_query_db::get_accounts_by_authorizers_result;
        using get_accounts_by_authorizers_params = account_query_db::get_accounts_by_authorizers_params;
        account_query_db::get_accounts_by_authorizers_result get_accounts_by_authorizers( const account_query_db::get_accounts_by_authorizers_params& args) const;

        chain::symbol extract_core_symbol()const;
        get_all_accounts_result get_all_accounts(const get_all_accounts_params &params) const;
        get_consensus_parameters_results get_consensus_parameters(const get_consensus_parameters_params &) const;

        get_genesis_result get_genesis(const get_genesis_params &params) const;
    }; // read_only
}} // eosio::chain_apis

FC_REFLECT( eosio::chain_apis::linked_action, (account)(action) )
FC_REFLECT( eosio::chain_apis::permission, (perm_name)(parent)(required_auth)(linked_actions) )
FC_REFLECT(eosio::chain_apis::empty, )
FC_REFLECT(eosio::chain_apis::read_only::get_info_results,
           (server_version)(chain_id)(head_block_num)(last_irreversible_block_num)(last_irreversible_block_id)
           (head_block_id)(head_block_time)(head_block_producer)
           (virtual_block_cpu_limit)(virtual_block_net_limit)(block_cpu_limit)(block_net_limit)
           (server_version_string)(fork_db_head_block_num)(fork_db_head_block_id)(server_full_version_string)
           (last_irreversible_block_time)(total_cpu_weight)(total_net_weight)(first_block_num))
FC_REFLECT(eosio::chain_apis::read_only::get_activated_protocol_features_params, (lower_bound)(upper_bound)(limit)(search_by_block_num)(reverse) )
FC_REFLECT(eosio::chain_apis::read_only::get_activated_protocol_features_results, (activated_protocol_features)(more) )
FC_REFLECT(eosio::chain_apis::read_only::get_block_params, (block_num_or_id))
FC_REFLECT(eosio::chain_apis::read_only::get_block_info_params, (block_num))
FC_REFLECT(eosio::chain_apis::read_only::get_block_header_state_params, (block_num_or_id))

FC_REFLECT( eosio::chain_apis::read_only::get_currency_balance_params, (code)(account)(symbol));
FC_REFLECT( eosio::chain_apis::read_only::get_currency_stats_params, (code)(symbol));
FC_REFLECT( eosio::chain_apis::read_only::get_currency_stats_result, (supply)(max_supply)(issuer));

FC_REFLECT( eosio::chain_apis::read_only::get_producers_params, (json)(lower_bound)(limit) )
FC_REFLECT( eosio::chain_apis::read_only::get_producers_result, (rows)(total_producer_vote_weight)(more) );

FC_REFLECT_EMPTY( eosio::chain_apis::read_only::get_producer_schedule_params )
FC_REFLECT( eosio::chain_apis::read_only::get_producer_schedule_result, (active)(pending)(proposed) );

FC_REFLECT( eosio::chain_apis::read_only::account_resource_info, (used)(available)(max)(last_usage_update_time)(current_used) )
FC_REFLECT( eosio::chain_apis::read_only::get_account_results,
            (account_name)(head_block_num)(head_block_time)(privileged)(last_code_update)(created)
            (core_liquid_balance)(ram_quota)(net_weight)(cpu_weight)(net_limit)(cpu_limit)(ram_usage)(permissions)
            (total_resources)(self_delegated_bandwidth)(refund_request)(voter_info)(rex_info)(eosio_any_linked_actions) )
// @swap code_hash
FC_REFLECT( eosio::chain_apis::read_only::get_code_results, (account_name)(code_hash)(wast)(wasm)(abi) )
FC_REFLECT( eosio::chain_apis::read_only::get_code_hash_results, (account_name)(code_hash) )
FC_REFLECT( eosio::chain_apis::read_only::get_abi_results, (account_name)(abi) )
FC_REFLECT( eosio::chain_apis::read_only::get_account_params, (account_name)(expected_core_symbol) )
FC_REFLECT( eosio::chain_apis::read_only::get_code_params, (account_name)(code_as_wasm) )
FC_REFLECT( eosio::chain_apis::read_only::get_code_hash_params, (account_name) )
FC_REFLECT( eosio::chain_apis::read_only::get_abi_params, (account_name) )
FC_REFLECT( eosio::chain_apis::read_only::get_raw_code_and_abi_params, (account_name) )
FC_REFLECT( eosio::chain_apis::read_only::get_raw_code_and_abi_results, (account_name)(wasm)(abi) )
FC_REFLECT( eosio::chain_apis::read_only::get_raw_abi_params, (account_name)(abi_hash) )
FC_REFLECT( eosio::chain_apis::read_only::get_raw_abi_results, (account_name)(code_hash)(abi_hash)(abi) )
FC_REFLECT( eosio::chain_apis::read_only::producer_info, (producer_name) )
FC_REFLECT( eosio::chain_apis::read_only::abi_json_to_bin_params, (code)(action)(args) )
FC_REFLECT( eosio::chain_apis::read_only::abi_json_to_bin_result, (binargs) )
FC_REFLECT( eosio::chain_apis::read_only::abi_bin_to_json_params, (code)(action)(binargs) )
FC_REFLECT( eosio::chain_apis::read_only::abi_bin_to_json_result, (args) )
FC_REFLECT( eosio::chain_apis::read_only::get_required_keys_params, (transaction)(available_keys) )
FC_REFLECT( eosio::chain_apis::read_only::get_required_keys_result, (required_keys) )
FC_REFLECT( eosio::chain_apis::read_only::get_all_accounts_params, (limit)(lower_bound)(upper_bound)(reverse) )
FC_REFLECT( eosio::chain_apis::read_only::get_all_accounts_result::account_result, (name)(creation_date))
FC_REFLECT( eosio::chain_apis::read_only::get_all_accounts_result, (accounts)(more))
FC_REFLECT( eosio::chain_apis::read_only::get_consensus_parameters_results, (chain_config)(kv_database_config)(wasm_config))
FC_REFLECT( eosio::chain_apis::read_only::send_ro_transaction_params_v1, (return_failure_traces)(transaction) )
FC_REFLECT( eosio::chain_apis::read_only::send_ro_transaction_results, (head_block_num)(head_block_id)(last_irreversible_block_num)(last_irreversible_block_id)(code_hash)(pending_transactions)(result) )

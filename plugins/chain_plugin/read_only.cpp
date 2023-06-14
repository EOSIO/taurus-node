#include <appbase/application.hpp>
#include <eosio/chain/authorization_manager.hpp>
#include <eosio/chain/block_header_state.hpp>
#include <eosio/chain/code_object.hpp>
#include <eosio/chain/name.hpp>
#include <eosio/chain/permission_link_object.hpp>
#include <eosio/chain/permission_object.hpp>
#include <eosio/chain/producer_schedule.hpp>
#include <eosio/chain_plugin/read_only.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/to_string.hpp>
#include <eosio/chain/block_log.hpp>
#include <fc/log/trace.hpp>

using namespace appbase;
using namespace eosio::chain;
namespace eosio {
namespace chain_apis {
    read_only::read_only(const controller& db, const std::optional<account_query_db>& aqdb, const fc::microseconds& abi_serializer_max_time, std::optional<chain::genesis_state> genesis)
            : db(db), aqdb(aqdb), abi_serializer_max_time(abi_serializer_max_time), _table_query(db, abi_serializer_max_time), genesis(genesis) {}

    template<typename I>
    std::string itoh(I n, size_t hlen = sizeof(I)<<1) {
        static const char* digits = "0123456789abcdef";
        std::string r(hlen, '0');
        for(size_t i = 0, j = (hlen - 1) * 4 ; i < hlen; ++i, j -= 4)
            r[i] = digits[(n>>j) & 0x0f];
        return r;
    }

    read_only::get_info_results read_only::get_info(const get_info_params&) const {

        const auto& rm = db.get_resource_limits_manager();
        read_only::get_info_results ret =
         {
            itoh(static_cast<uint32_t>(app().version())),
            db.get_chain_id(),
            db.head_block_num(),
            db.last_irreversible_block_num(),
            db.last_irreversible_block_id(),
            db.head_block_id(),
            db.head_block_time(),
            db.head_block_producer(),
            rm.get_virtual_block_cpu_limit(),
            rm.get_virtual_block_net_limit(),
            rm.get_block_cpu_limit(),
            rm.get_block_net_limit(),
            //std::bitset<64>(db.get_dynamic_global_properties().recent_slots_filled).to_string(),
            //__builtin_popcountll(db.get_dynamic_global_properties().recent_slots_filled) / 64.0,
            app().version_string(),
            db.fork_db_pending_head_block_num(),
            db.fork_db_pending_head_block_id(),
            app().full_version_string(),
            db.last_irreversible_block_time(),
            rm.get_total_cpu_weight(),
            rm.get_total_net_weight(),
            db.get_first_block_num()
        };

        return ret;
    }

    read_only::get_activated_protocol_features_results
    read_only::get_activated_protocol_features( const read_only::get_activated_protocol_features_params& params )const {
        read_only::get_activated_protocol_features_results result;
        const auto& pfm = db.get_protocol_feature_manager();

        uint32_t lower_bound_value = std::numeric_limits<uint32_t>::lowest();
        uint32_t upper_bound_value = std::numeric_limits<uint32_t>::max();

        if( params.lower_bound ) {
            lower_bound_value = *params.lower_bound;
        }

        if( params.upper_bound ) {
            upper_bound_value = *params.upper_bound;
        }

        if( upper_bound_value < lower_bound_value )
            return result;

        auto walk_range = [&]( auto itr, auto end_itr, auto&& convert_iterator ) {
            fc::mutable_variant_object mvo;
            mvo( "activation_ordinal", 0 );
            mvo( "activation_block_num", 0 );

            auto& activation_ordinal_value   = mvo["activation_ordinal"];
            auto& activation_block_num_value = mvo["activation_block_num"];

            auto cur_time = fc::time_point::now();
            auto end_time = cur_time + fc::microseconds(1000 * 10); /// 10ms max time
            for( unsigned int count = 0;
                cur_time <= end_time && count < params.limit && itr != end_itr;
                ++itr, cur_time = fc::time_point::now() )
            {
                const auto& conv_itr = convert_iterator( itr );
                activation_ordinal_value   = conv_itr.activation_ordinal();
                activation_block_num_value = conv_itr.activation_block_num();

                result.activated_protocol_features.emplace_back( conv_itr->to_variant( false, &mvo ) );
                ++count;
            }
            if( itr != end_itr ) {
                result.more = convert_iterator( itr ).activation_ordinal() ;
            }
        };

        auto get_next_if_not_end = [&pfm]( auto&& itr ) {
            return itr == pfm.end() ? itr : ++itr;
        };

        auto lower = ( params.search_by_block_num ? pfm.lower_bound( lower_bound_value )
                                                    : pfm.at_activation_ordinal( lower_bound_value ) );

        auto upper = ( params.search_by_block_num ? pfm.upper_bound( upper_bound_value )
                                                    : get_next_if_not_end( pfm.at_activation_ordinal( upper_bound_value ) ) );

        if( params.reverse ) {
            walk_range( std::make_reverse_iterator(upper), std::make_reverse_iterator(lower),
                        []( auto&& ritr ) { return --(ritr.base()); } );
        } else {
            walk_range( lower, upper, []( auto&& itr ) { return itr; } );
        }

        return result;
    }

    read_only::get_account_results read_only::get_account( const get_account_params& params )const {
        get_account_results result;
        result.account_name = params.account_name;

        const auto& d = db.db();
        const auto& rm = db.get_resource_limits_manager();

        result.head_block_num  = db.head_block_num();
        result.head_block_time = db.head_block_time();

        rm.get_account_limits( result.account_name, result.ram_quota, result.net_weight, result.cpu_weight );

        const auto& accnt_obj = db.get_account( result.account_name );
        const auto& accnt_metadata_obj = db.db().get<account_metadata_object,by_name>( result.account_name );

        result.privileged       = accnt_metadata_obj.is_privileged();
        result.last_code_update = accnt_metadata_obj.last_code_update;
        result.created          = accnt_obj.creation_date;

        uint32_t greylist_limit = db.is_resource_greylisted(result.account_name) ? 1 : config::maximum_elastic_resource_multiplier;
        const block_timestamp_type current_usage_time (db.head_block_time());
        result.net_limit.set( rm.get_account_net_limit_ex( result.account_name, greylist_limit, current_usage_time).first );
        if ( result.net_limit.last_usage_update_time && (result.net_limit.last_usage_update_time->slot == 0) ) {   // account has no action yet
            result.net_limit.last_usage_update_time = accnt_obj.creation_date;
        }
        result.cpu_limit.set( rm.get_account_cpu_limit_ex( result.account_name, greylist_limit, current_usage_time).first );
        if ( result.cpu_limit.last_usage_update_time && (result.cpu_limit.last_usage_update_time->slot == 0) ) {   // account has no action yet
            result.cpu_limit.last_usage_update_time = accnt_obj.creation_date;
        }
        result.ram_usage = rm.get_account_ram_usage( result.account_name );

        const auto linked_action_map = ([&](){
            const auto& links = d.get_index<permission_link_index,by_permission_name>();
            auto iter = links.lower_bound( boost::make_tuple( params.account_name ) );

            std::multimap<name, linked_action> result;
            while (iter != links.end() && iter->account == params.account_name ) {
                auto action = iter->message_type.empty() ? std::optional<name>() : std::optional<name>(iter->message_type);
                result.emplace(std::make_pair(iter->required_permission, linked_action{iter->code, std::move(action)}));
                ++iter;
            }

            return result;
        })();

        auto get_linked_actions = [&](name perm_name) {
            auto link_bounds = linked_action_map.equal_range(perm_name);
            auto linked_actions = std::vector<linked_action>();
            linked_actions.reserve(linked_action_map.count(perm_name));
            for (auto link = link_bounds.first; link != link_bounds.second; ++link) {
                linked_actions.push_back(link->second);
            }
            return linked_actions;
        };

        const auto& permissions = d.get_index<permission_index,by_owner>();
        auto perm = permissions.lower_bound( boost::make_tuple( params.account_name ) );
        while( perm != permissions.end() && perm->owner == params.account_name ) {
            /// TODO: lookup perm->parent name
            name parent;

            // Don't lookup parent if null
            if( perm->parent._id ) {
                const auto* p = d.find<permission_object,by_id>( perm->parent );
                if( p ) {
                    EOS_ASSERT(perm->owner == p->owner, invalid_parent_permission, "Invalid parent permission");
                    parent = p->name;
                }
            }

            auto linked_actions = get_linked_actions(perm->name);

            result.permissions.push_back( permission{ perm->name, parent, perm->auth.to_authority(), std::move(linked_actions)} );
            ++perm;
        }

        // add eosio.any linked authorizations
        result.eosio_any_linked_actions = get_linked_actions(config::eosio_any_name);

        const auto& code_account = db.db().get<account_object,by_name>( config::system_account_name );

        abi_def abi;
        if( abi_serializer::to_abi(code_account.abi, abi) ) {
            abi_serializer abis( abi, abi_serializer::create_yield_function( abi_serializer_max_time ) );

            const auto token_code = "eosio.token"_n;

            auto core_symbol = extract_core_symbol();

            if (params.expected_core_symbol)
                core_symbol = *(params.expected_core_symbol);

            _table_query.get_primary_key<asset>(token_code, params.account_name, "accounts"_n, core_symbol.to_symbol_code(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, [&core_symbol,&result](const asset& bal) {
                if( bal.get_symbol().valid() && bal.get_symbol() == core_symbol ) {
                    result.core_liquid_balance = bal;
                }
            });

            result.total_resources = _table_query.get_primary_key(config::system_account_name, params.account_name, "userres"_n, params.account_name.to_uint64_t(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, "user_resources", abis); 

            result.self_delegated_bandwidth = _table_query.get_primary_key(config::system_account_name, params.account_name, "delband"_n, params.account_name.to_uint64_t(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, "delegated_bandwidth", abis); 

            result.refund_request = _table_query.get_primary_key(config::system_account_name, params.account_name, "refunds"_n, params.account_name.to_uint64_t(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, "refund_request", abis); 

            result.voter_info = _table_query.get_primary_key(config::system_account_name, config::system_account_name, "voters"_n, params.account_name.to_uint64_t(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, "voter_info", abis); 

            result.rex_info = _table_query.get_primary_key(config::system_account_name, config::system_account_name, "rexbal"_n, params.account_name.to_uint64_t(),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, "rex_balance", abis); 
        }
        return result;
    }

    read_only::get_code_results read_only::get_code( const get_code_params& params )const {
        get_code_results result;
        result.account_name = params.account_name;
        const auto& d = db.db();
        const auto& accnt_obj          = d.get<account_object,by_name>( params.account_name );
        const auto& accnt_metadata_obj = d.get<account_metadata_object,by_name>( params.account_name );

        EOS_ASSERT( params.code_as_wasm, unsupported_feature, "Returning WAST from get_code is no longer supported" );

        if( accnt_metadata_obj.code_hash != digest_type() ) {
            const auto& code_obj = d.get<code_object, by_code_hash>(accnt_metadata_obj.code_hash);
            result.wasm = string(code_obj.code.begin(), code_obj.code.end());
            result.code_hash = code_obj.code_hash;
        } 

        abi_def abi;
        if( abi_serializer::to_abi(accnt_obj.abi, abi) ) {
            result.abi = std::move(abi);
        }

        return result;
    }

    read_only::get_code_hash_results read_only::get_code_hash( const get_code_hash_params& params )const {
        get_code_hash_results result;
        result.account_name = params.account_name;
        const auto& d = db.db();
        const auto& accnt  = d.get<account_metadata_object,by_name>( params.account_name );

        if( accnt.code_hash != digest_type() )
            result.code_hash = accnt.code_hash;

        return result;
    }

    read_only::get_abi_results read_only::get_abi( const get_abi_params& params )const {
        get_abi_results result;
        result.account_name = params.account_name;
        const auto& d = db.db();
        const auto& accnt  = d.get<account_object,by_name>( params.account_name );

        abi_def abi;
        if( abi_serializer::to_abi(accnt.abi, abi) ) {
            result.abi = std::move(abi);
        }

        return result;
    }

    read_only::get_raw_code_and_abi_results read_only::get_raw_code_and_abi( const get_raw_code_and_abi_params& params)const {
        get_raw_code_and_abi_results result;
        result.account_name = params.account_name;

        const auto& d = db.db();
        const auto& accnt_obj          = d.get<account_object,by_name>(params.account_name);
        const auto& accnt_metadata_obj = d.get<account_metadata_object,by_name>(params.account_name);
        if( accnt_metadata_obj.code_hash != digest_type() ) {
            const auto& code_obj = d.get<code_object, by_code_hash>(accnt_metadata_obj.code_hash);
            result.wasm = blob{{code_obj.code.begin(), code_obj.code.end()}};
        }
        result.abi = blob{{accnt_obj.abi.begin(), accnt_obj.abi.end()}};

        return result;
    }

    read_only::get_raw_abi_results read_only::get_raw_abi( const get_raw_abi_params& params )const {
        get_raw_abi_results result;
        result.account_name = params.account_name;

        const auto& d = db.db();
        const auto& accnt_obj          = d.get<account_object,by_name>(params.account_name);
        const auto& accnt_metadata_obj = d.get<account_metadata_object,by_name>(params.account_name);
        result.abi_hash = fc::sha256::hash( accnt_obj.abi.data(), accnt_obj.abi.size() );
        if( accnt_metadata_obj.code_hash != digest_type() )
            result.code_hash = accnt_metadata_obj.code_hash;
        if( !params.abi_hash || *params.abi_hash != result.abi_hash )
            result.abi = blob{{accnt_obj.abi.begin(), accnt_obj.abi.end()}};

        return result;
    }

    static fc::variant action_abi_to_variant( const abi_def& abi, type_name action_type ) {
        fc::variant v;
        auto it = std::find_if(abi.structs.begin(), abi.structs.end(), [&](auto& x){return x.name == action_type;});
        if( it != abi.structs.end() )
            to_variant( it->fields,  v );
        return v;
    }; 

    read_only::abi_json_to_bin_result read_only::abi_json_to_bin( const read_only::abi_json_to_bin_params& params )const try {
        abi_json_to_bin_result result;
        const auto code_account = db.db().find<account_object,by_name>( params.code );
        EOS_ASSERT(code_account != nullptr, contract_query_exception, "Contract can't be found {contract}", ("contract", params.code));

        abi_def abi;
        if( abi_serializer::to_abi(code_account->abi, abi) ) {
            abi_serializer abis( abi, abi_serializer::create_yield_function( abi_serializer_max_time ) );
            auto action_type = abis.get_action_type(params.action);
            EOS_ASSERT(!action_type.empty(), action_validate_exception, "Unknown action {action} in contract {contract}", ("action", params.action)("contract", params.code));
            try {
                result.binargs = abis.variant_to_binary( action_type, params.args, abi_serializer::create_yield_function( abi_serializer_max_time ), shorten_abi_errors );
            } EOS_RETHROW_EXCEPTIONS(invalid_action_args_exception,
                                        "'{args}' is invalid args for action '{action}' code '{code}'. expected '{proto}'",
                                        ("args", fc::json::to_string(params.args, fc::time_point::now() + fc::exception::format_time_limit))
                                        ("action", params.action)
                                        ("code", params.code)
                                        ("proto", fc::json::to_string(action_abi_to_variant(abi, action_type), fc::time_point::now() + fc::exception::format_time_limit)) ) // ?
        } else {
            EOS_ASSERT(false, abi_not_found_exception, "No ABI found for {contract}", ("contract", params.code));
        }
        return result;
    } FC_RETHROW_EXCEPTIONS( warn, "code: {code}, action: {action}, args: {args}",
                            ("code", params.code)( "action", params.action )( "args", fc::json::to_string(params.args, fc::time_point::now() + fc::exception::format_time_limit) ))

    read_only::abi_bin_to_json_result read_only::abi_bin_to_json( const read_only::abi_bin_to_json_params& params )const {
        abi_bin_to_json_result result;
        const auto& code_account = db.db().get<account_object,by_name>( params.code );
        abi_def abi;
        if( abi_serializer::to_abi(code_account.abi, abi) ) {
            abi_serializer abis( abi, abi_serializer::create_yield_function( abi_serializer_max_time ) );
            result.args = abis.binary_to_variant( abis.get_action_type( params.action ), params.binargs, abi_serializer::create_yield_function( abi_serializer_max_time ), shorten_abi_errors );
        } else {
            EOS_ASSERT(false, abi_not_found_exception, "No ABI found for {contract}", ("contract", params.code));
        }
        return result;
    }

    read_only::get_required_keys_result read_only::get_required_keys( const get_required_keys_params& params )const {
        transaction pretty_input;
        auto resolver = make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time ));
        try {
            abi_serializer::from_variant(params.transaction, pretty_input, resolver, abi_serializer::create_yield_function( abi_serializer_max_time ));
        } EOS_RETHROW_EXCEPTIONS(transaction_type_exception, "Invalid transaction")

        auto required_keys_set = db.get_authorization_manager().get_required_keys( pretty_input, params.available_keys );
        get_required_keys_result result;
        result.required_keys = required_keys_set;
        return result;
    }

    read_only::get_transaction_id_result read_only::get_transaction_id( const read_only::get_transaction_id_params& params)const {
        return params.id();
    }

    fc::variant read_only::get_block(const read_only::get_block_params& params) const {
        signed_block_ptr block;
        std::optional<uint64_t> block_num;

        EOS_ASSERT( !params.block_num_or_id.empty() && params.block_num_or_id.size() <= 64,
                    block_id_type_exception,
                    "Invalid Block number or ID, must be greater than 0 and less than 64 characters"
        );

        try {
            block_num = fc::to_uint64(params.block_num_or_id);
        } catch( ... ) {} // do nothing in case of exception 

        if( block_num ) {
            block = db.fetch_block_by_number( *block_num );
        } else {
            try {
                block = db.fetch_block_by_id( fc::variant(params.block_num_or_id).as<block_id_type>() );
            } EOS_RETHROW_EXCEPTIONS(block_id_type_exception, "Invalid block ID: {block_num_or_id}", ("block_num_or_id", params.block_num_or_id))
        }

        EOS_ASSERT( block, unknown_block_exception, "Could not find block: {block}", ("block", params.block_num_or_id));

        // serializes signed_block to variant in signed_block_v0 format
        fc::variant pretty_output;
        abi_serializer::to_variant(*block, pretty_output, make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time )),
                                    abi_serializer::create_yield_function( abi_serializer_max_time ));

        const auto id = block->calculate_id();
        const uint32_t ref_block_prefix = id._hash[1];

        return fc::mutable_variant_object(pretty_output.get_object())
                ("id", id)
                ("block_num",block->block_num())
                ("ref_block_prefix", ref_block_prefix);
    }

    fc::variant read_only::get_block_info(const read_only::get_block_info_params& params) const {

        signed_block_ptr block;
        try {
                block = db.fetch_block_by_number( params.block_num );
        } catch (...)   { // for any type of exception, just do nothing
            // assert below will handle the invalid block num
        }

        EOS_ASSERT( block, unknown_block_exception, "Could not find block: {block}", ("block", params.block_num));

        const auto id = block->calculate_id();
        const uint32_t ref_block_prefix = id._hash[1];

        /*
         * Note: block->producer_signature is NOT returned here because it may be written by the
         * separate thread for finalize_block() function's call back.
         */
        return fc::mutable_variant_object ()
                ("block_num", block->block_num())
                ("ref_block_num", static_cast<uint16_t>(block->block_num()))
                ("id", id)
                ("timestamp", block->timestamp)
                ("producer", block->producer)
                ("confirmed", block->confirmed)
                ("previous", block->previous)
                ("transaction_mroot", block->transaction_mroot)
                ("action_mroot", block->action_mroot)
                ("schedule_version", block->schedule_version)
                ("ref_block_prefix", ref_block_prefix);
    }

    fc::variant read_only::get_block_header_state(const get_block_header_state_params& params) const {
        block_state_ptr b;
        std::optional<uint64_t> block_num;
        std::exception_ptr e;
        try {
            block_num = fc::to_uint64(params.block_num_or_id);
        } catch( ... ) {} // do nothing in case of exception 

        if( block_num ) {
            b = db.fetch_block_state_by_number(*block_num);
        } else {
            try {
                b = db.fetch_block_state_by_id(fc::variant(params.block_num_or_id).as<block_id_type>());
            } EOS_RETHROW_EXCEPTIONS(block_id_type_exception, "Invalid block ID: {block_num_or_id}", ("block_num_or_id", params.block_num_or_id))
        }

        EOS_ASSERT( b, unknown_block_exception, "Could not find reversible block: {block}", ("block", params.block_num_or_id));

        fc::variant vo;
        fc::to_variant( static_cast<const block_header_state&>(*b), vo );
        return vo;
    }

    vector<asset> read_only::get_currency_balance( const read_only::get_currency_balance_params& p )const {

        const abi_def abi = eosio::chain_apis::get_abi( db, p.code );
        (void)_table_query.get_table_type( abi, name("accounts") );

        vector<asset> results;
        _table_query.walk_key_value_table(p.code, p.account, "accounts"_n, [&](const auto& obj){
            EOS_ASSERT( obj.value.size() >= sizeof(asset), asset_type_exception, "Invalid data on table");

            asset cursor;
            fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
            fc::raw::unpack(ds, cursor);

            EOS_ASSERT( cursor.get_symbol().valid(), asset_type_exception, "Invalid asset");

            if( !p.symbol || boost::iequals(cursor.symbol_name(), *p.symbol) ) {
                results.emplace_back(cursor);
            }

            // return false if we are looking for one and found it, true otherwise
            return !(p.symbol && boost::iequals(cursor.symbol_name(), *p.symbol));
        });

        return results;
    }

    fc::variant read_only::get_currency_stats( const read_only::get_currency_stats_params& p )const {
        fc::mutable_variant_object results;

        const abi_def abi = eosio::chain_apis::get_abi( db, p.code );
        (void)_table_query.get_table_type( abi, name("stat") );

        uint64_t scope = ( string_to_symbol( 0, boost::algorithm::to_upper_copy(p.symbol).c_str() ) >> 8 );

        _table_query.walk_key_value_table(p.code, name(scope), "stat"_n, [&](const auto& obj){
            EOS_ASSERT( obj.value.size() >= sizeof(read_only::get_currency_stats_result), asset_type_exception, "Invalid data on table");

            fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
            read_only::get_currency_stats_result result;

            fc::raw::unpack(ds, result.supply);
            fc::raw::unpack(ds, result.max_supply);
            fc::raw::unpack(ds, result.issuer);

            results[result.supply.symbol_name()] = result;
            return true;
        });

        return results;
    }

    read_only::get_producers_result read_only::get_producers( const read_only::get_producers_params& p ) const try {
        const auto producers_table = "producers"_n;
        const abi_def abi = eosio::chain_apis::get_abi(db, config::system_account_name);
        const auto table_type = _table_query.get_table_type(abi, producers_table);
        const abi_serializer abis{ abi, abi_serializer::create_yield_function( abi_serializer_max_time ) };
        EOS_ASSERT(table_type == _table_query.KEYi64, contract_table_query_exception, "Invalid table type {type} for table producers", ("type",table_type));

        const auto& d = db.db();
        const auto lower = name{p.lower_bound};

        keep_processing kp;
        read_only::get_producers_result result;
        auto done = [&kp,&result,&limit=p.limit](const auto& row) {
            if (result.rows.size() >= limit || !kp()) {
                result.more = name{row.primary_key}.to_string();
                return true;
            }
            return false;
        };
        auto type = abis.get_table_type(producers_table);
        auto get_val = _table_query.get_primary_key_value(type, abis, p.json);
        auto add_val = [&result,get_val{std::move(get_val)}](const auto& row) {
            fc::variant data_var;
            get_val(data_var, row);
            result.rows.emplace_back(std::move(data_var));
        };

        const auto code = config::system_account_name;
        const auto scope = config::system_account_name;
        static const uint8_t secondary_index_num = 0;
        const name sec_producers_table {producers_table.to_uint64_t() | secondary_index_num};

        const auto* const table_id = d.find<table_id_object, by_code_scope_table>(
                boost::make_tuple(code, scope, producers_table));
        const auto* const secondary_table_id = d.find<table_id_object, by_code_scope_table>(
                boost::make_tuple(code, scope, sec_producers_table));
        EOS_ASSERT(table_id && secondary_table_id, contract_table_query_exception, "Missing producers table");

        const auto& kv_index = d.get_index<key_value_index, by_scope_primary>();
        const auto& secondary_index = d.get_index<index_double_index>().indices();
        const auto& secondary_index_by_primary = secondary_index.get<by_primary>();
        const auto& secondary_index_by_secondary = secondary_index.get<by_secondary>();

        vector<char> data;

        auto it = lower.to_uint64_t() == 0
            ? secondary_index_by_secondary.lower_bound(
                    boost::make_tuple(secondary_table_id->id, to_softfloat64(std::numeric_limits<double>::lowest()), 0))
            : secondary_index.project<by_secondary>(
                    secondary_index_by_primary.lower_bound(
                    boost::make_tuple(secondary_table_id->id, lower.to_uint64_t())));
        for( ; it != secondary_index_by_secondary.end() && it->t_id == secondary_table_id->id; ++it ) {
            if (done(*it)) {
                break;
            }
            auto itr = kv_index.find(boost::make_tuple(table_id->id, it->primary_key));
            add_val(*itr);
        }

        constexpr name global = "global"_n;
        const auto global_table_type = _table_query.get_table_type(abi, global);
        EOS_ASSERT(global_table_type == _table_query.KEYi64, contract_table_query_exception, "Invalid table type {type} for table global", ("type",global_table_type));
        auto var = _table_query.get_primary_key(config::system_account_name, config::system_account_name, global, global.to_uint64_t(), table_query::row_requirements::required, table_query::row_requirements::required, abis.get_table_type(global));
        result.total_producer_vote_weight = var["total_producer_vote_weight"].as_double();
        return result;
    } catch (...) { // For any type exception from producer table query above get producers from db.active_producers
        read_only::get_producers_result result;

        for (auto p : db.active_producers().producers) {
            auto row = fc::mutable_variant_object()
                ("owner", p.producer_name)
                ("producer_authority", p.authority)
                ("url", "")
                ("total_votes", 0.0f);

            // detect a legacy key and maintain API compatibility for those entries
            if (std::holds_alternative<block_signing_authority_v0>(p.authority)) {
                const auto& auth = std::get<block_signing_authority_v0>(p.authority);
                if (auth.keys.size() == 1 && auth.keys.back().weight == auth.threshold) {
                    row("producer_key", auth.keys.back().key);
                }
            }

            result.rows.push_back(row);
        }

        return result;
    }

    read_only::get_producer_schedule_result read_only::get_producer_schedule( const read_only::get_producer_schedule_params& p ) const {
        read_only::get_producer_schedule_result result;
        to_variant(db.active_producers(), result.active);
        if(!db.pending_producers().producers.empty())
            to_variant(db.pending_producers(), result.pending);
        auto proposed = db.proposed_producers();
        if(proposed && !proposed->producers.empty())
            to_variant(*proposed, result.proposed);
        return result;
    }

    void read_only::send_ro_transaction(const read_only::send_ro_transaction_params_v1& params, plugin_interface::next_function<read_only::send_ro_transaction_results> next) const {
        try {
            packed_transaction_v0 input_trx_v0;
            auto resolver = make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time ));
            packed_transaction_ptr input_trx;
            try {
                abi_serializer::from_variant(params.transaction, input_trx_v0, std::move( resolver ), abi_serializer::create_yield_function( abi_serializer_max_time ));
                input_trx = std::make_shared<packed_transaction>( std::move( input_trx_v0 ), true );
            } EOS_RETHROW_EXCEPTIONS(packed_transaction_type_exception, "Invalid packed transaction")

            auto trx_trace = fc_create_trace_with_id("TransactionReadOnly", input_trx->id());
            auto trx_span = fc_create_span(trx_trace, "HTTP Received");
            fc_add_tag(trx_span, "trx_id", input_trx->id());
            fc_add_tag(trx_span, "method", "send_ro_transaction");

            app().get_method<plugin_interface::incoming::methods::transaction_async>()(input_trx, true, true, static_cast<const bool>(params.return_failure_traces),
                    [this, token=fc_get_token(trx_trace), input_trx, params, next]
                    (const std::variant<fc::exception_ptr, transaction_trace_ptr>& result) -> void {
                auto trx_span = fc_create_span_from_token(token, "Processed");
                fc_add_tag(trx_span, "trx_id", input_trx->id());

                if (std::holds_alternative<fc::exception_ptr>(result)) {
                    auto& eptr = std::get<fc::exception_ptr>(result);
                    fc_add_tag(trx_span, "error", eptr->to_string());
                    next(eptr);
                } else {
                    auto& trx_trace_ptr = std::get<transaction_trace_ptr>(result);

                    fc_add_tag(trx_span, "block_num", trx_trace_ptr->block_num);
                    fc_add_tag(trx_span, "block_time", trx_trace_ptr->block_time.to_time_point());
                    fc_add_tag(trx_span, "elapsed", trx_trace_ptr->elapsed.count());
                    if( trx_trace_ptr->receipt ) {
                        fc_add_tag(trx_span, "status", std::string(trx_trace_ptr->receipt->status));
                    }
                    if( trx_trace_ptr->except ) {
                        fc_add_tag(trx_span, "error", trx_trace_ptr->except->to_string());
                    }

                    try {
                        fc::variant output;
                        try {
                            output = db.to_variant_with_abi( *trx_trace_ptr, abi_serializer::create_yield_function( abi_serializer_max_time ) );
                        } catch( abi_exception& ) { // not able to apply abi to variant, so just include trace and no expanded abi
                            output = *trx_trace_ptr;
                        }
                        const auto& account_name = input_trx->get_transaction().actions[0].account;
                        const auto& accnt_metadata_obj = db.db().get<account_metadata_object,by_name>( account_name );
                        vector<transaction_id_type>  pending_transactions;
                        if (db.is_building_block()){
                            const auto& receipts = db.get_pending_trx_receipts();
                            pending_transactions.reserve(receipts.size());
                            for( transaction_receipt const& receipt : receipts ) {
                                if( std::holds_alternative<packed_transaction>(receipt.trx) ) {
                                    pending_transactions.push_back(std::get<packed_transaction>(receipt.trx).id());
                                } else {
                                    EOS_ASSERT( false, block_validate_exception, "encountered unexpected receipt type" );
                                }
                            }
                        }
                        next(read_only::send_ro_transaction_results{db.head_block_num(),
                                                                    db.head_block_id(),
                                                                    db.last_irreversible_block_num(),
                                                                    db.last_irreversible_block_id(),
                                                                    accnt_metadata_obj.code_hash,
                                                                    std::move(pending_transactions),
                                                                    output});
                    } CATCH_AND_CALL(next);
                }
            });
        } catch ( boost::interprocess::bad_alloc& ) {
            handle_db_exhaustion();
        } catch ( const std::bad_alloc& ) {
            handle_bad_alloc();
        } CATCH_AND_CALL(next);
    }



    account_query_db::get_accounts_by_authorizers_result read_only::get_accounts_by_authorizers( const account_query_db::get_accounts_by_authorizers_params& args) const
    {
        EOS_ASSERT(aqdb.has_value(), plugin_config_exception, "Account Queries being accessed when not enabled");
        return aqdb->get_accounts_by_authorizers(args);
    }

    namespace detail {
        struct ram_market_exchange_state_t {
            asset  ignore1;
            asset  ignore2;
            double ignore3{};
            asset  core_symbol;
            double ignore4{};
        };
    }

    symbol read_only::extract_core_symbol()const {
        symbol core_symbol(0);

        // The following code makes assumptions about the contract deployed on eosio account (i.e. the system contract) and how it stores its data.
        _table_query.get_primary_key<detail::ram_market_exchange_state_t>("eosio"_n, "eosio"_n, "rammarket"_n, string_to_symbol_c(4,"RAMCORE"),
                    table_query::row_requirements::optional, table_query::row_requirements::optional, [&core_symbol](const detail::ram_market_exchange_state_t& ram_market_exchange_state) {
                if( ram_market_exchange_state.core_symbol.get_symbol().valid() ) {
                    core_symbol = ram_market_exchange_state.core_symbol.get_symbol();
                }
        });

        return core_symbol;
    }

    read_only::get_all_accounts_result
    read_only::get_all_accounts( const get_all_accounts_params& params ) const {
        get_all_accounts_result result;

        using acct_obj_idx_type = chainbase::get_index_type<account_object>::type;
        const auto& accts = db.db().get_index<acct_obj_idx_type >().indices().get<by_name>();

        auto cur_time = fc::time_point::now();
        auto end_time = cur_time + fc::microseconds(1000 * 10); /// 10ms max time
        
        auto begin_itr = params.lower_bound? accts.lower_bound(*params.lower_bound) : accts.begin();
        auto end_itr = params.upper_bound? accts.upper_bound(*params.upper_bound) : accts.end();

        if( std::distance(begin_itr, end_itr) < 0 )
            return result;

        auto itr = params.reverse? end_itr : begin_itr;
        // since end_itr could potentially be past end of array, subtract one position
        if (params.reverse)
            --itr;

        // this flag will be set to true when we are reversing and we end on the begin iterator
        // if this is the case, 'more' field will remain null, and will nto be in JSON response
        bool reverse_end_begin = false;

        while(cur_time <= end_time
                && result.accounts.size() < params.limit
                && itr != end_itr)
        {
            const auto &a = *itr;
            result.accounts.push_back({a.name, a.creation_date});

            cur_time = fc::time_point::now();
            if (params.reverse && itr == begin_itr) {
                reverse_end_begin = true;
                break;
            }
            params.reverse? --itr : ++itr;
        }

        if (params.reverse && !reverse_end_begin) {
            result.more = itr->name;
        }
        else if (!params.reverse && itr != end_itr) {
            result.more = itr->name;
        }

        return result;
    }

    read_only::get_consensus_parameters_results
    read_only::get_consensus_parameters(const get_consensus_parameters_params& ) const {
        get_consensus_parameters_results results;

        results.chain_config = db.get_global_properties().configuration;
        results.kv_database_config = db.get_global_properties().kv_configuration;
        results.wasm_config = db.get_global_properties().wasm_configuration;

        return results;
    }

    read_only::get_genesis_result
    read_only::get_genesis(const get_genesis_params &params) const {
        EOS_ASSERT(genesis.has_value(), extract_genesis_state_exception, "No genesis value");
        return *genesis;
    }
}} //namespace eosio::chain_apis
FC_REFLECT( eosio::chain_apis::detail::ram_market_exchange_state_t, (ignore1)(ignore2)(ignore3)(core_symbol)(ignore4) )
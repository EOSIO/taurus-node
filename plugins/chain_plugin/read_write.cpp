#include <appbase/application.hpp>
#include <eosio/chain_plugin/read_write.hpp>
#include <fc/log/trace.hpp>

using namespace appbase;
using namespace eosio::chain::plugin_interface;
namespace eosio {
    namespace chain_apis
    {
static void push_recurse(read_write* rw, int index, const std::shared_ptr<read_write::push_transactions_params_v1>& params, const std::shared_ptr<read_write::push_transactions_results>& results, const next_function<read_write::push_transactions_results>& next) {
    auto wrapped_next = [=](const std::variant<fc::exception_ptr, read_write::push_transaction_results>& result) {
        if (std::holds_alternative<fc::exception_ptr>(result)) {
            const auto& e = std::get<fc::exception_ptr>(result);
            results->emplace_back( read_write::push_transaction_results{ transaction_id_type(), fc::mutable_variant_object( "error", e->to_detail_string() ) } );
        } else {
            const auto& r = std::get<read_write::push_transaction_results>(result);
            results->emplace_back( r );
        }

        size_t next_index = index + 1;
        if (next_index < params->size()) {
            push_recurse(rw, next_index, params, results, next );
        } else {
            next(*results);
        }
    };

    rw->push_transaction(params->at(index), wrapped_next);
}

read_write::read_write(controller& db, const fc::microseconds& abi_serializer_max_time, bool api_accept_transactions)
    : db(db)
    , abi_serializer_max_time(abi_serializer_max_time)
    , api_accept_transactions(api_accept_transactions)
    {}   
   
void read_write::validate() const {
    EOS_ASSERT( api_accept_transactions, missing_chain_api_plugin_exception,
                "Not allowed, node has api-accept-transactions = false" );
}

void read_write::push_block(push_block_params_v1&& params, next_function<push_block_results> next) {
    try {
        app().get_method<incoming::methods::block_sync>()(std::make_shared<signed_block>( std::move( params ), true), std::optional<block_id_type>{});
        next(push_block_results{});
    } catch ( boost::interprocess::bad_alloc& ) {
        handle_db_exhaustion();
    } catch ( const std::bad_alloc& ) {
        handle_bad_alloc();
    } CATCH_AND_CALL(next);
}

void read_write::push_transaction(const push_transaction_params_v1& params, next_function<push_transaction_results> next) {
    try {
        packed_transaction_v0 input_trx_v0;
        auto resolver = make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time ));
        chain::packed_transaction_ptr input_trx;
        try {
            abi_serializer::from_variant(params, input_trx_v0, std::move( resolver ), abi_serializer::create_yield_function( abi_serializer_max_time ));
            input_trx = std::make_shared<packed_transaction>( std::move( input_trx_v0 ), true );
        } EOS_RETHROW_EXCEPTIONS(chain::packed_transaction_type_exception, "Invalid packed transaction")

        auto trx_trace = fc_create_trace_with_id("Transaction", input_trx->id());
        auto trx_span = fc_create_span(trx_trace, "HTTP Received");
        fc_add_tag(trx_span, "trx_id", input_trx->id());
        fc_add_tag(trx_span, "method", "push_transaction");

        app().get_method<incoming::methods::transaction_async>()(input_trx, true, false, false,
                [this, token=fc_get_token(trx_trace), input_trx, next]
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

                    // Create map of (closest_unnotified_ancestor_action_ordinal, global_sequence) with action trace
                    std::map< std::pair<uint32_t, uint64_t>, fc::mutable_variant_object > act_traces_map;
                    for( const auto& act_trace : output["action_traces"].get_array() ) {
                        if (act_trace["receipt"].is_null() && act_trace["except"].is_null()) continue;
                        auto closest_unnotified_ancestor_action_ordinal =
                            act_trace["closest_unnotified_ancestor_action_ordinal"].as<fc::unsigned_int>().value;
                        auto global_sequence = act_trace["receipt"].is_null() ?
                                                    std::numeric_limits<uint64_t>::max() :
                                                    act_trace["receipt"]["global_sequence"].as<uint64_t>();
                        act_traces_map.emplace( std::make_pair( closest_unnotified_ancestor_action_ordinal,
                                                                global_sequence ),
                                                act_trace.get_object() );
                    }

                    std::function<vector<fc::variant>(uint32_t)> convert_act_trace_to_tree_struct =
                    [&](uint32_t closest_unnotified_ancestor_action_ordinal) {
                        vector<fc::variant> restructured_act_traces;
                        auto it = act_traces_map.lower_bound(
                                    std::make_pair( closest_unnotified_ancestor_action_ordinal, 0)
                        );
                        for( ;
                            it != act_traces_map.end() && it->first.first == closest_unnotified_ancestor_action_ordinal; ++it )
                        {
                            auto& act_trace_mvo = it->second;

                            auto action_ordinal = act_trace_mvo["action_ordinal"].as<fc::unsigned_int>().value;
                            act_trace_mvo["inline_traces"] = convert_act_trace_to_tree_struct(action_ordinal);
                            if (act_trace_mvo["receipt"].is_null()) {
                            act_trace_mvo["receipt"] = fc::mutable_variant_object()
                                ("abi_sequence", 0)
                                ("act_digest", digest_type::hash(trx_trace_ptr->action_traces[action_ordinal-1].act))
                                ("auth_sequence", flat_map<account_name,uint64_t>())
                                ("code_sequence", 0)
                                ("global_sequence", 0)
                                ("receiver", act_trace_mvo["receiver"])
                                ("recv_sequence", 0);
                            }
                            restructured_act_traces.push_back( std::move(act_trace_mvo) );
                        }
                        return restructured_act_traces;
                    };

                    fc::mutable_variant_object output_mvo(output);
                    output_mvo["action_traces"] = convert_act_trace_to_tree_struct(0);

                    output = output_mvo;
                } catch( chain::abi_exception& ) { // not able to apply abi to variant, so just include trace and no expanded abi
                    output = *trx_trace_ptr;
                }

                const chain::transaction_id_type& id = trx_trace_ptr->id;
                next(push_transaction_results{id, output});
                } CATCH_AND_CALL(next);
            }
        });
    } catch ( boost::interprocess::bad_alloc& ) {
        handle_db_exhaustion();
    } catch ( const std::bad_alloc& ) {
        handle_bad_alloc();
    } CATCH_AND_CALL(next);
}

void read_write::push_transactions(const push_transactions_params_v1& params, next_function<push_transactions_results> next) {
    try {
        EOS_ASSERT( params.size() <= 1000, too_many_tx_at_once, "Attempt to push too many transactions at once" );
        auto params_copy = std::make_shared<push_transactions_params_v1>(params.begin(), params.end());
        auto result = std::make_shared<push_transactions_results>();
        result->reserve(params.size());

        push_recurse(this, 0, params_copy, result, next);
    } catch ( boost::interprocess::bad_alloc& ) {
        handle_db_exhaustion();
    } catch ( const std::bad_alloc& ) {
        handle_bad_alloc();
    } CATCH_AND_CALL(next);
}



void read_write::send_transaction(const send_transaction_params_v1& params, next_function<send_transaction_results> next) {

    try {
        packed_transaction_v0 input_trx_v0;
        auto resolver = make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time ));
        chain::packed_transaction_ptr input_trx;
        try {
            abi_serializer::from_variant(params, input_trx_v0, std::move( resolver ), abi_serializer::create_yield_function( abi_serializer_max_time ));
            input_trx = std::make_shared<packed_transaction>( std::move( input_trx_v0 ), true );
        } EOS_RETHROW_EXCEPTIONS(chain::packed_transaction_type_exception, "Invalid packed transaction")

        read_write::send_transaction(input_trx, "send_transaction", false, next);

    } catch ( boost::interprocess::bad_alloc& ) {
        handle_db_exhaustion();
    } catch ( const std::bad_alloc& ) {
        handle_bad_alloc();
    } CATCH_AND_CALL(next);
}

void read_write::send_transaction(const send_transaction_params_v2& params, next_function<send_transaction_results> next) {

    try {
        packed_transaction_v0 input_trx_v0;
        auto resolver = make_resolver(db, abi_serializer::create_yield_function( abi_serializer_max_time ));
        chain::packed_transaction_ptr input_trx;
        try {
            abi_serializer::from_variant(params.transaction, input_trx_v0, std::move( resolver ), abi_serializer::create_yield_function( abi_serializer_max_time ));
            input_trx = std::make_shared<packed_transaction>( std::move( input_trx_v0 ), true );
        } EOS_RETHROW_EXCEPTIONS(chain::packed_transaction_type_exception, "Invalid packed transaction")

        send_transaction(input_trx, "/v2/chain/send_transaction", params.return_failure_traces, next);

    } catch ( boost::interprocess::bad_alloc& ) {
        handle_db_exhaustion();
    } catch ( const std::bad_alloc& ) {
        handle_bad_alloc();
    } CATCH_AND_CALL(next);
}

void read_write::send_transaction(chain::packed_transaction_ptr input_trx, const std::string method, bool return_failure_traces, next_function<send_transaction_results> next) {
    auto trx_trace = fc_create_trace_with_id("Transaction", input_trx->id());
    auto trx_span = fc_create_span(trx_trace, "HTTP Received");
    fc_add_tag(trx_span, "trx_id", input_trx->id());
    fc_add_tag(trx_span, "method", method);

    app().get_method<incoming::methods::transaction_async>()(input_trx, true, false, static_cast<const bool>(return_failure_traces),
            [this, token=fc_get_token(trx_trace), input_trx, next]
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
                } catch( chain::abi_exception& ) { // not able to apply abi to variant, so just include trace and no expanded abi
                    output = *trx_trace_ptr;
                }

                const chain::transaction_id_type& id = trx_trace_ptr->id;
                next(send_transaction_results{id, output});
            } CATCH_AND_CALL(next);
        }
    });
}
}} //namespace eosio::chain_apis



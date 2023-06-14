#include <eosio/chain/backing_store/kv_context.hpp>
#include <eosio/chain_plugin/key_helper.hpp>
#include <eosio/chain_plugin/table_query.hpp>
#include <eosio/chain/to_string.hpp>
#include <boost/lexical_cast.hpp>

using namespace eosio::chain;
using eosio::chain::uint128_t;
namespace eosio {
namespace chain_apis {
template<const char*key_type , const char *encoding=chain_apis::dec>
struct keytype_converter ;

template<>
struct keytype_converter<chain_apis::sha256, chain_apis::hex> {
    using input_type = chain::checksum256_type;
    using index_type = chain::index256_index;
    static auto function() {
        return [](const input_type& v) {
            // The input is in big endian, i.e. f58262c8005bb64b8f99ec6083faf050c502d099d9929ae37ffed2fe1bb954fb
            // fixed_bytes will convert the input to array of 2 uint128_t in little endian, i.e. 50f0fa8360ec998f4bb65b00c86282f5 fb54b91bfed2fe7fe39a92d999d002c5
            // which is the format used by secondary index
            uint8_t buffer[32];
            memcpy(buffer, v.data(), 32);
            fixed_bytes<32> fb(buffer); 
            return chain::key256_t(fb.get_array());
        };
    }
};

//key160 support with padding zeros in the end of key256
template<>
struct keytype_converter<chain_apis::ripemd160, chain_apis::hex> {
    using input_type = chain::checksum160_type;
    using index_type = chain::index256_index;
    static auto function() {
        return [](const input_type& v) {
            // The input is in big endian, i.e. 83a83a3876c64c33f66f33c54f1869edef5b5d4a000000000000000000000000
            // fixed_bytes will convert the input to array of 2 uint128_t in little endian, i.e. ed69184fc5336ff6334cc676383aa883 0000000000000000000000004a5d5bef
            // which is the format used by secondary index
            uint8_t buffer[20];
            memcpy(buffer, v.data(), 20);
            fixed_bytes<20> fb(buffer); 
            return chain::key256_t(fb.get_array());
        };
    }
};

template<>
struct keytype_converter<chain_apis::i256> {
    using input_type = boost::multiprecision::uint256_t;
    using index_type = chain::index256_index;
    static auto function() {
        return [](const input_type v) {
            // The input is in little endian of uint256_t, i.e. fb54b91bfed2fe7fe39a92d999d002c550f0fa8360ec998f4bb65b00c86282f5
            // the following will convert the input to array of 2 uint128_t in little endian, i.e. 50f0fa8360ec998f4bb65b00c86282f5 fb54b91bfed2fe7fe39a92d999d002c5
            // which is the format used by secondary index
            chain::key256_t k;
            uint8_t buffer[32];
            boost::multiprecision::export_bits(v, buffer, 8, false);
            memcpy(&k[0], buffer + 16, 16);
            memcpy(&k[1], buffer, 16);
            return k;
        };
    }
};

// see specializations for uint64_t and double in source file
template<typename Type>
    Type convert_to_type(const string& str, const string& desc) {
    try {
        return fc::variant(str).as<Type>();
    } FC_RETHROW_EXCEPTIONS(warn, "Could not convert {desc} string '{str}' to key type.", ("desc", desc)("str",str) )
}

uint64_t convert_to_type(const name &n, const string &desc) {
    return n.to_uint64_t();
}

template<>
uint64_t convert_to_type(const string& str, const string& desc) {

    try {
        return boost::lexical_cast<uint64_t>(str.c_str(), str.size());
    } catch( ... ) { } // for any exception type do nothing

    try {
        auto trimmed_str = str;
        boost::trim(trimmed_str);
        name s(trimmed_str);
        return s.to_uint64_t();
    } catch( ... ) { } // for any exception type do nothing

    if (str.find(',') != string::npos) { // fix #6274 only match formats like 4,EOS
        try {
            auto symb = eosio::chain::symbol::from_string(str);
            return symb.value();
        } catch( ... ) { } //for any exception type do nothing
    }

    try {
        return ( eosio::chain::string_to_symbol( 0, str.c_str() ) >> 8 );
    } catch( ... ) {
        EOS_ASSERT( false, chain::chain_type_exception, "Could not convert {desc} string '{str}' to any of the following: "
                            "uint64_t, valid name, or valid symbol (with or without the precision)",
                    ("desc", desc)("str", str));
    }
}

template<>
double convert_to_type(const string& str, const string& desc) {
    double val{};
    try {
        val = fc::variant(str).as<double>();
    } FC_RETHROW_EXCEPTIONS(warn, "Could not convert {desc} string '{str}' to key type.", ("desc", desc)("str",str) )

    EOS_ASSERT( !std::isnan(val), chain::contract_table_query_exception,
                "Converted {desc} string '{str}' to NaN which is not a permitted value for the key type", ("desc", desc)("str",str) );

    return val;
}

template<typename Type>
string convert_to_string(const Type& source, const string& key_type, const string& encode_type, const string& desc) {
    try {
        return fc::variant(source).as<string>();
    } FC_RETHROW_EXCEPTIONS(warn, "Could not convert {desc} from type '{type}' to string.", ("desc", desc)("type", fc::get_typename<Type>::name())) // ?
}

template<>
string convert_to_string(const chain::key256_t& source, const string& key_type, const string& encode_type, const string& desc) {
    try {
        if (key_type == chain_apis::sha256 || (key_type == chain_apis::i256 && encode_type == chain_apis::hex)) {
            auto byte_array = fixed_bytes<32>(source).extract_as_byte_array();
            fc::sha256 val(reinterpret_cast<char *>(byte_array.data()), byte_array.size());
            return std::string(val);
        } else if (key_type == chain_apis::i256) {
            auto byte_array = fixed_bytes<32>(source).extract_as_byte_array();
            fc::sha256 val(reinterpret_cast<char *>(byte_array.data()), byte_array.size());
            return std::string("0x") + std::string(val);
        } else if (key_type == chain_apis::ripemd160) {
            auto byte_array = fixed_bytes<20>(source).extract_as_byte_array();
            fc::ripemd160 val;
            memcpy(val._hash, byte_array.data(), byte_array.size() );
            return std::string(val);
        }
        EOS_ASSERT( false, chain::chain_type_exception, "Incompatible key_type and encode_type for key256_t next_key" );

    } FC_RETHROW_EXCEPTIONS(warn, "Could not convert {desc} source '{source}' to string.", ("desc", desc)("source",source) )
}

template<>
string convert_to_string(const float128_t& source, const string& key_type, const string& encode_type, const string& desc) {
    try {
        float64_t f = f128_to_f64(source);
        return fc::variant(f).as<string>();
    } FC_RETHROW_EXCEPTIONS(warn, "Could not convert {desc} from '{source-h}'.'{source-l}' to string.", ("desc", desc)("source-l", source.v[0])("source-h", source.v[1]) ) // ?
}

abi_def get_abi( const controller& db, const name& account ) {
    const auto &d = db.db();
    const account_object *code_accnt = d.find<account_object, by_name>(account);
    EOS_ASSERT(code_accnt != nullptr, chain::account_query_exception, "Fail to retrieve account for {account}", ("account", account) );
    abi_def abi;
    abi_serializer::to_abi(code_accnt->abi, abi);
    return abi;
}

constexpr uint32_t prefix_size = 17; // prefix 17bytes: status(1 byte) + table_name(8bytes) + index_name(8 bytes)
struct kv_table_rows_context {
    std::unique_ptr<eosio::chain::kv_context>  kv_context;
    const table_query::get_kv_table_rows_params& p;
    abi_serializer::yield_function_t           yield_function;                            
    abi_def                                    abi;
    abi_serializer                             abis;
    std::string                                index_type;
    bool                                       shorten_abi_errors;
    bool                                       is_primary_idx;

    kv_table_rows_context(const controller& db, const table_query::get_kv_table_rows_params& param,
                            const fc::microseconds abi_serializer_max_time, bool shorten_error)
        : kv_context(db_util::create_kv_context(db,
                param.code, {},
                db.get_global_properties().kv_configuration)) // To do: provide kv_resource_manmager to create_kv_context
        , p(param)
        , yield_function(abi_serializer::create_yield_function(abi_serializer_max_time))
        , abi(eosio::chain_apis::get_abi(db, param.code))
        , shorten_abi_errors(shorten_error) {

        EOS_ASSERT(p.limit > 0, chain::contract_table_query_exception, "invalid limit : {n}", ("n", p.limit));
        EOS_ASSERT(p.table.good() || !p.json, chain::contract_table_query_exception, "JSON value is not supported when the table is empty");
        if (p.table.good()) {
            string tbl_name = p.table.to_string();
            // Check valid table name
            const auto table_it = abi.kv_tables.value.find(p.table);
            if (table_it == abi.kv_tables.value.end()) {
                EOS_ASSERT(false, chain::contract_table_query_exception, "Unknown kv_table: {t}", ("t", tbl_name));
            }
            const auto& kv_tbl_def = table_it->second;
            // Check valid index_name
            is_primary_idx  = (p.index_name == kv_tbl_def.primary_index.name);
            bool is_sec_idx = (kv_tbl_def.secondary_indices.find(p.index_name) != kv_tbl_def.secondary_indices.end());
            EOS_ASSERT(is_primary_idx || is_sec_idx, chain::contract_table_query_exception, "Unknown kv index: {t} {i}",
                    ("t", p.table)("i", p.index_name));

            index_type = kv_tbl_def.get_index_type(p.index_name.to_string());
            abis.set_abi(abi, yield_function);
        }
        else {
            is_primary_idx = true;
        } 
    }

    bool point_query() const { return p.index_value.size(); }

    void write_prefix(fixed_buf_stream& strm) const {
        strm.write('\1');
        if (p.table.good()) {
            to_key(p.table.to_uint64_t(), strm);
            to_key(p.index_name.to_uint64_t(), strm);
        }
    }

    std::vector<char> get_full_key(string key) const {
        // the max possible encoded_key_byte_count occurs when the encoded type is string and when all characters 
        // in the string is '\0'
        const size_t max_encoded_key_byte_count = std::max(sizeof(uint64_t), 2 * key.size() + 1);
        std::vector<char> full_key(prefix_size + max_encoded_key_byte_count);
        fixed_buf_stream  strm(full_key.data(), full_key.size());
        write_prefix(strm);
        if (key.size())
            key_helper::write_key(index_type, p.encode_type, key, strm);
        full_key.resize(strm.pos - full_key.data());
        return full_key;
    }
};

struct kv_iterator_ex {
    uint32_t                     key_size   = 0;
    uint32_t                     value_size = 0;
    const kv_table_rows_context& context;
    std::unique_ptr<kv_iterator> base;
    kv_it_stat                   status;

    kv_iterator_ex(const kv_table_rows_context& ctx, const std::vector<char>& full_key)
        : context(ctx) {
        base   = context.kv_context->kv_it_create(context.p.code.to_uint64_t(), full_key.data(), std::min<uint32_t>(prefix_size, full_key.size()));
        status = base->kv_it_lower_bound(full_key.data(), full_key.size(), &key_size, &value_size);
        EOS_ASSERT(status != chain::kv_it_stat::iterator_erased, chain::contract_table_query_exception,
                    "Invalid iterator in {t} {i}", ("t", context.p.table)("i", context.p.index_name));
    }

    bool is_end() const { return status == kv_it_stat::iterator_end; }

    /// @pre ! is_end()
    std::vector<char> get_key() const {
        std::vector<char> result(key_size);
        uint32_t          actual_size;
        base->kv_it_key(0, result.data(), key_size, actual_size);
        return result;
    }

    /// @pre ! is_end()
    std::vector<char> get_value() const {
        std::vector<char> result(value_size);
        uint32_t          actual_size;
        base->kv_it_value(0, result.data(), value_size, actual_size);
        if (!context.is_primary_idx) {
            auto success =
                context.kv_context->kv_get(context.p.code.to_uint64_t(), result.data(), result.size(), actual_size);
            EOS_ASSERT(success, chain::contract_table_query_exception, "invalid secondary index in {t} {i}",
                        ("t", context.p.table)("i", context.p.index_name));
            result.resize(actual_size);
            context.kv_context->kv_get_data(0, result.data(), actual_size);
        }

        return result;
    }

    /// @pre ! is_end()
    fc::variant get_value_var() const {
        std::vector<char> row_value = get_value();
        if (context.p.json) {
            try {
                return context.abis.binary_to_variant(context.p.table.to_string(), row_value,
                                                    context.yield_function,
                                                    context.shorten_abi_errors);
            } catch (fc::exception& e) {} // do nothing in case of exception
        }
        return fc::variant(row_value);
    }

    /// @pre ! is_end()
    fc::variant get_value_and_maybe_payer_var() const {
        fc::variant result = get_value_var();
        if (context.p.show_payer || context.p.table.empty()) {
            auto r = fc::mutable_variant_object("data", std::move(result));
            auto maybe_payer = base->kv_it_payer();
            if (maybe_payer.has_value())
                r.set("payer", maybe_payer.value().to_string());
            if (context.p.table.empty()) 
                r.set("key", get_key_hex_string());
            return r;
        }
        
        return result;
    }

    /// @pre ! is_end()
    std::string get_key_hex_string() const {
        auto        row_key = get_key();
        std::string result;
        boost::algorithm::hex(row_key.begin() + prefix_size, row_key.end(), std::back_inserter(result));
        return result;
    }

    /// @pre ! is_end()
    kv_iterator_ex& operator++() {
        status = base->kv_it_next(&key_size, &value_size);
        return *this;
    }

    /// @pre ! is_end()
    kv_iterator_ex& operator--() {
        status = base->kv_it_prev(&key_size, &value_size);
        return *this;
    }

    int key_compare(const std::vector<char>& key) const {
        return base->kv_it_key_compare(key.data(), key.size());
    }
};

struct kv_forward_range {
    kv_iterator_ex           current;
    const std::vector<char>& last_key;

    kv_forward_range(const kv_table_rows_context& ctx, const std::vector<char>& first_key,
                        const std::vector<char>& last_key)
        : current(ctx, first_key)
        , last_key(last_key) {}

    bool is_done() const {
        return current.is_end() ||
                (last_key.size() > prefix_size && current.key_compare(last_key) > 0);
    }

    void next() { ++current; }
};

struct kv_reverse_range {
    kv_iterator_ex           current;
    const std::vector<char>& last_key;

    kv_reverse_range(const kv_table_rows_context& ctx, const std::vector<char>& first_key,
                        const std::vector<char>& last_key)
        : current(ctx, first_key)
        , last_key(last_key) {
        if (first_key.size() == prefix_size) {
            current.status = current.base->kv_it_move_to_end();
        }
        if (current.is_end() || current.key_compare(first_key) != 0)
            --current;
    }

    bool is_done() const {
        return current.is_end() ||
                (last_key.size() > prefix_size && current.key_compare(last_key) < 0);
    }

    void next() { --current; }
};

template <typename Range>
table_query::get_table_rows_result kv_get_rows(Range&& range) {

    keep_processing kp {};
    table_query::get_table_rows_result result;
    auto&                            ctx      = range.current.context;
    for (unsigned count = 0; count < ctx.p.limit && !range.is_done() && kp() ;
            ++count) {
        result.rows.emplace_back(range.current.get_value_and_maybe_payer_var());
        range.next();
    }

    if (!range.is_done()) {
        result.more           = true;
        result.next_key_bytes = range.current.get_key_hex_string();
        result.next_key = key_helper::read_key(ctx.index_type, ctx.p.encode_type, result.next_key_bytes);
    }
    return result;
}

table_query::table_query(const controller& db, const fc::microseconds& abi_serializer_max_time)
        : db(db), abi_serializer_max_time(abi_serializer_max_time) {}

const string table_query::KEYi64 = "i64";
string table_query::get_table_type( const abi_def& abi, const name& table_name ) const {
    for( const auto& t : abi.tables ) {
        if( t.name == table_name ){
            return t.index_type;
        }
    }
    EOS_ASSERT( false, chain::contract_table_query_exception, "Table {table} is not specified in the ABI", ("table",table_name) );
}

table_query::get_table_rows_result table_query::get_table_rows( const table_query::get_table_rows_params& p )const {
    const abi_def abi = eosio::chain_apis::get_abi( db, p.code );
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-aliasing"
    bool primary = false;
    auto table_with_index = table_query::get_table_index_name( p, primary );
    if( primary ) {
        EOS_ASSERT( p.table == table_with_index, chain::contract_table_query_exception, "Invalid table name {t}", ( "t", p.table ));
        auto table_type = table_query::get_table_type( abi, p.table );
        if( table_type == table_query::KEYi64 || p.key_type == "i64" || p.key_type == "name" ) {
            return table_query::get_table_rows_ex<key_value_index>(p,abi);
        }
        EOS_ASSERT( false, chain::contract_table_query_exception,  "Invalid table type {type}", ("type",table_type)("abi",abi));
    } else {
        EOS_ASSERT( !p.key_type.empty(), chain::contract_table_query_exception, "key type required for non-primary index" );

        if (p.key_type == chain_apis::i64 || p.key_type == "name") {
            return table_query::get_table_rows_by_seckey<index64_index, uint64_t>(p, abi, [](uint64_t v)->uint64_t {
                return v;
            });
        }
        else if (p.key_type == chain_apis::i128) {
            return table_query::get_table_rows_by_seckey<index128_index, uint128_t>(p, abi, [](uint128_t v)->uint128_t {
                return v;
            });
        }
        else if (p.key_type == chain_apis::i256) {
            if ( p.encode_type == chain_apis::hex) {
                using  conv = keytype_converter<chain_apis::sha256,chain_apis::hex>;
                return table_query::get_table_rows_by_seckey<conv::index_type, conv::input_type>(p, abi, conv::function());
            }
            using  conv = keytype_converter<chain_apis::i256>;
            return table_query::get_table_rows_by_seckey<conv::index_type, conv::input_type>(p, abi, conv::function());
        }
        else if (p.key_type == chain_apis::float64) {
            return table_query::get_table_rows_by_seckey<index_double_index, double>(p, abi, [](double v)->float64_t {
                float64_t f = *(float64_t *)&v;
                return f;
            });
        }
        else if (p.key_type == chain_apis::float128) {
            if ( p.encode_type == chain_apis::hex) {
                return table_query::get_table_rows_by_seckey<index_long_double_index, uint128_t>(p, abi, [](uint128_t v)->float128_t{
                return *reinterpret_cast<float128_t *>(&v);
                });
            }
            return table_query::get_table_rows_by_seckey<index_long_double_index, double>(p, abi, [](double v)->float128_t{
                float64_t f = *(float64_t *)&v;
                float128_t f128;
                f64_to_f128M(f, &f128);
                return f128;
            });
        }
        else if (p.key_type == chain_apis::sha256) {
            using  conv = keytype_converter<chain_apis::sha256,chain_apis::hex>;
            return table_query::get_table_rows_by_seckey<conv::index_type, conv::input_type>(p, abi, conv::function());
        }
        else if(p.key_type == chain_apis::ripemd160) {
            using  conv = keytype_converter<chain_apis::ripemd160,chain_apis::hex>;
            return table_query::get_table_rows_by_seckey<conv::index_type, conv::input_type>(p, abi, conv::function());
        }
        EOS_ASSERT(false, chain::contract_table_query_exception,  "Unsupported secondary index type: {t}", ("t", p.key_type));
    }
#pragma GCC diagnostic pop
}

table_query::get_table_rows_result table_query::get_kv_table_rows(const table_query::get_kv_table_rows_params& p) const {

    kv_table_rows_context context{db, p, abi_serializer_max_time, shorten_abi_errors};

    if (context.point_query()) {
        EOS_ASSERT(p.lower_bound.empty() && p.upper_bound.empty(), chain::contract_table_query_exception,
                    "specify both index_value and ranges (i.e. lower_bound/upper_bound) is not allowed");
        table_query::get_table_rows_result result;
        auto full_key = context.get_full_key(p.index_value);
        kv_iterator_ex                   itr(context, full_key);
        if (!itr.is_end() && itr.key_compare(full_key) == 0) {
            result.rows.emplace_back(itr.get_value_and_maybe_payer_var());
        }
        return result;
    }

    auto lower_bound = context.get_full_key(p.lower_bound);
    auto upper_bound = context.get_full_key(p.upper_bound);

    if (context.p.reverse == false)
        return kv_get_rows(kv_forward_range(context, lower_bound, upper_bound));
    else
        return kv_get_rows(kv_reverse_range(context, upper_bound, lower_bound));
}

template <typename IndexType, typename SecKeyType, typename ConvFn>
table_query::get_table_rows_result table_query::get_table_rows_by_seckey( const get_table_rows_params& p, const abi_def& abi, ConvFn conv ) const {
    table_query::get_table_rows_result result;
    const auto& d = db.db();

    name scope{ chain_apis::convert_to_type<uint64_t>(p.scope, "scope") };

    abi_serializer abis;
    abis.set_abi(abi, abi_serializer::create_yield_function( abi_serializer_max_time ) );
    bool primary = false;
    const uint64_t table_with_index = table_query::get_table_index_name(p, primary);
    // using secondary_key_type = std::result_of_t<decltype(conv)(SecKeyType)>;
    using secondary_key_type = decltype(conv(std::declval<SecKeyType>()));
    static_assert( std::is_same<typename IndexType::value_type::secondary_key_type, secondary_key_type>::value, "Return type of conv does not match type of secondary key for IndexType" );
    auto secondary_key_lower = eosio::chain::secondary_key_traits<secondary_key_type>::true_lowest();
    const auto primary_key_lower = std::numeric_limits<uint64_t>::lowest();
    auto secondary_key_upper = eosio::chain::secondary_key_traits<secondary_key_type>::true_highest();
    const auto primary_key_upper = std::numeric_limits<uint64_t>::max();
    if( p.lower_bound.size() ) {
        if( p.key_type == "name" ) {
            if constexpr (std::is_same_v<uint64_t, SecKeyType>) {
            SecKeyType lv = chain_apis::convert_to_type(name{p.lower_bound}, "lower_bound name");
            secondary_key_lower = conv( lv );
            } else {
            EOS_ASSERT(false, chain::contract_table_query_exception, "Invalid key type of eosio::name {nm} for lower bound", ("nm", p.lower_bound));
            }
        } else {
            SecKeyType lv = chain_apis::convert_to_type<SecKeyType>( p.lower_bound, "lower_bound" );
            secondary_key_lower = conv( lv );
        }
    }

    if( p.upper_bound.size() ) {
        if( p.key_type == "name" ) {
            if constexpr (std::is_same_v<uint64_t, SecKeyType>) {
            SecKeyType uv = chain_apis::convert_to_type(name{p.upper_bound}, "upper_bound name");
            secondary_key_upper = conv( uv );
            } else {
            EOS_ASSERT(false, chain::contract_table_query_exception, "Invalid key type of eosio::name {nm} for upper bound", ("nm", p.upper_bound));
            }
        } else {
            SecKeyType uv = chain_apis::convert_to_type<SecKeyType>( p.upper_bound, "upper_bound" );
            secondary_key_upper = conv( uv );
        }
    }
    if( secondary_key_upper < secondary_key_lower )
        return result;

    const bool reverse = p.reverse && *p.reverse;
    auto get_prim_key_val = get_primary_key_value(p.table, abis, p.json, p.show_payer);
    const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(p.code, scope, p.table));
    const auto* index_t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(p.code, scope, name(table_with_index)));
    if( t_id != nullptr && index_t_id != nullptr ) {

        const auto& secidx = d.get_index<IndexType, chain::by_secondary>();
        auto lower_bound_lookup_tuple = std::make_tuple( index_t_id->id._id,
                                                        secondary_key_lower,
                                                        primary_key_lower );
        auto upper_bound_lookup_tuple = std::make_tuple( index_t_id->id._id,
                                                        secondary_key_upper,
                                                        primary_key_upper );

        auto walk_table_row_range = [&]( auto itr, auto end_itr ) {
            chain_apis::keep_processing kp;
            vector<char> data;
            for( unsigned int count = 0; kp() && count < p.limit && itr != end_itr; ++itr ) {
            const auto* itr2 = d.find<chain::key_value_object, chain::by_scope_primary>( boost::make_tuple(t_id->id, itr->primary_key) );
            if( itr2 == nullptr ) continue;

            result.rows.emplace_back( get_prim_key_val(*itr2) );

            ++count;
            }
            if( itr != end_itr ) {
            result.more = true;
            result.next_key = chain_apis::convert_to_string(itr->secondary_key, p.key_type, p.encode_type, "next_key - next lower bound");
            }
        };

        auto lower = secidx.lower_bound( lower_bound_lookup_tuple );
        auto upper = secidx.upper_bound( upper_bound_lookup_tuple );
        if( reverse ) {
            walk_table_row_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
        } else {
            walk_table_row_range( lower, upper );
        }
    }

    return result;
}

table_query::get_table_by_scope_result table_query::get_table_by_scope( const table_query::get_table_by_scope_params& p ) const {
    table_query::get_table_by_scope_result result;
    auto lower_bound_lookup_tuple = std::make_tuple( p.code, name(std::numeric_limits<uint64_t>::lowest()), p.table );
    auto upper_bound_lookup_tuple = std::make_tuple( p.code, name(std::numeric_limits<uint64_t>::max()),
                                                        (p.table.empty() ? name(std::numeric_limits<uint64_t>::max()) : p.table) );

    if( p.lower_bound.size() ) {
        uint64_t scope = chain_apis::convert_to_type<uint64_t>(p.lower_bound, "lower_bound scope");
        std::get<1>(lower_bound_lookup_tuple) = name(scope);
    }

    if( p.upper_bound.size() ) {
        uint64_t scope = chain_apis::convert_to_type<uint64_t>(p.upper_bound, "upper_bound scope");
        std::get<1>(upper_bound_lookup_tuple) = name(scope);
    }

    if( upper_bound_lookup_tuple < lower_bound_lookup_tuple )
        return result;

    const bool reverse = p.reverse && *p.reverse;
    auto walk_table_range = [&result,&p]( auto itr, auto end_itr ) {
        keep_processing kp;
        for( unsigned int count = 0; kp() && count < p.limit && itr != end_itr; ++itr ) {
            if( p.table && itr->table != p.table ) continue;

            result.rows.push_back( {itr->code, itr->scope, itr->table, itr->payer, itr->count} );

            ++count;
        }
        if( itr != end_itr ) {
            result.more = itr->scope.to_string();
        }
    };

    const auto& d = db.db();
    const auto& idx = d.get_index<chain::table_id_multi_index, chain::by_code_scope_table>();
    auto lower = idx.lower_bound( lower_bound_lookup_tuple );
    auto upper = idx.upper_bound( upper_bound_lookup_tuple );
    if( reverse ) {
        walk_table_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
    } else {
        walk_table_range( lower, upper );
    }

    return result;
}

uint64_t table_query::get_table_index_name(const table_query::get_table_rows_params& p, bool& primary) {
    using boost::algorithm::starts_with;
    // see multi_index packing of index name
    const uint64_t table = p.table.to_uint64_t();
    uint64_t index = table & 0xFFFFFFFFFFFFFFF0ULL;
    EOS_ASSERT( index == table, chain::contract_table_query_exception, "Unsupported table name: {n}", ("n", p.table) );

    primary = false;
    uint64_t pos = 0;
    if (p.index_position.empty() || p.index_position == "first" || p.index_position == "primary" || p.index_position == "one") {
        primary = true;
    } else if (starts_with(p.index_position, "sec") || p.index_position == "two") { // second, secondary
    } else if (starts_with(p.index_position , "ter") || starts_with(p.index_position, "th")) { // tertiary, ternary, third, three
        pos = 1;
    } else if (starts_with(p.index_position, "fou")) { // four, fourth
        pos = 2;
    } else if (starts_with(p.index_position, "fi")) { // five, fifth
        pos = 3;
    } else if (starts_with(p.index_position, "six")) { // six, sixth
        pos = 4;
    } else if (starts_with(p.index_position, "sev")) { // seven, seventh
        pos = 5;
    } else if (starts_with(p.index_position, "eig")) { // eight, eighth
        pos = 6;
    } else if (starts_with(p.index_position, "nin")) { // nine, ninth
        pos = 7;
    } else if (starts_with(p.index_position, "ten")) { // ten, tenth
        pos = 8;
    } else {
        try {
            pos = fc::to_uint64( p.index_position );
        } catch(...) {
            EOS_ASSERT( false, chain::contract_table_query_exception, "Invalid index_position: {p}", ("p", p.index_position));
        }
        if (pos < 2) {
            primary = true;
            pos = 0;
        } else {
            pos -= 2;
        }
    }
    index |= (pos & 0x000000000000000FULL);
    return index;
}

template <typename IndexType>
table_query::get_table_rows_result table_query::get_table_rows_ex( const table_query::get_table_rows_params& p, const abi_def& abi ) const {
    table_query::get_table_rows_result result;
    const auto& d = db.db();

    name scope { chain_apis::convert_to_type<uint64_t>(p.scope, "scope") };

    abi_serializer abis;
    abis.set_abi(abi, abi_serializer::create_yield_function( abi_serializer_max_time ));

    auto primary_lower = std::numeric_limits<uint64_t>::lowest();
    auto primary_upper = std::numeric_limits<uint64_t>::max();

    if( p.lower_bound.size() ) {
        if( p.key_type == "name" ) {
            name s(p.lower_bound);
            primary_lower = s.to_uint64_t();
        } else {
            auto lv = chain_apis::convert_to_type<typename IndexType::value_type::key_type>( p.lower_bound, "lower_bound" );
            primary_lower = lv;
        }
    }

    if( p.upper_bound.size() ) {
        if( p.key_type == "name" ) {
            name s(p.upper_bound);
            primary_upper = s.to_uint64_t();
        } else {
            auto uv = chain_apis::convert_to_type<typename IndexType::value_type::key_type>( p.upper_bound, "upper_bound" );
            primary_upper = uv;
        }
    }

    if( primary_upper < primary_lower )
        return result;

    auto get_prim_key = table_query::get_primary_key_value(p.table, abis, p.json, p.show_payer);
    auto handle_more = [&result,&p](const auto& row) {
        result.more = true;
        result.next_key = chain_apis::convert_to_string(row.primary_key, p.key_type, p.encode_type, "next_key - next lower bound");
    };

    const bool reverse = p.reverse && *p.reverse;
    
    const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(p.code, scope, p.table));
    if( t_id != nullptr ) {
        const auto& idx = d.get_index<IndexType, chain::by_scope_primary>();
        auto lower_bound_lookup_tuple = std::make_tuple( t_id->id, primary_lower );
        auto upper_bound_lookup_tuple = std::make_tuple( t_id->id, primary_upper );

        auto walk_table_row_range = [&]( auto itr, auto end_itr ) {
            keep_processing kp;
            vector<char> data;
            for( unsigned int count = 0; kp() && count < p.limit && itr != end_itr; ++count, ++itr ) {
            result.rows.emplace_back( get_prim_key(*itr) );
            }
            if( itr != end_itr ) {
            handle_more(*itr);
            }
        };

        auto lower = idx.lower_bound( lower_bound_lookup_tuple );
        auto upper = idx.upper_bound( upper_bound_lookup_tuple );
        if( reverse ) {
            walk_table_row_range( boost::make_reverse_iterator(upper), boost::make_reverse_iterator(lower) );
        } else {
            walk_table_row_range( lower, upper );
        }
    }
    return result;
}

fc::variant table_query::get_primary_key(name code, name scope, name table, uint64_t primary_key, table_query::row_requirements require_table,
                                       table_query::row_requirements require_primary, const std::string_view& type, bool as_json) const {
    const abi_def abi = eosio::chain_apis::get_abi(db, code);
    abi_serializer abis;
    abis.set_abi(abi, abi_serializer::create_yield_function(abi_serializer_max_time));
    return get_primary_key(code, scope, table, primary_key, require_table, require_primary, type, abis, as_json);
}

fc::variant table_query::get_primary_key(name code, name scope, name table, uint64_t primary_key, table_query::row_requirements require_table,
                                       table_query::row_requirements require_primary, const std::string_view& type, const abi_serializer& abis,
                                       bool as_json) const {
    fc::variant val;
    const auto valid = table_query::get_primary_key_internal(code, scope, table, primary_key, require_table, require_primary, get_primary_key_value(val, type, abis, as_json));
    return val;
}
}}
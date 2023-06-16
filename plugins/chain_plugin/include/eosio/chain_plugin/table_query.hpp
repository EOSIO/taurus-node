#pragma once
#include <eosio/chain/abi_def.hpp>
#include <eosio/chain/abi_serializer.hpp>
#include <eosio/chain/account_object.hpp>
#include <eosio/chain/asset.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/contract_table_objects.hpp>
#include <eosio/chain/db_util.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/fixed_bytes.hpp>
#include <fc/reflect/reflect.hpp>
#include <fc/static_variant.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cstdlib>

using std::string;
using std::vector;
namespace eosio {
namespace chain_apis {
    class table_query {
        const chain::controller &db;
        const fc::microseconds abi_serializer_max_time;
        bool shorten_abi_errors = true;

    public:
        static const string KEYi64;
        table_query(const chain::controller& db, const fc::microseconds& abi_serializer_max_time);
        void validate() const {}

        struct get_table_rows_params {
            bool                 json = false;
            chain::name                 code;
            string               scope;
            chain::name                 table;
            string               table_key;
            string               lower_bound;
            string               upper_bound;
            uint32_t             limit = 10;
            string               key_type;  // type of key specified by index_position
            string               index_position; // 1 - primary (first), 2 - secondary index (in order defined by multi_index), 3 - third index, etc
            string               encode_type{"dec"}; //dec, hex , default=dec
            std::optional<bool>  reverse;
            std::optional<bool>  show_payer; // show RAM pyer
        };

        struct get_kv_table_rows_params {
            bool                   json = false;          // true if you want output rows in json format, false as variant
            chain::name                   code;                  // name of contract
            chain::name                   table;                 // name of kv table,
            chain::name                   index_name;            // name of index index
            string                 encode_type;           // encoded type for values in index_value/lower_bound/upper_bound
            string                 index_value;           // index value for point query.  If this is set, it is processed as a point query
            string                 lower_bound;           // lower bound value of index of index_name. If index_value is not set and lower_bound is not set, return from the beginning of range in the prefix
            string                 upper_bound;           // upper bound value of index of index_name, If index_value is not set and upper_bound is not set, It is set to the beginning of the next prefix range.
            uint32_t               limit = 10;            // max number of rows
            bool                   reverse = false;       // if true output rows in reverse order
            bool                   show_payer = false;
        };

        struct get_table_rows_result {
            vector<fc::variant> rows; ///< one row per item, either encoded as hex String or JSON object
            bool                more = false; ///< true if last element in data is not the end and sizeof data() < limit
            string              next_key; ///< fill lower_bound with this value to fetch more rows
            string              next_key_bytes; ///< fill lower_bound with this value to fetch more rows with encode-type of "bytes"
        };

        struct get_table_by_scope_params {
            chain::name                 code; // mandatory
            chain::name                 table; // optional, act as filter
            string               lower_bound; // lower bound of scope, optional
            string               upper_bound; // upper bound of scope, optional
            uint32_t             limit = 10;
            std::optional<bool>  reverse;
        };

        struct get_table_by_scope_result_row {
            chain::name        code;
            chain::name        scope;
            chain::name        table;
            chain::name        payer;
            uint32_t    count;
        };

        struct get_table_by_scope_result {
            vector<get_table_by_scope_result_row> rows;
            string      more; ///< fill lower_bound with this value to fetch more rows
        };
        void set_shorten_abi_errors( bool f ) { shorten_abi_errors = f; }
        string get_table_type( const chain::abi_def& abi, const chain::name& table_name ) const;
        get_table_rows_result get_table_rows(const get_table_rows_params &p) const;
        get_table_rows_result get_kv_table_rows( const get_kv_table_rows_params& params ) const;
        get_table_by_scope_result get_table_by_scope( const get_table_by_scope_params& params ) const;
        static uint64_t get_table_index_name(const get_table_rows_params &p, bool &primary);
        template <typename IndexType, typename SecKeyType, typename ConvFn>
        get_table_rows_result get_table_rows_by_seckey( const get_table_rows_params& p, const chain::abi_def& abi, ConvFn conv ) const;
        template <typename IndexType>
        get_table_rows_result get_table_rows_ex( const get_table_rows_params& p, const chain::abi_def& abi ) const;

        enum class row_requirements { required, optional };

        fc::variant get_primary_key(chain::name code, chain::name scope, chain::name table, uint64_t primary_key, row_requirements require_table,
                                row_requirements require_primary, const std::string_view& type, bool as_json = true) const;
        fc::variant get_primary_key(chain::name code, chain::name scope, chain::name table, uint64_t primary_key, row_requirements require_table,
                                    row_requirements require_primary, const std::string_view& type, const chain::abi_serializer& abis,
                                    bool as_json = true) const;
        template<typename Function>
        bool get_primary_key_internal(chain::name code, chain::name scope, chain::name table, uint64_t primary_key, row_requirements require_table,
                                        row_requirements require_primary, Function&& f) const {
            
            const auto* const table_id =
                    db.db().find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(code, scope, table));
            if (require_table == row_requirements::optional && !table_id) {
                return false;
            }
            EOS_ASSERT(table_id, chain::contract_table_query_exception,
                        "Missing code: {code}, scope: {scope}, table: {table}",
                        ("code",code.to_string())("scope",scope.to_string())("table",table.to_string()));
            const auto& kv_index = db.db().get_index<chain::key_value_index, chain::by_scope_primary>();
            const auto it = kv_index.find(boost::make_tuple(table_id->id, primary_key));
            if (require_primary == row_requirements::optional && it == kv_index.end()) {
                return false;
            }
            EOS_ASSERT(it != kv_index.end(), chain::contract_table_query_exception,
                        "Missing row for primary_key: {primary} in code: {code}, scope: {scope}, table: {table}",
                        ("primary", primary_key)("code",code.to_string())("scope",scope.to_string())
                        ("table",table.to_string()));
            f(*it);
            return true;
        }
        template<typename T, typename Function>
        bool get_primary_key(chain::name code, chain::name scope, chain::name table, uint64_t primary_key, row_requirements require_table,
                                row_requirements require_primary, Function&& f) const {
            auto ret = get_primary_key_internal(code, scope, table, primary_key, require_table, require_primary, [&f](const auto& obj) {
                if( obj.value.size() >= sizeof(T) ) {
                    T t;
                    fc::datastream<const char *> ds(obj.value.data(), obj.value.size());
                    fc::raw::unpack(ds, t);

                    f(t);
                }
            });
            return ret;
        }

        template<typename KeyValueObj>
        static void copy_inline_row(const KeyValueObj& obj, vector<char>& data) {
            data.resize( obj.value.size() );
            memcpy( data.data(), obj.value.data(), obj.value.size() );
        }

        auto get_primary_key_value(const std::string_view& type, const chain::abi_serializer& abis, bool as_json = true) const {
            return [table_type=std::string{type},abis,as_json,this](fc::variant& result_var, const auto& obj) {
                vector<char> data;
                copy_inline_row(obj, data);
                if (as_json) {
                    result_var = abis.binary_to_variant(table_type, data, chain::abi_serializer::create_yield_function( abi_serializer_max_time ), shorten_abi_errors );
                }
                else {
                    result_var = fc::variant(data);
                }
            };
        }

        auto get_primary_key_value(fc::variant& result_var, const std::string_view& type, const chain::abi_serializer& abis, bool as_json = true) const {
            auto get_primary = get_primary_key_value(type, abis, as_json);
            return [&result_var,get_primary{std::move(get_primary)}](const auto& obj) {
                return get_primary(result_var, obj);
            };
        }

        auto get_primary_key_value(chain::name table, const chain::abi_serializer& abis, bool as_json, const std::optional<bool>& show_payer) const {
            return [abis,table,show_payer,as_json,this](const auto& obj) -> fc::variant {
                fc::variant data_var;
                auto get_prim = get_primary_key_value(data_var, abis.get_table_type(table), abis, as_json);
                get_prim(obj);

                if( show_payer && *show_payer ) {
                    return fc::mutable_variant_object("data", std::move(data_var))("payer", obj.payer);
                } else {
                    return data_var;
                }
            };
        }

        template<typename Function>
        void walk_key_value_table(const chain::name& code, const chain::name& scope, const chain::name& table, Function f) const {
            const auto& d = db.db();
            const auto* t_id = d.find<chain::table_id_object, chain::by_code_scope_table>(boost::make_tuple(code, scope, table));
            if (t_id != nullptr) {
                const auto &idx = d.get_index<chain::key_value_index, chain::by_scope_primary>();
                decltype(t_id->id) next_tid(t_id->id._id + 1);
                auto lower = idx.lower_bound(boost::make_tuple(t_id->id));
                auto upper = idx.lower_bound(boost::make_tuple(next_tid));

                for (auto itr = lower; itr != upper; ++itr) {
                    if (!f(*itr)) {
                    break;
                    }
                }
            }
        }
        
    };


    //support for --key_types [sha256,ripemd160] and --encoding [dec/hex]
    constexpr const char i64[]       = "i64";
    constexpr const char i128[]      = "i128";
    constexpr const char i256[]      = "i256";
    constexpr const char float64[]   = "float64";
    constexpr const char float128[]  = "float128";
    constexpr const char sha256[]    = "sha256";
    constexpr const char ripemd160[] = "ripemd160";
    constexpr const char dec[]       = "dec";
    constexpr const char hex[]       = "hex";


    // see specializations for uint64_t and double in source file
    template<typename Type>
    Type convert_to_type(const string& str, const string& desc);
    uint64_t convert_to_type(const chain::name &n, const string &desc);
    template<>
    uint64_t convert_to_type(const string& str, const string& desc);
    template<>
    double convert_to_type(const string& str, const string& desc);
    template<typename Type>
    string convert_to_string(const Type& source, const string& key_type, const string& encode_type, const string& desc);
    template<>
    string convert_to_string(const chain::key256_t& source, const string& key_type, const string& encode_type, const string& desc);
    template<>
    string convert_to_string(const float128_t& source, const string& key_type, const string& encode_type, const string& desc);
    chain::abi_def get_abi( const chain::controller& db, const chain::name& account );


    class keep_processing {
        public:
        explicit keep_processing(fc::microseconds&& duration = fc::milliseconds(10)) : end_time_(fc::time_point::now() + duration) {}

        fc::microseconds time_remaining() const { return end_time_ - fc::time_point::now(); }
        bool operator()() const {
            return time_remaining().count() >= 0;
        }
        private:
        fc::time_point end_time_;
    };
}}// namespace eosio::chain_apis 

FC_REFLECT( eosio::chain_apis::table_query::get_table_rows_params, (json)(code)(scope)(table)(table_key)(lower_bound)(upper_bound)(limit)(key_type)(index_position)(encode_type)(reverse)(show_payer) )
FC_REFLECT( eosio::chain_apis::table_query::get_kv_table_rows_params, (json)(code)(table)(index_name)(encode_type)(index_value)(lower_bound)(upper_bound)(limit)(reverse)(show_payer) )
FC_REFLECT( eosio::chain_apis::table_query::get_table_rows_result, (rows)(more)(next_key)(next_key_bytes) );

FC_REFLECT( eosio::chain_apis::table_query::get_table_by_scope_params, (code)(table)(lower_bound)(upper_bound)(limit)(reverse) )
FC_REFLECT( eosio::chain_apis::table_query::get_table_by_scope_result_row, (code)(scope)(table)(payer)(count));
FC_REFLECT( eosio::chain_apis::table_query::get_table_by_scope_result, (rows)(more) );
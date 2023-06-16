#pragma once
#include <eosio/to_key.hpp>
#include <eosio/chain/bit.hpp>
#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>
#include <cstdlib>

namespace eosio {
namespace chain_apis {
    /// short_string is intended to optimize the string equality comparison where one of the operand is
    /// no greater than 8 bytes long.
    struct short_string {
        uint64_t data = 0;

        template <size_t SIZE>
        short_string(const char (&str)[SIZE]) {
            static_assert(SIZE <= 8, "data has to be 8 bytes or less");
            memcpy(&data, str, SIZE);
        }

        short_string(std::string str) { memcpy(&data, str.c_str(), std::min(sizeof(data), str.size())); }

        bool empty() const { return data == 0; }

        friend bool operator==(short_string lhs, short_string rhs) { return lhs.data == rhs.data; }
        friend bool operator!=(short_string lhs, short_string rhs) { return lhs.data != rhs.data; }
    };
    template <typename Type, typename Enable = void>
    struct key_converter;

    inline void key_convert_assert(bool condition) {
        // EOS_ASSERT is avoided intentionally here because EOS_ASSERT would create the fc::log_message object which is
        // relatively expensive. The throw statement here is only used for flow control purpose, not for error reporting
        // purpose. 
        if (!condition)
            throw std::invalid_argument("");
    }

    // convert unsigned integer in hex representation back to its integer representation
    template <typename UnsignedInt>
    UnsignedInt unhex(const std::string& bytes_in_hex) {
        assert(bytes_in_hex.size() == 2 * sizeof(UnsignedInt));
        std::array<char, sizeof(UnsignedInt)> bytes;
        boost::algorithm::unhex(bytes_in_hex.begin(), bytes_in_hex.end(), bytes.rbegin());
        UnsignedInt result;
        memcpy(&result, bytes.data(), sizeof(result));
        return result;
    }

    template <typename IntType>
    struct key_converter<IntType, std::enable_if_t<std::is_integral_v<IntType>>> {
        static void to_bytes(const std::string& str, short_string encode_type, fixed_buf_stream& strm) {
            int base = 10;
            if (encode_type == "hex")
                base = 16;
            else
                key_convert_assert(encode_type.empty() || encode_type == "dec");

            size_t pos = 0;
            if constexpr (std::is_unsigned_v<IntType>) {
                uint64_t value = std::stoul(str, &pos, base);
                key_convert_assert(pos > 0 && value <= std::numeric_limits<IntType>::max());
                to_key(static_cast<IntType>(value), strm);
            } else {
                int64_t value = std::stol(str, &pos, base);
                key_convert_assert(pos > 0 && value <= std::numeric_limits<IntType>::max() &&
                                    value >= std::numeric_limits<IntType>::min());
                to_key(static_cast<IntType>(value), strm);
            }
        }

        static IntType value_from_hex(const std::string& bytes_in_hex) {
            auto unsigned_val = unhex<std::make_unsigned_t<IntType>>(bytes_in_hex);
            if ( std::bit_cast<IntType>(unsigned_val) < 0) {
                return unsigned_val + static_cast<std::make_unsigned_t<IntType>>(std::numeric_limits<IntType>::min());
            } else {
                return unsigned_val + std::numeric_limits<IntType>::min();
            }
        }

        static std::string from_hex(const std::string& bytes_in_hex, short_string encode_type) {
            IntType val = value_from_hex(bytes_in_hex);
            if (encode_type.empty() || encode_type == "dec") {
                return std::to_string(val);
            } else if (encode_type == "hex") {
                std::array<char, sizeof(IntType)> v;
                memcpy(v.data(), &val, sizeof(val));
                char result[2 * sizeof(IntType) + 1] = {'\0'};
                boost::algorithm::hex(v.rbegin(), v.rend(), result);
                return std::find_if_not(result, result + 2 * sizeof(IntType), [](char v) { return v == '0'; });
            }
            throw std::invalid_argument("");
        }
    };

    template <typename Float>
    struct key_converter<Float, std::enable_if_t<std::is_floating_point_v<Float>>> {
        static void to_bytes(const std::string& str, short_string encode_type, fixed_buf_stream& strm) {
            key_convert_assert(encode_type.empty() || encode_type == "dec");
            if constexpr (sizeof(Float) == 4) {
                to_key(std::stof(str), strm);
            } else {
                to_key(std::stod(str), strm);
            }
        }

        static Float value_from_hex(const std::string& bytes_in_hex) {
            using UInt = std::conditional_t<sizeof(Float) == 4, uint32_t, uint64_t>;
            UInt val   = unhex<UInt>(bytes_in_hex);

            UInt mask    = 0;
            UInt signbit = (static_cast<UInt>(1) << (std::numeric_limits<UInt>::digits - 1));
            if (!(val & signbit)) // flip mask if val is positive
                mask = ~mask;
            val ^= (mask | signbit);
            Float result;
            memcpy(&result, &val, sizeof(val));
            return result;
        }

        static std::string from_hex(const std::string& bytes_in_hex, short_string encode_type) {
            return std::to_string(value_from_hex(bytes_in_hex));
        }
    };

    template <>
    struct key_converter<chain::checksum256_type, void> {
        static void to_bytes(const std::string& str, short_string encode_type, fixed_buf_stream& strm) {
            key_convert_assert(encode_type.empty() || encode_type == "hex");
            chain::checksum256_type sha{str};
            strm.write(sha.data(), sha.data_size());
        }
        static std::string from_hex(const std::string& bytes_in_hex, short_string encode_type) { return bytes_in_hex; }
    };

    template <>
    struct key_converter<chain::name, void> {
        static void to_bytes(const std::string& str, short_string encode_type, fixed_buf_stream& strm) {
            key_convert_assert(encode_type.empty() || encode_type == "name");
            to_key(chain::name(str).to_uint64_t(), strm);
        }

        static std::string from_hex(const std::string& bytes_in_hex, short_string encode_type) {
            return chain::name(key_converter<uint64_t>::value_from_hex(bytes_in_hex)).to_string();
        }
    };

    template <>
    struct key_converter<std::string, void> {
        static void to_bytes(const std::string& str, short_string encode_type, fixed_buf_stream& strm) {
            key_convert_assert(encode_type.empty() || encode_type == "string");
            to_key(str, strm);
        }

        static std::string from_hex(const std::string& bytes_in_hex, short_string encode_type) {
            std::string result = boost::algorithm::unhex(bytes_in_hex);
            /// restore the string following the encoding rule from `template <typename S> to_key(std::string, S&)` in abieos
            /// to_key.hpp
            boost::replace_all(result, "\0\1", "\0");
            // remove trailing '\0\0'
            auto sz = result.size();
            if (sz >= 2 && result[sz - 1] == '\0' && result[sz - 2] == '\0')
                result.resize(sz - 2);
            return result;
        }
    };


namespace key_helper {
    /// Caution: the order of `key_type` and `key_type_ids` should match exactly.
    using key_types = std::tuple<int8_t, int16_t, int32_t, int64_t, uint8_t, uint16_t, uint32_t, uint64_t, float, double,
                                chain::name, chain::checksum256_type, chain::checksum256_type, std::string>;
    static const short_string key_type_ids[] = {"int8",   "int16",   "int32",   "int64", "uint8",  "uint16", "uint32",
                                                "uint64", "float32", "float64", "name",  "sha256", "i256",   "string"};

    static_assert(sizeof(key_type_ids) / sizeof(short_string) == std::tuple_size<key_types>::value,
                "key_type_ids and key_types must be of the same size and the order of their elements has to match");

    uint64_t type_string_to_function_index(short_string name) {
        unsigned index = std::find(std::begin(key_type_ids), std::end(key_type_ids), name) - std::begin(key_type_ids);
        key_convert_assert(index < std::tuple_size<key_types>::value);
        return index;
    }

    void write_key(std::string index_type, std::string encode_type, const std::string& index_value, fixed_buf_stream& strm) {
        try {
            // converts arbitrary hex strings to bytes ex) "FFFEFD" to {255, 254, 253}
            if (encode_type == "bytes") {
                strm.pos = boost::algorithm::unhex(index_value.begin(), index_value.end(), strm.pos);
                return;
            }

            if (index_type == "ripemd160") {
                key_convert_assert(encode_type.empty() || encode_type == "hex");
                chain::checksum160_type ripem160{index_value};
                strm.write(ripem160.data(), ripem160.data_size());
                return;
            }

            std::apply(
                [index_type, &index_value, encode_type, &strm](auto... t) {
                    using to_byte_fun_t         = void (*)(const std::string&, short_string, fixed_buf_stream&);
                    static to_byte_fun_t funs[] = {&key_converter<decltype(t)>::to_bytes...};
                    auto                 index  = type_string_to_function_index(index_type);
                    funs[index](index_value, encode_type, strm);
                },
                key_types{});
        } catch (...) { // for any type of exception, throw table query exception
            FC_THROW_EXCEPTION(chain::contract_table_query_exception,
                                "Incompatible index type/encode_type/Index_value: {t}/{e}/{v} ",
                                ("t", index_type)("e", encode_type)("v", index_value));
        }
    }

    std::string read_key(std::string index_type, std::string encode_type, const std::string& bytes_in_hex) {
        try {
            if (encode_type == "bytes" || index_type == "ripemd160")
                return bytes_in_hex;

            return std::apply(
                [index_type, bytes_in_hex, &encode_type](auto... t) {
                    using from_hex_fun_t         = std::string (*)(const std::string&, short_string);
                    static from_hex_fun_t funs[] = {&key_converter<decltype(t)>::from_hex...};
                    auto                    index  = type_string_to_function_index(index_type);
                    return funs[index](bytes_in_hex, encode_type);
                },
                key_types{});
        } catch (...) { // for any type of exception, throw table query exception
            FC_THROW_EXCEPTION(chain::contract_table_query_exception, "Unsupported index type/encode_type: {t}/{e} ",
                                ("t", index_type)("e", encode_type));
        }
    }
}}}// namespace eosio::chain_apis::key_helper
#pragma once

#include <fc/reflect/variant.hpp>
#include <stdexcept>

namespace eosio { namespace chain {

   enum class backing_store_type {
      CHAINBASE, // A name for regular users. Uses Chainbase.
   };
   
   inline void handle_db_exhaustion() {
      elog("database memory exhausted: increase chain-state-db-size-mb");
      //return 1 -- it's what programs/nodeos/main.cpp considers "BAD_ALLOC"
      std::_Exit(1);
   }

   inline void handle_bad_alloc() {
      elog("std::bad_alloc - memory exhausted");
      //return -2 -- it's what programs/nodeos/main.cpp reports for std::exception
      std::_Exit(-2);
   }
}} // namespace eosio::chain

namespace fc {
template <>
inline void to_variant(const eosio::chain::backing_store_type& store, fc::variant& v) {
   v = (uint64_t)store;
}
template <>
inline void from_variant(const fc::variant& v, eosio::chain::backing_store_type& store) {
   switch (store = (eosio::chain::backing_store_type)v.as_uint64()) {
      case eosio::chain::backing_store_type::CHAINBASE:
         return;
   }
   throw std::runtime_error("Invalid backing store name: " + v.as_string());
}
} // namespace fc

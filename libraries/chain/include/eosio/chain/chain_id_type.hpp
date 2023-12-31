#pragma once

#include <fc/crypto/sha256.hpp>

namespace eosio {

namespace p2p {
   class net_plugin_impl;
   struct handshake_message;
}

   namespace chain_apis {
      class read_only;
   }

   class chain_plugin;

namespace chain {

   namespace legacy {
      struct snapshot_global_property_object_v3;
      struct snapshot_global_property_object_v4;
   }

   struct chain_id_type : public fc::sha256 {
      using fc::sha256::sha256;

      template<typename T>
      inline friend T& operator<<( T& ds, const chain_id_type& cid ) {
        ds.write( cid.data(), cid.data_size() );
        return ds;
      }

      template<typename T>
      inline friend T& operator>>( T& ds, chain_id_type& cid ) {
        ds.read( cid.data(), cid.data_size() );
        return ds;
      }

      void reflector_init()const;

      bool empty() const { return *this == chain_id_type{};}

      private:
         chain_id_type() = default;

         // Some exceptions are unfortunately necessary:
         template<typename T>
         friend T fc::variant::as()const;

         friend class eosio::chain_apis::read_only;

         friend class eosio::p2p::net_plugin_impl;
         friend struct eosio::p2p::handshake_message;
         friend class block_log;
         friend struct block_log_preamble;
         friend struct block_log_verifier;
         friend class controller;
         friend struct controller_impl;
         friend class global_property_object;
         friend struct snapshot_global_property_object;
         friend struct legacy::snapshot_global_property_object_v3;
         friend struct legacy::snapshot_global_property_object_v4;
   };

} }  // namespace eosio::chain

namespace fc {
  class variant;
  void to_variant(const eosio::chain::chain_id_type& cid, fc::variant& v);
  void from_variant(const fc::variant& v, eosio::chain::chain_id_type& cid);
} // fc

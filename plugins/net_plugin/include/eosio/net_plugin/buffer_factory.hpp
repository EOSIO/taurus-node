#pragma once

#include "protocol.hpp"
#include "defaults.hpp"

namespace eosio { namespace p2p {

using send_buffer_type = std::shared_ptr<std::vector<char>>;

struct buffer_factory {

   /// caches result for subsequent calls, only provide same net_message instance for each invocation
   const send_buffer_type& get_send_buffer( const net_message& m ) {
      if( !send_buffer ) {
         send_buffer = create_send_buffer( m );
      }
      return send_buffer;
   }

protected:
   send_buffer_type send_buffer;

protected:
   static send_buffer_type create_send_buffer( const net_message& m );

   template< typename T>
   static send_buffer_type create_send_buffer( uint32_t which, const T& v );

};

struct block_buffer_factory : public buffer_factory {

   /// caches result for subsequent calls, only provide same signed_block_ptr instance for each invocation.
   /// protocol_version can differ per invocation as buffer_factory potentially caches multiple send buffers.
   const send_buffer_type& get_send_buffer( const chain::signed_block_ptr& sb, uint16_t protocol_version );

private:
   send_buffer_type send_buffer_v0;

private:

   static std::shared_ptr<std::vector<char>> create_send_buffer( const chain::signed_block_ptr& sb );
   static std::shared_ptr<std::vector<char>> create_send_buffer( const chain::signed_block_v0& sb_v0 );
};

struct trx_buffer_factory : public buffer_factory {

   /// caches result for subsequent calls, only provide same packed_transaction_ptr instance for each invocation.
   /// protocol_version can differ per invocation as buffer_factory potentially caches multiple send buffers.
   const send_buffer_type& get_send_buffer( const chain::packed_transaction_ptr& trx, uint16_t protocol_version );
private:
   send_buffer_type send_buffer_v0;

private:

   static std::shared_ptr<std::vector<char>> create_send_buffer( const chain::packed_transaction_ptr& trx );
   static std::shared_ptr<std::vector<char>> create_send_buffer( const chain::packed_transaction_v0& trx );
};

}} //eosio::p2p

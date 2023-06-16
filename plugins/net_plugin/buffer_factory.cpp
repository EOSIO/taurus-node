#include <eosio/net_plugin/buffer_factory.hpp>
#include <eosio/net_plugin/net_plugin_impl.hpp>

using namespace eosio::chain;

namespace eosio { namespace p2p {

send_buffer_type buffer_factory::create_send_buffer( const net_message& m ) {
   const uint32_t payload_size = fc::raw::pack_size( m );

   const char* header = reinterpret_cast<const char*>(&payload_size); // avoid variable size encoding of uint32_t
   constexpr size_t header_size = sizeof(payload_size);
   static_assert( header_size == message_header_size, "invalid message_header_size" );
   const size_t buffer_size = header_size + payload_size;

   auto send_buffer = std::make_shared<std::vector<char>>(buffer_size);
   fc::datastream<char*> ds( send_buffer->data(), buffer_size);
   ds.write( header, header_size );
   fc::raw::pack( ds, m );

   return send_buffer;
}

template< typename T>
send_buffer_type buffer_factory::create_send_buffer( uint32_t which, const T& v ) {
   // match net_message static_variant pack
   const uint32_t which_size = fc::raw::pack_size( unsigned_int( which ) );
   const uint32_t payload_size = which_size + fc::raw::pack_size( v );

   const char* const header = reinterpret_cast<const char* const>(&payload_size); // avoid variable size encoding of uint32_t
   constexpr size_t header_size = sizeof( payload_size );
   static_assert( header_size == message_header_size, "invalid message_header_size" );
   const size_t buffer_size = header_size + payload_size;

   auto send_buffer = std::make_shared<vector<char>>( buffer_size );
   fc::datastream<char*> ds( send_buffer->data(), buffer_size );
   ds.write( header, header_size );
   fc::raw::pack( ds, unsigned_int( which ) );
   fc::raw::pack( ds, v );

   return send_buffer;
}

std::shared_ptr<std::vector<char>> block_buffer_factory::create_send_buffer( const signed_block_ptr& sb ) {
   static_assert( signed_block_which == fc::get_index<net_message, signed_block>() );
   // this implementation is to avoid copy of signed_block to net_message
   // matches which of net_message for signed_block
   fc_dlog( net_plugin_impl::get_logger(), "sending block {bn}", ("bn", sb->block_num()) );
   return buffer_factory::create_send_buffer( signed_block_which, *sb );
}

std::shared_ptr<std::vector<char>> block_buffer_factory::create_send_buffer( const signed_block_v0& sb_v0 ) {
   static_assert( signed_block_v0_which == fc::get_index<net_message, signed_block_v0>() );
   // this implementation is to avoid copy of signed_block_v0 to net_message
   // matches which of net_message for signed_block_v0
   fc_dlog( net_plugin_impl::get_logger(), "sending v0 block {bn}", ("bn", sb_v0.block_num()) );
   return buffer_factory::create_send_buffer( signed_block_v0_which, sb_v0 );
}

const send_buffer_type& block_buffer_factory::get_send_buffer( const signed_block_ptr& sb, uint16_t protocol_version ) {
   if( protocol_version >= proto_pruned_types ) {
      if( !send_buffer ) {
         send_buffer = create_send_buffer( sb );
      }
      return send_buffer;
   } else {
      if( !send_buffer_v0 ) {
         const auto v0 = sb->to_signed_block_v0();
         if( !v0 ) return send_buffer_v0;
         send_buffer_v0 = create_send_buffer( *v0 );
      }
      return send_buffer_v0;
   }
}

std::shared_ptr<std::vector<char>> trx_buffer_factory::create_send_buffer( const packed_transaction_ptr& trx ) {
   static_assert( trx_message_v1_which == fc::get_index<net_message, trx_message_v1>() );
   std::optional<transaction_id_type> trx_id;
   if( trx->get_estimated_size() > 1024 ) { // simple guess on threshold
      fc_dlog( net_plugin_impl::get_logger(), "including trx id, est size: {es}", ("es", trx->get_estimated_size()) );
      trx_id = trx->id();
   }
   // const cast required, trx_message_v1 has non-const shared_ptr because FC_REFLECT does not work with const types
   trx_message_v1 v1{std::move( trx_id ), std::const_pointer_cast<packed_transaction>( trx )};
   return buffer_factory::create_send_buffer( trx_message_v1_which, v1 );
}

std::shared_ptr<std::vector<char>> trx_buffer_factory::create_send_buffer( const packed_transaction_v0& trx ) {
   static_assert( packed_transaction_v0_which == fc::get_index<net_message, packed_transaction_v0>() );
   // this implementation is to avoid copy of packed_transaction_v0 to net_message
   // matches which of net_message for packed_transaction_v0
   return buffer_factory::create_send_buffer( packed_transaction_v0_which, trx );
}

const send_buffer_type& trx_buffer_factory::get_send_buffer( const packed_transaction_ptr& trx, uint16_t protocol_version ) {
   if( protocol_version >= proto_pruned_types ) {
      if( !send_buffer ) {
         send_buffer = create_send_buffer( trx );
      }
      return send_buffer;
   } else {
      if( !send_buffer_v0 ) {
         const auto v0 = trx->to_packed_transaction_v0();
         if( !v0 ) return send_buffer_v0;
         send_buffer_v0 = create_send_buffer( *v0 );
      }
      return send_buffer_v0;
   }
}

}} //eosio::p2p

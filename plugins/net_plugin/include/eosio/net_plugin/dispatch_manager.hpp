#pragma once

#include <eosio/chain/types.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/net_plugin/connection.hpp>

#include <boost/asio.hpp>

namespace eosio { namespace p2p {

struct by_peer_block_id;
struct by_block_num;
struct by_expiry;

struct peer_block_state {
   chain::block_id_type id;
   uint32_t      block_num = 0;
   uint32_t      connection_id = 0;
};

struct node_transaction_state {
   chain::transaction_id_type id;
   chain::time_point_sec  expires;        /// time after which this may be purged.
   uint32_t        block_num = 0;  /// block transaction was included in
   uint32_t        connection_id = 0;
};

struct update_block_num {
   uint32_t new_bnum;
   explicit update_block_num(uint32_t bnum) : new_bnum(bnum) {}
   void operator() (node_transaction_state& nts) {
      nts.block_num = new_bnum;
   }
};

typedef boost::multi_index_container<
   peer_block_state,
   indexed_by<
      ordered_unique< tag<by_id>,
            composite_key< peer_block_state,
                  member<peer_block_state, uint32_t, &peer_block_state::connection_id>,
                  member<peer_block_state, chain::block_id_type, &peer_block_state::id>
            >,
            composite_key_compare< std::less<uint32_t>, chain::sha256_less >
      >,
      ordered_non_unique< tag<by_peer_block_id>, member<peer_block_state, chain::block_id_type, &peer_block_state::id>,
            chain::sha256_less
      >,
      ordered_non_unique< tag<by_block_num>, member<peer_block_state, uint32_t, &peer_block_state::block_num > >
   >
   > peer_block_state_index;

typedef boost::multi_index_container<
   node_transaction_state,
   indexed_by<
      ordered_unique<
         tag<by_id>,
         composite_key< node_transaction_state,
            member<node_transaction_state, chain::transaction_id_type, &node_transaction_state::id>,
            member<node_transaction_state, uint32_t, &node_transaction_state::connection_id>
         >,
         composite_key_compare< chain::sha256_less, std::less<uint32_t> >
      >,
      ordered_non_unique<
         tag< by_expiry >,
         member< node_transaction_state, fc::time_point_sec, &node_transaction_state::expires > >,
      ordered_non_unique<
         tag<by_block_num>,
         member< node_transaction_state, uint32_t, &node_transaction_state::block_num > >
      >
   >
node_transaction_index;

class dispatch_manager {
   using connection_ptr = typename connection::ptr;

   mutable std::mutex      blk_state_mtx;
   peer_block_state_index  blk_state;
   mutable std::mutex      local_txns_mtx;
   node_transaction_index  local_txns;

public:
   boost::asio::io_context::strand  strand;

   explicit dispatch_manager(boost::asio::io_context& io_context)
   : strand( io_context ) {}

   fc::logger& get_logger();
   const std::string& peer_log_format();

   void bcast_transaction(const chain::packed_transaction_ptr& trx);
   void rejected_transaction(const chain::packed_transaction_ptr& trx, uint32_t head_blk_num);
   void bcast_block( const chain::signed_block_ptr& b, const chain::block_id_type& id );
   void rejected_block(const chain::block_id_type& id);

   void recv_block(const connection_ptr& conn, const chain::block_id_type& msg, uint32_t bnum);
   void expire_blocks( uint32_t bnum );
   void recv_notice(const connection_ptr& conn, const notice_message& msg, bool generated);

   void retry_fetch(const connection_ptr& conn);

   bool add_peer_block( const chain::block_id_type& blkid, uint32_t connection_id );
   bool peer_has_block(const chain::block_id_type& blkid, uint32_t connection_id) const;
   bool have_block(const chain::block_id_type& blkid) const;
   bool rm_peer_block( const chain::block_id_type& blkid, uint32_t connection_id );

   bool add_peer_txn( const node_transaction_state& nts );
   bool add_peer_txn( const chain::transaction_id_type& tid, uint32_t connection_id );
   void update_txns_block_num( const chain::signed_block_ptr& sb );
   void update_txns_block_num( const chain::transaction_id_type& id, uint32_t blk_num );
   bool peer_has_txn( const chain::transaction_id_type& tid, uint32_t connection_id ) const;
   bool have_txn( const chain::transaction_id_type& tid ) const;
   void expire_txns( uint32_t lib_num );
};

}} //eosio::p2p

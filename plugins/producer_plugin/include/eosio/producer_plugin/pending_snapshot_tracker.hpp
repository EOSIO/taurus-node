#pragma once

#include <eosio/producer_plugin/pending_snapshot.hpp>
#include <eosio/chain/types.hpp>
#include <eosio/chain/controller.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/filesystem/path.hpp>

namespace eosio {

template<typename T>
using next_function = std::function<void(const std::variant<fc::exception_ptr, T>&)>;

/**
 * Keeps track of pending snapshots for producer.
 * Snapshots are promoted to ready for user once it reaches LIB.
 */
class pending_snapshot_tracker {
public:

   pending_snapshot_tracker() = default;

   /// Where to write the snapshot
   void set_snapshot_dir(boost::filesystem::path p) { _snapshots_dir = std::move(p); }

   /// Connected and called by irreversible_block signal.
   /// Reports back to caller via next callback register in create_snapshot.
   /// @param lib_height LIB block number
   void promote_pending_snapshots(const chain::controller& chain, uint32_t lib_height);

   /// Called via /v1/producer/create_snapshot
   /// @param next is the callback to the user with snapshot_information
   void create_snapshot(const chain::controller& chain, next_function<snapshot_information> next);

private:
   struct by_id;
   struct by_height;

   using pending_snapshot_index_t = boost::multi_index::multi_index_container<
         pending_snapshot,
         indexed_by<
               boost::multi_index::hashed_unique<tag<by_id>, BOOST_MULTI_INDEX_MEMBER(pending_snapshot, chain::block_id_type, block_id)>,
               ordered_non_unique<tag<by_height>, BOOST_MULTI_INDEX_CONST_MEM_FUN( pending_snapshot, uint32_t, get_height)>
         >
   >;

   pending_snapshot_index_t _pending_snapshot_index;
   // path to write the snapshots to
   boost::filesystem::path _snapshots_dir;

};

} // namespace eosio

#pragma once

#include <eosio/chain/block_header.hpp>
#include <eosio/chain/types.hpp>

#include <boost/filesystem/path.hpp>

namespace eosio {

struct snapshot_information {
   chain::block_id_type head_block_id;
   uint32_t             head_block_num{};
   fc::time_point       head_block_time;
   uint32_t             version{};
   std::string          snapshot_name;
};

/**
 * Used by pending_snapshot_tracker for tracking individual snapshot requests from users.
 */
class pending_snapshot {
public:
   using next_t = std::function<void(const std::variant<fc::exception_ptr, snapshot_information>&)>;


   pending_snapshot(const chain::block_id_type& block_id, next_t& next, std::string pending_path, std::string final_path)
   : block_id(block_id)
   , next(next)
   , pending_path(pending_path)
   , final_path(final_path)
   {}

   uint32_t get_height() const {
      return chain::block_header::num_from_id(block_id);
   }

   static boost::filesystem::path
   get_final_path(const chain::block_id_type& block_id, const boost::filesystem::path& snapshots_dir) {
      return snapshots_dir / fc::format_string("snapshot-${id}.bin", fc::mutable_variant_object()("id", block_id));
   }

   static boost::filesystem::path
   get_pending_path(const chain::block_id_type& block_id, const boost::filesystem::path& snapshots_dir) {
      return snapshots_dir / fc::format_string(".pending-snapshot-${id}.bin", fc::mutable_variant_object()("id", block_id));
   }

   static boost::filesystem::path
   get_temp_path(const chain::block_id_type& block_id, const boost::filesystem::path& snapshots_dir) {
      return snapshots_dir / fc::format_string(".incomplete-snapshot-${id}.bin", fc::mutable_variant_object()("id", block_id));
   }

   snapshot_information finalize( const chain::controller& chain ) const;

   chain::block_id_type     block_id;
   next_t                   next;
   std::string              pending_path;
   std::string              final_path;
};

} // namespace eosio

FC_REFLECT(eosio::snapshot_information, (head_block_id)(head_block_num)(head_block_time)(version)(snapshot_name))

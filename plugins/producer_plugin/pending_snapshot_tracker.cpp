#include <eosio/producer_plugin/pending_snapshot_tracker.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>

namespace bfs = boost::filesystem;

namespace eosio {

void pending_snapshot_tracker::promote_pending_snapshots(const chain::controller& chain, uint32_t lib_height) {
   auto& snapshots_by_height = _pending_snapshot_index.get<by_height>();

   while( !snapshots_by_height.empty() && snapshots_by_height.begin()->get_height() <= lib_height ) {
      const auto& pending = snapshots_by_height.begin();
      auto next = pending->next;

      try {
         next( pending->finalize( chain ) );
      } CATCH_AND_CALL( next );

      snapshots_by_height.erase( snapshots_by_height.begin() );
   }
}

void pending_snapshot_tracker::create_snapshot(const chain::controller& chain, next_function<snapshot_information> next) {

   auto head_id = chain.head_block_id();
   const auto head_block_num = chain.head_block_num();
   const auto head_block_time = chain.head_block_time();
   const auto& snapshot_path = pending_snapshot::get_final_path(head_id, _snapshots_dir);
   const auto& temp_path     = pending_snapshot::get_temp_path(head_id, _snapshots_dir);

   // maintain legacy exception if the snapshot exists
   if( fc::is_regular_file(snapshot_path) ) {
      auto ex = chain::snapshot_exists_exception( FC_LOG_MESSAGE( error, "snapshot named {name} already exists",
                                                                  ("name", snapshot_path.generic_string()) ) );
      next(ex.dynamic_copy_exception());
      return;
   }

   auto write_snapshot = [&]( const bfs::path& p ) -> void {
      bfs::create_directory( p.parent_path() );

      // create the snapshot
      auto snap_out = std::ofstream(p.generic_string(), (std::ios::out | std::ios::binary));
      auto writer = std::make_shared<chain::ostream_snapshot_writer>(snap_out);
      chain.write_snapshot(writer);
      writer->finalize();
      snap_out.flush();
      snap_out.close();
   };

   // If in irreversible mode, create snapshot and return path to snapshot immediately.
   if( chain.get_read_mode() == chain::db_read_mode::IRREVERSIBLE ) {
      try {
         write_snapshot( temp_path );

         boost::system::error_code ec;
         bfs::rename(temp_path, snapshot_path, ec);
         EOS_ASSERT(!ec, chain::snapshot_finalization_exception,
                    "Unable to finalize valid snapshot of block number {bn}: [code: {ec}] {message}",
                    ("bn", head_block_num)("ec", ec.value())("message", ec.message()));

         next( snapshot_information{
            head_id,
            head_block_num,
            head_block_time,
            chain::chain_snapshot_header::current_version,
            snapshot_path.generic_string()
         } );

      } CATCH_AND_CALL (next);
      return;
   }

   // Otherwise, the result will be returned when the snapshot becomes irreversible.

   // determine if this snapshot is already in-flight
   auto& pending_by_id = _pending_snapshot_index.get<by_id>();
   auto existing = pending_by_id.find(head_id);
   if( existing != pending_by_id.end() ) {
      // if a snapshot at this block is already pending, attach this requests handler to it
      pending_by_id.modify(existing, [&next]( auto& entry ){
         entry.next = [prev = entry.next, next](const std::variant<fc::exception_ptr, snapshot_information>& res){
            prev(res);
            next(res);
         };
      });
   } else {
      const auto& pending_path = pending_snapshot::get_pending_path(head_id, _snapshots_dir);

      try {
         write_snapshot( temp_path ); // create a new pending snapshot

         boost::system::error_code ec;
         bfs::rename(temp_path, pending_path, ec);
         EOS_ASSERT(!ec, chain::snapshot_finalization_exception,
                    "Unable to promote temp snapshot to pending for block number {bn}: [code: {ec}] {message}",
                    ("bn", head_block_num)("ec", ec.value())("message", ec.message()));

         _pending_snapshot_index.emplace(head_id, next, pending_path.generic_string(), snapshot_path.generic_string());
      } CATCH_AND_CALL (next);
   }
}


} // namespace eosio

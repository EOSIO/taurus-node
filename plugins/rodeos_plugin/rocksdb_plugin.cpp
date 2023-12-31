#include <eosio/rodeos_plugin/rocksdb_plugin.hpp>

#include <boost/filesystem.hpp>
#include <fc/exception/exception.hpp>
namespace b1 {

using namespace appbase;
using namespace std::literals;

struct rocksdb_plugin_impl {
   boost::filesystem::path             db_path        = {};
   std::optional<bfs::path>            options_file_name = {};
   std::shared_ptr<chain_kv::database> database       = {};
   std::mutex                          mutex          = {};
};

static abstract_plugin& _rocksdb_plugin = app().register_plugin<rocksdb_plugin>();

rocksdb_plugin::rocksdb_plugin() : my(std::make_shared<rocksdb_plugin_impl>()) {}

rocksdb_plugin::~rocksdb_plugin() {}

void rocksdb_plugin::set_program_options(options_description& cli, options_description& cfg) {
   auto op = cfg.add_options();
   op("rdb-options-file", bpo::value<bfs::path>(),
      "File (including path) store RocksDB options. Must follow INI file format. Consult RocksDB documentation for details.");
   op("rdb-threads", bpo::value<uint32_t>(),
      "Deprecated. Please use max_background_jobs in options file to configure it. Default is 20. An example options file is <build-dir>/programs/rodeos/rocksdb_options.ini");
   op("rdb-max-files", bpo::value<uint32_t>(),
      "Deprecated. Please use max_open_files in options file to configure it. Default is 765. An example options file is <build-dir>/programs/rodeos/rocksdb_options.ini");
}

void rocksdb_plugin::plugin_initialize(const variables_map& options) {
   try {
      EOS_ASSERT(options["rdb-threads"].empty(), eosio::chain::plugin_config_exception, "rdb-threads is deprecated. Please use max_background_jobs in options file to configure it. Default is 20. An example options file is <build-dir>/programs/rodeos/rocksdb_options.ini");
      EOS_ASSERT(options["rdb-max-files"].empty(), eosio::chain::plugin_config_exception, "rdb-max-files is deprecated. Please use max_open_files in options file to configure it. Default is 765. An example options file is <build-dir>/programs/rodeos/rocksdb_options.ini");

      // On start up, rocksdb_plugin::get_db() will remove existing "rodeos.rocksdb" directory from nodeos's data dir. To ensure safety, this dir should be a regular dir instead of linking to somewhere.
      my->db_path = app().data_dir() / "rodeos.rocksdb";
      EOS_ASSERT(!bfs::is_symlink(my->db_path), eosio::chain::plugin_config_exception, "For security concerns, {d} can't be a symbolic link. Please resolve.", ("d", my->db_path.string()));

      if (!options["rdb-options-file"].empty()) {
         my->options_file_name = options["rdb-options-file"].as<bfs::path>();
         EOS_ASSERT( bfs::exists(*my->options_file_name), eosio::chain::plugin_config_exception, "options file {f} does not exist.", ("f", my->options_file_name->string()) );
      } else {
         wlog("--rdb-options-file is not configured! RocksDB system default options will be used. Check <build-dir>/programs/rodeos/rocksdb_options.ini on how to set options appropriate to your application.");
      }
   }
   FC_LOG_AND_RETHROW()
}

void rocksdb_plugin::plugin_startup() {}

void rocksdb_plugin::plugin_shutdown() {}

std::shared_ptr<chain_kv::database> rocksdb_plugin::get_db() {
   std::lock_guard<std::mutex> lock(my->mutex);
   if (!my->database) {
      if (bfs::exists(my->db_path)) {
         wlog("removing rodeos-plugin's old RocksDB database directory at {d}",
              ("d", my->db_path.string()));
         bfs::remove_all(my->db_path);
      }
      ilog("rodeos database is {d}", ("d", my->db_path.string()));
      if (!bfs::exists(my->db_path.parent_path())) {
         bfs::create_directories(my->db_path.parent_path());
      }
      my->database = std::make_shared<chain_kv::database>(my->db_path.c_str(), true, my->options_file_name);
   }
   return my->database;
}

} // namespace b1

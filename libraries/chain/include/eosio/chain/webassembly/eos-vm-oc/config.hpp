#pragma once

#include <istream>
#include <ostream>
#include <vector>
#include <string>

#include <boost/filesystem/path.hpp>
#include <fc/reflect/reflect.hpp>
#include <chainbase/pinnable_mapped_file.hpp>

namespace eosio { namespace chain { namespace eosvmoc {

struct config {
   uint64_t cache_size = 1024u*1024u*1024u;
   uint64_t threads    = 1u;
   chainbase::pinnable_mapped_file::map_mode map_mode = chainbase::pinnable_mapped_file::map_mode::mapped;
   bool persistent = true;
   bool reset_on_invalid = true; // used for unittest so see if we can detect the cache is valid or not.
   bool tierup = false;
};

}}}

#pragma once

#include <eosio/chain/types.hpp>
#include <fc/filesystem.hpp>

namespace eosio {
namespace chain {

namespace webassembly {
class interface;
}
struct native_module_context_type {
   virtual boost::filesystem::path code_dir()                    = 0;
   virtual void                    push(webassembly::interface*) = 0;
   virtual void                    pop()                         = 0;
};

struct native_module_config {
   native_module_context_type* native_module_context = nullptr;
};
} // namespace chain
} // namespace eosio
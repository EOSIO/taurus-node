#pragma once

namespace b1::rodeos {
namespace filter {
struct callbacks;
}
namespace wasm_ql {
struct callbacks;
}
struct native_module_context_type {
   virtual boost::filesystem::path code_dir()                = 0;
   virtual void                    push(filter::callbacks*)  = 0;
   virtual void                    push(wasm_ql::callbacks*) = 0;
   virtual void                    pop()                     = 0;
};
} // namespace b1::rodeos
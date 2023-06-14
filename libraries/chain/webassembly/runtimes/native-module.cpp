#include <eosio/chain/apply_context.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/webassembly/interface.hpp>
#include <eosio/chain/webassembly/native-module.hpp>
#include <fc/scoped_exit.hpp>

#include <dlfcn.h>

namespace eosio {
namespace chain {

native_instantiated_module::native_instantiated_module(const fc::path&             module_file,
                                                       native_module_context_type* native_context)
    : native_context(native_context)
    , apply_fun(module_file.string().c_str(), "apply") {}

void native_instantiated_module::apply(apply_context& context) {
   webassembly::interface ifs(context);
   native_context->push(&ifs);
   auto on_exit = fc::make_scoped_exit([this]() { native_context->pop(); });

   apply_fun.exec<void (*)(uint64_t, uint64_t, uint64_t)>(context.get_receiver().to_uint64_t(),
                                                          context.get_action().account.to_uint64_t(),
                                                          context.get_action().name.to_uint64_t());
}

native_runtime::native_runtime(const native_module_config& config)
    : config(config) {
   EOS_ASSERT(config.native_module_context, misc_exception, "invalid native_module_context");
}

bool native_runtime::inject_module(IR::Module& module) { return false; };

std::unique_ptr<wasm_instantiated_module_interface> native_runtime::instantiate_module(const char*, size_t,
                                                                                       std::vector<uint8_t>,
                                                                                       const digest_type& code_hash,
                                                                                       const uint8_t&, const uint8_t&) {
   return std::make_unique<native_instantiated_module>(
       config.native_module_context->code_dir() / (code_hash.str() + ".so"), config.native_module_context);
}

void native_runtime::immediately_exit_currently_running_module() {}

} // namespace chain
} // namespace eosio
#pragma once

#include "dynamic_loaded_function.hpp"
#include "native-module-config.hpp"
#include "runtime_interface.hpp"

namespace eosio {
namespace chain {

class native_instantiated_module : public wasm_instantiated_module_interface {
 public:
   native_instantiated_module(const fc::path&, native_module_context_type* native_context);
   void apply(apply_context& context) override;

 private:
   native_module_context_type* native_context;
   dynamic_loaded_function     apply_fun;
};

class native_runtime : public wasm_runtime_interface {
 public:
   explicit native_runtime(const native_module_config& config);
   bool inject_module(IR::Module& module) override;
   std::unique_ptr<wasm_instantiated_module_interface>
   instantiate_module(const char* code_bytes, size_t code_size, std::vector<uint8_t> initial_memory,
                      const digest_type& code_hash, const uint8_t& vm_type, const uint8_t& vm_version) override;

   // immediately exit the currently running wasm_instantiated_module_interface. Yep, this assumes only one can
   // possibly run at a time.
   void immediately_exit_currently_running_module() override;

 private:
   native_module_config config;
};

} // namespace chain
} // namespace eosio
#pragma once
#include <eosio/vm/host_function.hpp>
#include <eosio/chain/webassembly/eos-vm-oc/memory.hpp>
#include <tuple>
#include <type_traits>
#include "IR/Types.h"

namespace eosio::chain::eosvmoc {

/**
 * validate an in-wasm-memory array
 * @tparam T
 *
 * When a pointer will be invalid we want to stop execution right here right now. This is accomplished by forcing a read from an address
 * that must always be bad. A better approach would probably be to call in to a function that notes the invalid parameter and host function
 * and then bubbles up a more useful error message; maybe some day. Prior to WASM_LIMITS the code just simply did a load from address 33MB via
 * an immediate. 33MB was always invalid since 33MB was the most WASM memory you could have. Post WASM_LIMITS you theoretically could
 * have up to 4GB, but we can't do a load from a 4GB immediate since immediates are limited to signed 32bit ranges.
 *
 * So instead access the first_invalid_memory_address which by its name will always be invalid. Or will it? No... it won't, since it's
 * initialized to -1*64KB in the case WASM has _no_ memory! We actually cannot clamp first_invalid_memory_address to 0 during initialization
 * in such a case since there is some historical funny business going on when end==0 (note how jle will _pass_ when end==0 & first_invalid_memory_address==0)
 *
 * So instead just bump first_invalid_memory_address another 64KB before accessing it. If it's -64KB it'll go to 0 which fails correctly in that case.
 * If it's 4GB it'll go to 4GB+64KB which still fails too (there is an entire 8GB range of WASM memory set aside). There are other more straightforward
 * ways of accomplishing this, but at least this approach has zero overhead (e.g. no additional register usage, etc) in the nominal case.
 * */
template<typename T>
inline void* array_ptr_impl (size_t ptr, size_t length)
{
   constexpr int cb_full_linear_memory_start_segment_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(full_linear_memory_start);
   constexpr int cb_first_invalid_memory_address_segment_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(first_invalid_memory_address);

   size_t end = ptr + length*sizeof(T);

   asm volatile("cmp %%gs:%c[firstInvalidMemory], %[End]\n"
                "jle 1f\n"
                "mov %%gs:%c[firstInvalidMemory], %[End]\n"      // sets End with a known failing address
                "add %[sizeOfOneWASMPage], %[End]\n"             // see above comment
                "mov %%gs:(%[End]), %[Ptr]\n"                    // loads from the known failing address
                "1:\n"
                "add %%gs:%c[linearMemoryStart], %[Ptr]\n"
                : [Ptr] "+r" (ptr),
                  [End] "+r" (end)
                : [linearMemoryStart] "i" (cb_full_linear_memory_start_segment_offset),
                  [firstInvalidMemory] "i" (cb_first_invalid_memory_address_segment_offset),
                  [sizeOfOneWASMPage] "i" (wasm_constraints::wasm_page_size)
                : "cc"
               );


   return (void*)ptr;
}

/**
 * validate an in-wasm-memory char array that must be null terminated
 */
inline char* null_terminated_ptr_impl(uint64_t ptr)
{
   constexpr int cb_full_linear_memory_start_segment_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(full_linear_memory_start);
   constexpr int cb_first_invalid_memory_address_segment_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(first_invalid_memory_address);

   char dumpster;
   uint64_t scratch;

   asm volatile("mov %%gs:(%[Ptr]), %[Dumpster]\n"                   //probe memory location at ptr to see if valid
                "mov %%gs:%c[firstInvalidMemory], %[Scratch]\n"      //get first invalid memory address
                "cmpb $0, %%gs:-1(%[Scratch])\n"                     //is last byte in valid linear memory 0?
                "je 2f\n"                                            //if so, this will be a null terminated string one way or another
                "mov %[Ptr],%[Scratch]\n"
                "1:\n"                                               //start loop looking for either 0, or until we SEGV
                "inc %[Scratch]\n"
                "cmpb $0,%%gs:-1(%[Scratch])\n"
                "jne 1b\n"
                "2:\n"
                "add %%gs:%c[linearMemoryStart], %[Ptr]\n"           //add address of linear memory 0 to ptr
                : [Ptr] "+r" (ptr),
                  [Dumpster] "=r" (dumpster),
                  [Scratch] "=r" (scratch)
                : [linearMemoryStart] "i" (cb_full_linear_memory_start_segment_offset),
                  [firstInvalidMemory] "i" (cb_first_invalid_memory_address_segment_offset)
                : "cc"
               );

   return (char*)ptr;
}

inline auto convert_native_to_wasm(char* ptr) {
   constexpr int cb_full_linear_memory_start_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(full_linear_memory_start);
   char* full_linear_memory_start;
   asm("mov %%gs:%c[fullLinearMemOffset], %[fullLinearMem]\n"
      : [fullLinearMem] "=r" (full_linear_memory_start)
      : [fullLinearMemOffset] "i" (cb_full_linear_memory_start_offset)
      );
   U64 delta = (U64)(ptr - full_linear_memory_start);
   return (U32)delta;
}

struct eos_vm_oc_execution_interface {
   inline const auto& operand_from_back(std::size_t index) const { return *(os - index - 1); }

   template <typename T>
   inline void* validate_pointer(vm::wasm_ptr_t ptr, vm::wasm_size_t len) const {
      return array_ptr_impl<T>(ptr, len);
   }

   inline void* validate_null_terminated_pointer(vm::wasm_ptr_t ptr) const {
      return null_terminated_ptr_impl(ptr);
   }

   eosio::vm::native_value* os;
};

template<typename TC, typename Args, std::size_t... Is>
auto get_ct_args(std::index_sequence<Is...>);

inline uint32_t make_native_type(vm::i32_const_t x) { return x.data.ui; }
inline uint64_t make_native_type(vm::i64_const_t x) { return x.data.ui; }
inline float make_native_type(vm::f32_const_t x) { return x.data.f; }
inline double make_native_type(vm::f64_const_t x) { return x.data.f; }

template<typename TC, typename Args, std::size_t... Is>
auto get_ct_args_one(std::index_sequence<Is...>) {
   return std::tuple<decltype(make_native_type(std::declval<TC>().as_result(std::declval<std::tuple_element_t<Is, Args>>())))...>();
}

template<typename TC, typename T>
auto get_ct_args_i() {
   if constexpr (vm::detail::has_from_wasm_v<T, TC>) {
      using args_tuple = vm::detail::from_wasm_type_deducer_t<TC, T>;
      return get_ct_args_one<TC, args_tuple>(std::make_index_sequence<std::tuple_size_v<args_tuple>>());
   } else {
      return std::tuple<decltype(make_native_type(std::declval<TC>().as_result(std::declval<T>())))>();
   }
}

template<typename TC, typename Args, std::size_t... Is>
auto get_ct_args(std::index_sequence<Is...>) {
   return std::tuple_cat(get_ct_args_i<TC, std::tuple_element_t<Is, Args>>()...);
}

template<typename TC>
struct result_resolver {
   // Suppress "expression result unused" warnings
   result_resolver(TC& tc) : tc(tc) {}
   template<typename T>
   auto operator,(T&& res) {
      return make_native_type(vm::detail::resolve_result(tc, static_cast<T&&>(res)));
   }
   TC& tc;
};
template<typename TC>
result_resolver(TC&) -> result_resolver<TC>;

template<auto F, typename Interface, typename TC, typename Preconditions, typename... A>
auto fn(A... a) {
   try {
      {
         constexpr int cb_current_call_depth_remaining_segment_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(current_call_depth_remaining);
         constexpr int depth_assertion_intrinsic_offset = OFFSET_OF_FIRST_INTRINSIC - (int)boost::hana::index_if(intrinsic_table, ::boost::hana::equal.to(BOOST_HANA_STRING("eosvmoc_internal.depth_assert"))).value()*8;
         asm volatile("cmpl   $1,%%gs:%c[callDepthRemainOffset]\n"
                      "jne    1f\n"
                      "callq  *%%gs:%c[depthAssertionIntrinsicOffset]\n"
                      "1:\n"
                      :
                      : [callDepthRemainOffset] "i" (cb_current_call_depth_remaining_segment_offset),
                        [depthAssertionIntrinsicOffset] "i" (depth_assertion_intrinsic_offset)
                      : "cc");
      }
      using native_args = vm::flatten_parameters_t<AUTO_PARAM_WORKAROUND(F)>;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-value"
      eosio::vm::native_value stack[] = { a... };
#pragma GCC diagnostic pop      
      constexpr int cb_ctx_ptr_offset = OFFSET_OF_CONTROL_BLOCK_MEMBER(ctx);
      Interface* host;
      asm("mov %%gs:%c[applyContextOffset], %[cPtr]\n"
          : [cPtr] "=r" (host)
          : [applyContextOffset] "i" (cb_ctx_ptr_offset)
          );
      TC tc{host, eos_vm_oc_execution_interface{stack + sizeof...(A)}};
      return result_resolver{tc}, eosio::vm::invoke_with_host<F, Preconditions, native_args>(tc, host, std::make_index_sequence<sizeof...(A)>());
   }
   catch(...) {
      *reinterpret_cast<std::exception_ptr*>(eos_vm_oc_get_exception_ptr()) = std::current_exception();
   }
   siglongjmp(*eos_vm_oc_get_jmp_buf(), EOSVMOC_EXIT_EXCEPTION);
   __builtin_unreachable();
}

template<auto F, typename Cls, typename TC, typename Preconditions, typename Args, std::size_t... Is>
constexpr auto create_function(std::index_sequence<Is...>) {
   return &fn<F, Cls, TC, Preconditions, std::tuple_element_t<Is, Args>...>;
}

template<auto F, typename Cls, typename TC, typename Preconditions>
constexpr auto create_function() {
   using native_args = vm::flatten_parameters_t<AUTO_PARAM_WORKAROUND(F)>;
   using wasm_args = decltype(get_ct_args<TC, native_args>(std::make_index_sequence<std::tuple_size_v<native_args>>()));
   return create_function<F, Cls, TC, Preconditions, wasm_args>(std::make_index_sequence<std::tuple_size_v<wasm_args>>());
}

  
}

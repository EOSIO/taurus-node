#pragma once
#include <eosio/chain/exceptions.hpp>
#include <fc/scoped_exit.hpp>
#include <boost/type_traits.hpp>
#include <dlfcn.h>

namespace eosio::chain {
class dynamic_loaded_function {
   void* handle;
   void* sym;

 public:
   dynamic_loaded_function(const char* filename, const char* symbol) {
      handle = dlopen(filename, RTLD_NOW | RTLD_LOCAL);

      EOS_ASSERT(handle != nullptr, fc::exception, "unable to load {file}: {reason}", ("file", filename)
                 ("reason", dlerror()));
      sym         = dlsym(handle, symbol);
      EOS_ASSERT(sym != nullptr, fc::exception, "obtain the address of {symbol}: {reason}", ("symbol", symbol)
                 ("reason", dlerror()));
   }

   dynamic_loaded_function(const dynamic_loaded_function&) = delete;
   dynamic_loaded_function(dynamic_loaded_function&& other) 
   : handle(other.handle), sym(other.sym){
      other.handle = nullptr;
   }

   dynamic_loaded_function& operator = (const dynamic_loaded_function&) = delete; 
   dynamic_loaded_function& operator = (dynamic_loaded_function&& other)  {
      if (this != &other) {
         this->handle = other.handle;
         other.handle = nullptr;
         this->sym = other.sym;
      }
      return *this;
   }

   ~dynamic_loaded_function() {
      if (handle)
         dlclose(handle);
   }

   template <class F, typename... Args>
   auto exec(Args&& ...args) {
      auto fun = (F)sym;
      return fun(std::forward<Args&&>(args)...);
   }
};


} // namespace eosio::chain
#pragma push_macro("N")
#undef N
#include <llvm/IR/IRBuilder.h>
#pragma pop_macro("N")
namespace eosio { namespace chain { namespace eosvmoc {
namespace LLVMJIT {

llvm::Value* CreateInBoundsGEPWAR(llvm::IRBuilder<>& irBuilder, llvm::Value* Ptr, llvm::Value* v1, llvm::Value* v2) {
   if(!v2)
      return irBuilder.CreateInBoundsGEP(Ptr, v1);
   else
      return irBuilder.CreateInBoundsGEP(Ptr, {v1, v2});
}

}

}}}

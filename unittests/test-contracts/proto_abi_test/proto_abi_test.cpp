#include <eosio/eosio.hpp>
#include <test/test.pb.hpp>

namespace test {

class [[eosio::contract]] proto_abi_test : public eosio::contract {
 public:
   using eosio::contract::contract;

   [[eosio::action]]  eosio::pb<ActResult> hiproto(const eosio::pb<ActData>& msg) {
      eosio::check(msg.id == 1, "validate msg.id");
      eosio::check(msg.type == 2, "validate msg.type");
      eosio::check(msg.note == "abc", "validate msg.note");
      eosio::check(msg.account == 4, "validate msg.accout");
      return ActResult{1};
   }

   [[eosio::action]] ActResult hi(const ActData& msg) {
      return ActResult{2};
   } 
};
} // namespace test
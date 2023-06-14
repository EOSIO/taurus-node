#pragma once

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

class [[eosio::contract]] longrunning : public eosio::contract {
public:
   using eosio::contract::contract;

   [[eosio::action]]
   void run( std::string str, uint64_t iterations )
   {
      for( uint64_t i = 0; i < iterations; ++i) {
         eosio::checksum256 digest = eosio::sha256(str.data(), str.size());
      }
   }

};

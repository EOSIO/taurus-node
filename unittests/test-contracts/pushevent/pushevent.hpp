#pragma once

#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

__attribute__((import_name("push_event"))) void push_event(void*, size_t);

struct event_wrapper {
   eosio::name       tag;
   std::string       route;
   std::vector<char> data;
};
EOSIO_REFLECT(event_wrapper, tag, route, data);

class [[eosio::contract]] pushevent : public eosio::contract {
public:
   using eosio::contract::contract;

   [[eosio::action]]
   void push( eosio::name tag, std::string route, std::string data )
   {
      event_wrapper e;
      e.tag = tag;
      e.route = route;
      e.data = eosio::pack(data);

      auto p = eosio::pack(e);
      push_event(p.data(), p.size());
   }

};

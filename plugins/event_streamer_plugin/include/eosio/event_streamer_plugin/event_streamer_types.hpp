// copyright defined in LICENSE.txt

#pragma once
#include <eosio/abi.hpp>


namespace eosio::streams {

struct event_wrapper {
   eosio::name       tag;
   std::string       route;
   std::vector<char> data;
};
EOSIO_REFLECT(event_wrapper, tag, route, data);

} // namespace eosio::streams

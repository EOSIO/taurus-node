// copyright defined in LICENSE.txt

#pragma once
#include <eosio/abi.hpp>


namespace b1 {

struct stream_wrapper_v0 {
   eosio::name       route;
   std::vector<char> data;
};
EOSIO_REFLECT(stream_wrapper_v0, route, data);
struct stream_wrapper_v1 {
   std::string       route;
   std::vector<char> data;
};
EOSIO_REFLECT(stream_wrapper_v1, route, data);
using stream_wrapper = std::variant<stream_wrapper_v0, stream_wrapper_v1>;

} // namespace b1

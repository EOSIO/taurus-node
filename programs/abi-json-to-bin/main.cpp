#include <eosio/abi.hpp>
#include <iostream>
#include <algorithm>

/// read ABI JSON from stdin and write the binary format to stdout
int main(int, const char**) {
    std::string abi_json{std::istream_iterator<char>(std::cin), std::istream_iterator<char>()};
    auto r = eosio::abi_def::json_to_bin(abi_json);
    std::copy(r.begin(), r.end(), std::ostream_iterator<char>(std::cout));
    return 0;
}
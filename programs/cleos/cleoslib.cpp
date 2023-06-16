#include <eosio/cleoslib.hpp>
#include <eosio/cleos_client.hpp>

int cleos_main(int argc, const char** argv) {
   cleos_client client;
   return client.cleos(argc, argv);
}

int cleos_main(int argc, const char** argv, std::ostream& out, std::ostream& err) {
   cleos_client client(out, err);
   return client.cleos(argc, argv);
}
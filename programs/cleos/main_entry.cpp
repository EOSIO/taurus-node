
/*
 * cleos entry point
 *
 * please check main.cpp for details of cleos usage and introduction
 */

#include <eosio/cleoslib.hpp>

#include <fc/log/logger.hpp>

int main(int argc, const char** argv) {
   fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::debug);
   return cleos_main(argc, argv);
}

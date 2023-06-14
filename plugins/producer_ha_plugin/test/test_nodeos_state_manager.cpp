#define BOOST_TEST_MODULE nodeos_state_manager
#include <boost/test/included/unit_test.hpp>

#include <eosio/producer_ha_plugin/test_db.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_db.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_log_store.hpp>
#include <eosio/producer_ha_plugin/nodeos_state_manager.hpp>

BOOST_AUTO_TEST_SUITE(nodeos_state_manager)

BOOST_AUTO_TEST_CASE(save_load_state) {
   test_db tdb;

   eosio::producer_ha_config config;
   config.self = 1;
   eosio::producer_ha_config_peer peer;
   peer.id = 1;
   peer.address = "localhost:9090";
   config.peers.push_back(peer);

   auto log_store = nuraft::cs_new<eosio::nodeos_state_log_store>(tdb.db);

   eosio::nodeos_state_manager mgr(config, tdb.db, log_store);

   auto prefix = eosio::nodeos_state_db::manager;
   auto key = eosio::nodeos_state_manager::state_key;

   nuraft::srv_state state;
   state.set_term(100);

   mgr.save_state(state);

   auto read_state = mgr.read_state();

   BOOST_REQUIRE(read_state);
   BOOST_CHECK_EQUAL(state.get_term(), read_state->get_term());
}


BOOST_AUTO_TEST_CASE(save_load_config) {
   test_db tdb;

   eosio::producer_ha_config config;
   config.self = 1;
   eosio::producer_ha_config_peer peer;
   peer.id = 1;
   peer.address = "localhost:9090";
   config.peers.push_back(peer);

   auto log_store = nuraft::cs_new<eosio::nodeos_state_log_store>(tdb.db);

   eosio::nodeos_state_manager mgr(config, tdb.db, log_store);

   auto prefix = eosio::nodeos_state_db::manager;
   auto key = eosio::nodeos_state_manager::state_key;

   nuraft::cluster_config cconf;
   cconf.set_log_idx(100);

   mgr.save_config(cconf);

   auto read_cconf = mgr.load_config();

   BOOST_REQUIRE(read_cconf);
   BOOST_CHECK_EQUAL(cconf.get_log_idx(), read_cconf->get_log_idx());
}

BOOST_AUTO_TEST_SUITE_END()

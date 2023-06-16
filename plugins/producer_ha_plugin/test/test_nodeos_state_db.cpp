#define BOOST_TEST_MODULE nodeos_state_db
#include <boost/test/included/unit_test.hpp>

#include <eosio/producer_ha_plugin/test_db.hpp>

BOOST_AUTO_TEST_SUITE(nodeos_state_db)

BOOST_AUTO_TEST_CASE(write_value) {
   test_db tdb;
   auto db = tdb.db;

   std::string prefix{"testprefix"};
   std::string key{"testkey"};
   std::string value{"hello world"};

   db->write(prefix, key, value);
   db->flush();

   auto read_value = db->read_value(prefix, key);

   BOOST_REQUIRE(read_value);
   BOOST_REQUIRE(value == *read_value);

}

BOOST_AUTO_TEST_CASE(write) {
   test_db tdb;
   auto db = tdb.db;

   std::string prefix{"testprefix"};
   std::string key{"testkey"};
   std::string value{"hello world"};

   nuraft::ptr<nuraft::buffer> value_buf = nuraft::buffer::alloc(value.size() + 1);
   value_buf->put(value);

   db->write(prefix, key, value_buf);
   db->flush();

   auto read_buf = db->read(prefix, key);

   BOOST_REQUIRE(read_buf);

   std::string read_value(read_buf->get_str());

   BOOST_REQUIRE(value == read_value);
}

BOOST_AUTO_TEST_SUITE_END()

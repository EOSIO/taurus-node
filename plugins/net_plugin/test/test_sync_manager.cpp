#define BOOST_TEST_MODULE sync_manager
#define FC_DISABLE_LOGGING

#include <eosio/net_plugin/sync_manager.hpp>
#include <eosio/net_plugin/mock_net_plugin_impl.hpp>

#include <boost/test/included/unit_test.hpp>
#include <boost/fakeit.hpp>

#include <tuple>

using namespace eosio::chain;
using namespace eosio::p2p;
using namespace fakeit;

template<typename _Fn>
using cache_t = sync_manager<mock_connection, mock_net_plugin_interface>::state_machine::cache<_Fn>;
template<typename _Fn>
using always_t = sync_manager<mock_connection, mock_net_plugin_interface>::state_machine::always<_Fn>;

Mock<mock_net_plugin_interface> create_mock_net_plugin() {
   Mock<mock_net_plugin_interface> mock_net_plugin;
   Fake(Method(mock_net_plugin, get_logger));
   Fake(Method(mock_net_plugin, get_log_format));
   Fake(Method(mock_net_plugin, shared_connections_lock));
   Fake(Method(mock_net_plugin, get_chain_info));
   Fake(Method(mock_net_plugin, for_each_connection));
   Fake(Method(mock_net_plugin, for_each_block_connection));
   Fake(Method(mock_net_plugin, get_connections));

   return mock_net_plugin;
}

Mock<mock_connection> create_mock_connection() {
   Mock<mock_connection> mock_conn;
   Fake(Method(mock_conn, locked_connection_mutex));
   Fake(Method(mock_conn, get_strand));
   Fake(Method(mock_conn, request_sync_blocks));
   Fake(Method(mock_conn, post));
   Fake(Method(mock_conn, send_handshake));
   Fake(Method(mock_conn, get_ci));
   Fake(Method(mock_conn, get_fork_head_num));
   Fake(Method(mock_conn, get_fork_head));
   Fake(Method(mock_conn, get_id));
   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(handshake_message());
   Fake(Method(mock_conn, current));
   Fake(Method(mock_conn, is_transactions_only_connection));
   Fake(Method(mock_conn, reset_fork_head));

   return mock_conn;
}

std::shared_ptr<mock_net_plugin_interface> get_net_plugin_interface(Mock<mock_net_plugin_interface>& mock_net_plugin) {
   return {&mock_net_plugin.get(), [](mock_net_plugin_interface*){}};
}

std::shared_ptr<mock_connection> get_connection_interface(Mock<mock_connection>& mock_conn) {
   return {&mock_conn.get(), [](mock_connection*){}};
}

sync_manager<mock_connection, mock_net_plugin_interface> create_sync_manager(Mock<mock_net_plugin_interface>& mock_net_plugin) {
   return sync_manager<mock_connection, mock_net_plugin_interface>(10, get_net_plugin_interface(mock_net_plugin));
}

handshake_message create_handshake_message(uint32_t last_lib) {
   handshake_message m = handshake_message();
   m.last_irreversible_block_num = last_lib;
   return m;
}

BOOST_AUTO_TEST_SUITE( sync_manager_test )

BOOST_AUTO_TEST_CASE( is_sync_required_test ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   block_id_type null_id;
   std::set<mock_connection_ptr> conn_set;
   conn_set.insert( get_connection_interface(mock_conn) );

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(2,0,3,null_id,null_id,null_id));
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_net_plugin, get_connections)).AlwaysReturn(conn_set);

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);

   BOOST_REQUIRE( sm.is_sync_required(3) );
   BOOST_REQUIRE( !sm.is_sync_required(2) );

   // set sync_known_lib_num to 11
   sm.set_highest_lib();

   // now target lib doesn't matter, we rely on sync_known_lib_num
   BOOST_REQUIRE( sm.is_sync_required(2) );

   //needed for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   //now sync_last_requested_num is 1
   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(1));
   sm.set_highest_lib();
   // still sync required because of sync_last_requested_num is 10 (sync_last_requested_num - 1)
   BOOST_REQUIRE( sm.is_sync_required(2) );

   // setting sync_last_requested_num to 0 (sync_last_requested_num - 1)
   sm.continue_sync();

   // now sync is not required as we rely on controller lib again
   BOOST_REQUIRE( !sm.is_sync_required(2) );
}

BOOST_AUTO_TEST_CASE( send_handshakes ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn1 = create_mock_connection();
   auto mock_conn2 = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn1, current)).AlwaysReturn(true);
   When(Method(mock_net_plugin, for_each_connection)).AlwaysDo(
      [&mock_conn1, &mock_conn2](auto lmd){ 
         lmd(get_connection_interface(mock_conn1));
         lmd(get_connection_interface(mock_conn2));
      });

   sm.send_handshakes();

   Verify(Method(mock_conn1, send_handshake)).Exactly(1);
   Verify(Method(mock_conn1, current)).Exactly(1);
   Verify(Method(mock_conn2, send_handshake)).Exactly(0);
   Verify(Method(mock_conn2, current)).Exactly(1);
}

BOOST_AUTO_TEST_CASE( is_sync_source ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, current)).AlwaysReturn(true);

   BOOST_REQUIRE( !sm.is_sync_source( *get_connection_interface(mock_conn)) );

   sm.set_new_sync_source(get_connection_interface(mock_conn));

   BOOST_REQUIRE( sm.is_sync_source( *get_connection_interface(mock_conn)) );
}

BOOST_AUTO_TEST_CASE( sync_reset_lib_num ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   BOOST_REQUIRE( sm.get_known_lib() == 0 );
   sm.sync_reset_lib_num(5);
   BOOST_REQUIRE( sm.get_known_lib() == 5 );
   sm.sync_reset_lib_num(4);
   BOOST_REQUIRE( sm.get_known_lib() == 5 );
}

BOOST_AUTO_TEST_CASE( sync_update_expected ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });

   // set sync_known_lib_num to 11
   sm.set_highest_lib();

   //needed for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   // after setting sync_known_lib_num and sync_last_requested_num in previous steps we can try to update next expected
   sm.sync_update_expected({}, 2, true);
   BOOST_REQUIRE( sm.get_sync_next_expected() == 3 );

   // next expected should change because of it is equal to old value even though applied is false
   sm.sync_update_expected({}, 3, false);
   BOOST_REQUIRE( sm.get_sync_next_expected() == 4 );

   // next expected is not changed because of applied is false
   sm.sync_update_expected({}, 5, false);
   BOOST_REQUIRE( sm.get_sync_next_expected() == 4 );

   // next expected is not changed because of suggested value is greater than sync_last_requested_num
   sm.sync_update_expected({}, 11, true);
   BOOST_REQUIRE( sm.get_sync_next_expected() == 4 );
}

BOOST_AUTO_TEST_CASE( begin_sync ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   sm.begin_sync(get_connection_interface(mock_conn), 0);

   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(1);

   When(Method(mock_conn, current)).AlwaysReturn(true);

   sm.sync_reset_lib_num(10);
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   sm.begin_sync(get_connection_interface(mock_conn), 0);

   // verify for_each_connection was not called more since last check
   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(1);
   // verify request was posted to connection
   Verify(Method(mock_conn, post)).Exactly(1);
   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );

   // TODO: this case looks unrealistic but code logic permits this
   // maybe that is indicator to check how this can be possible and remove this logic from sync_manager at all
   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(1));
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   sm.set_highest_lib();
   sm.sync_update_expected({}, 9, true);
   // now we have sync_known_lib_num = 1 and sync_next_expected_num = 10
   // start should be greater then end span
   sm.begin_sync(get_connection_interface(mock_conn), 0);
   //verify sync didn't begin and we sent handshakes to conections
   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(2);
   Verify(Method(mock_conn, post)).Exactly(1);
}

BOOST_AUTO_TEST_CASE( continue_sync ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   sm.continue_sync();

   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(1);

   When(Method(mock_conn, current)).AlwaysReturn(true);

   sm.sync_reset_lib_num(10);
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   sm.continue_sync();

   // verify for_each_connection was not called more since last check
   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(1);
   // verify request was posted to connection
   Verify(Method(mock_conn, post)).Exactly(1);
   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );

   // TODO: this case looks unrealistic but code logic permits this
   // maybe that is indicator to check how this can be possible and remove this logic from sync_manager at all
   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(1));
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   sm.set_highest_lib();
   sm.sync_update_expected({}, 9, true);
   // now we have sync_known_lib_num = 1 and sync_next_expected_num = 10
   // start should be greater then end span
   sm.continue_sync();
   //verify sync didn't begin and we sent handshakes to conections
   Verify(Method(mock_net_plugin, for_each_connection)).Exactly(2);
   Verify(Method(mock_conn, post)).Exactly(1);
}

BOOST_AUTO_TEST_CASE( fork_head_ge ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   //64 characters
   block_id_type test_block_id("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");

   BOOST_REQUIRE( !sm.fork_head_ge(0, {}) );

   Verify(Method(mock_net_plugin, for_each_block_connection)).Exactly(1);

   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_conn, get_fork_head_num)).AlwaysReturn(10);
   When(Method(mock_conn, get_fork_head)).AlwaysReturn(test_block_id);

   BOOST_REQUIRE( sm.fork_head_ge(0, test_block_id) );
   BOOST_REQUIRE( sm.fork_head_ge(9, {}) );
   BOOST_REQUIRE( sm.fork_head_ge(10, test_block_id) );
   // 11 > 10 but block_id match so it returns true  here
   BOOST_REQUIRE( sm.fork_head_ge(11, test_block_id) );
   // same comparison with different blck id fails
   BOOST_REQUIRE( !sm.fork_head_ge(11, {}) );
}

BOOST_AUTO_TEST_CASE( reset_last_requested_num ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });

   // set sync_known_lib_num to 11
   sm.set_highest_lib();
   //needed to set sync_source for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );

   sm.reset_last_requested_num();

   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 0 );
}

BOOST_AUTO_TEST_CASE( reset_sync_source ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);

   sm.set_new_sync_source(get_connection_interface(mock_conn));

   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn)) );

   sm.reset_sync_source();

   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );
}

BOOST_AUTO_TEST_CASE( closing_sync_source ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   block_id_type null_id;

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(0, 11, 0, null_id, null_id, null_id));

   // set sync_known_lib_num to 11
   sm.set_highest_lib();
   //needed to set sync_source for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );

   sm.closing_sync_source();
   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 0 );
   BOOST_REQUIRE( sm.get_sync_next_expected() == 12 );
}

BOOST_AUTO_TEST_CASE( sync_in_progress ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   block_id_type null_id;

   BOOST_REQUIRE( !sm.sync_in_progress() );

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(0, 0, 9, null_id, null_id, null_id));

      // set sync_known_lib_num to 11
   sm.set_highest_lib();

   //needed for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );
   // sync_last_requested_num > fork head and sync source current
   BOOST_REQUIRE( sm.sync_in_progress() );

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(0, 0, 11, null_id, null_id, null_id));
   // sync_last_requested_num < fork head and sync source current
   BOOST_REQUIRE( !sm.sync_in_progress() );
   
   // restore to previous state
   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(0, 0, 9, null_id, null_id, null_id));
   BOOST_REQUIRE( sm.sync_in_progress() );

   // sync_last_requested_num > fork head but sync source is not current
   When(Method(mock_conn, current)).AlwaysReturn(false);
   BOOST_REQUIRE( !sm.sync_in_progress() );

   // restore to previous state
   When(Method(mock_conn, current)).AlwaysReturn(true);
   BOOST_REQUIRE( sm.sync_in_progress() );

   //fork head < sync_last_requested_num but sync_source is null
   sm.reset_sync_source();
   BOOST_REQUIRE( !sm.sync_in_progress() );
}

BOOST_AUTO_TEST_CASE( set_new_sync_source ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   block_id_type null_id;
   std::set<mock_connection_ptr> conn_set;
   conn_set.insert( get_connection_interface(mock_conn) );

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_net_plugin, get_connections)).AlwaysReturn({});
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(10, 0, 0, null_id, null_id, null_id));
   
   // set sync_known_lib_num to 11
   sm.set_highest_lib();

   //needed for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn)) );
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();
   
   // empty connections list and null sync_hint - can't set sync_source
   BOOST_REQUIRE( sm.get_known_lib() == 11 );
   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 10 );
   BOOST_REQUIRE( !sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );
   // make sure lib was reset to known lib
   BOOST_REQUIRE( sm.get_known_lib() == 10 );
   BOOST_REQUIRE( sm.get_sync_last_requested_num() == 0 );
   
   // empty connections list and non-current sync_hint - can't set sync_source
   When(Method(mock_conn, current)).AlwaysReturn(false);
   BOOST_REQUIRE( !sm.set_new_sync_source(get_connection_interface(mock_conn)) );
   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );
   
   // empty connections list and transaction-only sync_hint - can't set sync_source
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(true);
   BOOST_REQUIRE( !sm.set_new_sync_source(get_connection_interface(mock_conn)) );
   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(0, 0, 0, null_id, null_id, null_id));

   // valid current sync hint - success
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   BOOST_REQUIRE( sm.set_new_sync_source(get_connection_interface(mock_conn)) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn)) );

   // null sync hint but connections has one valid - success
   When(Method(mock_net_plugin, get_connections)).AlwaysReturn(conn_set);
   BOOST_REQUIRE( sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn)) );

   //no current connection in connections
   When(Method(mock_conn, current)).AlwaysReturn(false);
   BOOST_REQUIRE( !sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );

   //no blocks connection in connections
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(true);
   BOOST_REQUIRE( !sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( !sm.is_sync_source(*get_connection_interface(mock_conn)) );

   // adding few more connections
   auto mock_conn2 = create_mock_connection();
   auto mock_conn3 = create_mock_connection();
   When(Method(mock_conn3, current)).AlwaysReturn(true);
   When(Method(mock_conn3, is_transactions_only_connection)).AlwaysReturn(false);
   conn_set.insert( get_connection_interface(mock_conn2) );
   conn_set.insert( get_connection_interface(mock_conn3) );
   When(Method(mock_net_plugin, get_connections)).AlwaysReturn(conn_set);
   
   // conn2 is not current and conn is transaction only
   BOOST_REQUIRE( sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn3)) );

   When(Method(mock_conn3, current)).AlwaysReturn(false);
   When(Method(mock_conn2, current)).AlwaysReturn(true);

   // now chosing next current blocks connection which is conn2
   BOOST_REQUIRE( sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn2)) );

   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_conn, is_transactions_only_connection)).AlwaysReturn(false);
   When(Method(mock_conn2, current)).AlwaysReturn(false);

   // suggesting mock_conn2 but mock_conn should be chosen
   BOOST_REQUIRE( sm.set_new_sync_source(get_connection_interface(mock_conn2)) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn)) );

   // set sync_known_lib_num to 11
   sm.set_highest_lib();

   When(Method(mock_conn2, get_last_handshake)).AlwaysReturn(create_handshake_message(9));
   When(Method(mock_conn2, current)).AlwaysReturn(true);
   When(Method(mock_conn3, get_last_handshake)).AlwaysReturn(create_handshake_message(12));
   When(Method(mock_conn3, current)).AlwaysReturn(true);

   // should skip mock_conn2 because of lower lib and choose mock_conn3
   BOOST_REQUIRE( sm.set_new_sync_source(nullptr) );
   BOOST_REQUIRE( sm.is_sync_source(*get_connection_interface(mock_conn3)) );
}

BOOST_AUTO_TEST_CASE( block_ge_lib ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });

   // set sync_known_lib_num to 11
   sm.set_highest_lib();

   BOOST_REQUIRE( !sm.block_ge_lib(10) );
   BOOST_REQUIRE( sm.block_ge_lib(11) );
   BOOST_REQUIRE( sm.block_ge_lib(12) );
}

BOOST_AUTO_TEST_CASE( block_ge_last_requested ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);
   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });

   // set sync_known_lib_num to 11
   sm.set_highest_lib();
   //needed for calling continue_sync
   sm.set_new_sync_source(get_connection_interface(mock_conn));
   // after that call sync_last_requested_num should be 10
   sm.continue_sync();

   BOOST_REQUIRE( !sm.block_ge_last_requested(9) );
   BOOST_REQUIRE( sm.block_ge_last_requested(10) );
   BOOST_REQUIRE( sm.block_ge_last_requested(11) );
}

BOOST_AUTO_TEST_CASE( continue_head_catchup ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);
   //64 characters
   block_id_type test_block_id("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
   block_id_type null_id;

   // no connections
   BOOST_REQUIRE( !sm.continue_head_catchup({},{}) );

   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });
   When(Method(mock_conn, get_fork_head_num)).AlwaysReturn(10);
   When(Method(mock_conn, get_fork_head)).AlwaysReturn(null_id);

   // fork_head_id is null
   BOOST_REQUIRE( !sm.continue_head_catchup(null_id,9) );
   Verify(Method(mock_conn, reset_fork_head)).Never();

   // fork_head < 11 but fork_head_id is null
   BOOST_REQUIRE( !sm.continue_head_catchup(null_id,11) );
   Verify(Method(mock_conn, reset_fork_head)).Never();

   When(Method(mock_conn, get_fork_head)).AlwaysReturn(test_block_id);

   // fork_head_id is not null
   BOOST_REQUIRE( sm.continue_head_catchup(null_id,9) );
   Verify(Method(mock_conn, reset_fork_head)).Never();

   // fork_head_id is not null and less then 11
   BOOST_REQUIRE( !sm.continue_head_catchup(null_id,11) );
   Verify(Method(mock_conn, reset_fork_head)).Once();
}

BOOST_AUTO_TEST_CASE( set_highest_lib ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto mock_conn = create_mock_connection();
   auto sm = create_sync_manager(mock_net_plugin);

   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo([&mock_conn](auto lmd){ lmd(get_connection_interface(mock_conn)); });

   When(Method(mock_conn, get_last_handshake)).AlwaysReturn(create_handshake_message(11));
   When(Method(mock_conn, current)).AlwaysReturn(true);

   sm.set_highest_lib();

   BOOST_REQUIRE( sm.get_known_lib() == 11 );

   auto mock_conn2 = create_mock_connection();
   When(Method(mock_conn2, get_last_handshake)).AlwaysReturn(create_handshake_message(13));
   When(Method(mock_conn2, current)).AlwaysReturn(false);

   auto mock_conn3 = create_mock_connection();
   When(Method(mock_conn3, get_last_handshake)).AlwaysReturn(create_handshake_message(12));
   When(Method(mock_conn3, current)).AlwaysReturn(true);

   When(Method(mock_net_plugin, for_each_block_connection)).AlwaysDo(
      [&](auto lmd){ 
         lmd(get_connection_interface(mock_conn));
         lmd(get_connection_interface(mock_conn2));
         lmd(get_connection_interface(mock_conn3));
      });
   
   sm.set_highest_lib();

   BOOST_REQUIRE( sm.get_known_lib() == 12 );
}

BOOST_AUTO_TEST_CASE( update_next_expected ) {
   auto mock_net_plugin = create_mock_net_plugin();
   auto sm = create_sync_manager(mock_net_plugin);
   block_id_type null_id;

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(10,0,0,null_id,null_id,null_id));
   sm.update_next_expected();
   BOOST_REQUIRE( sm.get_sync_next_expected() == 11 );

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(9,0,0,null_id,null_id,null_id));
   sm.update_next_expected();
   BOOST_REQUIRE( sm.get_sync_next_expected() == 11 );

   When(Method(mock_net_plugin, get_chain_info)).AlwaysReturn(std::make_tuple(11,0,0,null_id,null_id,null_id));
   sm.update_next_expected();
   BOOST_REQUIRE( sm.get_sync_next_expected() == 12 );
}

BOOST_AUTO_TEST_CASE( cache ) {
   int counter = 0;
   auto test_lmd = [&counter](){ return ++counter; };

   auto c1 = cache_t<decltype(test_lmd)>(test_lmd);
   auto c2 = cache_t<decltype(test_lmd)>(test_lmd, true);
   BOOST_REQUIRE( c1() == c2() );
   BOOST_REQUIRE( c1() != c1() );
   BOOST_REQUIRE( c1() == c2() );
   BOOST_REQUIRE( counter == 4 );
}

BOOST_AUTO_TEST_CASE( always ) {
   auto test_lmd1 = [](){ return false; };
   auto test_lmd2 = [](){};
   auto test_lmd3 = [](){ return std::vector<std::string>(); };

   BOOST_REQUIRE( always_t<decltype(test_lmd1)>(test_lmd1)() == true );
   BOOST_REQUIRE( always_t<decltype(test_lmd2)>(test_lmd2)() == true );
   BOOST_REQUIRE( always_t<decltype(test_lmd3)>(test_lmd3)() == true );
}

BOOST_AUTO_TEST_SUITE_END()
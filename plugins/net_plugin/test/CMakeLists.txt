add_executable( test_sync_manager test_sync_manager.cpp )

target_link_libraries( test_sync_manager fc eosio_chain net_plugin eosio_testing )
target_include_directories( test_sync_manager PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" )
target_include_directories( test_sync_manager PUBLIC "${CMAKE_SOURCE_DIR}/libraries/FakeIt/single_header" )

message("${CMAKE_CURRENT_SOURCE_DIR}/libraries/FakeIt/single_header")

add_test(NAME test_sync_manager COMMAND plugins/net_plugin/test/test_sync_manager WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable( test_account_query_db test_account_query_db.cpp )
add_executable( test_chain_plugin test_chain_plugin.cpp )

target_link_libraries( test_account_query_db chain_plugin eosio_testing)
target_link_libraries( test_chain_plugin chain_plugin eosio_testing)

add_test(NAME test_account_query_db COMMAND plugins/chain_plugin/test/test_account_query_db WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
add_test(NAME test_chain_plugin COMMAND plugins/chain_plugin/test/test_chain_plugin WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

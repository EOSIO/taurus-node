add_executable( test_snapshot_information test_snapshot_information.cpp )
target_link_libraries( test_snapshot_information producer_plugin eosio_testing )

add_test(NAME test_snapshot_information COMMAND plugins/producer_plugin/test/test_snapshot_information WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable( test_subjective_billing test_subjective_billing.cpp )
target_link_libraries( test_subjective_billing producer_plugin eosio_testing )

add_test(NAME test_subjective_billing COMMAND plugins/producer_plugin/test/test_subjective_billing WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable( test_trx_full test_trx_full.cpp )
target_link_libraries( test_trx_full producer_plugin eosio_testing )

add_test(NAME test_trx_full COMMAND plugins/producer_plugin/test/test_trx_full WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable( test_producer test_producer.cpp )
target_link_libraries( test_producer producer_plugin eosio_testing )

add_test(NAME test_producer COMMAND plugins/producer_plugin/test/test_producer WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

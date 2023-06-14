add_executable( test_nodeos_state_db test_nodeos_state_db.cpp )
target_link_libraries( test_nodeos_state_db producer_ha_plugin )
add_test(NAME test_nodeos_state_db COMMAND plugins/producer_ha_plugin/test/test_nodeos_state_db WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

add_executable( test_nodeos_state_manager test_nodeos_state_manager.cpp )
target_link_libraries( test_nodeos_state_manager producer_ha_plugin )
add_test(NAME test_nodeos_state_manager COMMAND plugins/producer_ha_plugin/test/test_nodeos_state_manager WORKING_DIRECTORY ${CMAKE_BINARY_DIR})


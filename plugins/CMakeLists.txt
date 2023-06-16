
if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory(net_plugin)
add_subdirectory(net_api_plugin)
endif()

add_subdirectory(http_plugin)
add_subdirectory(http_client_plugin)
add_subdirectory(chain_plugin)
add_subdirectory(chain_api_plugin)

add_subdirectory(producer_plugin)

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory(producer_api_plugin)
endif()

add_subdirectory(producer_ha_plugin)
add_subdirectory(state_history_plugin)

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory(trace_api_plugin)
endif()

add_subdirectory(signature_provider_plugin)
add_subdirectory(resource_monitor_plugin)
add_subdirectory(wallet_plugin)

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory(wallet_api_plugin)
add_subdirectory(txn_test_gen_plugin)
add_subdirectory(db_size_api_plugin)
add_subdirectory(login_plugin)
add_subdirectory(test_control_plugin)
add_subdirectory(test_control_api_plugin)
endif()

add_subdirectory(amqp_trx_plugin)
add_subdirectory(amqp_trx_api_plugin)

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory(rodeos_plugin)
add_subdirectory(event_streamer_plugin)
endif()

# Forward variables to top level so packaging picks them up
set(CPACK_DEBIAN_PACKAGE_DEPENDS ${CPACK_DEBIAN_PACKAGE_DEPENDS} PARENT_SCOPE)

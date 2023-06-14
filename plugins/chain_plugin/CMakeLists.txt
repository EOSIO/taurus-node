file(GLOB HEADERS "include/eosio/chain_plugin/*.hpp")
add_library( chain_plugin
             account_query_db.cpp
             chain_plugin.cpp
             table_query.cpp
             read_only.cpp
             read_write.cpp
             ${HEADERS} )

if (NOT DISABLE_NATIVE_RUNTIME)
    target_sources(chain_plugin PRIVATE native_module_runtime.cpp)
endif()

if(EOSIO_ENABLE_DEVELOPER_OPTIONS)
    message(WARNING "EOSIO Developer Options are enabled; these are NOT supported")
    target_compile_definitions(chain_plugin PUBLIC EOSIO_DEVELOPER)
endif()
if(EOSIO_NOT_REQUIRE_FULL_VALIDATION)
    target_compile_definitions(chain_plugin PRIVATE EOSIO_NOT_REQUIRE_FULL_VALIDATION)
endif()

target_link_libraries( chain_plugin eosio_chain appbase producer_plugin resource_monitor_plugin )
target_include_directories( chain_plugin PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/../chain_interface/include" "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/appbase/include" "${CMAKE_CURRENT_SOURCE_DIR}/../resource_monitor_plugin/include" "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/abieos/include" "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/abieos/external/rapidjson/include")

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( test )
endif()

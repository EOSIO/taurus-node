file(GLOB HEADERS "include/eosio/net_plugin/*.hpp" )
add_library( net_plugin
             connection.cpp
             dispatch_manager.cpp
             net_plugin_impl.cpp
             net_plugin.cpp
             block_status_monitor.cpp
             buffer_factory.cpp
             ${HEADERS} )

target_link_libraries( net_plugin chain_plugin producer_plugin appbase fc sml )

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
   target_compile_definitions(sml INTERFACE BOOST_SML_CFG_DISABLE_MIN_SIZE)
endif()

target_include_directories( net_plugin PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/../chain_interface/include  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/appbase/include")

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( test )
endif()

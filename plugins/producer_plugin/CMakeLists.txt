file(GLOB HEADERS "include/eosio/producer_plugin/*.hpp")

add_library( producer_plugin
             producer_plugin.cpp
             producer.cpp
             block_producer.cpp
             pending_snapshot.cpp
             pending_snapshot_tracker.cpp
             transaction_processor.cpp
             ${HEADERS}
           )

target_link_libraries( producer_plugin chain_plugin signature_provider_plugin appbase eosio_chain producer_ha_plugin )
target_include_directories( producer_plugin
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/../chain_interface/include" )

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( test )
endif()

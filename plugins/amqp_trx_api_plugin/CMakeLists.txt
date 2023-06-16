file(GLOB HEADERS "include/eosio/amqp_trx_api_plugin/*.hpp")
add_library( amqp_trx_api_plugin
             amqp_trx_api_plugin.cpp
             ${HEADERS} )

target_link_libraries( amqp_trx_api_plugin amqp_trx_plugin http_plugin appbase )
target_include_directories( amqp_trx_api_plugin
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include" "${CMAKE_CURRENT_SOURCE_DIR}/../amqp_trx_plugin/include" )

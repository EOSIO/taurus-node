file(GLOB HEADERS "include/eosio/producer_ha_plugin/*.hpp")

add_library(producer_ha_plugin
  producer_ha_plugin.cpp
  nodeos_state_log_store.cpp
  ${HEADERS}
  include/eosio/producer_ha_plugin/nodeos_state_db.hpp)

target_link_libraries(producer_ha_plugin chain_plugin http_plugin appbase fc nuraft)
target_include_directories(producer_ha_plugin PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( test )
endif()

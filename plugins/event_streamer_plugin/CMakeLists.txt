file(GLOB HEADERS "include/eosio/event_streamer_plugin/*.hpp" "include/eosio/event_streamer_plugin/streams/*.hpp")

add_library(event_streamer_plugin
            event_streamer_plugin.cpp
            ${HEADERS})

target_link_libraries(event_streamer_plugin chain_plugin rodeos_lib state_history amqp appbase fc amqpcpp)
target_include_directories(event_streamer_plugin PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/abieos/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/amqp-cpp/include")

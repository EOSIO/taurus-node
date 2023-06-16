if("eos-vm-jit" IN_LIST EOSIO_WASM_RUNTIMES)
file(GLOB HEADERS "include/eosio/rodeos_plugin/*.hpp" "include/eosio/rodeos_plugin/streams/*.hpp")

add_library(rodeos_plugin
  rodeos_plugin.cpp
  cloner_plugin.cpp
  rocksdb_plugin.cpp
  streamer_plugin.cpp
  wasm_ql_http.cpp
  wasm_ql_plugin.cpp
  ${HEADERS})

target_link_libraries(rodeos_plugin chain_plugin rodeos_lib state_history amqp appbase fc amqpcpp)
target_include_directories(rodeos_plugin PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/abieos/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../libraries/amqp-cpp/include")

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/rocksdb_options.ini DESTINATION ${CMAKE_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/rocksdb_ramdisk_options.ini DESTINATION ${CMAKE_BINARY_DIR}/)
endif()

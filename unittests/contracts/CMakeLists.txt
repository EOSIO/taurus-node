# will be implictly used for any compilation unit if not overrided by SYSTEM_INCLUDE_FOLDERS parameter
# these directories go as -isystem <dir> to avoid warnings from code of third-party libraries

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/eosio.bios/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/eosio.bios/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/eosio.msig/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/eosio.msig/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/eosio.system/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/eosio.system/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/eosio.token/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/eosio.token/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/eosio.wrap/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/eosio.wrap/)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/old_versions/v1.6.0-rc3/eosio.bios/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/old_versions/v1.6.0-rc3/eosio.bios/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/old_versions/v1.7.0-develop-preactivate_feature/eosio.bios/ DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/old_versions/v1.7.0-develop-preactivate_feature/eosio.bios/)

file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/kv_bios.abi DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/kv_bios.wasm DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/read_only_query_tests.abi DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/read_only_query_tests.wasm DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)

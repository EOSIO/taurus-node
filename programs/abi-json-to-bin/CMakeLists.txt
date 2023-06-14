add_executable(eosio-abi-json-to-bin main.cpp)
target_link_libraries(eosio-abi-json-to-bin PRIVATE abieos)
set_target_properties(eosio-abi-json-to-bin PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
install(TARGETS
    eosio-abi-json-to-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR} COMPONENT base
)
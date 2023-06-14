#cmake_minimum_required(VERSION 3.10)

if( EOSIO_COMPILE_TEST_CONTRACTS )
    #find_package(eosio.cdt REQUIRED)
    add_contract( verify_ecdsa verify_ecdsa verify_ecdsa.cpp )
else()
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/verify_ecdsa.wasm ${CMAKE_CURRENT_BINARY_DIR}/verify_ecdsa.wasm COPYONLY )
    configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/verify_ecdsa.abi ${CMAKE_CURRENT_BINARY_DIR}/verify_ecdsa.abi COPYONLY )
endif()

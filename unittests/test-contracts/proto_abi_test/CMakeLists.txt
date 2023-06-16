if( EOSIO_COMPILE_TEST_CONTRACTS )  
   add_contract(proto_abi_test proto_abi_test proto_abi_test.cpp )
   target_add_protobuf(proto_abi_test OUTPUT_DIRECTORY test 
                                      FILES test.proto)
else()
   configure_file( proto_abi_test.wasm proto_abi_test.wasm COPYONLY )
   configure_file( proto_abi_test.abi  proto_abi_test.abi  COPYONLY )
endif()
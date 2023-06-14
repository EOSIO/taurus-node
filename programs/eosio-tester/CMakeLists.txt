if( UNIX AND NOT APPLE )
    set(rt_library rt )
endif()

function(add_tester target)
  add_executable( ${target} ${ARGN} )
  target_link_libraries( ${target}
    PRIVATE rodeos_lib state_history eosio_chain ${CMAKE_DL_LIBS} ${PLATFORM_SPECIFIC_LIBS} )
  target_include_directories(${target} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

  copy_bin( ${target} )
  install( TARGETS
    ${target} RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR} COMPONENT base
  )
endfunction()

if("eos-vm-jit" IN_LIST EOSIO_WASM_RUNTIMES)
  add_tester(${TESTER_EXECUTABLE_NAME} main.cpp)
endif()

if (NOT DISABLE_NATIVE_RUNTIME)
  add_tester(native-tester native-tester.cpp)
  target_export_intrinsics(native-tester native-tester.cpp)
endif()
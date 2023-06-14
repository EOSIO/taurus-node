function(target_export_intrinsics target src)
  set(gen_export_script ${CMAKE_SOURCE_DIR}/scripts/gen_export_list.py)

  if (CMAKE_GENERATOR STREQUAL "Unix Makefiles" )
    add_custom_command(
      TARGET ${target} PRE_BUILD
      COMMAND ${gen_export_script} ${src} > ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
      BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMENT Generate ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
    )
  else()
    add_custom_command(
          OUTPUT  ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
          COMMAND ${gen_export_script} ${src} > ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
          DEPENDS ${gen_export_script} ${src}
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_custom_target(
      ${target}_export_list 
      DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt
    )
    set_target_properties(${target} PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt)
  endif()

  if (UNIX)
    if (APPLE)
      target_link_options(${target} PRIVATE -Wl,-exported_symbols_list,${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt)
    else()
      target_link_options(${target} PRIVATE -Wl,--dynamic-list=${CMAKE_CURRENT_BINARY_DIR}/${target}_export_list.txt)
    endif()
  endif()
endfunction()

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( nodeos )
endif()

add_subdirectory( cleos )

if (NOT TAURUS_NODE_AS_LIB)
add_subdirectory( keosd )
add_subdirectory( eosio-launcher )
add_subdirectory( eosio-blocklog )
add_subdirectory( eosio-chainid )
add_subdirectory( nodeos-sectl )
add_subdirectory( rodeos )
add_subdirectory( eosio-tester )
add_subdirectory( eosio-tpmtool )
add_subdirectory( eosio-tpmattestcheck )
add_subdirectory( network-relay )
add_subdirectory( abi-json-to-bin )
endif()

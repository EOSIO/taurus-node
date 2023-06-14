
configure_file(help_text.cpp.in help_text.cpp @ONLY)
configure_file(config.json.in config.json @ONLY)

add_library(cleoslib cleoslib.cpp httpc.cpp ${CMAKE_CURRENT_BINARY_DIR}/help_text.cpp)

if( UNIX AND NOT APPLE )
  set(rt_library rt )
endif()

configure_file(config.hpp.in config.hpp ESCAPE_QUOTES)

target_include_directories(cleoslib PUBLIC
  ${Intl_INCLUDE_DIRS}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(cleoslib PUBLIC
  appbase version chain_api_plugin producer_plugin chain_plugin http_plugin amqp_trx_plugin eosio_chain fc abieos
  ${CMAKE_DL_LIBS} ${PLATFORM_SPECIFIC_LIBS} ${Intl_LIBRARIES})

if (NOT TAURUS_NODE_AS_LIB)
set(LOCALEDIR ${CMAKE_INSTALL_PREFIX}/share/locale)
set(LOCALEDOMAIN ${CLI_CLIENT_EXECUTABLE_NAME})

add_executable(${CLI_CLIENT_EXECUTABLE_NAME} main_entry.cpp)
target_link_libraries(${CLI_CLIENT_EXECUTABLE_NAME} PUBLIC cleoslib)

copy_bin( ${CLI_CLIENT_EXECUTABLE_NAME} )
install( TARGETS
   ${CLI_CLIENT_EXECUTABLE_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR} COMPONENT base
)
endif()

add_executable( relay relay.cpp )
target_compile_options( relay PUBLIC -Wno-unused-variable -Wno-sign-compare ) 
target_link_libraries( relay pthread )

copy_bin(relay)

install(
  TARGETS
  relay
  RUNTIME
  DESTINATION
  ${CMAKE_INSTALL_FULL_BINDIR}
  COMPONENT
  base
)


file(GLOB HEADERS "include/eosio/signature_provider_plugin/*.hpp")
add_library( signature_provider_plugin
             signature_provider_plugin.cpp
             ${HEADERS} )

target_link_libraries( signature_provider_plugin appbase fc http_client_plugin )
target_include_directories( signature_provider_plugin PUBLIC include )
if(APPLE)
   target_link_libraries( signature_provider_plugin se-helpers )
endif()
if(TARGET tpm-helpers)
   target_compile_definitions( signature_provider_plugin PRIVATE ENABLE_TPM)
   target_link_libraries( signature_provider_plugin tpm-helpers )
endif()

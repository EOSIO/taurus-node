

add_library( state_history
             create_deltas.cpp
             log.cpp
             transaction_trace_cache.cpp
           )

target_link_libraries( state_history 
                       PUBLIC eosio_chain fc chainbase softfloat
                     )

target_include_directories( state_history
                            PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include"
                          )

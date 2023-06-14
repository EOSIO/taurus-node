option(PORTABLE CACHE ON)               # rocksdb: don't use sse4.2
option(WITH_GFLAGS CACHE OFF)           # rocksdb: don't use gflags
option(WITH_TESTS CACHE OFF)            # rocksdb: don't build this
option(WITH_TOOLS CACHE OFF)            # rocksdb: don't build this
option(WITH_BENCHMARK_TOOLS CACHE OFF)  # rocksdb: don't build this
option(FAIL_ON_WARNINGS CACHE OFF)      # rocksdb: stop the madness: warnings change over time


option(SML_BUILD_BENCHMARKS "Build benchmarks" OFF)
option(SML_BUILD_EXAMPLES   "Build examples"   OFF)
option(SML_BUILD_TESTS      "Build tests"      OFF)

if(NOT APPLE)
  # statically linking openssl library, for non macOS
  set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()


#on Linux, rocksdb will monkey with CMAKE_INSTALL_PREFIX is this is on
set(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT OFF)
# rocksdb disables USE_RTTI for release build, which breaks
# exception handling on MacOS.
if(APPLE)
  set(USE_RTTI ON)
endif()

add_subdirectory( fc )
add_subdirectory( builtins )

# Suppress warnings on 3rdParty Library
add_definitions( -w )
add_subdirectory( softfloat )
add_subdirectory( wasm-jit )
remove_definitions( -w )

add_subdirectory( chainbase )
add_subdirectory( appbase )
add_subdirectory( chain )
add_subdirectory( testing )
add_subdirectory( version )
add_subdirectory( state_history )
set(ABIEOS_BUILD_SHARED_LIB OFF)
add_subdirectory( abieos )

# Suppress warnings on 3rdParty Library
add_definitions( -w )
add_subdirectory( rocksdb )
remove_definitions( -w )

add_subdirectory( chain_kv )
add_subdirectory( se-helpers )
add_subdirectory( tpm-helpers )
add_subdirectory( amqp )
add_subdirectory( sml )
add_subdirectory( FakeIt )

set(USE_EXISTING_SOFTFLOAT ON CACHE BOOL "use pre-exisiting softfloat lib")
set(ENABLE_TOOLS OFF CACHE BOOL "Build tools")
set(ENABLE_TESTS OFF CACHE BOOL "Build tests")
set(ENABLE_ADDRESS_SANITIZER OFF CACHE BOOL "Use address sanitizer")
set(ENABLE_UNDEFINED_BEHAVIOR_SANITIZER OFF CACHE BOOL "Use UB sanitizer")
set(ENABLE_PROFILE OFF CACHE BOOL "Enable for profile builds")
add_subdirectory( eos-vm )

set(ENABLE_STATIC ON)
set(CMAKE_MACOSX_RPATH OFF)
set(BUILD_ONLY_LIB ON CACHE BOOL "Library only build")
message(STATUS "Starting yubihsm configuration...")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/CMakeLists.txt
               ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi_bk.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/lib/CMakeLists.txt
               ${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi_lib_bk.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi.txt
               ${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/CMakeLists.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi_lib.txt
               ${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/lib/CMakeLists.txt COPYONLY)

add_subdirectory( yubihsm EXCLUDE_FROM_ALL )
target_compile_options(yubihsm_static PRIVATE -fno-lto -fcommon)
message(STATUS "yubihsm configuration complete")

get_property(_CTEST_CUSTOM_TESTS_IGNORE GLOBAL PROPERTY CTEST_CUSTOM_TESTS_IGNORE)
set_property(GLOBAL PROPERTY CTEST_CUSTOM_TESTS_IGNORE
  "change_authkey import_ed decrypt_ec decrypt_rsa ssh logs generate_rsa import_ec echo\
  yubico_otp wrap_data wrap info import_rsa import_authkey generate_hmac generate_ec\
  attest pbkdf2 parsing ${_CTEST_CUSTOM_TESTS_IGNORE}")

add_subdirectory( rodeos )

find_package(OpenSSL REQUIRED)

# Suppress warnings on 3rdParty Library
add_definitions( -w )
option(AMQP-CPP_LINUX_TCP CACHE ON)
add_subdirectory( amqp-cpp EXCLUDE_FROM_ALL )
target_include_directories(amqpcpp PRIVATE "${OPENSSL_INCLUDE_DIR}")
remove_definitions( -w )

# Use boost asio for asio library in NuRaft
find_package(Boost COMPONENTS system)
message(Boost_INCLUDE_DIRS:)
message(${Boost_INCLUDE_DIRS})
message(Boost_LIBRARY_DIRS:)
message(${Boost_LIBRARY_DIRS})
if (Boost_INCLUDE_DIRS STREQUAL "")
  message(FATAL_ERROR "Boost is needed for building NuRaft")
endif()
if (Boost_LIBRARY_DIRS STREQUAL "")
  message(FATAL_ERROR "Boost is needed for building NuRaft")
endif()
set(BOOST_INCLUDE_PATH ${Boost_INCLUDE_DIRS})
set(BOOST_LIBRARY_PATH ${Boost_LIBRARY_DIRS})
include_directories(${Boost_INCLUDE_DIRS})
include_directories(${Boost_INCLUDE_DIRS}/boost)

set(DEPS_PREFIX ${OPENSSL_INCLUDE_DIR}/..)

add_subdirectory(nuraft)

# better looking library name, by creating a bundle
add_library(nuraft "")

target_link_libraries(nuraft PUBLIC RAFT_CORE_OBJ)

# add the include directories which NuRaft library CMakeLists.txt file does not provide
# use SYSTEM to make compiler know we are not supposed to modify the code there so that the compiler
# doesn't print warnings from the nuraft library code
target_include_directories(nuraft SYSTEM PUBLIC
  nuraft/include
  nuraft/include/libnuraft
  nuraft/src)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi_bk.txt
                ${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/CMakeLists.txt COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/CMakeLists_yubi_lib_bk.txt
               ${CMAKE_CURRENT_SOURCE_DIR}/yubihsm/lib/CMakeLists.txt COPYONLY)

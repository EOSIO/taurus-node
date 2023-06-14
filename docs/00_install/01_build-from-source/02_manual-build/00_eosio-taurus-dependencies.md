---
content_title: EOSIO-Taurus Software Dependencies
---

The EOSIO-Taurus software requires specific software dependencies to build the EOSIO-Taurus binaries. These dependencies can be built from source or installed from binaries directly. Dependencies can be pinned to a specific version release or unpinned to the current version, usually the latest one. The main EOSIO-Taurus dependencies hosted outside the EOSIO-Taurus repos are:

* Clang - the C++17 compliant compiler used by EOSIO-Taurus
* CMake - the build system used by EOSIO-Taurus
* Boost - the C++ Boost library used by EOSIO-Taurus
* OpenSSL - the secure communications (and crypto) library
* LLVM - the LLVM compiler/toolchain infrastructure

Other dependencies are either inside the EOSIO-Taurus repo, such as the `secp256k1` elliptic curve DSA library, or they are otherwise used for testing or housekeeping purposes, such as:

* automake, autoconf, autotools
* doxygen, graphviz
* python2, python3
* bzip2, zlib
* etc.

Scripts are provided for preparing the dependencies. Please check the `/scripts/` directory under the repository root.

#!/bin/bash

# A script to quickly prepare a Ubuntu 22.04 based VM development environment for building
# blockchain and smart contract repos.

if [[ "$(id -u)" != "0" ]]; then
  echo "Please run this as root or by sudo"
  exit 3
fi

if [[ -f /etc/profile.d/proxy.sh ]]; then
  source /etc/profile.d/proxy.sh
fi

source /etc/lsb-release
curl -L https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-13 main" > /etc/apt/sources.list.d/llvm.list
apt-get update -y
apt-get install -y build-essential cmake clang-13 libclang-13-dev lld-13 libc++-13-dev libc++abi-13-dev bzip2

export PROTOBUF_VERSION_SHORT=21.5
export PROTOBUF_VERSION=3.21.5
export PROTOBUF_CHECKSUM=58c8a18b4ec22655535c493155c5465a8903e8249094ceead87e00763bdbc44f
rm -rf "protobuf-${PROTOBUF_VERSION}"
curl -fsSLO https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION_SHORT}/protobuf-cpp-${PROTOBUF_VERSION}.tar.gz && \
    echo "${PROTOBUF_CHECKSUM} protobuf-cpp-${PROTOBUF_VERSION}.tar.gz" | sha256sum -c - && \
    tar xzvf protobuf-cpp-${PROTOBUF_VERSION}.tar.gz && \
    cd protobuf-${PROTOBUF_VERSION} && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=/usr/local -Dprotobuf_BUILD_TESTS=OFF && \
    cmake --build build -j && \
    cmake --install build && \
    cd .. && \
    rm -rf protobuf-cpp-${PROTOBUF_VERSION}.tar.gz "protobuf-${PROTOBUF_VERSION}" &&
    ldconfig

pip3 install google
pip3 install protobuf

rm /usr/local/include/boost/ -rf
rm /usr/local/lib/libboost_* -f

export BOOST_VERSION=1_78_0
export BOOST_VERSION_DOT=1.78.0
export BOOST_CHECKSUM=8681f175d4bdb26c52222665793eef08490d7758529330f98d3b29dd0735bccc
rm -rf "boost_${BOOST_VERSION}"
curl -fsSLO "https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION_DOT}/source/boost_${BOOST_VERSION}.tar.bz2" && \
    echo "${BOOST_CHECKSUM} boost_${BOOST_VERSION}.tar.bz2" | sha256sum -c - && \
    tar -xjf "boost_${BOOST_VERSION}.tar.bz2" && \
    cd "boost_${BOOST_VERSION}" && \
    ./bootstrap.sh --prefix=/usr/local && \
    ./b2 --with-iostreams --with-date_time --with-filesystem --with-system --with-program_options --with-chrono --with-test -j$(nproc) install && \
    cd .. && \
    rm -rf "boost_${BOOST_VERSION}.tar.bz2" "boost_${BOOST_VERSION}"

export LLVM_VERSION=7.1.0
curl -fsSLO "https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/llvm-${LLVM_VERSION}.src.tar.xz" && \
    tar -xvf "llvm-${LLVM_VERSION}.src.tar.xz" && \
    cd "llvm-${LLVM_VERSION}.src" && \
    mkdir build && cd build && \
    cmake -G 'Unix Makefiles' -DLLVM_TARGETS_TO_BUILD=host -DLLVM_BUILD_TOOLS=false -DLLVM_ENABLE_RTTI=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local  -DCMAKE_EXE_LINKER_FLAGS=-pthread -DCMAKE_SHARED_LINKER_FLAGS=-pthread -DLLVM_ENABLE_PIC=NO -DLLVM_ENABLE_TERMINFO=OFF .. && \
    make -j$(nproc) && make install && \
    cd / && \
    rm -rf "llvm-${LLVM_VERSION}.src.tar.xz" "llvm-${LLVM_VERSION}.src"

echo ""
echo "Configuration done."
echo ""


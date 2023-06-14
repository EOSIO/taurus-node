#!/bin/bash

# A script to quickly prepare a Ubuntu 22.04 based VM development environment for building
# blockchain and smart contract repos.

if [[ "$(id -u)" != "0" ]]; then
  echo "Please run this as root or by sudo"
  exit 3
fi

apt update -y
apt install -y curl gnupg bzip2 python3-pip cmake libgmp-dev pkg-config colordiff libusb-1.0-0-dev libcurl4-openssl-dev tpm2-openssl libtpms-dev autoconf libtool-bin

apt remove -y gcc g++
apt autoremove -y

source /etc/lsb-release
curl -L https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-13 main" > /etc/apt/sources.list.d/llvm.list
apt update -y
apt install -y clang-13 libclang-13-dev lld-13 libc++-13-dev libc++abi-13-dev

export PATH=/usr/lib/llvm-13/bin:$PATH
export CC=/usr/lib/llvm-13/bin/clang

apt install -y llvm-11

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

echo ""
echo "Configuration done."
echo ""
echo "Please add to your environment:"
echo ""
echo "  export PATH=/usr/lib/llvm-11/bin:\$PATH"
echo "  export CC=/usr/lib/llvm-13/bin/clang"
echo "  export CXX=/usr/lib/llvm-13/bin/clang++"
echo ""
echo "Please build and install the following packages"
echo ""
echo " - openssl 1.1.1 https://www.openssl.org/source/"
echo " - tpm2-tss https://github.com/tpm2-software/tpm2-tss"
echo " - libtpms https://github.com/stefanberger/libtpms"
echo ""


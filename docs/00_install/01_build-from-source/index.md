---
content_title: Build EOSIO-Taurus from Source
---

## Supported Operating Systems

EOSIO-Taurus currently supports the following operating systems:

- Ubuntu 22.04

Note: It may be possible to install EOSIO-Taurus on other Unix-based operating systems. This is not officially supported, though.

## Make sure the dependencies are all prepared in the building environment

Please check [the dependencies document](./02_manual-build/00_eosio-taurus-dependencies.md) for the depended libraries.

## Building the project

The project makes use of cmake and it can be built by

```
git clone <repository URL>
cd taurus-node
git submodule update --init --recursive
mkdir -p build
cd build
cmake ..
make -j8
```

## Running the tests

This repository contains many tests. To run the integration tests:

```
cd build
ctest . -LE '_tests$'
```

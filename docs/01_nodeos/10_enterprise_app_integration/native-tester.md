## Overview

Smart contracts are compiled to WASM code to be run on the blockchain nodeos. This carries some benefits and drawbacks, one of the drawbacks is that traditional debugging is not well supported for WASM code in general, and not even to mention debugging smart contract WASM code in a running environment with a blockchain state. For this reason, EOSIO-Taurus supports a solution consisting of a) generating native code files for contract, b) tester tool to execute and debug the native code files on a local machine, and c) support in nodeos to load the native code file as contract code.

## How to debug a smart contract

Below are the steps required setup the environment for smart contract debugging.

### Build Native-Tester from Source
First, check out EOSIO-Taurus and clone submodules.

Next, build Debug version:

```shell
cmake -DCMAKE_PREFIX_PATH=/usr/lib/llvm-10 -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

To verify the success of the build, check and make sure that there is a binary named native-tester in build directory.

### Compile the smart contracts

```shell
export CONFIG=native-debug
export TAURUS_NODE_ROOT=/path/to/taurus-node/build
export TAURUS_CDT_ROOT=/path/to/taurus-cdt/build
cmake --preset $CONFIG
cmake --build --preset $CONFIG -- -j8
ctest --preset $CONFIG
```

Note: the taurus-cdt compiler is one compiler that can generate the native contract code that is compatible with EOSIO-Taurus. Please stay tuned for future releases.

### Run the Debugger Directly

Using gdb as an example (lldb works too).

```shell
gdb --args ./native-tester myapp_tests.so
```

then in the gdb console, disable SIG34 signal (if you haven’t)

```shell
(gdb) handle SIG34 nostop noprint
```

add a breakpoint, e.g. by file and line number,

```shell
(gdb) b myapp.cpp:1327
```

then run

```shell
(gdb) r
```
finally, you will see output like

```shell
====== Starting the "myapp_execution - myact()" test ======

getString size(24)
ipchdr: len(184) sys(3) msg_type(1500) dyn_offset(160) tm(0)

Thread 1 "native-tester" hit Breakpoint 1, myapp::myapp_contract::myact (this=0x7fffffffaee8, msg=...)
1329	   eosio::require_auth(get_self());
```

### Run the Debugger through an IDE (VS Code)

There is an issue with VS Code lldb-mi on macOS. Please install VS Code CodeLLDB extension.
Below is an example launch.json file (note type is set to lldb as an example)

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "lldb: myapp_tests",
            "type": "lldb",
            "request": "launch",
            "program": "${workspaceFolder}/build/native/debug/native-tester",
            "args": ["${workspaceFolder}/build/native/debug/myapp_tests.so"],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}/build/native/debug",
            "environment": [],
            "externalConsole": false,
            "MIMode": "lldb"
        }
    ]
}
```

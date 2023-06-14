
## Overview

The `rodeos_plugin` provides a high performance storage engine and interface to run concurrent read-only queries against the blockchain state. The plugin incorporates all the functionality formerly povided by the `rodeos` binary and obviates the need for running a separate `state_history_plugin` to source the requisite data. The `rodeos_plugin` relies on an in-memory transfer of blockchain state from nodeos to the plugin at end of every block. The plugin provides a series of rpc end points to query data.

Since the plugin is initialized after nodeos has loaded its copy of state, the plugin does not itself maintain a durable copy of the latest state on disk between restarts. At startup the plugin will resync with the latest copy of state from nodeos and continue doing so until the nodeos process is shut down.

## Usage

```console
# config.ini
plugin =  b1::rodeos_plugin
[options]
```
```sh
# command-line
nodeos ... --plugin  b1::rodeos_plugin  [options]
```

## RPC end points supported

These end points can be used in a manner similar to the equivalent nodeos end points
```
  /v1/chain/get_info
  /v1/chain/get_block
  /v1/chain/get_account
  /v1/chain/get_abi
  /v1/chain/get_raw_abi
  /v1/chain/get_required_keys
  /v1/chain/send_transaction
  /v1/rodeos/create_checkpoint
```

## Configuration Options

These can be specified from the `config.ini` file:

```console
Config Options for b1::rodeos_plugin:

  wql-threads (8)
                                        Number of threads to process requests
  wql-listen (=127.0.0.1:8880)
                                        Endpoint to listen on
  wql-unix-listen
                                        Unix socket path to listen on
  wql-retries (0xffff'ffff)
                                        Number of times to retry binding to
                                        wql-listen. Each retry is approx 1 second
                                        apart. Set to 0 to prevent retries
  wql-allow-origin
                                        Access-Control-Allow-Origin header.
                                        Use "*" to allow any
  wql-contract-dir
                                        Directory to fetch contracts from. These
                                        override contracts on the chain.
                                        (default: disabled)
  wql-static-dir
                                        Directory to serve static files from
                                        (default: disabled)
  wql-query-mem (33)
                                        Maximum size of wasm memory (MiB)
  wql-console-size (0)
                                        Maximum size of console data
  wql-wasm-cache-size (100)
                                        Maximum number of compiled wasms to cache
  wql-max-request-size (10000)
                                        HTTP maximum request body size (bytes)
  wql-idle-timeout
                                        HTTP idle connection timeout (ms)
  wql-exec-time (200)
                                        Max query execution time (ms)
  wql-checkpoint-dir
                                        Directory to place checkpoints. Caution:
                                        this allows anyone to create a checkpoint
                                        using RPC (default: disabled)

  wql-max-action-return-value
                                        Max action return value size (bytes)
```


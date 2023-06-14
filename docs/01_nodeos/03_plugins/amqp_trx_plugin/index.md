
## Overview

This plugin enables the consumption of transactions to be executed through the use of an AMQP queue provided by a queue system, such as RabbitMQ, widely used in enterprise applications.

The transactions are processed on a first-in first-out (FIFO) order, even when the producer nodeos switches during [auto failover](../producer_ha_plugin/index.md). This feature can make the enterprise applications easier to write on top of the blockchain.

It can receive transactions encoded using the `chain::packed_transaction_v0` or `chain::packed_transaction` formats.

## Usage

```console
# config.ini
plugin = eosio::eosio::amqp_trx_plugin
[options]
```
```sh
# command-line
nodeos ... --plugin eosio::eosio::amqp_trx_plugin [options]
```

## Configuration Options

These can be specified from both the `nodeos` command-line or the `config.ini` file:

```console
  --amqp-trx-address arg                AMQP address: Format:
                                        amqp://USER:PASSWORD@ADDRESS:PORT
                                        Will consume from amqp-trx-queue-name
                                        (amqp-trx-queue-name) queue.
                                        If --amqp-trx-address is not specified,
                                        will use the value from the environment
                                        variable EOSIO_AMQP_ADDRESS.
  --amqp-trx-queue-name arg (=trx)      AMQP queue to consume transactions
                                        from, must already exist.
  --amqp-trx-queue-size arg (=1000)     The maximum number of transactions to
                                        pull from the AMQP queue at any given
                                        time.
  --amqp-trx-retry-timeout-us arg (=60000000)
                                        Time in microseconds to continue to
                                        retry a connection to AMQP when
                                        connection is loss or startup.
  --amqp-trx-retry-interval-us arg (=500000)
                                        When connection is lost to
                                        amqp-trx-queue-name, interval time in
                                        microseconds before retrying
                                        connection.
  --amqp-trx-speculative-execution      Allow non-ordered speculative execution
                                        of transactions
  --amqp-trx-ack-mode arg (=in_block)   AMQP ack when 'received' from AMQP,
                                        when 'executed', or when 'in_block' is
                                        produced that contains trx.
                                        Options: received, executed, in_block
  --amqp-trx-startup-stopped            do not start plugin on startup -
                                        require RPC amqp_trx/start to start
                                        plugin
  --amqps-ca-cert-perm arg (=test_ca_cert.perm)
                                        ca cert perm file path for ssl,
                                        required only for amqps.
  --amqps-cert-perm arg (=test_cert.perm)
                                        client cert perm file path for ssl,
                                        required only for amqps.
  --amqps-key-perm arg (=test_key.perm) client key perm file path for ssl,
                                        required only for amqps.
  --amqps-verify-peer                   config ssl/tls verify peer or not.
```


## Overview

This plugin enables streaming messages from the smart contract. The smart contracts can call the `push_event` intrinsic to send a message to an AMQP queue. Any nodeos in a blockchain cluster can be configured to push messages, and a cluster can be configured to have 1 or more dedicated nodeos instances for streaming.

The intrinsic `push_event` can send a message if the nodeos executing the transaction is configured to stream, or do nothing if the nodeos is not configured for streaming.

```cpp
inline void push_event(eosio::name tag, std::string route, const std::vector<char>& data)
```

where

* tag: corresponds to individual AQMP queue or exchange.
* route: route for the event.
* data: payload for the event.

## Usage

```console
# config.ini
plugin = eosio::event_streamer_plugin
[options]
```
```sh
# command-line
nodeos ... --plugin eosio::event_streamer_plugin [options]
```

## Configuration Options

These can be specified from both the `nodeos` command-line or the `config.ini` file:

```console
  --event-tag arg                       Event tags for configuration of
                                        environment variables
                                        TAURUS_STREAM_RABBITS_<tag> &
                                        TAURUS_STREAM_RABBITS_EXCHANGE_<tag>.
                                        The tags correspond to eosio::name tags
                                        in the event_wrapper for mapping to
                                        individual AQMP queue or exchange.
                                        TAURUS_STREAM_RABBITS_<tag> Addresses
                                        of RabbitMQ queues to stream to.
                                        Format: amqp://USER:PASSWORD@ADDRESS:PO
                                        RT/QUEUE[/STREAMING_ROUTE, ...].
                                        Multiple queue addresses can be
                                        specified with ::: as the delimiter,
                                        such as "amqp://u1:p1@amqp1:5672/queue1
                                        :::amqp://u2:p2@amqp2:5672/queue2".
                                        TAURUS_STREAM_RABBITS_EXCHANGE_<tag>
                                        Addresses of RabbitMQ exchanges to
                                        stream to. amqp://USER:PASSWORD@ADDRESS
                                        :PORT/EXCHANGE[::EXCHANGE_TYPE][/STREAM
                                        ING_ROUTE, ...]. Multiple queue
                                        addresses can be specified with ::: as
                                        the delimiter, such as
                                        "amqp://u1:p1@amqp1:5672/exchange1:::am
                                        qp://u2:p2@amqp2:5672/exchange2".
  --event-rabbits-immediately           Stream to RabbitMQ immediately instead
                                        of batching per block. Disables
                                        reliable message delivery.
  --event-loggers arg                   Logger for events if any; Format:
                                        [routing_keys, ...]
  --event-delete-unsent                 Delete unsent AMQP stream data retained
                                        from previous connections
```

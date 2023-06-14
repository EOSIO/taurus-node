
## Overview

The `producer_ha_plugin` provides a block producer nodeos (BP) high availability (HA) solution for the EOSIO-Taurus blockchain based on the [Raft consensus protocol](https://raft.github.io/raft.pdf), to meeting the high availability for enterprise blockchain deployment with 24x7 availability requirements.

The `producer_ha_plugin` based HA solution can provide:

- If any producing BP is down or producing stopped, another BP nodeos should automatically take over as the producing BP to continue producing blocks, if it can do this safely. The delay is relative short.
- If there are conflicting blocks, one and only one will be broadcast by the signing BP nodeos and visible to the blockchain network.
- Only after a block newly produced has been broadcast out and committed by the quorum of BPs, the trace for the transaction can be sent back to the client, when the `amqp_trx_plugin` is used and the `amqp-trx-ack-mode` is set to be `in_block`.

The `producer_ha_plugin` works as follows.

- BPs using `producer_ha_pugin` to form a consensus group through the Raft protocol, to commit messages for blocks to the Raft group and reach consensus among BPs to accept the blocks.
- Elect the single leader, through the Raft protocol, and only the leader is the BP that can try to produce blocks.
  - Leadership has expiration time.
    - We require the lead ship expiration in the Raft consensus protocol to make sure that there is at most 1 single leader that may produce blocks at any time point. Through the leader expiration time, we guarantee there is no overlap between 2 leaders within the Raft group even there are network splits.
    - If the leader is still active, it renews its leadership before the leadership expiration.
  - If the producing BP (leader) is down or fails to renew its leadership before its leadership expires, another new BP will automatically take over as the new leader after the previous leader’s leadership expiration time, and will try to produce blocks.
    - If the leader BP is down, the remaining BP nodeos can elect a new leader to be the producing BP, if the remaining BPs can form a quorum.
    - If more BPs are down, if the remaining BPs can not form a quorum to elect a leader, they will retry until BPs join the group and form a quorum to reach consensus and elect a new leader. During the time, no leader and no producing BP.
- Producing BP (the leader) commits blocks produced through the Raft protocol among the BPs before adding the block to its blocklog.
  - After signing a block and before including the block into its blocklog, the leader BP first broadcasts the block head and commits to the Raft group to make sure the quorum (> half of the Raft group size) of the BPs accepts the block. After the new block is confirmed by the Raft group, the new block is marked as `accepted head block`.
  - `net_plugin`/`producer_plugin` in the BPs in the active Raft group, upon receiving a new block, will first check a) whether the block is smaller than the current commit’ed head block, or b) whether the new block is the `accepted head block` with the `producer_ha_plugin`. If the check fails, `net_plugin`/`producer_plugin` will reject that block.
  - `net_plugin`/`producer_plugin` in the downstream nodeos' sync blocks the same as usual.
- More than one independent Raft group can be configured for failover in different disaster recovery (DR) regions.
  - Each region’s BPs form a Raft group.
  - The Raft group maintains a `is_active_raft_cluster` variable to indicate whether it is active or not. The standby region's Raft’s `is_active_raft_cluster` is false. And no BP is allowed to produce in the standby region.
  - Operators, by changing the `producer_ha_plugin` configuration file to set the `is_active_raft_cluster` variable, can activate or deactivate the production in the region.

## Usage

```console
# config.ini
plugin = eosio::producer_ha_plugin
[options]
```
```sh
# command-line
nodeos ... --plugin eosio::producer_ha_plugin [options]
```

## Configuration Options

These can be specified from both the `nodeos` command-line or the `config.ini` file:

```console
Config Options for eosio::producer_ha_plugin:

Config Options for eosio::producer_ha_plugin:
  --producer-ha-config arg              producer_ha_plugin configuration file
                                        path. The configuration file should
                                        contain a JSON string specifying the
                                        parameters, whether the producer_ha
                                        cluster is active or standby, self ID,
                                        and the peers (including this node
                                        itself) configurations with ID (>=0),
                                        endpoint address and listening_port
                                        (optional, used only if the port is
                                        different from the port in its endpoint
                                        address).
                                        Example (for peer 1 whose address is
                                        defined in peers too):
                                        {
                                          "is_active_raft_cluster": true,
                                          "leader_election_quorum_size": 2,
                                          "self": 1,
                                          "logging_level": 3,
                                          "peers": [
                                            {
                                              "id": 1,
                                              "listening_port": 8988,
                                              "address": "localhost:8988"
                                            },
                                            {
                                              "id": 2,
                                              "address": "localhost:8989"
                                            },
                                            {
                                              "id": 3,
                                              "address": "localhost:8990"
                                            }
                                          ]
                                        }

                                        logging_levels:
                                           <= 2: error
                                              3: warn
                                              4: info
                                              5: debug
                                           >= 6: all
```


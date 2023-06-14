---
content_title: RPC APIs
link_text: RPC APIs
---

`nodeos` provides RPC APIs through the RPC. During startup, `nodeos` prints out the list of supported APIs into the logs.

Here is an example list

```
/v1/producer/pause
/v1/producer/resume
/v1/producer/add_greylist_accounts
/v1/producer/create_snapshot
/v1/producer/get_account_ram_corrections
/v1/producer/get_greylist
/v1/producer/get_integrity_hash
/v1/producer/get_runtime_options
/v1/producer/get_scheduled_protocol_feature_activations
/v1/producer/get_supported_protocol_features
/v1/producer/get_whitelist_blacklist
/v1/producer/paused
/v1/producer/remove_greylist_accounts
/v1/producer/schedule_protocol_feature_activations
/v1/producer/set_whitelist_blacklist
/v1/producer/update_runtime_options
/v1/chain/get_info
/v1/chain/abi_bin_to_json
/v1/chain/abi_json_to_bin
/v1/chain/get_abi
/v1/chain/get_account
/v1/chain/get_activated_protocol_features
/v1/chain/get_all_accounts
/v1/chain/get_block
/v1/chain/get_block_header_state
/v1/chain/get_block_info
/v1/chain/get_code
/v1/chain/get_code_hash
/v1/chain/get_consensus_parameters
/v1/chain/get_currency_balance
/v1/chain/get_currency_stats
/v1/chain/get_genesis
/v1/chain/get_kv_table_rows
/v1/chain/get_producer_schedule
/v1/chain/get_producers
/v1/chain/get_raw_abi
/v1/chain/get_raw_code_and_abi
/v1/chain/get_required_keys
/v1/chain/get_table_by_scope
/v1/chain/get_table_rows
/v1/chain/get_transaction_id
/v1/chain/push_block
/v1/chain/push_transaction
/v1/chain/push_transactions
/v1/chain/send_ro_transaction
/v1/chain/send_transaction
/v2/chain/send_transaction
/v1/net/connect
/v1/net/connections
/v1/net/disconnect
/v1/net/status
/v1/db_size/get
/v1/db_size/get_reversible
```



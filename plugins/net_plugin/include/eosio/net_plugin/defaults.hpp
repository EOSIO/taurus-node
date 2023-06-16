#pragma once

#include <chrono>

namespace eosio {

/**
 * default value initializers
 */
constexpr auto     def_send_buffer_size_mb = 4;
constexpr auto     def_send_buffer_size = 1024*1024*def_send_buffer_size_mb;
constexpr auto     def_max_write_queue_size = def_send_buffer_size*10;
constexpr auto     def_max_trx_in_progress_size = 100*1024*1024; // 100 MB
constexpr auto     def_max_consecutive_immediate_connection_close = 9; // back off if client keeps closing
constexpr auto     def_max_clients = 25; // 0 for unlimited clients
constexpr auto     def_max_nodes_per_host = 1;
constexpr auto     def_conn_retry_wait = 30;
constexpr auto     def_txn_expire_wait = std::chrono::seconds(3);
constexpr auto     def_resp_expected_wait = std::chrono::seconds(5);
constexpr auto     def_sync_fetch_span = 100;
constexpr auto     def_keepalive_interval = 32000;

constexpr uint32_t def_handshake_backoff_floor_ms = 5;
constexpr uint32_t def_handshake_backoff_cap_ms = 5000;

constexpr auto     message_header_size = 4;

constexpr uint16_t heartbeat_interval = 4;        // supports configurable heartbeat interval
constexpr uint16_t proto_pruned_types = 3;        // supports new signed_block & packed_transaction types
constexpr uint16_t dup_goaway_resolution = 5;     // support peer address based duplicate connection resolution
constexpr uint16_t dup_node_id_goaway = 6;        // support peer node_id based duplicate connection resolution

} //eosio

#pragma once
#include <eosio/net_plugin/connection.hpp>

#include <memory>

namespace eosio{ namespace p2p {
template <typename Strand>
void verify_strand_in_this_thread(const Strand&, const char*, int) {}
}} //eosio::p2p

struct mock_lock{
   void lock(){};
   void unlock(){};
};

struct mock_strand {};

struct mock_connection {
   using ptr = std::shared_ptr<mock_connection>;

   virtual bool current() const = 0;
   virtual bool is_transactions_only_connection() const = 0;
   virtual void send_handshake() = 0;
   virtual const eosio::p2p::peer_conn_info& get_ci() = 0;
   virtual void post(std::function<void()> f) = 0;
   virtual mock_lock locked_connection_mutex() const = 0;
   virtual uint32_t get_fork_head_num() const = 0;
   virtual const eosio::chain::block_id_type& get_fork_head() const = 0;
   virtual uint32_t get_id() const = 0;
   virtual eosio::p2p::handshake_message get_last_handshake() const = 0;
   virtual mock_strand get_strand() const = 0;
   virtual void request_sync_blocks(uint32_t, uint32_t) = 0;
   virtual void reset_fork_head() = 0;
};
#pragma once

#include <fc/log/logger.hpp>
#include <eosio/net_plugin/mock_connection.hpp>

#include <eosio/chain/types.hpp>

using mock_connection_ptr = mock_connection::ptr;

struct mock_net_plugin_interface {
   virtual fc::logger& get_logger() const = 0;
   virtual const std::string& get_log_format() const = 0;
   virtual std::tuple<uint32_t, 
                      uint32_t, 
                      uint32_t, 
                      eosio::chain::block_id_type, 
                      eosio::chain::block_id_type, 
                      eosio::chain::block_id_type> get_chain_info() = 0;
   virtual void for_each_connection( std::function<bool(const mock_connection_ptr&)>) const = 0;
   virtual void for_each_block_connection( std::function<bool(const mock_connection_ptr&)> ) const = 0;
   virtual mock_lock shared_connections_lock() const = 0;
   virtual std::set<mock_connection_ptr> get_connections() const = 0;
};
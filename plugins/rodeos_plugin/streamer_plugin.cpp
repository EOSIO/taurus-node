// copyright defined in LICENSE.txt

#include <eosio/rodeos_plugin/streamer_plugin.hpp>
#include <eosio/rodeos_plugin/streamer_types.hpp>
#include <eosio/rodeos_plugin/cloner_plugin.hpp>
#include <eosio/rodeos_plugin/streams/logger.hpp>
#include <eosio/rodeos_plugin/streams/rabbitmq.hpp>
#include <eosio/rodeos_plugin/streams/stream.hpp>
#include <eosio/abieos.hpp>
#include <eosio/abi.hpp>
#include <eosio/chain/exceptions.hpp>
#include <chainbase/pinnable_mapped_file.hpp>
#include <fc/exception/exception.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/trace.hpp>
#include <boost/filesystem/operations.hpp>
#include <regex>
#include <memory>

namespace b1 {

using namespace appbase;
using namespace std::literals;

struct streamer_plugin_impl : public streamer_t {

   void start_block(uint32_t block_num, uint32_t streamer_id) override {
      EOS_ASSERT( 0 <= streamer_id && streamer_id < max_num_streamers, eosio::chain::plugin_exception, "invalid streamer_id: {streamer_id}. max_num_streamers: {max_num_streamers}", ("streamer_id", streamer_id) ("max_num_streamers", max_num_streamers) );

      for (const auto& stream : streams[streamer_id]) {
         stream->start_block(block_num);
      }
   }

   void stream_data(const char* data, uint64_t data_size, uint32_t streamer_id) override {
      EOS_ASSERT( 0 <= streamer_id && streamer_id < max_num_streamers, eosio::chain::plugin_exception, "invalid streamer_id: {streamer_id}. max_num_streamers: {max_num_streamers}", ("streamer_id", streamer_id) ("max_num_streamers", max_num_streamers) );

      eosio::input_stream bin(data, data_size);
      stream_wrapper      res = eosio::from_bin<stream_wrapper>(bin);
      std::visit([&](const auto& sw) { publish_to_streams(sw, streamer_id); }, res);
   }

   void publish_to_streams(const stream_wrapper_v0& sw, uint32_t streamer_id) {
      std::string route;
      for (const auto& stream : streams[streamer_id]) {
         route = sw.route.to_string();
         if (stream->check_route(route)) {
            stream->publish(sw.data, route);
         }
      }
   }

   void publish_to_streams(const stream_wrapper_v1& sw, uint32_t streamer_id) {
      for (const auto& stream : streams[streamer_id]) {
         if (stream->check_route(sw.route)) {
            stream->publish(sw.data, sw.route);
         }
      }
   }

   void stop_block(uint32_t block_num, uint32_t streamer_id) override {
      EOS_ASSERT( 0 <= streamer_id && streamer_id < max_num_streamers, eosio::chain::plugin_exception, "invalid streamer_id: {streamer_id}. max_num_streamers: {max_num_streamers}", ("streamer_id", streamer_id) ("max_num_streamers", max_num_streamers) );

      for (const auto& stream : streams[streamer_id]) {
         stream->stop_block(block_num);
      }
   }

   std::vector<std::vector<std::unique_ptr<stream_handler>>> streams;
   bool delete_previous = false;
   bool publish_immediately = false;
   std::set<int> filter_ids;  // indexes of streamers used
};

static abstract_plugin& _streamer_plugin = app().register_plugin<streamer_plugin>();

streamer_plugin::streamer_plugin() : my(std::make_shared<streamer_plugin_impl>()) {
   app().register_config_type<chainbase::pinnable_mapped_file::map_mode>();
}

streamer_plugin::~streamer_plugin() {}

void streamer_plugin::set_program_options(options_description& cli, options_description& cfg) {
   auto op = cfg.add_options();

   std::string rabbits_default_value;
   char* rabbits_env_var = std::getenv(EOSIO_STREAM_RABBITS_ENV_VAR);
   if (rabbits_env_var) rabbits_default_value = rabbits_env_var;
   op("stream-rabbits", bpo::value<std::string>()->default_value(rabbits_default_value),
      "Addresses of RabbitMQ queues to stream to. Format: amqp://USER:PASSWORD@ADDRESS:PORT/QUEUE[/STREAMING_ROUTE, ...]. "
      "Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/queue1:::amqp://u2:p2@amqp2:5672/queue2\"."
      "If this option is not specified, the value from the environment variable "
      EOSIO_STREAM_RABBITS_ENV_VAR
      " will be used.");

   std::string rabbits_exchange_default_value;
   char* rabbits_exchange_env_var = std::getenv(EOSIO_STREAM_RABBITS_EXCHANGE_ENV_VAR);
   if (rabbits_exchange_env_var) rabbits_exchange_default_value = rabbits_exchange_env_var;
   op("stream-rabbits-exchange", bpo::value<std::string>()->default_value(rabbits_exchange_default_value),
      "Addresses of RabbitMQ exchanges to stream to. amqp://USER:PASSWORD@ADDRESS:PORT/EXCHANGE[::EXCHANGE_TYPE][/STREAMING_ROUTE, ...]. "
      "Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/exchange1:::amqp://u2:p2@amqp2:5672/exchange2\"."
      "If this option is not specified, the value from the environment variable "
      EOSIO_STREAM_RABBITS_EXCHANGE_ENV_VAR
      " will be used.");

   op("stream-rabbits-immediately", bpo::bool_switch(&my->publish_immediately)->default_value(false),
      "Stream to RabbitMQ immediately instead of batching per block. Disables reliable message delivery.");
   op("stream-loggers", bpo::value<std::vector<string>>()->composing(),
      "Logger Streams if any; Format: [routing_keys, ...]");

   cli.add_options()
     ("stream-delete-unsent", bpo::bool_switch(&my->delete_previous),
      "Delete unsent AMQP stream data retained from previous connections");

   // Multiple filter contracts support
   for (unsigned int i = 0; i < max_num_streamers; ++i) {
      std::string i_str = std::to_string(i);

      std::string rabbits_default_value;
      std::string rabbits_env_var_str = std::string{EOSIO_STREAM_RABBITS_ENV_VAR} + std::string{"_"} + i_str;
      std::string rabbits_op_str = std::string{"stream-rabbits-"} + i_str;
      char* rabbits_env_var_value = std::getenv(rabbits_env_var_str.c_str());
      if (rabbits_env_var_value) rabbits_default_value = rabbits_env_var_value;

      std::string rabbits_op_desc = std::string{"Streamer "} + i_str +
          std::string{" of addresses of RabbitMQ queues to stream to. Format:amqp://USER:PASSWORD@ADDRESS:PORT/QUEUE[/STREAMING_ROUTE, ...]. Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/queue1:::amqp://u2:p2@amqp2:5672/queue2\". If this option is not specified, the value from the environment variable. "} +
          std::string{EOSIO_STREAM_RABBITS_ENV_VAR} + std::string{"_"} +
          i_str + std::string{" will be used. Make sure matching the order of filter contracts."};
      op(rabbits_op_str.c_str(), bpo::value<std::string>()->default_value(rabbits_default_value), rabbits_op_desc.c_str());

      std::string rabbits_exchange_default_value;
      std::string rabbits_exchange_env_var_str = std::string{EOSIO_STREAM_RABBITS_EXCHANGE_ENV_VAR} + std::string{"_"} + i_str;
      char* rabbits_exchange_env_var_value = std::getenv(rabbits_exchange_env_var_str.c_str());
      if (rabbits_exchange_env_var_value) rabbits_exchange_default_value = rabbits_exchange_env_var_value;
      std::string exchange_op_str = std::string{"stream-rabbits-exchange-"} + i_str;
      std::string exchange_op_desc = std::string{"Streamer "} + i_str +
         std::string{" addresses of RabbitMQ exchanges to stream to. amqp://USER:PASSWORD@ADDRESS:PORT/EXCHANGE[::EXCHANGE_TYPE][/STREAMING_ROUTE, ...]. Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/exchange1:::amqp://u2:p2@amqp2:5672/exchange2\". If this option is not specified, the value from the environment variable "} +
         std::string{EOSIO_STREAM_RABBITS_EXCHANGE_ENV_VAR} + std::string{"_"} + i_str + std::string{" will be used. Make sure matching the order of filter contracts"};
      op(exchange_op_str.c_str(), bpo::value<std::string>()->default_value(rabbits_exchange_default_value), exchange_op_desc.c_str());

      std::string logger_op_str = std::string{"stream-loggers-"} + i_str;
      std::string logger_op_desc = std::string{"Streamer "} + i_str +
         std::string{" logger streams. Multiple loggers can be specified with ::: as the delimiter, such as \"routing_keys1:::routing_keys2\"."};
      op(logger_op_str.c_str(), bpo::value<std::string>(), logger_op_desc.c_str());
   }
}

void streamer_plugin::plugin_initialize(const variables_map& options) {
   try {
      my->streams.resize(max_num_streamers);

      const boost::filesystem::path stream_data_path = appbase::app().data_dir() / "stream";
      auto is_single_filter_config = false;

      if( my->delete_previous ) {
         if( boost::filesystem::exists( stream_data_path ) )
            boost::filesystem::remove_all( stream_data_path );
      }

      if (options.count("stream-loggers")) {
         auto loggers = options.at("stream-loggers").as<std::vector<std::string>>();
         initialize_loggers(my->streams[0], loggers);
         is_single_filter_config = true;
      }

      auto split_option = [](const std::string& str, std::vector<std::string>& results) {
         std::regex delim{":::"};
         std::sregex_token_iterator end;
         std::sregex_token_iterator iter(str.begin(), str.end(), delim, -1);
         for ( ; iter != end; ++iter) {
            std::string split(*iter);
            if (split.size()) results.push_back(split);
         }
      };

      if (options.count("stream-rabbits")) {
         std::vector<std::string> rabbits;
         split_option(options.at("stream-rabbits").as<std::string>(), rabbits);
         if ( !rabbits.empty() ) {
            initialize_rabbits_queue(my->streams[0], rabbits, my->publish_immediately, stream_data_path);
            is_single_filter_config = true;
         }
      }

      if (options.count("stream-rabbits-exchange")) {
         std::vector<std::string> rabbits_exchanges;
         split_option(options.at("stream-rabbits-exchange").as<std::string>(), rabbits_exchanges);
         if ( !rabbits_exchanges.empty() ) {
            initialize_rabbits_exchange(my->streams[0], rabbits_exchanges, my->publish_immediately, stream_data_path);
            is_single_filter_config = true;
         }
      }

      ilog("number of legacy streams: {size}", ("size", my->streams[0].size()));

      // Multiple filter contracts support

      std::vector<boost::filesystem::path> stream_data_paths (max_num_streamers);

      for (unsigned int i = 0; i < max_num_streamers; ++i) {
         std::string i_str = std::to_string(i);

         std::string s = std::string{"streams_"} + i_str;
         stream_data_paths[i] = appbase::app().data_dir() / s.c_str();

         if( my->delete_previous ) {
            if( boost::filesystem::exists( stream_data_paths[i]) )
               boost::filesystem::remove_all( stream_data_paths[i] );
         }

         auto split_option = [](const std::string& str, std::vector<std::string>& results) {
            std::regex delim{":::"};
            std::sregex_token_iterator end;
            std::sregex_token_iterator iter(str.begin(), str.end(), delim, -1);
            for ( ; iter != end; ++iter) {
               std::string split(*iter);
               if (split.size()) results.push_back(split);
            }
         };

         std::string loggers_op_str = std::string{"stream-loggers-"} + i_str;
         if (options.count(loggers_op_str.c_str())) {
            std::vector<std::string> loggers;
            split_option(options.at(loggers_op_str.c_str()).as<std::string>(), loggers);
            if (loggers.size() > 0) {
               EOS_ASSERT(!is_single_filter_config, eosio::chain::plugin_config_exception, "{loggers_op_str} cannot be mixed with stream-rabbits, stream-rabbits-exchange, or stream-loggers", ("loggers_op_str", loggers_op_str));
               initialize_loggers(my->streams[i], loggers);
               my->filter_ids.insert(i);
            }
	         ilog("streamer: {i}, number of loggers: {s}", ("i", i) ("s", loggers.size()));
         }

         std::string rabbits_op_str = std::string{"stream-rabbits-"} + i_str;
         ilog("rabbits count: {c}", ("c", options.count(rabbits_op_str.c_str())));
         if (options.count(rabbits_op_str.c_str())) {
            std::vector<std::string> rabbits;
            split_option(options.at(rabbits_op_str.c_str()).as<std::string>(), rabbits);
            if (rabbits.size() > 0) {
               EOS_ASSERT(!is_single_filter_config, eosio::chain::plugin_config_exception, "{rabbits_op_str} cannot be mixed with stream-rabbits, stream-rabbits-exchange, or stream-loggers", ("rabbits_op_str", rabbits_op_str));
               initialize_rabbits_queue(my->streams[i], rabbits, my->publish_immediately, stream_data_paths[i]);
               my->filter_ids.insert(i);
            }
            ilog("streamer: {i}, number of rabbits: {s}", ("i", i) ("s", rabbits.size()));
         }

         std::string exchange_op_str = std::string{"stream-rabbits-exchange-"} + i_str;
         if (options.count(exchange_op_str.c_str())) {
            std::vector<std::string> exchanges;
            split_option(options.at(exchange_op_str.c_str()).as<std::string>(), exchanges);
            if (exchanges.size() > 0) {
               EOS_ASSERT(!is_single_filter_config, eosio::chain::plugin_config_exception, "{exchange_op_str} cannot be mixed with stream-rabbits, stream-rabbits-exchange, or stream-loggers", ("exchange_op_str", exchange_op_str));
               initialize_rabbits_exchange(my->streams[i], exchanges, my->publish_immediately, stream_data_paths[i]);
               my->filter_ids.insert(i);
            }
            ilog("streamer: {i}, number of rabbits exchanges: {s}", ("i", i) ("s", exchanges.size()));
         }

         ilog("streamer: {i}, number of initialized streams: {size}", ("i", i) ("size", my->streams[i].size()));
      }
   } FC_LOG_AND_RETHROW()
}

void streamer_plugin::plugin_startup() {
   try {
      cloner_plugin* cloner = app().find_plugin<cloner_plugin>();
      EOS_ASSERT( cloner, eosio::chain::plugin_config_exception, "cloner_plugin not found" );
      cloner->validate_filter_ids( std::move(my->filter_ids) ); // check filter contract IDs exist
      cloner->set_streamer( my );
   } FC_LOG_AND_RETHROW()
}

void streamer_plugin::plugin_shutdown() {}

} // namespace b1

// copyright defined in LICENSE.txt

#include <eosio/event_streamer_plugin/event_streamer_plugin.hpp>
#include <eosio/event_streamer_plugin/event_streamer_types.hpp>
#include <eosio/event_streamer_plugin/streams/logger.hpp>
#include <eosio/event_streamer_plugin/streams/rabbitmq.hpp>
#include <eosio/event_streamer_plugin/streams/stream.hpp>
#include <eosio/abi.hpp>
#include <eosio/chain/exceptions.hpp>
#include <fc/exception/exception.hpp>
#include <fc/reflect/variant.hpp>
#include <fc/log/trace.hpp>
#include <boost/filesystem/operations.hpp>
#include <boost/signals2/connection.hpp>
#include <memory>
#include <regex>

namespace eosio {

using namespace appbase;
using namespace std::literals;
using namespace eosio::streams;
using boost::signals2::scoped_connection;

constexpr eosio::name event_logger{"xqxlogxqx"}; // unique tag for loggers

struct event_streamer_plugin_impl : public streamer_t {

   void start_block(uint32_t block_num) override {
      for( const auto& a : streams ) {
         for( const auto& stream : a.second ) {
            stream->start_block( block_num );
         }
      }
   }

   void stream_data(const char* data, uint64_t data_size) override {
      eosio::input_stream bin(data, data_size);
      event_wrapper res = eosio::from_bin<event_wrapper>(bin);
      publish_to_streams(res);
   }

   void publish_to_streams(const event_wrapper& sw) {
      auto itr = streams.find(sw.tag);
      if( itr == streams.end() ) return;
      for (const auto& stream : itr->second) {
         if (stream->check_route(sw.route)) {
            stream->publish(sw.data, sw.route);
         }
      }
   }

   void stop_block(uint32_t block_num) override {
      for( const auto& a : streams ) {
         for( const auto& stream : a.second ) {
            stream->stop_block( block_num );
         }
      }
   }

   std::optional<scoped_connection> block_start_connection;
   std::optional<scoped_connection> block_abort_connection;
   std::optional<scoped_connection> accepted_block_connection;
   std::map<eosio::name, std::vector<std::unique_ptr<stream_handler>>> streams;
   bool delete_previous = false;
   bool publish_immediately = false;
};

static abstract_plugin& _event_streamer_plugin = app().register_plugin<event_streamer_plugin>();

event_streamer_plugin::event_streamer_plugin() : my(std::make_shared<event_streamer_plugin_impl>()) {
}

event_streamer_plugin::~event_streamer_plugin() {}

void event_streamer_plugin::set_program_options(options_description& cli, options_description& cfg) {
   auto op = cfg.add_options();

   op("event-tag", boost::program_options::value<vector<string>>()->composing()->multitoken(),
      "Event tags for configuration of environment variables "
      TAURUS_STREAM_RABBITS_ENV_VAR "_<tag> & " TAURUS_STREAM_RABBITS_EXCHANGE_ENV_VAR "_<tag>."
      " The tags correspond to eosio::name tags in the event_wrapper for mapping to individual AQMP queue or exchange.\n"
      TAURUS_STREAM_RABBITS_ENV_VAR "_<tag> "
      "Addresses of RabbitMQ queues to stream to. Format: amqp://USER:PASSWORD@ADDRESS:PORT/QUEUE[/STREAMING_ROUTE, ...]. "
      "Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/queue1:::amqp://u2:p2@amqp2:5672/queue2\".\n"
      TAURUS_STREAM_RABBITS_EXCHANGE_ENV_VAR "_<tag> "
      "Addresses of RabbitMQ exchanges to stream to. amqp://USER:PASSWORD@ADDRESS:PORT/EXCHANGE[::EXCHANGE_TYPE][/STREAMING_ROUTE, ...]. "
      "Multiple queue addresses can be specified with ::: as the delimiter, such as \"amqp://u1:p1@amqp1:5672/exchange1:::amqp://u2:p2@amqp2:5672/exchange2\"."
      );

   op("event-rabbits-immediately", bpo::bool_switch(&my->publish_immediately)->default_value(false),
      "Stream to RabbitMQ immediately instead of batching per block. Disables reliable message delivery.");
   op("event-loggers", bpo::value<std::vector<string>>()->composing(),
      "Logger for events if any; Format: [routing_keys, ...]");

   cli.add_options()
     ("event-delete-unsent", bpo::bool_switch(&my->delete_previous),
      "Delete unsent AMQP stream data retained from previous connections");
}

void event_streamer_plugin::plugin_initialize(const variables_map& options) {
   try {
      EOS_ASSERT( !options.count( "producer-name"), chain::plugin_config_exception,
                  "event_streamer_plugin not allowed on producer nodes." );

      if( options.count( "event-tag" ) ) {
         std::vector<std::string> event_tags = options["event-tag"].as<std::vector<std::string>>();
         for( const auto& e : event_tags ) {
            eosio::name n(e);
            auto p = my->streams.emplace(n, std::vector<std::unique_ptr<stream_handler>>{});
            EOS_ASSERT(p.second, chain::plugin_config_exception, "event-tag: {t} not unique.", ("t", e));
         }
      } else {
         EOS_ASSERT( false, chain::plugin_config_exception, "At least one event-tag is required." );
      }

      auto split_option = [](const std::string& str, std::vector<std::string>& results) {
         std::regex delim{":::"};
         std::sregex_token_iterator end;
         std::sregex_token_iterator iter(str.begin(), str.end(), delim, -1);
         for ( ; iter != end; ++iter) {
            std::string split(*iter);
            if (!split.empty()) results.push_back(split);
         }
      };

      if (options.count("event-loggers")) {
         auto loggers = options.at("event-loggers").as<std::vector<std::string>>();
         initialize_loggers(my->streams[event_logger], loggers);
      }

      // Multiple event-tag support to support multiple contracts
      std::vector<boost::filesystem::path> stream_data_paths(my->streams.size());

      size_t i = 0;
      for (auto& s : my->streams) {
         std::string tag_str = s.first.to_string();
         std::string e = std::string{"events_"} + tag_str;
         stream_data_paths[i] = appbase::app().data_dir() / e.c_str();

         if( my->delete_previous ) {
            if( boost::filesystem::exists( stream_data_paths[i]) )
               boost::filesystem::remove_all( stream_data_paths[i] );
         }

         if( s.first == event_logger ) {
            ++i;
            continue;
         }

         std::string rabbits_env_var_str = std::string{TAURUS_STREAM_RABBITS_ENV_VAR} + std::string{"_"} + tag_str;
         char* rabbits_env_var_value = std::getenv( rabbits_env_var_str.c_str() );
         std::string rabbits_exchange_env_var_str = std::string{TAURUS_STREAM_RABBITS_EXCHANGE_ENV_VAR} + std::string{"_"} + tag_str;
         char* rabbits_exchange_env_var_value = std::getenv( rabbits_exchange_env_var_str.c_str() );
         EOS_ASSERT( rabbits_env_var_value || rabbits_exchange_env_var_value, chain::plugin_config_exception,
                     "Expected env {v1} or {v2} variable to be defined",
                     ("v1", rabbits_env_var_str)("v2", rabbits_exchange_env_var_str) );
         if( rabbits_env_var_value) {
            std::vector<std::string> rabbits;
            split_option( rabbits_env_var_value, rabbits );
            EOS_ASSERT( !rabbits.empty(), chain::plugin_config_exception, "Invalid format: {v}", ("v", rabbits_env_var_value) );
            initialize_rabbits_queue( my->streams[s.first], rabbits, my->publish_immediately, stream_data_paths[i] );
         }
         if( rabbits_exchange_env_var_value ) {
            std::vector<std::string> exchanges;
            split_option( rabbits_exchange_env_var_value, exchanges );
            EOS_ASSERT( !exchanges.empty(), chain::plugin_config_exception, "Invalid format: {v}", ("v", rabbits_exchange_env_var_value) );
            initialize_rabbits_exchange( my->streams[s.first], exchanges, my->publish_immediately, stream_data_paths[i] );
         }

         ilog("event streamer: {i}, number of initialized streams: {s}", ("i", tag_str)("s", my->streams[s.first].size()));

         ++i;
      }

      chain_plugin* chain_plug = app().find_plugin<chain_plugin>();
      EOS_ASSERT( chain_plug, chain::plugin_config_exception, "chain_plugin not found" );
      chain::controller& chain = chain_plug->chain();

      my->block_start_connection = chain.block_start.connect( [this]( uint32_t block_num ) {
         my->start_block(block_num);
      } );
      my->block_abort_connection = chain.block_abort.connect( [this]( uint32_t block_num ) {
         my->stop_block(block_num);
      } );
      my->accepted_block_connection = chain.accepted_block.connect( [this]( const chain::block_state_ptr& bsp ) {
         my->stop_block(bsp->block_num);
      } );

      chain.set_push_event_function( [my = my, chain_plug]( const char* data, size_t size ) {
         try {
            // only push events on validation of blocks
            if ( !chain_plug->chain().is_producing_block() )
               my->stream_data(data, size); // push_event
         } FC_LOG_AND_DROP()
      } );

   } FC_LOG_AND_RETHROW()
}

void event_streamer_plugin::plugin_startup() {
   try {
   } FC_LOG_AND_RETHROW()
}

void event_streamer_plugin::plugin_shutdown() {
   try {
      my->block_start_connection.reset();
      my->block_abort_connection.reset();
      my->accepted_block_connection.reset();
   } FC_LOG_AND_RETHROW()
}

} // namespace eosio

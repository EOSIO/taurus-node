#include <eosio/amqp_trx_plugin/amqp_trx_plugin.hpp>
#include <eosio/amqp_trx_plugin/fifo_trx_processing_queue.hpp>
#include <eosio/amqp/amqp_handler.hpp>
#include <boost/asio/ssl.hpp>

#include <eosio/amqp_trx_plugin/amqp_trace_plugin_impl.hpp>
#include <eosio/chain_plugin/chain_plugin.hpp>

#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/transaction.hpp>
#include <eosio/chain/thread_utils.hpp>

#include <fc/log/trace.hpp>

#include <boost/signals2/connection.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace {

static appbase::abstract_plugin& amqp_trx_plugin_ = appbase::app().register_plugin<eosio::amqp_trx_plugin>();

enum class ack_mode {
   received,
   executed,
   in_block
};

std::istream& operator>>(std::istream& in, ack_mode& m) {
   std::string s;
   in >> s;
   if( s == "received" )
      m = ack_mode::received;
   else if( s == "executed" )
      m = ack_mode::executed;
   else if( s == "in_block" )
      m = ack_mode::in_block;
   else
      in.setstate( std::ios_base::failbit );
   return in;
}

std::ostream& operator<<(std::ostream& osm, ack_mode m) {
   if( m == ack_mode::received )
      osm << "received";
   else if( m == ack_mode::executed )
      osm << "executed";
   else if( m == ack_mode::in_block )
      osm << "in_block";
   return osm;
}

} // anonymous

namespace eosio {

using boost::signals2::scoped_connection;

struct amqp_trx_plugin_impl : std::enable_shared_from_this<amqp_trx_plugin_impl> {

   chain_plugin* chain_plug = nullptr;
   producer_plugin* prod_plugin = nullptr;
   std::optional<amqp_handler> amqp_trx;

   std::string amqp_trx_address;
   std::string amqp_trx_queue;
   ack_mode acked = ack_mode::executed;
   ////////////////////////////////////////////////////////////////////////
   // for ssl/tls
   bool secured = false;
   bool ssl_verify_peer = false;
   std::string ca_cert_perm_path;
   std::string cert_perm_path;
   std::string key_perm_path;
   /////////////////////////////////////////////////////////////////////////
   struct block_tracking {
      eosio::amqp_handler::delivery_tag_t tracked_delivery_tag{}; // highest delivery_tag for block
      std::string block_uuid;
      std::set<std::string> tracked_block_uuid_rks;
   };
   std::map<uint32_t, block_tracking> tracked_blocks;

   uint32_t trx_processing_queue_size = 1000;
   uint32_t trx_retry_interval_us = 500 * 1000; // 500 milliseconds
   uint32_t trx_retry_timeout_us = 60 * 1000 * 1000; // 60 seconds
   bool allow_speculative_execution = false;
   bool started_consuming = false;
   std::shared_ptr<fifo_trx_processing_queue<producer_plugin>> trx_queue_ptr;

   std::optional<scoped_connection> block_start_connection;
   std::optional<scoped_connection> block_abort_connection;
   std::optional<scoped_connection> accepted_block_connection;

   bool startup_stopped = false;
   bool is_stopped = true;

   // called from amqp thread
   void consume_message( const AMQP::Message& message, const amqp_handler::delivery_tag_t& delivery_tag, bool redelivered ) {
      try {
         fc::datastream<const char*> ds( message.body(), message.bodySize() );
         fc::unsigned_int which;
         fc::raw::unpack(ds, which);
         std::string block_uuid_rk = message.headers().get("block-uuid-msg");
         if( which == fc::unsigned_int(fc::get_index<transaction_msg, chain::packed_transaction_v0>()) ) {
            chain::packed_transaction_v0 v0;
            fc::raw::unpack(ds, v0);
            auto ptr = std::make_shared<chain::packed_transaction>( std::move( v0 ), true );
            handle_message( delivery_tag, message.replyTo(), message.correlationID(), std::move(block_uuid_rk), std::move( ptr ) );
         } else if ( which == fc::unsigned_int(fc::get_index<transaction_msg, chain::packed_transaction>()) ) {
            auto ptr = std::make_shared<chain::packed_transaction>();
            fc::raw::unpack(ds, *ptr);
            handle_message( delivery_tag, message.replyTo(), message.correlationID(), std::move(block_uuid_rk), std::move( ptr ) );
         } else {
            FC_THROW_EXCEPTION( fc::out_of_range_exception, "Invalid which {w} for consume of transaction_type message", ("w", which) );
         }
         if( acked == ack_mode::received ) {
            amqp_trx->ack( delivery_tag );
         }
         return;
      } FC_LOG_AND_DROP()

      amqp_trx->reject( delivery_tag, false, false );
   }

   void on_block_start( uint32_t bn ) {
      if (is_stopped)
         return;

      if (!prod_plugin->paused() || allow_speculative_execution) {
         if (!started_consuming) {
            ilog("Starting consuming amqp messages during on_block_start");
            amqp_trx->start_consume(amqp_trx_queue,
               [&]( const AMQP::Message& message, const amqp_handler::delivery_tag_t& delivery_tag, bool redelivered ) {
                  if( app().is_quiting() ) return; // leave non-ack
                  consume_message( message, delivery_tag, redelivered );
            }, true);
            started_consuming = true;
         }

         tracked_blocks[bn] = block_tracking{.block_uuid = boost::uuids::to_string( boost::uuids::random_generator()() )};
         trx_queue_ptr->on_block_start(bn);
      } else {
         if (prod_plugin->paused()) {
            if (started_consuming) {
               ilog("Stopping consuming amqp messages during on_block_start");
               amqp_trx->stop_consume([](const std::string& consumer_tag) {
                  dlog("Stopped consuming from amqp tag: {t}", ( "t", consumer_tag ));
               });
               started_consuming = false;
            }

            // Try to clear any delivery_tag left, to avoid holding these messages and block other consumers from
            // consuming these messages. During the above stop_consume, the background thread may have consumed some
            // messages and the delivery tag is kept there.
            if (amqp_trx) {
               const bool clear = true;
               amqp_handler::delivery_tag_t delivery_tag = 0;
               // any blocks left
               for (auto const& [blkn, blk]: tracked_blocks) {
                  if (blkn != bn) {
                     delivery_tag = std::max(delivery_tag, blk.tracked_delivery_tag);
                     tracked_blocks.erase(blkn);
                  }
               }
               if (delivery_tag != 0) {
                  ilog("Found delivery tag after checking tracked_blocks to reject/return: {t}", ("t", delivery_tag));
               }

               // clear queue
               trx_queue_ptr->for_each_delivery_tag([&](const amqp_handler::delivery_tag_t& i_delivery_tag) {
                  delivery_tag = std::max(delivery_tag, i_delivery_tag);
               }, clear);

               if (delivery_tag != 0) {
                  amqp_trx->reject(delivery_tag, true, true);
                  ilog("Rejected and returned back the message range with delivery tag {t}", ("t", delivery_tag));
               }
            }
         }
      }
   }

   void on_block_abort( uint32_t bn ) {
      if (is_stopped)
         return;

      trx_queue_ptr->on_block_stop(bn);
   }

   void on_accepted_block( const chain::block_state_ptr& bsp ) {
      if (is_stopped)
         return;

      trx_queue_ptr->on_block_stop(bsp->block_num);
      const auto& entry = tracked_blocks.find( bsp->block_num );
      if( entry != tracked_blocks.end() ) {
         if( acked == ack_mode::in_block && entry->second.tracked_delivery_tag != 0 ) {
            amqp_trx->ack( entry->second.tracked_delivery_tag, true );
         }
         for( auto& e : entry->second.tracked_block_uuid_rks ) {
            amqp_trace_plugin_impl::publish_block_uuid( *amqp_trx, std::move( e ), entry->second.block_uuid, bsp->id );
         }
         tracked_blocks.erase(entry);
      }
   }

private:

   // called from amqp thread
   void handle_message( const amqp_handler::delivery_tag_t& delivery_tag,
                        const std::string& reply_to,
                        const std::string& correlation_id,
                        std::string block_uuid_rk,
                        chain::packed_transaction_ptr trx ) {
      static_assert(std::is_same_v<amqp_handler::delivery_tag_t, uint64_t>, "fifo_trx_processing_queue assumes delivery_tag is an uint64_t");
      const auto& tid = trx->id();
      dlog( "received packed_transaction {id}, delivery_tag: {tag}, reply_to: {rt}, correlation_id: {cid}, block_uuid_rk: {buid}",
            ("id", tid)("tag", delivery_tag)("rt", reply_to)("cid", correlation_id)("buid", block_uuid_rk) );

      auto trx_trace = fc_create_trace_with_id("Transaction", tid);
      auto trx_span = fc_create_span(trx_trace, "AMQP Received");
      fc_add_tag(trx_span, "trx_id", tid);

      trx_queue_ptr->push( trx, delivery_tag,
                [my=shared_from_this(), token=fc_get_token(trx_trace),
                 delivery_tag, reply_to, correlation_id, block_uuid_rk=std::move(block_uuid_rk), trx]
                (const std::variant<fc::exception_ptr, chain::transaction_trace_ptr>& result) mutable {
            auto trx_span = fc_create_span_from_token(token, "Processed");
            fc_add_tag(trx_span, "trx_id", trx->id());

            // publish to trace plugin as exceptions are not reported via controller signal applied_transaction
            if( std::holds_alternative<chain::exception_ptr>(result) ) {
               auto& eptr = std::get<chain::exception_ptr>(result);
               fc_add_tag(trx_span, "error", eptr->to_string());
               dlog( "accept_transaction {id} exception: {e}", ("id", trx->id())("e", eptr->to_string()) );
               if( my->acked == ack_mode::executed || my->acked == ack_mode::in_block ) { // ack immediately on failure
                  my->amqp_trx->ack( delivery_tag );
               }
               if( !reply_to.empty() ) {
                  dlog( "publish error, reply_to: {rt}, correlation_id: {cid}, trx id: {tid}, error code: {ec}, error: {e}",
                        ("rt", reply_to)("cid", correlation_id)("tid", trx->id())("ec", eptr->code())("e", eptr->to_string()) );
                  using namespace amqp_trace_plugin_impl;
                  publish_error( *my->amqp_trx, std::move(reply_to), std::move(correlation_id), eptr->code(), eptr->to_string() );
               }
            } else {
               auto& trace = std::get<chain::transaction_trace_ptr>(result);
               fc_add_tag(trx_span, "block_num", trace->block_num);
               fc_add_tag(trx_span, "block_time", trace->block_time.to_time_point());
               fc_add_tag(trx_span, "elapsed", trace->elapsed.count());
               if( trace->receipt ) {
                  fc_add_tag(trx_span, "status", std::string(trace->receipt->status));
               }
               auto itr = my->tracked_blocks.find(trace->block_num);
               EOS_ASSERT(itr != my->tracked_blocks.end(), chain::unknown_block_exception, "amqp_trx_plugin attempted to update tracking for unknown block {block_num}", ("block_num", trace->block_num));
               if( trace->except ) {
                  fc_add_tag(trx_span, "error", trace->except->to_string());
                  dlog( "accept_transaction {id} exception: {e}", ("id", trx->id())("e", trace->except->to_string()) );
                  if( my->acked == ack_mode::executed || my->acked == ack_mode::in_block ) { // ack immediately on failure
                     my->amqp_trx->ack( delivery_tag );
                  }
               } else {
                  dlog( "accept_transaction {id}", ("id", trx->id()) );
                  if( my->acked == ack_mode::executed ) {
                     my->amqp_trx->ack( delivery_tag );
                  } else if( my->acked == ack_mode::in_block ) {
                     itr->second.tracked_delivery_tag = delivery_tag;
                  }
                  if( !block_uuid_rk.empty() ) {
                     itr->second.tracked_block_uuid_rks.emplace( std::move( block_uuid_rk ) );
                  }
               }
               if( !reply_to.empty() ) {
                  dlog( "publish result, reply_to: {rt}, correlation_id: {cid}, block uuid: {uid}, trx id: {tid}",
                        ("rt", reply_to)("cid", correlation_id)("uid", itr->second.block_uuid)("tid", trx->id()) );
                  using namespace amqp_trace_plugin_impl;
                  publish_result( *my->amqp_trx, std::move(reply_to), std::move(correlation_id), itr->second.block_uuid, trx, trace );
               }
            }
         } );
   }
};

amqp_trx_plugin::amqp_trx_plugin()
: my(std::make_shared<amqp_trx_plugin_impl>()) {
   app().register_config_type<ack_mode>();
}

amqp_trx_plugin::~amqp_trx_plugin() {}

void amqp_trx_plugin::set_program_options(options_description& cli, options_description& cfg) {
   auto op = cfg.add_options();
   op("amqp-trx-address", bpo::value<std::string>()->default_value(std::getenv(EOSIO_AMQP_ADDRESS_ENV_VAR) ? std::getenv(EOSIO_AMQP_ADDRESS_ENV_VAR) : ""),
      "AMQP address: Format: amqp://USER:PASSWORD@ADDRESS:PORT\n"
      "Will consume from amqp-trx-queue-name (amqp-trx-queue-name) queue.\n"
      "If --amqp-trx-address is not specified, will use the value from the environment variable "
      EOSIO_AMQP_ADDRESS_ENV_VAR
      ".");
   op("amqp-trx-queue-name", bpo::value<std::string>()->default_value("trx"),
      "AMQP queue to consume transactions from, must already exist.");
   op("amqp-trx-queue-size", bpo::value<uint32_t>()->default_value(my->trx_processing_queue_size),
      "The maximum number of transactions to pull from the AMQP queue at any given time.");
   op("amqp-trx-retry-timeout-us", bpo::value<uint32_t>()->default_value(my->trx_retry_timeout_us),
      "Time in microseconds to continue to retry a connection to AMQP when connection is loss or startup.");
   op("amqp-trx-retry-interval-us", bpo::value<uint32_t>()->default_value(my->trx_retry_interval_us),
      "When connection is lost to amqp-trx-queue-name, interval time in microseconds before retrying connection.");
   op("amqp-trx-speculative-execution", bpo::bool_switch()->default_value(false),
      "Allow non-ordered speculative execution of transactions");
   op("amqp-trx-ack-mode", bpo::value<ack_mode>()->default_value(ack_mode::in_block),
      "AMQP ack when 'received' from AMQP, when 'executed', or when 'in_block' is produced that contains trx.\n"
      "Options: received, executed, in_block");
   op("amqp-trx-startup-stopped", bpo::bool_switch()->default_value(false), "do not start plugin on startup - require RPC amqp_trx/start to start plugin");
   op("amqps-ca-cert-perm", bpo::value<std::string>()->default_value("test_ca_cert.perm"),  "ca cert perm file path for ssl, required only for amqps.");
   op("amqps-cert-perm", bpo::value<std::string>()->default_value("test_cert.perm"),  "client cert perm file path for ssl, required only for amqps.");
   op("amqps-key-perm", bpo::value<std::string>()->default_value("test_key.perm"),  "client key perm file path for ssl, required only for amqps.");
   op("amqps-verify-peer", bpo::bool_switch()->default_value(false), "config ssl/tls verify peer or not.");
}

void amqp_trx_plugin::plugin_initialize(const variables_map& options) {
   try {
      my->chain_plug = app().find_plugin<chain_plugin>();
      my->prod_plugin = app().find_plugin<producer_plugin>();
      EOS_ASSERT( my->chain_plug, chain::missing_chain_plugin_exception, "chain_plugin required" );

      EOS_ASSERT( options.count("amqp-trx-address"), chain::plugin_config_exception, "amqp-trx-address required" );
      my->amqp_trx_address = options.at("amqp-trx-address").as<std::string>();
      if(my->amqp_trx_address.substr(0, 5) == "amqps" || my->amqp_trx_address.substr(0, 5) == "AMQPS"){
         my->secured = true;
         EOS_ASSERT( options.count("amqps-ca-cert-perm"), chain::plugin_config_exception, "amqps-ca-cert-perm required" );
         EOS_ASSERT( options.count("amqps-cert-perm"), chain::plugin_config_exception, "amqps-cert-perm required" );
         EOS_ASSERT( options.count("amqps-key-perm"), chain::plugin_config_exception, "amqps-key-perm required" );

         my->ca_cert_perm_path = options.at("amqps-ca-cert-perm").as<std::string>();
         my->cert_perm_path = options.at("amqps-cert-perm").as<std::string>();
         my->key_perm_path = options.at("amqps-key-perm").as<std::string>();
         my->ssl_verify_peer = options.at("amqps-verify-peer").as<bool>();
      }

      my->amqp_trx_queue = options.at("amqp-trx-queue-name").as<std::string>();
      EOS_ASSERT( !my->amqp_trx_queue.empty(), chain::plugin_config_exception, "amqp-trx-queue-name required" );

      my->acked = options.at("amqp-trx-ack-mode").as<ack_mode>();

      my->trx_processing_queue_size = options.at("amqp-trx-queue-size").as<uint32_t>();
      my->trx_retry_timeout_us = options.at("amqp-trx-retry-timeout-us").as<uint32_t>();
      my->trx_retry_interval_us = options.at("amqp-trx-retry-interval-us").as<uint32_t>();
      my->allow_speculative_execution = options.at("amqp-trx-speculative-execution").as<bool>();

      my->startup_stopped = options.at("amqp-trx-startup-stopped").as<bool>();
      EOS_ASSERT( my->acked != ack_mode::in_block || !my->allow_speculative_execution, chain::plugin_config_exception,
                  "amqp-trx-ack-mode = in_block not supported with amqp-trx-speculative-execution" );

      my->chain_plug->enable_accept_transactions();
   }
   FC_LOG_AND_RETHROW()
}

void amqp_trx_plugin::plugin_startup() {
   handle_sighup();

   ilog( "Starting amqp_trx_plugin" );

   EOS_ASSERT( my->prod_plugin, chain::plugin_config_exception, "producer_plugin required" ); // should not be possible
   EOS_ASSERT( my->allow_speculative_execution || my->prod_plugin->has_producers(), chain::plugin_config_exception,
               "Must be a producer to run without amqp-trx-speculative-execution" );

   auto& chain = my->chain_plug->chain();

   my->block_start_connection.emplace(
         chain.block_start.connect( [this]( uint32_t bn ) { my->on_block_start( bn ); } ) );
   my->block_abort_connection.emplace(
         chain.block_abort.connect( [this]( uint32_t bn ) { my->on_block_abort( bn ); } ) );
   my->accepted_block_connection.emplace(
         chain.accepted_block.connect( [this]( const auto& bsp ) { my->on_accepted_block( bsp ); } ) );

   if(!my->startup_stopped)
      start();
}

void amqp_trx_plugin::plugin_shutdown() {
   try {
      dlog( "shutdown.." );

      stop();

      dlog( "exit amqp_trx_plugin" );
   }
   FC_LOG_AND_DROP()
}

void amqp_trx_plugin::handle_sighup() {
}

void amqp_trx_plugin::start() {
   if (!my->is_stopped)
      return;

   auto& chain = my->chain_plug->chain();
   my->trx_queue_ptr =
         std::make_shared<fifo_trx_processing_queue<producer_plugin>>( chain.get_chain_id(),
                                                                       chain.configured_subjective_signature_length_limit(),
                                                                       my->allow_speculative_execution,
                                                                       chain.get_thread_pool(),
                                                                       my->prod_plugin,
                                                                       my->trx_processing_queue_size );
   my->trx_queue_ptr->run();

   if(!my->secured){
      my->amqp_trx.emplace( my->amqp_trx_address,
                           fc::microseconds(my->trx_retry_timeout_us),
                           fc::microseconds(my->trx_retry_interval_us),
                           []( const std::string& err ) {
                              elog( "amqp error: {e}", ("e", err) );
                              app().quit();
                           }
      );
   } else {
      boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::sslv23);
      try {
         ssl_ctx.set_verify_mode(my->ssl_verify_peer ? boost::asio::ssl::context::verify_peer : boost::asio::ssl::context::verify_none);
         // Currently use tls 1.3 only, rabbitmq can support tls 1.3
         // The tls 1.3 default cipher suite to be use is TLS_AES_256_GCM_SHA384
         ssl_ctx.set_options(boost::asio::ssl::context::default_workarounds |
                                boost::asio::ssl::context::no_compression |
                                boost::asio::ssl::context::no_sslv2 |
                                boost::asio::ssl::context::no_sslv3 |
                                boost::asio::ssl::context::no_tlsv1 |
                                boost::asio::ssl::context::no_tlsv1_1 |
                                boost::asio::ssl::context::no_tlsv1_2);
         // If allow tls 1.2 and lower version, we can use the below SSL_CTX_set_cipher_list to add more ciphers
         // if(SSL_CTX_set_cipher_list(ssl_ctx.native_handle(),
         //         "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:EECDH+ECDSA+SHA384:EECDH+ECDSA+SHA256:AES256:DHE:RSA:AES128"
         //         "!RC4:!DES:!3DES:!DSS:!SRP:!PSK:!EXP:!MD5:!LOW:!aNULL:!eNULL") != 1)
         //         EOS_THROW(chain::plugin_config_exception, "Failed to set  amqps tls 1.2 cipher list");

         ssl_ctx.load_verify_file(my->ca_cert_perm_path);
         ilog( my->ca_cert_perm_path);
         boost::system::error_code error;
         ssl_ctx.use_certificate_file (my->cert_perm_path, boost::asio::ssl::context::pem, error);
         ilog( my->cert_perm_path);
         EOS_ASSERT( !error, chain::plugin_config_exception, "Error happen with using client certificate pem file, error code : {ec} ", ("ec", error.message()));
         ssl_ctx.use_private_key_file (my->key_perm_path, boost::asio::ssl::context::pem, error);
         ilog( my->key_perm_path);
         EOS_ASSERT( !error, chain::plugin_config_exception, "Error happen with using client key pem file, error code : {ec} ", ("ec", error.message()));
      } catch (const fc::exception& e) {
         elog("amqps client initialization error: {w}", ("w", e.to_detail_string()) );
      } catch(std::exception& e) {
         elog("amqps client initialization error: {w}", ("w", e.what()) );
      }

      my->amqp_trx.emplace( my->amqp_trx_address, ssl_ctx,
                     fc::microseconds(my->trx_retry_timeout_us),
                     fc::microseconds(my->trx_retry_interval_us),
                     []( const std::string& err ) {
                        elog( "amqp error: {e}", ("e", err) );
                        app().quit();
                     }
      );
   }

   if (!my->prod_plugin->paused() || my->allow_speculative_execution) {
      ilog("Starting amqp consumption at startup.");
      my->amqp_trx->start_consume(my->amqp_trx_queue,
         [&]( const AMQP::Message& message, const amqp_handler::delivery_tag_t& delivery_tag, bool redelivered ) {
            if( app().is_quiting() ) return; // leave non-ack
            my->consume_message( message, delivery_tag, redelivered );
         }, true);
      my->started_consuming = true;
   }

   my->is_stopped = false;
}

void amqp_trx_plugin::stop() {
   if (my->is_stopped)
      return;

   if( my->trx_queue_ptr ) {
      // Need to stop processing from queue since amqp_handler can be paused waiting on queue to empty.
      // Without this it is possible for the amqp_trx->stop() to hang forever waiting on the trx_queue.
      my->trx_queue_ptr->signal_stop();
   }
   if( my->amqp_trx ) {
      my->amqp_trx->stop();
   }
   my->amqp_trx.reset();
   dlog( "stopping fifo queue" );
   if( my->trx_queue_ptr ) {
      my->trx_queue_ptr->stop();
   }
   my->trx_queue_ptr = nullptr;
   my->is_stopped = true;
}

} // namespace eosio

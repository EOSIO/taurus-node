#define BOOST_TEST_MODULE producer
#include <boost/test/included/unit_test.hpp>

#include <eosio/producer_plugin/producer_plugin.hpp>
#include <eosio/producer_plugin/producer.hpp>
#include <eosio/chain/plugin_interface.hpp>

#include <eosio/testing/tester.hpp>

#include <eosio/chain/genesis_state.hpp>
#include <eosio/chain/thread_utils.hpp>
#include <eosio/chain/transaction_metadata.hpp>
#include <eosio/chain/trace.hpp>
#include <eosio/chain/name.hpp>
#include <eosio/chain/to_string.hpp>

#include <appbase/application.hpp>
#include <fc/mock_time.hpp>
#include <fc/log/custom_formatter.hpp>

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <thread>

namespace eosio::test::detail {
using namespace eosio::chain::literals;
struct testit {
   uint64_t      id;

   testit( uint64_t id = 0 )
         :id(id){}

   static account_name get_account() {
      return chain::config::system_account_name;
   }

   static chain::action_name get_name() {
      return "testit"_n;
   }
};
}
FC_REFLECT( eosio::test::detail::testit, (id) )

namespace {

using namespace eosio;
using namespace eosio::chain;
using namespace eosio::test::detail;

auto default_priv_key = private_key_type::regenerate<fc::ecc::private_key_shim>(fc::sha256::hash(std::string("nathan")));
auto default_pub_key = default_priv_key.get_public_key();

auto make_unique_trx( const chain_id_type& chain_id, const fc::time_point& now ) {
   static uint64_t nextid = 0;
   ++nextid; // make unique

   account_name creator = config::system_account_name;
   signed_transaction trx;
   trx.expiration = now + fc::seconds( 60 );
   trx.actions.emplace_back( vector<permission_level>{{creator, config::active_name}},
                             testit{ nextid } );
   trx.sign( default_priv_key, chain_id );

   return std::make_shared<packed_transaction>( std::move(trx), true, packed_transaction::compression_type::none);
}


} // anonymous namespace

BOOST_AUTO_TEST_SUITE(producer_time)

// Example test case that manipulates time via fc::mock_time_traits and fc::mock_deadline_timer.
// Currently doesn't test much as it is just a demonstration of what is possible.
BOOST_AUTO_TEST_CASE(producer_time) {
   boost::filesystem::path temp = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();

   try {

      fc::logger::get(DEFAULT_LOGGER).set_log_level(fc::log_level::debug);
      std::optional<controller> chain;
      genesis_state gs{};
      {
         controller::config chain_config = controller::config();
         chain_config.blog.log_dir = temp;
         chain_config.state_dir = temp;
         chain_config.blog.retained_dir = temp / "retained";
         chain_config.blog.archive_dir = temp / "archived";
         // We are manipulating time around calls to get_log_trx_trace and get_log_trx which use
         // chain.get_abi_serializer_max_time(), set this to a high value in case time is changed while logging.
         chain_config.abi_serializer_max_time_us = fc::seconds(30);

         const auto& genesis_chain_id = gs.compute_chain_id();
         protocol_feature_set pfs;
         chain.emplace( chain_config, std::move( pfs ), genesis_chain_id );
         chain->add_indices();
      }

      // control time by using set_now, call before spawing any threads
      auto now = boost::posix_time::time_from_string("2022-02-22 2:22:22.001");
      fc::mock_time_traits::set_now(now);

      // Use fc::mock_deadline_timer so that time can be controlled via fc::mock_time_traits::set_now()
      // shared_ptr so shared_from_this works
      auto prod = std::make_shared<producer>( std::unique_ptr<producer_timer_base>( new producer_timer<fc::mock_deadline_timer>( app().get_io_service() ) ),
            [trx_ack_channel{&app().get_channel<plugin_interface::compat::channels::transaction_ack>()}](const fc::exception_ptr& except_ptr, const transaction_metadata_ptr& trx) {
               trx_ack_channel->publish( priority::low, std::pair<fc::exception_ptr, transaction_metadata_ptr>( except_ptr, trx ) );
            },
            [rejected_block_channel{&app().get_channel<plugin_interface::channels::rejected_block>()}](const signed_block_ptr& block) {
               rejected_block_channel->publish( priority::medium, block );
            } );

      prod->chain_control = &chain.value();
      prod->_transaction_processor.start( 2 );
      prod->_transaction_processor.set_max_transaction_time( fc::seconds(999) ); // large value as we may change time while transaction is executing
      prod->_production_enabled = true;
      prod->_max_irreversible_block_age_us = fc::seconds(-1);
      prod->_block_producer.add_producer("eosio"_n);
      prod->_signature_providers[default_pub_key] = [](const chain::digest_type& digest) { return default_priv_key.sign(digest); };

      std::mutex last_block_mtx;
      std::condition_variable last_block_cv;
      uint32_t last_block_num{};

      auto wait_for_next_block = [&]() -> uint32_t {
         uint32_t b = 0;
         {
            using namespace std::chrono_literals;
            auto now = std::chrono::system_clock::now(); // set a timeout so test does not hang forever if block not produced
            std::unique_lock lk( last_block_mtx );
            last_block_cv.wait_until( lk, now+5000ms, [&] { return last_block_num != 0; } );
            std::swap(b, last_block_num);
         }
         return b;
      };

      auto ab = prod->chain_control->accepted_block.connect( [&](const block_state_ptr& bsp) {
         std::unique_lock lk(last_block_mtx);
         last_block_num = bsp->block_num;
         lk.unlock();
         last_block_cv.notify_one();
      } );
      auto ba = prod->chain_control->block_abort.connect( [&]( uint32_t bn ) {
      } );
      auto bs = prod->chain_control->block_start.connect( [&]( uint32_t bn ) {
      } );


      auto shutdown = [](){ return app().quit(); };
      auto check_shutdown = [](){ return app().is_quiting(); };
      chain->startup(shutdown, check_shutdown, gs);

      prod->handle_sighup();

      std::promise<void> started;
      auto started_future = started.get_future();
      std::thread app_thread( [&]() {
         prod->startup();
         started.set_value();
         appbase::app().exec();
      } );
      started_future.get();

      auto ptrx = make_unique_trx( chain->get_chain_id(), fc::time_point::now() );
      std::promise<std::variant<fc::exception_ptr, transaction_trace_ptr>> p;
      auto f = p.get_future();
      prod->on_incoming_transaction_async(ptrx, false, false, true,
            [&p](const std::variant<fc::exception_ptr, transaction_trace_ptr>& result) mutable {
               // next (this lambda) called from application thread
               if (std::holds_alternative<fc::exception_ptr>(result)) {
                  dlog( "bad packed_transaction : {m}", ("m", std::get<fc::exception_ptr>(result)->what()) );
               } else {
                  const transaction_trace_ptr& trace = std::get<transaction_trace_ptr>(result);
                  if( !trace->except ) {
                     dlog( "chain accepted transaction, bcast {id}", ("id", trace->id) );
                  } else {
                     elog( "bad packed_transaction : {m}", ("m", trace->except->what()));
                  }
               }
               p.set_value(result);
            }
      );
      auto r = f.get();

      if (std::holds_alternative<transaction_trace_ptr>(r)){
         fc::action_expander<transaction_trace>  tt{*std::get<transaction_trace_ptr>(r), &chain.value()};
         dlog( "result: {r}", ("r", tt) );
      } else {
         dlog( "result: {r}", ("r", *std::get<exception_ptr>(r)) );
      }
      BOOST_REQUIRE( std::holds_alternative<transaction_trace_ptr>(r) );
      BOOST_CHECK( !std::get<transaction_trace_ptr>(r)->except ); // did not fail

      // now produce some blocks with transactions
      std::atomic<uint32_t> trx_errors = 0;
      std::atomic<uint32_t> trx_success = 0;
      auto trx_callback = [&trx_errors, &trx_success](const std::variant<fc::exception_ptr, transaction_trace_ptr>& result) {
         if (std::holds_alternative<fc::exception_ptr>(result)) {
            ++trx_errors;
         } else {
            ++trx_success;
         }
      };
      uint32_t num_trx = 0;
      for( size_t i = 2; i < 20; ++i) {
         // generate some transactions
         if( i % 2 == 0) {
            auto ptrx1 = make_unique_trx( chain->get_chain_id(), fc::time_point::now() );
            auto ptrx2 = make_unique_trx( chain->get_chain_id(), fc::time_point::now() );
            prod->on_incoming_transaction_async(ptrx1, false, false, true, trx_callback);
            ++num_trx;
            prod->on_incoming_transaction_async(ptrx2, false, false, true, trx_callback);
            ++num_trx;
         }

         // jump ahead in time to when next block should be produced
         now = now + boost::posix_time::milliseconds(chain::config::block_interval_ms);
         fc::mock_time_traits::set_now( now );
         BOOST_CHECK_EQUAL( wait_for_next_block(), i );
      }

      prod->shutdown();
      appbase::app().quit();
      app_thread.join();

      BOOST_CHECK_EQUAL(0, trx_errors.load());
      BOOST_CHECK_EQUAL(num_trx, trx_success.load()); // verify all transactions executed before shutdown

   } catch ( ... ) {
      bfs::remove_all( temp );
      throw;
   }
   bfs::remove_all( temp );
}


BOOST_AUTO_TEST_SUITE_END()

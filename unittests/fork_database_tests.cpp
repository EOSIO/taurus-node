#include <eosio/chain/fork_database.hpp>
#include <eosio/chain/genesis_state.hpp>
#include <eosio/testing/tester.hpp>
#include <fc/scoped_exit.hpp>
#include <boost/filesystem.hpp>

#include <boost/test/unit_test.hpp>

using namespace eosio::testing;

BOOST_AUTO_TEST_SUITE(fork_database_tests)

auto create_genesis_block() {
    genesis_state genesis;
    genesis.initial_timestamp = fc::time_point::from_iso_string("2020-01-01T00:00:00.000");
    genesis.initial_key = base_tester::get_public_key( config::system_account_name, "active" );

    producer_authority_schedule initial_schedule = { 0, { producer_authority{config::system_account_name, block_signing_authority_v0{ 1, {{genesis.initial_key, 1}} } } } };
    legacy::producer_schedule_type initial_legacy_schedule{ 0, {{config::system_account_name, genesis.initial_key}} };

    block_header_state genheader;
    genheader.active_schedule                = initial_schedule;
    genheader.pending_schedule.schedule      = initial_schedule;
    // NOTE: if wtmsig block signatures are enabled at genesis time this should be the hash of a producer authority schedule
    genheader.pending_schedule.schedule_hash = fc::sha256::hash(initial_legacy_schedule);
    genheader.header.timestamp               = genesis.initial_timestamp;
    genheader.header.action_mroot            = genesis.compute_chain_id();
    genheader.id                             = genheader.header.calculate_id();
    genheader.block_num                      = genheader.header.block_num();

    block_state_ptr head = std::make_shared<block_state>();
    static_cast<block_header_state&>(*head) = genheader;
    head->activated_protocol_features = std::make_shared<protocol_feature_activation_set>();
    head->block = std::make_shared<signed_block>(genheader.header);
    return head;
}

auto create_test_block_state( uint32_t block_num, uint32_t irreversible_blocknum, block_id_type previous,
                              block_timestamp_type timestamp,
                              deque<transaction_metadata_ptr> trx_metas = deque<transaction_metadata_ptr>{} ) {
   signed_block_ptr block = std::make_shared<signed_block>();
   for( auto& trx_meta : trx_metas ) {
      block->transactions.emplace_back( *trx_meta->packed_trx() );
   }

   block->producer = eosio::chain::config::system_account_name;
   block->timestamp = timestamp;
   block->previous = previous;

   auto priv_key = base_tester::get_private_key( block->producer, "active" );
   auto pub_key  = base_tester::get_public_key( block->producer, "active" );

   auto prev = std::make_shared<block_state>();
   auto header_bmroot = digest_type::hash( std::make_pair( block->digest(), prev->blockroot_merkle.get_root() ) );
   auto sig_digest = digest_type::hash( std::make_pair(header_bmroot, prev->pending_schedule.schedule_hash) );
   block->producer_signature = priv_key.sign( sig_digest );

   vector<private_key_type> signing_keys;
   signing_keys.emplace_back( std::move( priv_key ) );

   auto signer = [&]( digest_type d ) {
      std::vector<signature_type> result;
      result.reserve(signing_keys.size());
      for (const auto& k: signing_keys)
         result.emplace_back(k.sign(d));
      return result;
   };
   pending_block_header_state pbhs;
   pbhs.block_num = block_num;
   pbhs.dpos_irreversible_blocknum = irreversible_blocknum;
   pbhs.timestamp = timestamp;
   pbhs.previous = previous;
   pbhs.producer = block->producer;
   producer_authority_schedule schedule = { 0, { producer_authority{block->producer, block_signing_authority_v0{ 1, {{pub_key, 1}} } } } };
   pbhs.active_schedule = schedule;
   pbhs.valid_block_signing_authority = block_signing_authority_v0{ 1, {{pub_key, 1}} };
   auto pfa = pbhs.prev_activated_protocol_features;
   protocol_feature_set pfs;
   auto bsp = std::make_shared<block_state>(
       std::move(pbhs), std::move(block), std::move(trx_metas),
       pfs,
       [](block_timestamp_type timestamp,
          const flat_set<digest_type> &cur_features,
          const vector<digest_type> &new_features) {});
   bool wtmsig_enabled = eosio::chain::detail::is_builtin_activated(pfa, pfs, builtin_protocol_feature_t::wtmsig_block_signatures);
   bsp->assign_signatures( signer(bsp->sig_digest()),  wtmsig_enabled);

   return bsp;
}

BOOST_AUTO_TEST_CASE( regular_blocks ) try {
    auto path = boost::filesystem::temp_directory_path();
    boost::filesystem::path our_dir = std::tmpnam(nullptr);
    path /= our_dir.filename();
    BOOST_REQUIRE_MESSAGE( !boost::filesystem::exists(path), "tmpnam failed to generate a directory name we can safely remove");
    boost::filesystem::create_directory(path);
    auto remove_temp_dir = fc::make_scoped_exit([&path] { boost::filesystem::remove_all(path); });

    auto forkdb = fork_database{path.string()};

    BOOST_REQUIRE_EXCEPTION(forkdb.add(create_test_block_state( 2, 1, block_id_type(), block_timestamp_type())), fork_database_exception,
                             [](fork_database_exception const& ex) { return ex.top_message() == "root not yet set"; });

    auto head = create_genesis_block();
    forkdb.reset(*head);

    BOOST_CHECK_EQUAL(forkdb.head()->block_num, 1);
    auto block = create_test_block_state( 2, forkdb.head()->block_num, forkdb.head()->id, forkdb.head()->header.timestamp.next() );
    forkdb.add(block);
    BOOST_CHECK_EQUAL(forkdb.head()->block_num, 1);
    BOOST_CHECK_EQUAL(forkdb.pending_head()->block_num, 2);
    forkdb.mark_valid(block);
    BOOST_CHECK_EQUAL(forkdb.head()->block_num, 2);
    auto save_block = create_test_block_state( 3, forkdb.head()->block_num, forkdb.head()->id, forkdb.head()->header.timestamp.next() );
    forkdb.add(save_block);
    forkdb.mark_valid(save_block);
    BOOST_CHECK_EQUAL(forkdb.head()->block_num, 3);
    BOOST_REQUIRE_EXCEPTION(forkdb.add(save_block), fork_database_exception,
                            [](fork_database_exception const& ex) { return ex.top_message() == "duplicate block added"; });
    auto fork_block_1 = create_test_block_state( 4, forkdb.head()->block_num, forkdb.head()->id, forkdb.head()->header.timestamp.next() );
    BOOST_REQUIRE_EXCEPTION(forkdb.mark_valid(fork_block_1), fork_database_exception,
                            [](fork_database_exception const& ex) { return ex.top_message() == "block state not in fork database; cannot mark as valid"; });
    forkdb.add(fork_block_1);
    forkdb.mark_valid(fork_block_1);
    BOOST_CHECK_EQUAL(forkdb.head()->block_num, 4);
    auto fork_block_2 = create_test_block_state( 4, save_block->block_num, save_block->id, forkdb.head()->header.timestamp.next() );
    forkdb.add(fork_block_2);
    forkdb.mark_valid(fork_block_2);
    BOOST_TEST(fork_block_1->id != fork_block_2->id);
    auto branches = forkdb.fetch_branch_from(fork_block_1->id, fork_block_2->id);
    BOOST_CHECK_EQUAL(branches.first.size(), 1);
    BOOST_CHECK_EQUAL(branches.second.size(), 1);
    BOOST_TEST(branches.first.front() == fork_block_1);
    BOOST_TEST(branches.second.front() == fork_block_2);
    BOOST_TEST(forkdb.is_head_block(fork_block_1->id));
    BOOST_TEST(!forkdb.is_head_block(fork_block_2->id));
    BOOST_CHECK_EQUAL(forkdb.head(), fork_block_1);
    forkdb.remove_head(fork_block_1->id);
    BOOST_CHECK_EQUAL(forkdb.head(), fork_block_2);
} FC_LOG_AND_RETHROW()

BOOST_AUTO_TEST_SUITE_END()

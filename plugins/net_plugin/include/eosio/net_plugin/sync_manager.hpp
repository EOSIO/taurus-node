#pragma once

#include <eosio/net_plugin/connection.hpp>
#include <eosio/net_plugin/utility.hpp>

#include <boost/sml.hpp>

#include <mutex>
#include <shared_mutex>

namespace eosio { namespace p2p {

using mutex_locker = std::unique_lock<std::mutex>;

template <typename Connection, typename NetPlugin>
class sync_manager {
   using connection_ptr = std::shared_ptr<Connection>;
   using net_plugin_ptr = std::shared_ptr<NetPlugin>;
private:
   mutable std::mutex  sync_mtx;
   uint32_t            sync_known_lib_num{0};
   uint32_t            sync_last_requested_num{0};
   uint32_t            sync_next_expected_num{0};
   uint32_t            sync_req_span{0};
   connection_ptr      sync_source;
   net_plugin_ptr      net_plugin;

public:
   explicit sync_manager( uint32_t span, net_plugin_ptr ptr )
   :sync_known_lib_num( 0 )
   ,sync_last_requested_num( 0 )
   ,sync_next_expected_num( 1 )
   ,sync_req_span( span )
   ,sync_source()
   ,net_plugin(ptr){}

   bool is_sync_required( uint32_t target ) const {
      uint32_t lib_num = 0;
      uint32_t fork_head_block_num = 0;
      std::tie( lib_num, std::ignore, fork_head_block_num,
                  std::ignore, std::ignore, std::ignore ) = net_plugin->get_chain_info();

      fc_dlog( net_plugin->get_logger(), "last req = {req}, last recv = {recv} known = {known} our head = {head}",
               ("req", sync_last_requested_num)( "recv", sync_next_expected_num )( "known", sync_known_lib_num )
               ("head", fork_head_block_num ) );

      bool sync_required = ( sync_last_requested_num < sync_known_lib_num ||
                           fork_head_block_num < sync_last_requested_num ||
                           target > lib_num );
      if (!sync_required) {
         fc_dlog( net_plugin->get_logger(), "We are already caught up, my irr = {b}, head = {h}, target = {t}",
            ("b", lib_num)( "h", fork_head_block_num )( "t", target ) );
      }

      return sync_required;
   }

   void send_handshakes() {
      net_plugin->for_each_connection(
         []( auto& ci ) {
         if( ci->current() ) {
            ci->send_handshake();
         }
         return true;
      });
   }

   inline fc::logger& get_logger() const {
      return net_plugin->get_logger();
   }
   inline const std::string& peer_log_format() const {
      return net_plugin->get_log_format();
   }

   bool is_sync_source( Connection& c, const mutex_locker& ) const {
      if (!sync_source)
         return false;
      return sync_source.get() == &c;
   }
   inline bool is_sync_source( Connection& c ) const { return is_sync_source(c, locked_sync_mutex()); }

   void sync_reset_lib_num( uint32_t lib, const mutex_locker& lock ) {
      if( lib > sync_known_lib_num ) {
         sync_known_lib_num = lib;
         log_syncing_status(lock);
      }
   }
   inline void sync_reset_lib_num( uint32_t lib ) { sync_reset_lib_num(lib, locked_sync_mutex()); }

   void sync_update_expected( const chain::block_id_type&, uint32_t blk_num, bool blk_applied ) {
      auto lock = locked_sync_mutex();
      if( blk_num <= sync_last_requested_num ) {
         log_syncing_status(lock);
         if (blk_num != sync_next_expected_num && !blk_applied) {
            fc_dlog( net_plugin->get_logger(), "expected block {ne} but got {bn}", ("ne", sync_next_expected_num)("bn", blk_num) );
            return;
         }
         sync_next_expected_num = blk_num + 1;
      }
   }
   inline uint32_t get_sync_next_expected() const {
      return sync_next_expected_num;
   }
   inline uint32_t get_known_lib() const {
      return sync_known_lib_num;
   }
   inline uint32_t get_sync_last_requested_num() const {
      return sync_last_requested_num;
   }

   void begin_sync(const connection_ptr& c, uint32_t target) {
      auto lock = locked_sync_mutex();

      // p2p_high_latency_test.py test depends on this exact log statement.
      peer_dlog( c, "Catching up with chain, our last req is {cc}, theirs is {t}",
                  ("cc", sync_last_requested_num)("t", target) );
      continue_sync(lock);
   }

   void continue_sync(const mutex_locker&) {
      bool request_sent = false;
      if( sync_last_requested_num != sync_known_lib_num ) {
         uint32_t start = sync_next_expected_num;
         uint32_t end = start + sync_req_span - 1;
         if( end > sync_known_lib_num )
            end = sync_known_lib_num;
         if( end >= start ) {
            sync_last_requested_num = end;
            connection_ptr c = sync_source;
            request_sent = true;
            c->post( [this, c, start, end]() {
               peer_ilog( c, "requesting range {s} to {e}", ("s", start)("e", end) );
               c->request_sync_blocks( start, end );
            } );
         }
      }
      if( !request_sent ) {
         send_handshakes();
      }
   }
   inline void continue_sync() { continue_sync(locked_sync_mutex()); }

   bool fork_head_ge(uint32_t num, const chain::block_id_type& id) const {
      bool ge = false;
      net_plugin->for_each_block_connection(
         [num, &id, &ge]( const auto& cc ) {
         auto lock = cc->locked_connection_mutex(); (void)lock;
         if( cc->get_fork_head_num() > num || cc->get_fork_head() == id ) {
            ge = true;
            return false;
         }
         return true;
      });

      return ge;
   }
   inline mutex_locker locked_sync_mutex() const {
      return mutex_locker(sync_mtx);
   }

   inline void reset_last_requested_num(const mutex_locker&) {
      sync_last_requested_num = 0;
   }
   inline void reset_last_requested_num() { reset_last_requested_num(locked_sync_mutex()); }

   void log_syncing_status(const mutex_locker&) const {
      fc_dlog( net_plugin->get_logger(), "sync_last_requested_num: {r}, sync_next_expected_num: {e}, sync_known_lib_num: {k}, sync_req_span: {s}",
               ("r", sync_last_requested_num)("e", sync_next_expected_num)("k", sync_known_lib_num)("s", sync_req_span) );
   }
   inline void log_syncing_status() const { log_syncing_status(locked_sync_mutex()); }

   void reset_sync_source(const mutex_locker&) {
      sync_source.reset();
   }
   void reset_sync_source() { reset_sync_source(locked_sync_mutex()); }

   void closing_sync_source(const mutex_locker& lock) {
      uint32_t head_blk_num = 0;
      std::tie( std::ignore, head_blk_num, std::ignore, std::ignore, std::ignore, std::ignore ) = net_plugin->get_chain_info();
      sync_next_expected_num = head_blk_num + 1;
      fc_ilog( net_plugin->get_logger(), "reassign_fetch, our last req is {cc}, next expected is {ne}",
               ("cc", sync_last_requested_num)("ne", sync_next_expected_num) );

      reset_last_requested_num(lock);
   }
   inline void closing_sync_source() { closing_sync_source(locked_sync_mutex()); }

   bool sync_in_progress(const mutex_locker&) const {
      uint32_t fork_head_block_num = 0;
      std::tie( std::ignore, std::ignore, fork_head_block_num,
                  std::ignore, std::ignore, std::ignore ) = net_plugin->get_chain_info();

      if( fork_head_block_num < sync_last_requested_num && sync_source && sync_source->current() ) {
         fc_ilog( net_plugin->get_logger(), "ignoring request, head is {h} last req = {r}, source connection {c}",
                  ("h", fork_head_block_num)("r", sync_last_requested_num)("c", sync_source->get_id()) );
         return true;
      }

      return false;
   }
   inline bool sync_in_progress() const { return sync_in_progress(locked_sync_mutex()); }

   bool set_new_sync_source(const connection_ptr& sync_hint) {
      auto lock = locked_sync_mutex();
      if (sync_hint && sync_hint->current() ) {
         sync_source = sync_hint;
      } else {
         auto clock = net_plugin->shared_connections_lock(); (void)clock;
         const auto& connections = net_plugin->get_connections();
         if( connections.size() == 0 ) {
            sync_source.reset();
         } else if( connections.size() == 1 ) {
            if (!sync_source) {
               sync_source = *connections.begin();
            }
         } else {
            // init to a linear array search
            auto cptr = connections.begin();
            auto cend = connections.end();
            // do we remember the previous source?
            if (sync_source) {
               //try to find it in the list
               cptr = connections.find( sync_source );
               cend = cptr;
               if( cptr == connections.end() ) {
                  //not there - must have been closed! cend is now connections.end, so just flatten the ring.
                  sync_source.reset();
                  cptr = connections.begin();
               } else {
                  //was found - advance the start to the next. cend is the old source.
                  if( ++cptr == connections.end() && cend != connections.end() ) {
                     cptr = connections.begin();
                  }
               }
            }

            //scan the list of peers looking for another able to provide sync blocks.
            if( cptr != connections.end() ) {
               auto cstart_it = cptr;
               do {
                  //select the first one which is current and has valid lib and break out.
                  if( !(*cptr)->is_transactions_only_connection() && (*cptr)->current() ) {
                     auto lock = (*cptr)->locked_connection_mutex(); (void)lock;
                     if( (*cptr)->get_last_handshake().last_irreversible_block_num >= sync_known_lib_num ) {
                        sync_source = *cptr;
                        break;
                     }
                  }
                  if( ++cptr == connections.end() )
                     cptr = connections.begin();
               } while( cptr != cstart_it );
            }
            // no need to check the result, either source advanced or the whole list was checked and the old source is reused.
         }
      }

      // verify there is an available source
      if( !sync_source || !sync_source->current() || sync_source->is_transactions_only_connection() ) {
         fc_elog( net_plugin->get_logger(), "Unable to choose proper sync source");
         uint32_t lib_block_num = 0;
         std::tie( lib_block_num, std::ignore, std::ignore,
                  std::ignore, std::ignore, std::ignore ) = net_plugin->get_chain_info();

         sync_known_lib_num = lib_block_num;
         reset_last_requested_num(lock);
         reset_sync_source(lock);
         return false;
      }

      return true;
   }

   bool block_ge_lib(uint32_t blk_num, const mutex_locker&) const {
      fc_dlog( net_plugin->get_logger(), "sync_known_lib_num = {lib}", ("lib", sync_known_lib_num) );
      return blk_num >= sync_known_lib_num;
   }
   inline bool block_ge_lib(uint32_t blk_num) const {
      return block_ge_lib(blk_num, locked_sync_mutex());
   }
   bool block_ge_last_requested(uint32_t blk_num, const mutex_locker&) const {
      return blk_num >= sync_last_requested_num;
   }
   bool block_ge_last_requested(uint32_t blk_num) const {
      return block_ge_last_requested(blk_num, locked_sync_mutex());
   }

   bool continue_head_catchup(const chain::block_id_type& blk_id, uint32_t blk_num) const {
      chain::block_id_type null_id;
      bool continue_head_catchup = false;
      net_plugin->for_each_block_connection(
         [&null_id, blk_num, &blk_id, &continue_head_catchup]( const auto& cp ) {
         auto lock = cp->locked_connection_mutex();
         uint32_t fork_head_num = cp->get_fork_head_num();
         chain::block_id_type fork_head_id = cp->get_fork_head();
         lock.unlock();
         if( fork_head_id == null_id ) {
            return true;
         } else if( fork_head_num < blk_num || fork_head_id == blk_id ) {
            auto lock = cp->locked_connection_mutex(); (void)lock;
            cp->reset_fork_head();
         } else {
            continue_head_catchup = true;
         }
         return true;
      });

      fc_ilog( net_plugin->get_logger(), "continue_head_catchup = {c}", ("c", continue_head_catchup) );
      return continue_head_catchup;
   }

   void set_highest_lib() {
      fc_ilog( net_plugin->get_logger(), "sync_source is {s}", ("s", (sync_source ? "not null" : "null")));
      uint32_t highest_lib_num = 0;
      net_plugin->for_each_block_connection(
         [&highest_lib_num]( const auto& cc ) {
         auto lock = cc->locked_connection_mutex(); (void)lock;
         if( cc->current() && cc->get_last_handshake().last_irreversible_block_num > highest_lib_num ) {
            highest_lib_num = cc->get_last_handshake().last_irreversible_block_num;
         }
         return true;
      });
      auto lock = locked_sync_mutex();
      sync_known_lib_num = highest_lib_num;
   }

   void update_next_expected() {
      auto lock = locked_sync_mutex();

      uint32_t lib_num = 0;
      std::tie( lib_num, std::ignore, std::ignore,
                  std::ignore, std::ignore, std::ignore ) = net_plugin->get_chain_info();
      sync_next_expected_num = std::max( lib_num + 1, sync_next_expected_num );
   }

   struct state_machine {
   private:
      mutable std::shared_ptr<std::mutex>  sml_mtx;
   public:
      inline auto locked_sml_mutex() const {
         return mutex_locker(*sml_mtx);
      }

      std::shared_ptr<sync_manager> impl;
      explicit state_machine(const std::shared_ptr<sync_manager>& pimpl)
         : sml_mtx(new std::mutex()),
           impl(pimpl) {}

      struct base_event {};

      struct lib_catchup : base_event {
         uint32_t target;
         connection_ptr sync_hint;

         lib_catchup(uint32_t t, const connection_ptr& c) : target(t), sync_hint(c) {}
      };

      struct head_catchup : base_event {
      };

      struct recv_block : base_event {
         chain::block_id_type blk_id;
         uint32_t blk_num;
         bool blk_applied;

         recv_block(const chain::block_id_type& id, uint32_t n, bool applied) : blk_id(id), blk_num(n), blk_applied(applied) {}
      };

      struct close_connection : base_event {
         connection_ptr c;

         close_connection(const connection_ptr& con) : c(con) {}
      };

      struct reassign_fetch : base_event {
         connection_ptr c;

         reassign_fetch(const connection_ptr& con) : c(con) {}
      };

      template<typename _Fn>
      struct cache {
         using cached_type = return_type_t<_Fn>;
         _Fn fn;
         bool return_cached = false;

         explicit cache(_Fn f, bool ret_cache = false)
         : fn(f), return_cached(ret_cache) {}

         template<typename... Args>
         cached_type operator()(Args... args) {
            static cached_type cached;
            if (return_cached)
               return cached;

            cached = fn(args...);
            return cached;
         }
      };

      template<typename _Fn>
      struct always {
         _Fn fn;
         explicit always(_Fn f) : fn(f) {}

         template<typename... _Args>
         bool operator()(_Args... args) {
            fn(args...);
            return true;
         }
      };

      auto operator ()() {
         using namespace boost::sml;

         auto reset_source     = [this]()                                          { impl->reset_sync_source(); };
         auto set_lib          = [this](const state_machine::lib_catchup& ev)      { impl->sync_reset_lib_num(ev.target); };
         auto sync_required    = [this](const state_machine::lib_catchup& ev)      { return impl->is_sync_required(ev.target); };
         auto sync_in_progress = [this](const state_machine::lib_catchup&)         { return impl->sync_in_progress(); };
         auto set_expected     = [this](const state_machine::lib_catchup&)         { impl->update_next_expected(); };
         auto start_sync       = [this](const state_machine::lib_catchup& ev)      { impl->begin_sync(ev.sync_hint, ev.target); };
         auto set_new_source   = [this](const state_machine::lib_catchup& ev)      { return impl->set_new_sync_source(ev.sync_hint); };
         auto update_expected  = [this](const state_machine::recv_block& ev)       { impl->sync_update_expected(ev.blk_id, ev.blk_num, ev.blk_applied); };
         auto blk_ge_lib       = [this](const state_machine::recv_block& ev)       { return impl->block_ge_lib(ev.blk_num); };
         auto blk_ge_last_req  = [this](const state_machine::recv_block& ev)       { return impl->block_ge_last_requested(ev.blk_num); };
         auto verify_source    = [this](const state_machine::recv_block& )         { return impl->set_new_sync_source({}); };
         auto verify_source_cc = [this](const state_machine::close_connection&)    { return impl->set_new_sync_source({}); };
         auto verify_source_rf = [this](const state_machine::reassign_fetch&)      { return impl->set_new_sync_source({}); };
         auto snd_handshakes   = [this]()                                          { impl->send_handshakes(); };
         auto continue_snc     = [this]()                                          { impl->continue_sync(); };
         auto continue_catchup = [this](const state_machine::recv_block& ev)       { return impl->continue_head_catchup(ev.blk_id, ev.blk_num); };
         auto reset_lib        = [this](const state_machine::close_connection&)    { impl->set_highest_lib(); };
         auto is_source        = [this](const state_machine::close_connection& ev) { return impl->is_sync_source(*ev.c); };
         auto is_source_rf     = [this](const state_machine::reassign_fetch& ev)   { return impl->is_sync_source(*ev.c); };
         auto close_source     = [this]()                                          { impl->closing_sync_source(); };
         auto reset_last_r     = [this](const state_machine::reassign_fetch&)      { impl->reset_last_requested_num(); };
         auto log_status       = [this]()                                          { impl->log_syncing_status(); };

         auto a_set_lib  = always<decltype(set_lib)>(set_lib);
         auto a_set_exp  = always<decltype(set_expected)>(set_expected);
         auto a_update_expected = always<decltype(update_expected)>(update_expected);
         auto a_reset_lib = always<decltype(reset_lib)>(reset_lib);
         auto a_reset_last_r = always<decltype(reset_last_r)>(reset_last_r);

         auto c_verify_source      = cache<decltype(verify_source)>(verify_source);
         auto c_verify_source_t    = cache<decltype(verify_source)>(verify_source, true);
         auto c_verify_source_cc   = cache<decltype(verify_source_cc)>(verify_source_cc);
         auto c_verify_source_cc_t = cache<decltype(verify_source_cc)>(verify_source_cc, true);
         auto c_verify_source_rf   = cache<decltype(verify_source_rf)>(verify_source_rf);
         auto c_verify_source_rf_t = cache<decltype(verify_source_rf)>(verify_source_rf, true);
         auto c_sync_required      = cache<decltype(sync_required)>(sync_required);
         auto c_sync_in_progress   = cache<decltype(sync_in_progress)>(sync_in_progress);
         auto c_sync_in_progress_t = cache<decltype(sync_in_progress)>(sync_in_progress, true);

         return make_transition_table(
         *  "in_sync"_s      + on_entry<_>                                                                                           / reset_source,
            "in_sync"_s      + event<lib_catchup>      [ a_set_lib && sync_required && a_set_exp && set_new_source ]                 / start_sync                     = "lib_catchup"_s,
            "in_sync"_s      + event<head_catchup>     /* head catchup is done by connection */                                      / log_status                     = "head_catchup"_s,
            "in_sync"_s      + event<recv_block>                                                                                     / update_expected                = "in_sync"_s,
            "in_sync"_s      + event<close_connection>                                                                               / reset_lib                      = "in_sync"_s,
            "in_sync"_s      + event<reassign_fetch>                                                                                 / reset_last_r                   = "in_sync"_s,
            "lib_catchup"_s  + event<head_catchup>     /* ignore head_catchup */                                                                                      = "lib_catchup"_s,
            "lib_catchup"_s  + event<recv_block>       [ a_update_expected && blk_ge_lib ]                                           / snd_handshakes                 = "in_sync"_s,
            "lib_catchup"_s  + event<recv_block>       [ blk_ge_last_req && c_verify_source ]                                        / continue_snc                   = "lib_catchup"_s,
            "lib_catchup"_s  + event<recv_block>       [ blk_ge_last_req && !c_verify_source_t ]                                                                      = "in_sync"_s,
            "lib_catchup"_s  + event<close_connection> [ a_reset_lib && is_source && c_verify_source_cc ]                            / (close_source, continue_snc)   = "lib_catchup"_s,
            "lib_catchup"_s  + event<close_connection> [ is_source && !c_verify_source_cc_t ]                                                                         = "in_sync"_s,
            "lib_catchup"_s  + event<reassign_fetch>   [ a_reset_last_r && is_source_rf && c_verify_source_rf ]                      / (continue_snc)                 = "lib_catchup"_s,
            "lib_catchup"_s  + event<reassign_fetch>   [ is_source_rf && !c_verify_source_rf_t ]                                                                      = "in_sync"_s,
            "lib_catchup"_s  + event<lib_catchup>      [ a_set_lib && c_sync_required && a_set_exp
                                                                         && !c_sync_in_progress && set_new_source ]                  / start_sync                     = "lib_catchup"_s,
            "lib_catchup"_s  + event<lib_catchup>      [ c_sync_required && c_sync_in_progress_t ]                                                                    = "lib_catchup"_s,
            "lib_catchup"_s  + event<lib_catchup>                                                                                                                     = "in_sync"_s,
            "head_catchup"_s + event<recv_block>       [ a_update_expected && !continue_catchup ]                                    / snd_handshakes                 = "in_sync"_s,
            "head_catchup"_s + event<close_connection>                                                                               / reset_lib                      = "in_sync"_s,
            "head_catchup"_s + event<reassign_fetch>                                                                                 / reset_last_r                   = "head_catchup"_s,
            "error"_s        + exception<_>                                                                                                                           = "in_sync"_s
         );
      }
   };//sm
};

}} //eosio::p2p

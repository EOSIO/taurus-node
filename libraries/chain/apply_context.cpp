#include <eosio/chain/account_object.hpp>
#include <eosio/chain/apply_context.hpp>
#include <eosio/chain/authorization_manager.hpp>
#include <eosio/chain/code_object.hpp>
#include <eosio/chain/controller.hpp>
#include <eosio/chain/exceptions.hpp>
#include <eosio/chain/global_property_object.hpp>
#include <eosio/chain/kv_chainbase_objects.hpp>
#include <eosio/chain/resource_limits.hpp>
#include <eosio/chain/to_string.hpp>
#include <eosio/chain/transaction_context.hpp>
#include <eosio/chain/wasm_interface.hpp>

#include <boost/container/flat_set.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

using boost::container::flat_set;
using namespace eosio::chain::backing_store;

namespace eosio { namespace chain {

static inline void print_debug(account_name receiver, const action_trace& ar) {
   if (!ar.console.empty()) {
      auto prefix = fc::format_string(
                                      "\n[(${a},${n})->${r}]",
                                      fc::mutable_variant_object()
                                      ("a", ar.act.account)
                                      ("n", ar.act.name)
                                      ("r", receiver));
      dlog(prefix + ": CONSOLE OUTPUT BEGIN =====================\n"
           + ar.console
           + prefix + ": CONSOLE OUTPUT END   =====================" );
   }
}

apply_context::apply_context(controller& con, transaction_context& trx_ctx, uint32_t action_ordinal, uint32_t depth)
:control(con)
,db(con.mutable_db())
,trx_context(trx_ctx)
,recurse_depth(depth)
,first_receiver_action_ordinal(action_ordinal)
,action_ordinal(action_ordinal)
,idx64(*this)
,idx128(*this)
,idx256(*this)
,idx_double(*this)
,idx_long_double(*this)
{
   kv_iterators.emplace_back(); // the iterator handle with value 0 is reserved
   action_trace& trace = trx_ctx.get_action_trace(action_ordinal);
   act = &trace.act;
   receiver = trace.receiver;
   context_free = trace.context_free;
}

template <typename Exception>
void apply_context::check_unprivileged_resource_usage(const char* resource, const flat_set<account_delta>& deltas) {
   const size_t checktime_interval    = 10;
   const bool   not_in_notify_context = (receiver == act->account);
   size_t counter = 0;
   for (const auto& entry : deltas) {
      if (counter == checktime_interval) {
         trx_context.checktime();
         counter = 0;
      }
      if (entry.delta > 0 && entry.account != receiver) {
         EOS_ASSERT(not_in_notify_context, Exception,
                     "unprivileged contract cannot increase {resource} usage of another account within a notify context: "
                     "{account}",
                     ("resource", resource)
                     ("account", entry.account));
         EOS_ASSERT(has_authorization(entry.account), Exception,
                     "unprivileged contract cannot increase {resource} usage of another account that has not authorized the "
                     "action: {account}",
                     ("resource", resource)
                     ("account", entry.account));
      }
      ++counter;
   }
}

void apply_context::exec_one()
{
   auto start = fc::time_point::now();

   digest_type act_digest;

   const auto& cfg = control.get_global_properties().configuration;
   const account_metadata_object* receiver_account = nullptr;

   auto handle_exception = [&](const auto& e)
   {
      action_trace& trace = trx_context.get_action_trace( action_ordinal );
      trace.error_code = controller::convert_exception_to_error_code( e );
      trace.except = e;
      finalize_trace( trace, start );
      throw;
   };

   try {
      try {
         action_return_value.clear();
         kv_iterators.resize(1);
         kv_destroyed_iterators.clear();
         if (!context_free) {
            kv_backing_store = db_util::create_kv_context(control, receiver, create_kv_resource_manager(*this), control.get_global_properties().kv_configuration);
        }
         receiver_account = &db.get<account_metadata_object,by_name>( receiver );
         if( !(context_free && control.skip_trx_checks()) ) {
            privileged = receiver_account->is_privileged();
            auto native = control.find_apply_handler( receiver, act->account, act->name );
            if( native ) {
               if( trx_context.enforce_whiteblacklist && control.is_producing_block() ) {
                  control.check_contract_list( receiver );
                  control.check_action_list( act->account, act->name );
               }
               (*native)( *this );
            }

            if( ( receiver_account->code_hash != digest_type() ) &&
                  (  !( act->account == config::system_account_name
                        && act->name == "setcode"_n
                        && receiver == config::system_account_name )
                     || control.is_builtin_activated( builtin_protocol_feature_t::forward_setcode )
                  )
            ) {
               if( trx_context.enforce_whiteblacklist && control.is_producing_block() ) {
                  control.check_contract_list( receiver );
                  control.check_action_list( act->account, act->name );
               }
               try {
                  control.get_wasm_interface().apply( receiver_account->code_hash, receiver_account->vm_type, receiver_account->vm_version, *this );
               } catch( const wasm_exit& ) {}
            }

            if (!privileged) {
               if (control.is_builtin_activated(builtin_protocol_feature_t::ram_restrictions)) {
                  check_unprivileged_resource_usage<unauthorized_ram_usage_increase>("RAM", _account_ram_deltas);
               }
            }
         }
      } FC_RETHROW_EXCEPTIONS( warn, "pending console output: {console}", ("console", _pending_console_output) )

      if( control.is_builtin_activated( builtin_protocol_feature_t::action_return_value ) ) {
         act_digest =   generate_action_digest(
                           [this](const char* data, uint32_t datalen) {
                              return trx_context.hash_with_checktime<digest_type>(data, datalen);
                           },
                           *act,
                           action_return_value
                        );
      } else {
         act_digest = digest_type::hash(*act);
      }
   } catch ( const std::bad_alloc& ) {
      throw;
   } catch ( const boost::interprocess::bad_alloc& ) {
      throw;
   } catch( const fc::exception& e ) {
      handle_exception(e);
   } catch ( const std::exception& e ) {
      auto wrapper = fc::std_exception_wrapper::from_current_exception(e);
      handle_exception(wrapper);
   }

   // Note: It should not be possible for receiver_account to be invalidated because:
   //    * a pointer to an object in a chainbase index is not invalidated if other objects in that index are modified, removed, or added;
   //    * a pointer to an object in a chainbase index is not invalidated if the fields of that object are modified;
   //    * and, the *receiver_account object itself cannot be removed because accounts cannot be deleted in EOSIO.

   action_trace& trace = trx_context.get_action_trace( action_ordinal );
   trace.return_value  = std::move(action_return_value);
   trace.receipt.emplace();

   action_receipt& r = *trace.receipt;
   r.receiver        = receiver;
   r.act_digest      = act_digest;


   r.global_sequence  = next_global_sequence();
   r.recv_sequence    = next_recv_sequence( *receiver_account );

   const account_metadata_object* first_receiver_account = nullptr;
   if( act->account == receiver ) {
      first_receiver_account = receiver_account;
   } else {
      first_receiver_account = &db.get<account_metadata_object, by_name>(act->account);
   }

   r.code_sequence    = first_receiver_account->code_sequence; // could be modified by action execution above
   r.abi_sequence     = first_receiver_account->abi_sequence;  // could be modified by action execution above

   for( const auto& auth : act->authorization ) {
      r.auth_sequence[auth.actor] = next_auth_sequence( auth.actor );
   }

   trx_context.executed_action_receipt_digests.emplace_back( r.digest() );

   finalize_trace( trace, start );

   if ( control.contracts_console() ) {
      print_debug(receiver, trace);
   }
}

void apply_context::finalize_trace( action_trace& trace, const fc::time_point& start )
{
   trace.account_ram_deltas = std::move( _account_ram_deltas );
   _account_ram_deltas.clear();

   trace.console = std::move( _pending_console_output );
   _pending_console_output.clear();

   trace.elapsed = fc::time_point::now() - start;
}

void apply_context::exec()
{
   _notified.emplace_back( receiver, action_ordinal );
   exec_one();
   increment_action_id();
   for( uint32_t i = 1; i < _notified.size(); ++i ) {
      std::tie( receiver, action_ordinal ) = _notified[i];
      exec_one();
      increment_action_id();
   }

   if( _cfa_inline_actions.size() > 0 || _inline_actions.size() > 0 ) {
      EOS_ASSERT( recurse_depth < control.get_global_properties().configuration.max_inline_action_depth,
                  transaction_exception, "max inline action depth per transaction reached" );
   }

   for( uint32_t ordinal : _cfa_inline_actions ) {
      trx_context.execute_action( ordinal, recurse_depth + 1 );
   }

   for( uint32_t ordinal : _inline_actions ) {
      trx_context.execute_action( ordinal, recurse_depth + 1 );
   }

} /// exec()

bool apply_context::is_account( const account_name& account )const {
   return nullptr != db.find<account_object,by_name>( account );
}

void apply_context::require_authorization( const account_name& account ) const {
   for( uint32_t i=0; i < act->authorization.size(); i++ ) {
     if( act->authorization[i].actor == account ) {
        return;
     }
   }
   EOS_ASSERT( false, missing_auth_exception, "missing authority of {account}", ("account",account));
}

bool apply_context::has_authorization( const account_name& account )const {
   for( const auto& auth : act->authorization )
     if( auth.actor == account )
        return true;
  return false;
}

void apply_context::require_authorization(const account_name& account,
                                          const permission_name& permission) const {
  for( uint32_t i=0; i < act->authorization.size(); i++ )
     if( act->authorization[i].actor == account ) {
        if( act->authorization[i].permission == permission ) {
           return;
        }
     }
  EOS_ASSERT( false, missing_auth_exception, "missing authority of {account}/{permission}",
              ("account",account)("permission",permission) );
}

bool apply_context::has_recipient( account_name code )const {
   for( const auto& p : _notified )
      if( p.first == code )
         return true;
   return false;
}

void apply_context::require_recipient( account_name recipient ) {
   if( !has_recipient(recipient) ) {
      _notified.emplace_back(
         recipient,
         schedule_action( action_ordinal, recipient, false )
      );
   }
}


/**
 *  This will execute an action after checking the authorization. Inline transactions are
 *  implicitly authorized by the current receiver (running code). This method has significant
 *  security considerations and several options have been considered:
 *
 *  1. privileged accounts (those marked as such by block producers) can authorize any action
 *  2. all other actions are only authorized by 'receiver' which means the following:
 *         a. the user must set permissions on their account to allow the 'receiver' to act on their behalf
 *
 *  Discarded Implementation: at one point we allowed any account that authorized the current transaction
 *   to implicitly authorize an inline transaction. This approach would allow privilege escalation and
 *   make it unsafe for users to interact with certain contracts.  We opted instead to have applications
 *   ask the user for permission to take certain actions rather than making it implicit. This way users
 *   can better understand the security risk.
 */
void apply_context::execute_inline( action&& a ) {
   auto* code = control.db().find<account_object, by_name>(a.account);
   EOS_ASSERT( code != nullptr, action_validate_exception,
               "inline action's code account {account} does not exist", ("account", a.account) );

   bool enforce_actor_whitelist_blacklist = trx_context.enforce_whiteblacklist && control.is_producing_block();
   flat_set<account_name> actors;

   bool disallow_send_to_self_bypass = control.is_builtin_activated( builtin_protocol_feature_t::restrict_action_to_self );
   bool send_to_self = (a.account == receiver);
   bool inherit_parent_authorizations = (!disallow_send_to_self_bypass && send_to_self && (receiver == act->account) && control.is_producing_block());

   flat_set<permission_level> inherited_authorizations;
   if( inherit_parent_authorizations ) {
      inherited_authorizations.reserve( a.authorization.size() );
   }

   for( const auto& auth : a.authorization ) {
      auto* actor = control.db().find<account_object, by_name>(auth.actor);
      EOS_ASSERT( actor != nullptr, action_validate_exception,
                  "inline action's authorizing actor {account} does not exist", ("account", auth.actor) );
      EOS_ASSERT( control.get_authorization_manager().find_permission(auth) != nullptr, action_validate_exception,
                  "inline action's authorizations include a non-existent permission: {permission}",
                  ("permission", auth) );
      if( enforce_actor_whitelist_blacklist )
         actors.insert( auth.actor );

      if( inherit_parent_authorizations && std::find(act->authorization.begin(), act->authorization.end(), auth) != act->authorization.end() ) {
         inherited_authorizations.insert( auth );
      }
   }

   if( enforce_actor_whitelist_blacklist ) {
      control.check_actor_list( actors );
   }

   if( !privileged && control.is_producing_block() ) {
      const auto& chain_config = control.get_global_properties().configuration;
      EOS_ASSERT( a.data.size() < std::min(chain_config.max_inline_action_size, control.get_max_nonprivileged_inline_action_size()),
                  inline_action_too_big_nonprivileged,
                  "inline action too big for nonprivileged account {account}", ("account", a.account));
   }
   // No need to check authorization if replaying irreversible blocks or contract is privileged
   if( !control.skip_auth_check() && !privileged ) {
      try {
         control.get_authorization_manager()
                .check_authorization( {a},
                                      {},
                                      {{receiver, config::eosio_code_name}},
                                      std::bind(&transaction_context::checktime, &this->trx_context),
                                      false,
                                      inherited_authorizations
                                    );

         //QUESTION: Is it smart to allow a deferred transaction that has been delayed for some time to get away
         //          with sending an inline action that requires a delay even though the decision to send that inline
         //          action was made at the moment the deferred transaction was executed with potentially no forewarning?
      } catch( const fc::exception& e ) {
         if( disallow_send_to_self_bypass || !send_to_self ) {
            throw;
         } else if( control.is_producing_block() ) {
            subjective_block_production_exception new_exception(FC_LOG_MESSAGE( error, "Authorization failure with inline action sent to self"));
            for (const auto& log: e.get_log()) {
               new_exception.append_log(log);
            }
            throw new_exception;
         }
      } catch( ... ) {
         if( disallow_send_to_self_bypass || !send_to_self ) {
            throw;
         } else if( control.is_producing_block() ) {
            EOS_THROW(subjective_block_production_exception, "Unexpected exception occurred validating inline action sent to self");
         }
      }
   }

   auto inline_receiver = a.account;
   _inline_actions.emplace_back(
      schedule_action( std::move(a), inline_receiver, false )
   );
}

void apply_context::execute_context_free_inline( action&& a ) {
   auto* code = control.db().find<account_object, by_name>(a.account);
   EOS_ASSERT( code != nullptr, action_validate_exception,
               "inline action's code account {account} does not exist", ("account", a.account) );

   EOS_ASSERT( a.authorization.size() == 0, action_validate_exception,
               "context-free actions cannot have authorizations" );

   if( !privileged && control.is_producing_block() ) {
      const auto& chain_config = control.get_global_properties().configuration;
      EOS_ASSERT( a.data.size() < std::min(chain_config.max_inline_action_size, control.get_max_nonprivileged_inline_action_size()),
                  inline_action_too_big_nonprivileged,
                  "inline action too big for nonprivileged account {account}", ("account", a.account));
   }

   auto inline_receiver = a.account;
   _cfa_inline_actions.emplace_back(
      schedule_action( std::move(a), inline_receiver, true )
   );
}

uint32_t apply_context::schedule_action( uint32_t ordinal_of_action_to_schedule, account_name receiver, bool context_free )
{
   uint32_t scheduled_action_ordinal = trx_context.schedule_action( ordinal_of_action_to_schedule,
                                                                    receiver, context_free,
                                                                    action_ordinal, first_receiver_action_ordinal );

   act = &trx_context.get_action_trace( action_ordinal ).act;
   return scheduled_action_ordinal;
}

uint32_t apply_context::schedule_action( action&& act_to_schedule, account_name receiver, bool context_free )
{
   uint32_t scheduled_action_ordinal = trx_context.schedule_action( std::move(act_to_schedule),
                                                                    receiver, context_free,
                                                                    action_ordinal, first_receiver_action_ordinal );

   act = &trx_context.get_action_trace( action_ordinal ).act;
   return scheduled_action_ordinal;
}

const table_id_object* apply_context::find_table( name code, name scope, name table ) {
   return db.find<table_id_object, by_code_scope_table>(boost::make_tuple(code, scope, table));
}

const table_id_object& apply_context::find_or_create_table( name code, name scope, name table, const account_name &payer ) {
   const auto* existing_tid =  db.find<table_id_object, by_code_scope_table>(boost::make_tuple(code, scope, table));
   if (existing_tid != nullptr) {
      return *existing_tid;
   }

   update_db_usage(payer, config::billable_size_v<table_id_object>);

   return db.create<table_id_object>([&](table_id_object &t_id){
      t_id.code = code;
      t_id.scope = scope;
      t_id.table = table;
      t_id.payer = payer;
   });
}

void apply_context::remove_table( const table_id_object& tid ) {
   update_db_usage(tid.payer, - config::billable_size_v<table_id_object> );

   db.remove(tid);
}

vector<account_name> apply_context::get_active_producers() const {
   const auto& ap = control.active_producers();
   vector<account_name> accounts; accounts.reserve( ap.producers.size() );

   for(const auto& producer : ap.producers )
      accounts.push_back(producer.producer_name);

   return accounts;
}

void apply_context::update_db_usage( const account_name& payer, int64_t delta ) {
   if( delta > 0 ) {
      if( !(privileged || payer == account_name(receiver)
               || control.is_builtin_activated( builtin_protocol_feature_t::ram_restrictions ) ) )
      {
         EOS_ASSERT( control.is_ram_billing_in_notify_allowed() || (receiver == act->account),
                     subjective_block_production_exception, "Cannot charge RAM to other accounts during notify." );
         require_authorization( payer );
      }
   }
   add_ram_usage(payer, delta);
}


int apply_context::get_action( uint32_t type, uint32_t index, char* buffer, size_t buffer_size )const
{
   const auto& trx = trx_context.packed_trx.get_transaction();
   const action* act_ptr = nullptr;

   if( type == 0 ) {
      if( index >= trx.context_free_actions.size() )
         return -1;
      act_ptr = &trx.context_free_actions[index];
   }
   else if( type == 1 ) {
      if( index >= trx.actions.size() )
         return -1;
      act_ptr = &trx.actions[index];
   }

   EOS_ASSERT(act_ptr, action_not_found_exception, "action is not found" );

   auto ps = fc::raw::pack_size( *act_ptr );
   if( ps <= buffer_size ) {
      fc::datastream<char*> ds(buffer, buffer_size);
      fc::raw::pack( ds, *act_ptr );
   }
   return ps;
}

int apply_context::get_context_free_data( uint32_t index, char* buffer, size_t buffer_size )const
{
   const packed_transaction::prunable_data_type::prunable_data_t& data = trx_context.packed_trx.get_prunable_data().prunable_data;
   const bytes* cfd = nullptr;
   if( std::holds_alternative<packed_transaction::prunable_data_type::none>(data) ) {
   } else if( std::holds_alternative<packed_transaction::prunable_data_type::partial>(data) ) {
      if( index >= std::get<packed_transaction::prunable_data_type::partial>(data).context_free_segments.size() ) return -1;

      cfd = trx_context.packed_trx.get_context_free_data(index);
   } else {
      const std::vector<bytes>& context_free_data =
            std::holds_alternative<packed_transaction::prunable_data_type::full_legacy>(data) ?
               std::get<packed_transaction::prunable_data_type::full_legacy>(data).context_free_segments :
               std::get<packed_transaction::prunable_data_type::full>(data).context_free_segments;
      if( index >= context_free_data.size() ) return -1;

      cfd = &context_free_data[index];
   }

   if( !cfd ) {
      if( control.is_producing_block() ) {
         EOS_THROW( subjective_block_production_exception, "pruned context free data not available" );
      } else {
         EOS_THROW( pruned_context_free_data_bad_block_exception, "pruned context free data not available" );
      }
   }

   auto s = cfd->size();
   if( buffer_size == 0 ) return s;

   auto copy_size = std::min( buffer_size, s );
   memcpy( buffer, cfd->data(), copy_size );

   return copy_size;
}

int apply_context::db_store_i64( name scope, name table, const account_name& payer, uint64_t id, const char* buffer, size_t buffer_size ) {
//   require_write_lock( scope );
   const auto& tab = find_or_create_table( receiver, scope, table, payer );
   auto tableid = tab.id;

   EOS_ASSERT( payer != account_name(), invalid_table_payer, "must specify a valid account to pay for new record" );

   const auto& obj = db.create<key_value_object>( [&]( auto& o ) {
      o.t_id        = tableid;
      o.primary_key = id;
      o.value.assign( buffer, buffer_size );
      o.payer       = payer;
   });

   db.modify( tab, [&]( auto& t ) {
     ++t.count;
   });

   int64_t billable_size = (int64_t)(buffer_size + config::billable_size_v<key_value_object>);

   update_db_usage( payer, billable_size );

   db_iter_store.cache_table( tab );
   return db_iter_store.add( obj );
}

void apply_context::db_update_i64( int iterator, account_name payer, const char* buffer, size_t buffer_size ) {
   const key_value_object& obj = db_iter_store.get( iterator );

   const auto& table_obj = db_iter_store.get_table( obj.t_id );
   EOS_ASSERT( table_obj.code == receiver, table_access_violation, "db access violation" );

//   require_write_lock( table_obj.scope );

   const int64_t overhead = config::billable_size_v<key_value_object>;
   int64_t old_size = (int64_t)(obj.value.size() + overhead);
   int64_t new_size = (int64_t)(buffer_size + overhead);

   if( payer == account_name() ) payer = obj.payer;

   if( account_name(obj.payer) != payer ) {
      // refund the existing payer
      update_db_usage( obj.payer, -(old_size) );
      // charge the new payer
      update_db_usage( payer,  (new_size) );
   } else if(old_size != new_size) {
      // charge/refund the existing payer the difference
      update_db_usage( obj.payer, new_size - old_size );
   }

   db.modify( obj, [&]( auto& o ) {
     o.value.assign( buffer, buffer_size );
     o.payer = payer;
   });
}

void apply_context::db_remove_i64( int iterator ) {
   const key_value_object& obj = db_iter_store.get( iterator );

   const auto& table_obj = db_iter_store.get_table( obj.t_id );
   EOS_ASSERT( table_obj.code == receiver, table_access_violation, "db access violation" );

//   require_write_lock( table_obj.scope );

   update_db_usage( obj.payer,  -(obj.value.size() + config::billable_size_v<key_value_object>) );

   db.modify( table_obj, [&]( auto& t ) {
      --t.count;
   });
   db.remove( obj );

   if (table_obj.count == 0) {
      remove_table(table_obj);
   }

   db_iter_store.remove( iterator );
}

int apply_context::db_get_i64( int iterator, char* buffer, size_t buffer_size ) {
   const key_value_object& obj = db_iter_store.get( iterator );

   auto s = obj.value.size();
   if( buffer_size == 0 ) return s;

   auto copy_size = std::min( buffer_size, s );
   memcpy( buffer, obj.value.data(), copy_size );

   return copy_size;
}

int apply_context::db_next_i64( int iterator, uint64_t& primary ) {
   if( iterator < -1 ) return -1; // cannot increment past end iterator of table

   const auto& obj = db_iter_store.get( iterator ); // Check for iterator != -1 happens in this call
   const auto& idx = db.get_index<key_value_index, by_scope_primary>();

   auto itr = idx.iterator_to( obj );
   ++itr;

   if( itr == idx.end() || itr->t_id != obj.t_id ) return db_iter_store.get_end_iterator_by_table_id(obj.t_id);

   primary = itr->primary_key;
   return db_iter_store.add( *itr );
}

int apply_context::db_previous_i64( int iterator, uint64_t& primary ) {
   const auto& idx = db.get_index<key_value_index, by_scope_primary>();

   if( iterator < -1 ) // is end iterator
   {
      auto tab = db_iter_store.find_table_by_end_iterator(iterator);
      EOS_ASSERT( tab, invalid_table_iterator, "not a valid end iterator" );

      auto itr = idx.upper_bound(tab->id);
      if( idx.begin() == idx.end() || itr == idx.begin() ) return -1; // Empty table

      --itr;

      if( itr->t_id != tab->id ) return -1; // Empty table

      primary = itr->primary_key;
      return db_iter_store.add(*itr);
   }

   const auto& obj = db_iter_store.get(iterator); // Check for iterator != -1 happens in this call

   auto itr = idx.iterator_to(obj);
   if( itr == idx.begin() ) return -1; // cannot decrement past beginning iterator of table

   --itr;

   if( itr->t_id != obj.t_id ) return -1; // cannot decrement past beginning iterator of table

   primary = itr->primary_key;
   return db_iter_store.add(*itr);
}

int apply_context::db_find_i64( name code, name scope, name table, uint64_t id ) {
   //require_read_lock( code, scope ); // redundant?

   const auto* tab = find_table( code, scope, table );
   if( !tab ) return -1;

   auto table_end_itr = db_iter_store.cache_table( *tab );

   const key_value_object* obj = db.find<key_value_object, by_scope_primary>( boost::make_tuple( tab->id, id ) );
   if( !obj ) return table_end_itr;

   return db_iter_store.add( *obj );
}

int apply_context::db_lowerbound_i64( name code, name scope, name table, uint64_t id ) {
   //require_read_lock( code, scope ); // redundant?

   const auto* tab = find_table( code, scope, table );
   if( !tab ) return -1;

   auto table_end_itr = db_iter_store.cache_table( *tab );

   const auto& idx = db.get_index<key_value_index, by_scope_primary>();
   auto itr = idx.lower_bound( boost::make_tuple( tab->id, id ) );
   if( itr == idx.end() ) return table_end_itr;
   if( itr->t_id != tab->id ) return table_end_itr;

   return db_iter_store.add( *itr );
}

int apply_context::db_upperbound_i64( name code, name scope, name table, uint64_t id ) {
   //require_read_lock( code, scope ); // redundant?

   const auto* tab = find_table( code, scope, table );
   if( !tab ) return -1;

   auto table_end_itr = db_iter_store.cache_table( *tab );

   const auto& idx = db.get_index<key_value_index, by_scope_primary>();
   auto itr = idx.upper_bound( boost::make_tuple( tab->id, id ) );
   if( itr == idx.end() ) return table_end_itr;
   if( itr->t_id != tab->id ) return table_end_itr;

   return db_iter_store.add( *itr );
}

int apply_context::db_end_i64( name code, name scope, name table ) {
   //require_read_lock( code, scope ); // redundant?

   const auto* tab = find_table( code, scope, table );
   if( !tab ) return -1;

   return db_iter_store.cache_table( *tab );
}

int64_t apply_context::kv_erase(uint64_t contract, const char* key, uint32_t key_size) {
   return get_kv_context().kv_erase(contract, key, key_size);
}

int64_t apply_context::kv_set(uint64_t contract, const char* key, uint32_t key_size, const char* value, uint32_t value_size, account_name payer) {
   return get_kv_context().kv_set(contract, key, key_size, value, value_size, payer);
}

bool apply_context::kv_get(uint64_t contract, const char* key, uint32_t key_size, uint32_t& value_size) {
   return get_kv_context().kv_get(contract, key, key_size, value_size);
}

uint32_t apply_context::kv_get_data(uint32_t offset, char* data, uint32_t data_size) {
   return get_kv_context().kv_get_data(offset, data, data_size);
}

uint32_t apply_context::kv_it_create(uint64_t contract, const char* prefix, uint32_t size) {
   uint32_t itr;
   if (!kv_destroyed_iterators.empty()) {
      itr = kv_destroyed_iterators.back();
      kv_destroyed_iterators.pop_back();
   } else {
      // Sanity check in case the per-database limits are set poorly
      EOS_ASSERT(kv_iterators.size() <= 0xFFFFFFFFu, kv_bad_iter, "Too many iterators");
      itr = kv_iterators.size();
      kv_iterators.emplace_back();
   }
   kv_iterators[itr] = get_kv_context().kv_it_create(contract, prefix, size);
   return itr;
}

void apply_context::kv_it_destroy(uint32_t itr) {
   kv_check_iterator(itr);
   kv_destroyed_iterators.push_back(itr);
   kv_iterators[itr].reset();
}

int32_t apply_context::kv_it_status(uint32_t itr) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_status());
}

int32_t apply_context::kv_it_compare(uint32_t itr_a, uint32_t itr_b) {
   kv_check_iterator(itr_a);
   kv_check_iterator(itr_b);
   return kv_iterators[itr_a]->kv_it_compare(*kv_iterators[itr_b]);
}

int32_t apply_context::kv_it_key_compare(uint32_t itr, const char* key, uint32_t size) {
   kv_check_iterator(itr);
   return kv_iterators[itr]->kv_it_key_compare(key, size);
}

int32_t apply_context::kv_it_move_to_end(uint32_t itr) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_move_to_end());
}

int32_t apply_context::kv_it_next(uint32_t itr, uint32_t* found_key_size, uint32_t* found_value_size) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_next(found_key_size, found_value_size));
}

int32_t apply_context::kv_it_prev(uint32_t itr, uint32_t* found_key_size, uint32_t* found_value_size) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_prev(found_key_size, found_value_size));
}

int32_t apply_context::kv_it_lower_bound(uint32_t itr, const char* key, uint32_t size, uint32_t* found_key_size, uint32_t* found_value_size) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_lower_bound(key, size, found_key_size, found_value_size));
}

int32_t apply_context::kv_it_key(uint32_t itr, uint32_t offset, char* dest, uint32_t size, uint32_t& actual_size) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_key(offset, dest, size, actual_size));
}

int32_t apply_context::kv_it_value(uint32_t itr, uint32_t offset, char* dest, uint32_t size, uint32_t& actual_size) {
   kv_check_iterator(itr);
   return static_cast<int32_t>(kv_iterators[itr]->kv_it_value(offset, dest, size, actual_size));
}

void apply_context::kv_check_iterator(uint32_t itr) {
   EOS_ASSERT(itr < kv_iterators.size() && kv_iterators[itr], kv_bad_iter, "Bad key-value iterator");
}

uint64_t apply_context::next_global_sequence() {
   const auto& p = control.get_dynamic_global_properties();
   db.modify( p, [&]( auto& dgp ) {
      ++dgp.global_action_sequence;
   });
   return p.global_action_sequence;
}

uint64_t apply_context::next_recv_sequence( const account_metadata_object& receiver_account ) {
   db.modify( receiver_account, [&]( auto& ra ) {
      ++ra.recv_sequence;
   });
   return receiver_account.recv_sequence;
}
uint64_t apply_context::next_auth_sequence( account_name actor ) {
   const auto& amo = db.get<account_metadata_object,by_name>( actor );
   db.modify( amo, [&](auto& am ){
      ++am.auth_sequence;
   });
   return amo.auth_sequence;
}

void apply_context::add_ram_usage( account_name account, int64_t ram_delta ) {
   trx_context.add_ram_usage( account, ram_delta );

   auto p = _account_ram_deltas.emplace( account, ram_delta );
   if( !p.second ) {
      p.first->delta += ram_delta;
   }
}

void apply_context::push_event(const char* data, size_t size) const {
   control.push_event( data, size );
}

action_name apply_context::get_sender() const {
   const action_trace& trace = trx_context.get_action_trace( action_ordinal );
   if (trace.creator_action_ordinal > 0) {
      const action_trace& creator_trace = trx_context.get_action_trace( trace.creator_action_ordinal );
      return creator_trace.receiver;
   }
   return action_name();
}

uint32_t apply_context::get_action_id() const {
   return trx_context.action_id.current();
}

void apply_context::increment_action_id() {
   trx_context.action_id.increment();
}
} } /// eosio::chain

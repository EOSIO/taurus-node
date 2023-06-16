#pragma once

#include "protocol.hpp"
#include "defaults.hpp"
#include "block_status_monitor.hpp"
#include "queued_buffer.hpp"

#include <fc/network/message_buffer.hpp>
#include <fc/log/trace.hpp>

#include <boost/asio.hpp>
#include <boost/sml.hpp>

#include <chrono>

namespace eosio { namespace p2p {

constexpr uint16_t net_version = dup_node_id_goaway;

constexpr uint32_t signed_block_which          = fc::get_index<net_message, chain::signed_block>();          // see protocol net_message
constexpr uint32_t trx_message_v1_which        = fc::get_index<net_message, trx_message_v1>();        // see protocol net_message
constexpr uint32_t packed_transaction_v0_which = fc::get_index<net_message, chain::packed_transaction_v0>(); // see protocol net_message
constexpr uint32_t signed_block_v0_which       = fc::get_index<net_message, chain::signed_block_v0>();       // see protocol net_message
constexpr uint16_t proto_base = 0;
/**
 *  For a while, network version was a 16 bit value equal to the second set of 16 bits
 *  of the current build's git commit id. We are now replacing that with an integer protocol
 *  identifier. Based on historical analysis of all git commit identifiers, the larges gap
 *  between adjacent commit id values is shown below.
 *  these numbers were found with the following commands on the master branch:
 *
 *  git log | grep "^commit" | awk '{print substr($2,5,4)}' | sort -u > sorted.txt
 *  rm -f gap.txt; prev=0; for a in $(cat sorted.txt); do echo $prev $((0x$a - 0x$prev)) $a >> gap.txt; prev=$a; done; sort -k2 -n gap.txt | tail
 *
 *  DO NOT EDIT net_version_base OR net_version_range!
 */
constexpr uint16_t net_version_base = 0x04b5;
constexpr uint16_t net_version_range = 106;

/**
 * Index by start_block_num
 */
struct peer_sync_state {
   explicit peer_sync_state(uint32_t start = 0, uint32_t end = 0, uint32_t last_acted = 0)
      :start_block( start ), end_block( end ), last( last_acted ),
         start_time(chain::time_point::now())
   {}
   uint32_t            start_block;
   uint32_t            end_block;
   uint32_t            last; ///< last sent or received
   chain::time_point   start_time; ///< time request made or received
};

struct connection_status {
   std::string       peer;
   bool              connecting = false;
   bool              syncing    = false;
   handshake_message last_handshake;
};

struct peer_conn_info {
   std::string             log_p2p_address;
   uint32_t                connection_id;
   fc::sha256              conn_node_id;
   std::string             short_conn_node_id;
   std::string             log_remote_endpoint_ip;
   std::string             log_remote_endpoint_port;
   std::string             local_endpoint_ip;
   std::string             local_endpoint_port;
};

class connection : public std::enable_shared_from_this<connection> {
   using tcp_socket = boost::asio::ip::tcp::socket;
   using tcp_resolver = boost::asio::ip::tcp::resolver;
   using nanoseconds = std::chrono::nanoseconds;
   using milliseconds = std::chrono::milliseconds;
public:
   using ptr = std::shared_ptr<connection>;
   using wptr = std::weak_ptr<connection>;

   explicit connection( const std::string& endpoint );
   connection();

   ~connection() = default;

   static fc::logger& get_logger();
   static const std::string& peer_log_format();

   static const uint32_t block_interval_ns = std::chrono::duration_cast<nanoseconds>(milliseconds(chain::config::block_interval_ms)).count();

   bool start_session();

   bool socket_is_open() const { return socket_open.load(); } // thread safe, atomic
   const std::string& peer_address() const { return peer_addr; } // thread safe, const

   void set_connection_type( const std::string& peer_addr );
   bool is_transactions_only_connection()const { return connection_type == transactions_only; }
   bool is_blocks_only_connection()const { return connection_type == blocks_only; }
   void set_heartbeat_timeout(std::chrono::milliseconds msec) {
      std::chrono::system_clock::duration dur = msec;
      hb_timeout = dur.count();
   }

private:
   static const std::string unknown;

   void update_endpoints();
   void update_logger_connection_info();

   std::optional<peer_sync_state> peer_requested;  // this peer is requesting info from us

   std::atomic<bool>                         socket_open{false};

   const std::string            peer_addr;
   enum connection_types : char {
      both,
      transactions_only,
      blocks_only
   };

   std::atomic<connection_types>             connection_type{both};

public:
   boost::asio::io_context::strand           strand;
   std::shared_ptr<tcp_socket>               socket; // only accessed through strand after construction

   fc::message_buffer<1024*1024>    pending_message_buffer;
   std::atomic<std::size_t>         outstanding_read_bytes{0}; // accessed only from strand threads

   queued_buffer           buffer_queue;

   fc::sha256              conn_node_id;
   std::string             short_conn_node_id;
   std::string             log_p2p_address;
   std::string             log_remote_endpoint_ip;
   std::string             log_remote_endpoint_port;
   std::string             local_endpoint_ip;
   std::string             local_endpoint_port;

   std::atomic<uint32_t>   trx_in_progress_size{0};
   const uint32_t          connection_id;
   int16_t                 sent_handshake_count = 0;
   std::atomic<bool>       connecting{true};
   std::atomic<bool>       syncing{false};

   peer_conn_info ci;

   std::atomic<uint16_t>   protocol_version = 0;
   block_status_monitor    block_status_monitor_;
   std::atomic<uint16_t>   consecutive_immediate_connection_close = 0;

   std::mutex                            response_expected_timer_mtx;
   boost::asio::steady_timer             response_expected_timer;

   std::atomic<go_away_reason>           no_retry{no_reason};

   mutable std::mutex               conn_mtx; //< mtx for last_req .. remote_endpoint_ip
   std::optional<request_message>   last_req;
   handshake_message                last_handshake_recv;
   handshake_message                last_handshake_sent;

   const std::chrono::milliseconds handshake_backoff_floor;
   const std::chrono::milliseconds handshake_backoff_cap;

   std::chrono::time_point<std::chrono::steady_clock> last_handshake_time;
   std::chrono::milliseconds                          last_handshake_backoff = handshake_backoff_floor;

   chain::block_id_type             fork_head;
   uint32_t                         fork_head_num{0};
   fc::time_point                   last_close;
   std::string                      remote_endpoint_ip;

   connection_status get_status()const;

   /** \name Peer Timestamps
    *  Time message handling
    *  @{
    */
   // Members set from network data
   tstamp                         org{0};          //!< originate timestamp
   tstamp                         rec{0};          //!< receive timestamp
   tstamp                         dst{0};          //!< destination timestamp
   tstamp                         xmt{0};          //!< transmit timestamp
   /** @} */
   // timestamp for the lastest message
   tstamp                         latest_msg_time{0};
   tstamp                         latest_blk_time{0};
   tstamp                         hb_timeout{std::chrono::milliseconds{def_keepalive_interval}.count()};

   bool connected() const;
   bool current() const;

   /// @param reconnect true if we should try and reconnect immediately after close
   /// @param shutdown true only if plugin is shutting down
   void close( bool reconnect = true, bool shutdown = false );

   inline const boost::asio::io_context::strand& get_strand() const {
      return strand;
   }
private:
   static void _close( const std::shared_ptr<connection>& self, bool reconnect, bool shutdown ); // for easy capture

   bool process_next_block_message(uint32_t message_length);
   bool process_next_trx_message(uint32_t message_length);

   void process_handshake(const handshake_message& msg);
   void process_notice(const notice_message& msg);
   void send_none_request();
   void verify_catchup(uint32_t num, const chain::block_id_type& id);
   void rejected_block(uint32_t blk_num);
   void sync_recv_block( const chain::block_id_type& blk_id, uint32_t blk_num, bool blk_applied );
   void backoff_handshake();
   bool populate_handshake( handshake_message& hello );

public:
   bool resolve_and_connect();
   void connect( const std::shared_ptr<tcp_resolver>& resolver, tcp_resolver::results_type endpoints );
   void start_read_message();

   /** \brief Process the next message from the pending message buffer
    *
    * Process the next message from the pending_message_buffer.
    * message_length is the already determined length of the data
    * part of the message that will handle the message.
    * Returns true is successful. Returns false if an error was
    * encountered unpacking or processing the message.
    */
   bool process_next_message(uint32_t message_length);

   void send_handshake();

   /** \name Peer Timestamps
    *  Time message handling
    */
   /**  \brief Check heartbeat time and send Time_message
    */
   void check_heartbeat( tstamp current_time );
   /**  \brief Populate and queue time_message
    */
   void send_time();
   /** \brief Populate and queue time_message immediately using incoming time_message
    */
   void send_time(const time_message& msg);
   /** \brief Read system time and convert to a 64 bit integer.
    *
    * There are only two calls on this routine in the program.  One
    * when a packet arrives from the network and the other when a
    * packet is placed on the send queue.  Calls the kernel time of
    * day routine and converts to a (at least) 64 bit integer.
    */
   static tstamp get_time() {
      return std::chrono::system_clock::now().time_since_epoch().count();
   }
   /** @} */

   void blk_send_branch( const chain::block_id_type& msg_head_id );
   void blk_send_branch_impl( uint32_t msg_head_num, uint32_t lib_num, uint32_t head_num );
   void blk_send(const chain::block_id_type& blkid);
   void stop_send();

   void enqueue( const net_message &msg );
   void enqueue_block( const chain::signed_block_ptr& sb, bool to_sync_queue = false);
   void enqueue_buffer( const std::shared_ptr<std::vector<char>>& send_buffer,
                        go_away_reason close_after_send,
                        bool to_sync_queue = false);
   void cancel_sync(go_away_reason);
   void flush_queues();
   bool enqueue_sync_block();
   void request_sync_blocks(uint32_t start, uint32_t end);

   void cancel_wait();
   void sync_wait();
   void fetch_wait();
   void sync_timeout(boost::system::error_code ec);
   void fetch_timeout(boost::system::error_code ec);

   void queue_write(const std::shared_ptr<std::vector<char>>& buff,
                     std::function<void(boost::system::error_code, std::size_t)> callback,
                     bool to_sync_queue = false);
   void do_queue_write();

   bool is_valid( const handshake_message& msg ) const;

   void handle_message( const handshake_message& msg );
   void handle_message( const chain_size_message& msg );
   void handle_message( const go_away_message& msg );
   /** \name Peer Timestamps
    *  Time message handling
    *  @{
    */
   /** \brief Process time_message
    *
    * Calculate offset, delay and dispersion.  Note carefully the
    * implied processing.  The first-order difference is done
    * directly in 64-bit arithmetic, then the result is converted
    * to floating double.  All further processing is in
    * floating-double arithmetic with rounding done by the hardware.
    * This is necessary in order to avoid overflow and preserve precision.
    */
   void handle_message( const time_message& msg );
   /** @} */
   void handle_message( const notice_message& msg );
   void handle_message( const request_message& msg );
   void handle_message( const sync_request_message& msg );
   void handle_message( const chain::signed_block& msg ) = delete; // signed_block_ptr overload used instead
   void handle_message( const chain::block_id_type& id, chain::signed_block_ptr msg );
   void handle_message( const chain::packed_transaction& msg ) = delete; // packed_transaction_ptr overload used instead
   void handle_message( chain::packed_transaction_ptr msg );

   void process_signed_block( const chain::block_id_type& id, chain::signed_block_ptr msg );

   fc::variant_object get_logger_variant() const {
      fc::mutable_variant_object mvo;
      mvo( "_name", log_p2p_address)
         ( "_cid", connection_id )
         ( "_id", conn_node_id )
         ( "_sid", short_conn_node_id )
         ( "_ip", log_remote_endpoint_ip )
         ( "_port", log_remote_endpoint_port )
         ( "_lip", local_endpoint_ip )
         ( "_lport", local_endpoint_port );
      return mvo;
   }

   inline const peer_conn_info& get_ci() const {
      return ci;
   }

   template<typename _Fn>
   inline void post(_Fn f) {
      strand.post(f);
   }

   inline std::unique_lock<std::mutex> locked_connection_mutex() const {
      return std::unique_lock<std::mutex>(conn_mtx);
   }

   inline uint32_t get_fork_head_num() const {
      return fork_head_num;
   }

   inline const chain::block_id_type& get_fork_head() const {
      return fork_head;
   }

   inline uint32_t get_id() const {
      return connection_id;
   }

   inline void reset_fork_head() {
      fork_head_num = 0;
      fork_head = {};
   }

   inline const handshake_message& get_last_handshake() const {
      return last_handshake_recv;
   }
};

template <typename Strand>
void verify_strand_in_this_thread(const Strand& strand, const char* func, int line);

// called from connection strand
struct msg_handler : public fc::visitor<void> {
   connection::ptr c;
   explicit msg_handler( const connection::ptr& conn) : c(conn) {}

   static fc::logger& get_logger();
   static const std::string& peer_log_format();

   template<typename T>
   void operator()( const T& ) const;
   void operator()( const handshake_message& msg ) const;
   void operator()( const chain_size_message& msg ) const;
   void operator()( const go_away_message& msg ) const;
   void operator()( const time_message& msg ) const;
   void operator()( const notice_message& msg ) const;
   void operator()( const request_message& msg ) const;
   void operator()( const sync_request_message& msg ) const;
};

}} // eosio::p2p

FC_REFLECT( eosio::p2p::connection_status, (peer)(connecting)(syncing)(last_handshake) )

/* A simple server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <math.h>
#include <sys/ioctl.h>
#include <iostream>
#include <thread>
#include <memory>
#include <set>
#include <map>
#include <vector>

static int mode = 3;
static int next_session_id = 0;

static double x_sec = 0, y_sec = 0;
static long long bw_out = 0, bw_in = 0;
static double lat_out = 0, lat_in = 0, lat_delta = 0;
static int terminate_signal = false;
static double accept_rate = 1.0;
static double drop_rate = 0.9;

struct listening_session {
   int listen_port = 0;
   std::string dest_ip;
   int dest_port = 0;
   int listening_fd = 0;
   struct sockaddr_in out_addr;
};

std::vector<listening_session>  listening_list;

bool parse_param(int argc, char **argv) {
   if (argc < 2) {
      printf("usage:%s [options...]\n", argv[0]);
      printf("Options: \n"
             "--mode=         0 - No disconnect\n"
             "                1 - Disconnect incoming side\n"
             "                2 - Disconnect outgoing side\n"
             "                3 - (default) Disconnect both sides\n"
             "--relay=listening_port:dest_ip:dest_port\n"
             "                        - all incoming connects to listening_port will be forwared to dest_ip:dest_port\n"
             "                        - repeat this to specify multiple destinations\n"
             "--disconnect-min=X\n"
             "--disconnect-max=Y\n"
             "                        - random disconnect will trigger between X and Y second, can have floating point values, unset = no disconnect\n"
             "\n"
             "--bandwidth-out=VAL     - forward traffic bandwitdh (bytes per second)\n"
             "--bandwidth-in=VAL      - backward traffic bandwitdh (bytes per second)\n"
             "--latency-out=VAL       - forward traffic latency in seconds, can have floating point values\n"
             "--latency-in=VAL        - backward traffic latency in seconds, can have floating point values\n"
             "--latency-delta=VAL     - increase latency by VAL per sec after the start of each session, default = 0.0\n"
             "--accept-rate=VAL       - probably of accepting an new connection, default = 1.0\n"
             "--drop-rate=VAL         - probably of dropping existing connection between X & Y sec, default = 0.9, take effect only if --disconnect-max is set\n");
      exit(1);
   }

   int p = 1;
   const char *param;
   while (p < argc) {
      bool unknown_param = true;
      param = "--accept-rate=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &accept_rate); unknown_param = false;
      }
      param = "--drop-rate=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &drop_rate); unknown_param = false;
      }
      param = "--relay=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         char *value = argv[p] + strlen(param);
         char *p1 = value;
         while (*p1 && *p1 != ':') p1++;
         if (!*p1) {
            std::cerr << "invalid parameter " << argv[p] << std::endl; return false;
         }
         char *p2 = p1 + 1;
         while (*p2 && *p2 != ':') p2++;
         if (!*p2) {
            std::cerr << "invalid parameter " << argv[p] << std::endl; return false;
         }
         listening_session se;
         sscanf(value, "%d", &se.listen_port);
         se.dest_ip = std::string(p1 + 1, p2 - (p1 + 1));
         sscanf(p2 + 1, "%d", &se.dest_port);
         listening_list.push_back(se);
         unknown_param = false;
      }
      param = "--mode=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%d", &mode); unknown_param = false;
      }
      param = "--disconnect-min=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &x_sec); unknown_param = false;
      }
      param = "--disconnect-max=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &y_sec); unknown_param = false;
      }
      param = "--bandwidth-out=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lld", &bw_out); unknown_param = false;
      }
      param = "--bandwidth-in=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lld", &bw_in); unknown_param = false;
      }
      param = "--latency-out=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &lat_out); unknown_param = false;
      }
      param = "--latency-in=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &lat_in); unknown_param = false;
      }
      param = "--latency-delta=";
      if (memcmp(argv[p], param, strlen(param)) == 0) {
         sscanf(argv[p] + strlen(param), "%lf", &lat_delta); unknown_param = false;
      }
      if (unknown_param) {
         std::cerr << "invalid unknown pararmeter " << argv[p] << std::endl; return false;
      }
      p++;
   }
   if (listening_list.size() == 0) {
      std::cerr << "please specify at least one relay parameter\n"; return false;
   }
   if (y_sec < x_sec) y_sec = x_sec;
   return true;
}

struct session_t {
   int id = 0;
   long long start_time_us = 0;
   long long disconnect_time_us = 9e18;
   int incoming_sockfd = 0;
   int outgoing_sockfd = 0;
   int shouldstop = 0;
   bool incoming_thread_stopped = false;
   bool outgoing_thread_stopped = false;
   bool session_ended = false;
   bool incoming_closed = false;
   bool outgoing_closed = false;
   long long r0 = 0, s0 = 0, r1 = 0, s1 = 0; // byte counts
};

long long gettimeus() {
   static long long _init_time = 0;
   long long t;
   struct timespec spec;
   clock_gettime(CLOCK_MONOTONIC, &spec); 
   t = spec.tv_sec * 1000000ll + spec.tv_nsec / 1000ll;
   if (!_init_time) {
      _init_time = t;
      return 0;
   }
   return t - _init_time;
}

void worker(std::shared_ptr<session_t> session_ptr, bool is_outgoing);

void session_start(std::shared_ptr<session_t> session_ptr) {

   std::thread th0( [session_ptr]() { worker(session_ptr, true); });
   std::thread th1( [session_ptr]() { worker(session_ptr, false); });

   long long t0 = gettimeus();
   long long r0 = -1, s0 = -1, r1 = -1, s1 = -1;
   while (session_ptr->incoming_thread_stopped == false && session_ptr->outgoing_thread_stopped == false) {
      usleep(1000000);
      long long t = gettimeus();
      if (r0 != session_ptr->r0 || r1 != session_ptr->r1 || s0 != session_ptr->s0 || s1 != session_ptr->s1) {
         r0 = session_ptr->r0;
         r1 = session_ptr->r1;
         s0 = session_ptr->s0;
         s1 = session_ptr->s1;
         printf("session %d: %lldus: outgoing: rbytes %lld, sbytes %lld, incoming: rbytes %lld, sbytes %lld\n", 
            session_ptr->id, t - t0, r0, s0, r1, s1);
      }
   }
   if (!terminate_signal) usleep(5000000);
   session_ptr->shouldstop = true;
   th0.join();
   th1.join();
   if (session_ptr->incoming_closed == false) {
      close(session_ptr->incoming_sockfd);
   }
   if (session_ptr->outgoing_closed == false) {
      close(session_ptr->outgoing_sockfd);
   }
   session_ptr->session_ended = true;
   printf("session %d ended\n", session_ptr->id);
}

int select_read(int fd) {
   struct timeval tv;
   tv.tv_sec = 0;
   tv.tv_usec = 1000;
   fd_set rfds;
   FD_ZERO(&rfds);
   FD_SET(fd, &rfds);
   if (select(FD_SETSIZE, &rfds, NULL, NULL, &tv) > 0 && FD_ISSET(fd, &rfds)) {
      int navail = 0;
      int retval = ioctl(fd, FIONREAD, &navail);
      return navail; // has bytes to read or disconnected
   }
   return -1; // EAGAIN;
}

void worker(std::shared_ptr<session_t> session_ptr, bool is_outgoing) {

   int from_fd, to_fd;
   long long *recv_count, *send_count;
   if (is_outgoing) {
      from_fd = session_ptr->incoming_sockfd;
      to_fd = session_ptr->outgoing_sockfd;
      recv_count = &(session_ptr->r0);
      send_count = &(session_ptr->s0);
   } else {
      from_fd = session_ptr->outgoing_sockfd;
      to_fd = session_ptr->incoming_sockfd;
      recv_count = &(session_ptr->r1);
      send_count = &(session_ptr->s1);
   }
   int bandwidth = is_outgoing ? bw_out : bw_in;
   if (bandwidth == 0) bandwidth = INT_MAX;
   double latency = is_outgoing ? lat_out : lat_in;

   if (latency > 1.0) {
      double new_bw = latency * (double)bandwidth;
      if (new_bw >= INT_MAX) bandwidth = INT_MAX;
      else bandwidth = new_bw; // compensate bandwidth for sleeping
   }

   long long t0 = gettimeus();
   long long t00 = t0;
   std::vector<char> buffer;
   buffer.resize(1024 * 1024);
   size_t buf_size = buffer.size() - 1;
   char *buf = &(buffer[0]);
   int used_bandwidth = 0;
   bool should_active_disconnect = (mode == 3 ||
                  (mode == 2 && is_outgoing) ||
                  (mode == 1 && !is_outgoing));

   if (!should_active_disconnect || session_ptr->disconnect_time_us == INT64_MAX) {
      printf("session %d %s thread started, bandwidth = %d, latency = %.6lf\n", 
             session_ptr->id, (is_outgoing ? "outgoing":"incoming"), bandwidth, latency);
   } else {
      printf("session %d %s thread started, bandwidth = %d, latency = %.6lf, prosposed disconnect at %lldus later\n",
             session_ptr->id, (is_outgoing ? "outgoing":"incoming"), bandwidth, latency, session_ptr->disconnect_time_us - t0);
   }

   while (!terminate_signal && !session_ptr->shouldstop && !session_ptr->incoming_thread_stopped && !session_ptr->outgoing_thread_stopped) {      
      int navail = select_read(from_fd);

      long long t = gettimeus();
      if (t >= session_ptr->disconnect_time_us && should_active_disconnect) {
         goto _active_disconnect;
      }
      if (t >= t0 + 1000000) {
         t0 = t;
         used_bandwidth = 0;
      }

      if (navail == 0) goto _disconnected;

      if (navail < 0) { // AGAIN
         usleep(1000);
         continue;
      }

      int remain_bandwidth = bandwidth - used_bandwidth;
      if (remain_bandwidth <= 0) {
         usleep(1000); 
         continue;
      }

      if (navail > remain_bandwidth) navail = remain_bandwidth;
      if (navail > buf_size) navail = buf_size;

      if (navail > 1 && rand() < RAND_MAX / 4) {
         navail = 1 + rand() % navail; // emulate TCP packet segmentation by reading less bytes at random
      }

      int nr = read(from_fd, buf, navail);
      if (nr > 0) {
         used_bandwidth += nr;
         *recv_count += nr;
         double current_latency = latency + (gettimeus() - t00) * lat_delta / 1000000;
         if (current_latency) {
            long long sleep_remain = current_latency * 1000000;
            while (sleep_remain > 0) {
               usleep(sleep_remain > 1000 ? 1000 : sleep_remain);
               sleep_remain -= 1000;
               t = gettimeus();
               if (terminate_signal || (gettimeus() >= session_ptr->disconnect_time_us && should_active_disconnect)) {
                  goto _active_disconnect;
               }
            }
         }
         int r2 = 0;
         while (!terminate_signal && r2 < nr) {
            int r3 = write(to_fd, &(buf[r2]), nr - r2);
            if (r3 > 0) {
               r2 += r3;
               *send_count += r3;
            }
            else if (r3 == 0) goto _disconnected;
            else {
               if (errno == EPIPE) goto _disconnected;
            }
            if (r2 < nr) {
               usleep(100); // EAGAIN
               if (gettimeus() >= session_ptr->disconnect_time_us && should_active_disconnect) {
                  goto _active_disconnect;
               }
            }
         }
         if (terminate_signal) break;
      }
      else if (nr == 0) goto _disconnected;
      else {
         usleep(100); // EAGAIN
      }
   }

_active_disconnect:
   if (should_active_disconnect) {
      close(to_fd);
      if (to_fd == session_ptr->incoming_sockfd) session_ptr->incoming_closed = true;
      if (to_fd == session_ptr->outgoing_sockfd) session_ptr->outgoing_closed = true;
      printf("session %d: ready to disconnect %s side\n", session_ptr->id, (is_outgoing ? "outgoing":"incoming"));
   }

_disconnected:
   if (is_outgoing) session_ptr->outgoing_thread_stopped = true;
   else session_ptr->incoming_thread_stopped = true;
   printf("session %d: %s worker thread stopped\n", session_ptr->id, (is_outgoing ? "outgoing":"incoming"));
}

void sig_handler(int sig) {
   terminate_signal = true;
}

void sig_handler_broken_pipe(int signum) {
   printf("Got broken pipe signal\n");
}

int main(int argc, char *argv[])
{
   socklen_t clilen;
   struct sockaddr_in incoming_addr;
   
   signal(SIGINT, sig_handler);
   signal(SIGPIPE, sig_handler_broken_pipe);

   if (!parse_param(argc, argv)) {
      exit(1);
   }

   for (int i = 0; i < listening_list.size() && !terminate_signal; i++) {
      listening_list[i].listening_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (listening_list[i].listening_fd <= 0) {
         fprintf(stderr, "failed to create socket handles\n");
         exit(2);
      }
      std::cout << "start to listen on port " << listening_list[i].listen_port << " for " << listening_list[i].dest_ip << ":" << listening_list[i].dest_port << "...";

      struct sockaddr_in serv_addr;
      memset((char *)&(serv_addr), 0, sizeof(serv_addr));
      serv_addr.sin_family = AF_INET;
      serv_addr.sin_addr.s_addr = INADDR_ANY;
      serv_addr.sin_port = htons(listening_list[i].listen_port);

      memset((char *)&(listening_list[i].out_addr), 0, sizeof(listening_list[i].out_addr));
      listening_list[i].out_addr.sin_family = AF_INET;
      listening_list[i].out_addr.sin_addr.s_addr = inet_addr(listening_list[i].dest_ip.c_str());
      listening_list[i].out_addr.sin_port = htons(listening_list[i].dest_port);

      while (bind(listening_list[i].listening_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
         fprintf(stderr, "\nfailed to bind listening port %d, wait ...\n", listening_list[i].listen_port);
         if (terminate_signal) break;
         usleep(2000000);
      }

      if (terminate_signal) break;
      int r;
      do {
         r = listen(listening_list[i].listening_fd, 10);
         if (r) {
            fprintf(stderr, "\nfailed to listen on port %d with error %d, wait ...\n", listening_list[i].listen_port, r);
            usleep(2000000);
         }
         if (terminate_signal) break;
      } while (r);
      
      if (terminate_signal) break;
      std::cout << "OK\n";
   }

   int state = 1; // 1 - random reject, 0 - reject new connections;
   long long next_disconnect_time = INT64_MAX;
   long long next_accept_time = INT64_MAX;
   if (x_sec && y_sec) {
      next_disconnect_time = gettimeus() + (x_sec + rand() / (double)RAND_MAX * (y_sec - x_sec)) * 1000000;
      next_accept_time = next_disconnect_time + (x_sec + 1.0) * 1000000;
   }
   std::cout << gettimeus() << "us: accepting new connections at " 
                      << accept_rate 
                      << " probability";
   if (next_disconnect_time != INT64_MAX) {
      std::cout <<  ", future disconnect time set to " 
               << (next_disconnect_time - gettimeus()) << "us later with "
               << drop_rate
               << " probability";
   }
   std::cout << std::endl;
   
   std::map<std::thread *, std::shared_ptr<session_t> > live_sessions;

   while (!terminate_signal) {

      // house keeping
      std::vector<std::thread *> to_delete;
      for (std::map<std::thread *, std::shared_ptr<session_t> >::iterator itr = live_sessions.begin(); itr != live_sessions.end(); ++itr) {
         if (itr->second->session_ended) {
            to_delete.push_back(itr->first);
         }
      }
      for (int i = 0; i < to_delete.size(); i++) {
         to_delete[i]->join();
         live_sessions.erase(to_delete[i]);
         delete to_delete[i];
      }

      if (state == 1) {
         if (gettimeus() >= next_disconnect_time) {
            std::cout << gettimeus() << "us: REJECT all new connections until " << next_accept_time << "us\n";
            state = 0; 
         }
      } else if (state == 0) {
         if (gettimeus() >= next_accept_time) {
            state = 1; // start to accept again;
            next_disconnect_time = gettimeus() + (x_sec + rand() / (double)RAND_MAX * (y_sec - x_sec)) * 1000000;
            next_accept_time = next_disconnect_time + (x_sec + 1.0) * 1000000;

            long long t = gettimeus();
            std::cout << t << "us: accepting new connections at " 
                      << accept_rate 
                      << " probability, future disconnect time set to " 
                      << (next_disconnect_time - t) << "us later with "
                      << drop_rate
                      << " probability\n";

            // update disconnect time randomly for exisitng sessions.
            for (std::map<std::thread *, std::shared_ptr<session_t> >::iterator itr = live_sessions.begin(); itr != live_sessions.end(); ++itr) {
               if (mode && rand() > (RAND_MAX / 3) && itr->second->disconnect_time_us > next_disconnect_time) {
                  itr->second->disconnect_time_us = next_disconnect_time;
               }
            }
         }
      }

      int addrlen = sizeof(struct sockaddr_in);
      struct timeval tv;
      tv.tv_sec = 0;
      tv.tv_usec = 1000;
      fd_set rfds;
      FD_ZERO(&rfds);
      for (int i = 0; i < listening_list.size(); i++) {
         FD_SET(listening_list[i].listening_fd, &rfds);
      }
      int active = select(FD_SETSIZE, &rfds, NULL, NULL, &tv);
      
      if (active >= 0) {
         for (int i = 0; i < listening_list.size(); i++) {
            if (FD_ISSET(listening_list[i].listening_fd, &rfds)) {
               int incoming_sockfd = accept(listening_list[i].listening_fd, (struct sockaddr *)&incoming_addr, (socklen_t*)&addrlen);
               if (incoming_sockfd > 0) {
                  if (state == 0 || (rand() >= (RAND_MAX * accept_rate))) {
                     close(incoming_sockfd); 
                     if (state != 0) {
                        printf("randomly reject incoming connection from %d\n", listening_list[i].listen_port);
                     }
                  } else {
                     printf("accepted from %d, ready to connect %s:%d...", listening_list[i].listen_port, listening_list[i].dest_ip.c_str(), listening_list[i].dest_port);
                     int outgoing_sockfd = socket(AF_INET, SOCK_STREAM, 0);
                     if (outgoing_sockfd <= 0 || connect(outgoing_sockfd, (struct sockaddr *)&listening_list[i].out_addr, sizeof(listening_list[i].out_addr)) < 0) {
                        printf("failed to connect %s:%d\n", listening_list[i].dest_ip.c_str(), listening_list[i].dest_port);
                        close(incoming_sockfd);
                     } else {
                        printf("connected!\n");
                        std::shared_ptr<session_t> session_ptr(new session_t());
                        session_ptr->disconnect_time_us = (mode && rand() < (RAND_MAX * drop_rate) ? next_disconnect_time : INT64_MAX);
                        session_ptr->incoming_sockfd = incoming_sockfd;
                        session_ptr->outgoing_sockfd = outgoing_sockfd;
                        session_ptr->id = next_session_id++;
                        
                        std::thread *thread = new std::thread( [session_ptr]() { session_start(session_ptr); } );
                        live_sessions[thread] = session_ptr;
                     }
                  }
               }
            }
         }
      }

   }

   terminate_signal = true;
   std::cout << gettimeus() << "us: terminating: joining all working threads..." << std::endl;
   for (std::map<std::thread *, std::shared_ptr<session_t> >::iterator itr = live_sessions.begin(); itr != live_sessions.end(); ++itr) {
      itr->first->join();
      delete itr->first;
   }
   std::cout << gettimeus() << "us: terminating: closing all listening sockets..." << std::endl;
   for (int i = 0; i < listening_list.size(); i++) {
      close(listening_list[i].listening_fd);
   }

   return 0;
}



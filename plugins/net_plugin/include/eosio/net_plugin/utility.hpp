#pragma once

#include <fc/log/logger.hpp>

#define GET_PEER_CONNECTION_ARGS(args)   \
    ( "_name", args.log_p2p_address) \
    ( "_cid", args.connection_id ) \
    ( "_id", args.conn_node_id ) \
    ( "_sid", args.short_conn_node_id ) \
    ( "_ip", args.log_remote_endpoint_ip ) \
    ( "_port", args.log_remote_endpoint_port ) \
    ( "_lip", args.local_endpoint_ip ) \
    ( "_lport", args.local_endpoint_port )

// peer_[x]log must be called from thread in connection strand
#define peer_dlog_1( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( get_logger().is_enabled( fc::log_level::debug ) ) { \
      verify_strand_in_this_thread( PEER->get_strand(), __func__, __LINE__ ); \
      try{ \
         SPDLOG_LOGGER_DEBUG(get_logger().get_agent_logger(), FC_FMT( peer_log_format(), GET_PEER_CONNECTION_ARGS(PEER->get_ci()) ) ); \
         SPDLOG_LOGGER_DEBUG(get_logger().get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ ) ); \
      } FC_LOG_CATCH \
   } \
  FC_MULTILINE_MACRO_END

// this is to deal with -Wgnu-zero-variadic-macro-arguments
#define peer_dlog_0(PEER, FORMAT) peer_dlog_1(PEER, FORMAT,)
#define peer_dlog(...) SWITCH_MACRO1(peer_dlog_0, peer_dlog_1, 2, __VA_ARGS__)

#define peer_ilog_1( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( get_logger().is_enabled( fc::log_level::info ) ) { \
      verify_strand_in_this_thread( PEER->get_strand(), __func__, __LINE__ ); \
      try{ \
         SPDLOG_LOGGER_INFO(get_logger().get_agent_logger(), FC_FMT( peer_log_format(), GET_PEER_CONNECTION_ARGS(PEER->get_ci()) ) ); \
         SPDLOG_LOGGER_INFO(get_logger().get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ ) ); \
      } FC_LOG_CATCH \
   } \
  FC_MULTILINE_MACRO_END

#define peer_ilog_0(PEER, FORMAT) peer_ilog_1(PEER, FORMAT,)
#define peer_ilog(...) SWITCH_MACRO1(peer_ilog_0, peer_ilog_1, 2, __VA_ARGS__)

#define peer_wlog_1( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( get_logger().is_enabled( fc::log_level::warn ) ) { \
      verify_strand_in_this_thread( PEER->get_strand(), __func__, __LINE__ ); \
      try{ \
         SPDLOG_LOGGER_WARN(get_logger().get_agent_logger(), FC_FMT( peer_log_format(), GET_PEER_CONNECTION_ARGS(PEER->get_ci()) ) ); \
         SPDLOG_LOGGER_WARN(get_logger().get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ ) ); \
      } FC_LOG_CATCH \
   } \
  FC_MULTILINE_MACRO_END

#define peer_wlog_0(PEER, FORMAT) peer_wlog_1(PEER, FORMAT,)
#define peer_wlog(...) SWITCH_MACRO1(peer_wlog_0, peer_wlog_1, 2, __VA_ARGS__)

#define peer_elog_1( PEER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( get_logger().is_enabled( fc::log_level::error ) ) { \
      verify_strand_in_this_thread( PEER->get_strand(), __func__, __LINE__ ); \
      try{ \
         SPDLOG_LOGGER_ERROR(get_logger().get_agent_logger(), FC_FMT( peer_log_format(), GET_PEER_CONNECTION_ARGS(PEER->get_ci()) ) ); \
         SPDLOG_LOGGER_ERROR(get_logger().get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ ) ); \
      } FC_LOG_CATCH \
   } \
  FC_MULTILINE_MACRO_END

#define peer_elog_0(PEER, FORMAT) peer_elog_1(PEER, FORMAT,)
#define peer_elog(...) SWITCH_MACRO1(peer_elog_0, peer_elog_1, 2, __VA_ARGS__)

template <typename F>
struct return_type_impl;

template <typename R, typename... Args>
struct return_type_impl<R(Args...)> { using type = R; };

template <typename R, typename... Args>
struct return_type_impl<R(Args..., ...)> { using type = R; };

template <typename R, typename... Args>
struct return_type_impl<R(*)(Args...)> { using type = R; };

template <typename R, typename... Args>
struct return_type_impl<R(*)(Args..., ...)> { using type = R; };

template <typename R, typename... Args>
struct return_type_impl<R(&)(Args...)> { using type = R; };

template <typename R, typename... Args>
struct return_type_impl<R(&)(Args..., ...)> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...)> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...)> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) &> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) &> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) &&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) &&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const&&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const&&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) volatile> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) volatile> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) volatile&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) volatile&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) volatile&&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) volatile&&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const volatile> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const volatile> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const volatile&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const volatile&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args...) const volatile&&> { using type = R; };

template <typename R, typename C, typename... Args>
struct return_type_impl<R(C::*)(Args..., ...) const volatile&&> { using type = R; };

template <typename T, typename = void>
struct return_type
    : return_type_impl<T> {};

template <typename T>
struct return_type<T, decltype(void(&T::operator()))>
    : return_type_impl<decltype(&T::operator())> {};

template <typename T>
using return_type_t = typename return_type<T>::type;

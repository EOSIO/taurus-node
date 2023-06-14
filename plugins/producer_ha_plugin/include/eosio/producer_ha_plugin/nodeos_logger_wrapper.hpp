#pragma once

#include <libnuraft/nuraft.hxx>

#include <fc/log/logger.hpp>

namespace eosio {

class logger_wrapper : public nuraft::logger {
public:
   explicit logger_wrapper(int log_level = 3) : level(log_level) {};
   ~logger_wrapper() = default;

   void put_details(int log_level,
                     const char* source_file,
                     const char* func_name,
                     size_t line_number,
                     const std::string& msg) override final
   {
      if ( log_level > this->level) {
         return;
      }

      fc::log_level::values fclog_level;
      spdlog::level::level_enum spdlog_level;

      if ( log_level <= 2) {
         fclog_level = fc::log_level::values::error;
         spdlog_level = spdlog::level::err;
      } else if ( log_level == 3) {
         fclog_level = fc::log_level::values::warn;
         spdlog_level = spdlog::level::warn;
      } else if ( log_level == 4) {
         fclog_level = fc::log_level::values::info;
         spdlog_level = spdlog::level::info;
      } else if ( log_level == 5) {
         fclog_level = fc::log_level::values::debug;
         spdlog_level = spdlog::level::debug;
      } else {
         fclog_level = fc::log_level::values::all;
         spdlog_level = spdlog::level::trace;
      }

      auto fc_logger = fc::logger::get(DEFAULT_LOGGER);

      if ( !fc_logger.is_enabled( fclog_level ) ) {
         return;
      }

      fc_logger.get_agent_logger()->log( spdlog::source_loc(source_file, line_number, func_name), spdlog_level, msg );
   }

   void set_level(int l) override final {
      if (l < 0) l = 1;
      if (l > 6) l = 6;
      level = l;
   }

   int get_level() override final {
      return level;
   }

private:
   int level;
};

}


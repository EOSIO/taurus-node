#pragma once

/*
 * A temporary db for testing purpose. Used by the test cases.
 * db will be automatically cleaned up after the test_db object is out of scope.
 */

#include "nodeos_state_db.hpp"

#include <boost/filesystem.hpp>

class test_db_path {
public:
   boost::filesystem::path path;

   test_db_path() {
      path = boost::filesystem::temp_directory_path() / boost::filesystem::unique_path();
   }

   virtual ~test_db_path() {
      boost::filesystem::remove_all(path);
   }
};

class test_db {
public:
   test_db() {
      db = std::make_shared<eosio::nodeos_state_db>(db_path.path.c_str());
   }

   virtual ~test_db() {}

private:
   test_db_path db_path;

public:
   std::shared_ptr<eosio::nodeos_state_db> db;
};
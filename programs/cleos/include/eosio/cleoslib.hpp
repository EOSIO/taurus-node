#pragma once

#include <ostream>

// out, err will be std::out and std::err
int cleos_main(int argc, const char** argv);

// out, err will be those provided by the argument
int cleos_main(int argc, const char** argv, std::ostream& out, std::ostream& err);
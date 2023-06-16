#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

std::string get_short_name(const std::string &full_name) {
   int p = full_name.size();
   while (p && full_name[p-1] != '/') --p;

   if (p >= full_name.size() - 1) return std::string();
   return std::string(full_name.begin() + p, full_name.end());
}

FILE *open_size(const char *path, long long *fsize) {
   *fsize = -1;
   FILE *f = fopen(path, "rb");
   if (!f) {
      std::cout << "failed to open file " << path << " for reading" << std::endl;
      return 0;
   }
   fseek(f, 0l, SEEK_END);
   *fsize = ftell(f);
   fseek(f, 0l, SEEK_SET);
   return f;
}

bool copy_truncate(FILE *fp, const char *to, long long size) {
   std::cout << "backing up " << to << " ..." << std::endl;
   FILE *fout = fopen(to, "wb");
   if (!fout) {
      std::cout << "failed to open " << to << " for writing" << std::endl;
      return false;
   }
   std::vector<char> buf;
   buf.resize(16 *1048576); // 16M
   fseek(fp, 0, SEEK_SET);
   while (size) {
      long long ws = std::min(size, (long long)buf.size());
      if (fread(&(buf[0]), 1, ws, fp) != ws) {
         std::cout << "failed to copy data into " << to << std::endl;
         return false;
      }
      if (fwrite(&(buf[0]), 1, ws, fout) != ws) {
         std::cout << "failed to copy data into " << to << std::endl;
         return false;
      }
      size -= ws;
   }
   fclose(fout);
   return true;
}

int main(int argc, char **argv) {

   if (argc <= 3) {
      printf("usage: %s backup_path index_file log_file [index_file log_file]\n", argv[0]);
      return 1;
   }
   std::string dest_path = argv[1];
   std::vector<std::string> index_files;
   std::vector<std::string> log_files;
   std::vector<FILE *>      index_fps;
   std::vector<FILE *>      log_fps;
   std::vector<long long>   log_file_sizes;

   int arg_index = 2;
   while (arg_index < argc) {
      index_files.push_back(argv[arg_index++]);
      if (arg_index >= argc) {
         printf("invalid argument number\n");
         return 1;
      }
      log_files.push_back(argv[arg_index++]);
   }
   index_fps.resize(index_files.size());
   log_fps.resize(index_files.size());
   log_file_sizes.resize(index_files.size());

   if (dest_path.length() && dest_path[dest_path.length() - 1] != '/') {
      dest_path += '/';
   }

   long long backup_index = -1;
   for (int i = 0; i < log_files.size(); ++i) {
      if (get_short_name(log_files[i]).length() == 0) {
         printf("failed to parse the log file name %s\n", log_files[i].c_str());
         return 2;
      }
      if (get_short_name(index_files[i]).length() == 0) {
         printf("failed to parse the index file name %s\n", index_files[i].c_str());
         return 2;
      }

      long long index_file_size;
      FILE *index_fp = open_size(index_files[i].c_str(), &index_file_size);
      if (!index_fp) return 3;

      long long last_index = index_file_size / 8 - 1;
      if (backup_index < 0 || last_index < backup_index) {
         backup_index = last_index;
      }
      std::cout << "index file " << index_files[i] << " has " << (last_index + 1) << " indexes\n";
      index_fps[i] = index_fp;

      log_fps[i] = open_size(log_files[i].c_str(), &(log_file_sizes[i]));
      if (!log_fps[i]) return 4;
   }
   if (backup_index <= 1) {
      std::cout << "nothing to backup\n";
      return 4;
   }

   // read backup_size from index file
   for (int i = 0; i < index_fps.size(); ++i) {
      fseek(index_fps[i], backup_index * 8, SEEK_SET);
      long long backup_size = 0;
      if (fread(&backup_size, 8, 1, index_fps[i]) != 1) {
         std::cout << "failed to read from index file " << index_files[i] << "\n";
         return 5;
      }
      if (backup_size > log_file_sizes[i]) {
         std::cout << "backup size is more than log file size in file " << log_files[i] << "\n";
         return 6;
      }
      log_file_sizes[i] = backup_size;
   }

   // copy with truncation
   long long total_bytes = 0;
   for (int i = 0; i < log_file_sizes.size(); ++i) {
      std::stringstream ss, ss2;
      ss << dest_path << get_short_name(log_files[i]);
      if (!copy_truncate(log_fps[i], ss.str().c_str(), log_file_sizes[i])) return 7;
      total_bytes += log_file_sizes[i];

      ss2 << dest_path << get_short_name(index_files[i]);
      if (!copy_truncate(index_fps[i], ss2.str().c_str(), backup_index * 8)) return 8;
      total_bytes += backup_index * 8;
   }

   std::cout << "successfully backup all files of " << total_bytes << " bytes" << std::endl;
   return 0;
}



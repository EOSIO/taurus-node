#include <eosio/chain/snapshot.hpp>
#include <eosio/chain/exceptions.hpp>
#include <fc/scoped_exit.hpp>
#include <fc/io/json.hpp>
#include <rapidjson/filereadstream.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <rapidjson/error/en.h>

namespace eosio { namespace chain {

variant_snapshot_writer::variant_snapshot_writer(fc::mutable_variant_object& snapshot)
: snapshot(snapshot)
{
   snapshot.set("sections", fc::variants());
   snapshot.set("version", current_snapshot_version );
}

void variant_snapshot_writer::write_start_section( const std::string& section_name ) {
   current_rows.clear();
   current_section_name = section_name;
}

void variant_snapshot_writer::write_row( const detail::abstract_snapshot_row_writer& row_writer ) {
   current_rows.emplace_back(row_writer.to_variant());
}

void variant_snapshot_writer::write_end_section( ) {
   snapshot["sections"].get_array().emplace_back(fc::mutable_variant_object()("name", std::move(current_section_name))("rows", std::move(current_rows)));
}

void variant_snapshot_writer::finalize() {

}

variant_snapshot_reader::variant_snapshot_reader(const fc::variant& snapshot)
:snapshot(snapshot)
,cur_section(nullptr)
,cur_row(0)
{
}

void variant_snapshot_reader::validate() const {
   EOS_ASSERT(snapshot.is_object(), snapshot_validation_exception,
         "Variant snapshot is not an object");
   const fc::variant_object& o = snapshot.get_object();

   EOS_ASSERT(o.contains("version"), snapshot_validation_exception,
         "Variant snapshot has no version");

   const auto& version = o["version"];
   EOS_ASSERT(version.is_integer(), snapshot_validation_exception,
         "Variant snapshot version is not an integer");

   EOS_ASSERT(version.as_uint64() == (uint64_t)current_snapshot_version, snapshot_validation_exception,
         "Variant snapshot is an unsuppored version.  Expected : {expected}, Got: {actual}",
         ("expected", current_snapshot_version)("actual",o["version"].as_uint64()));

   EOS_ASSERT(o.contains("sections"), snapshot_validation_exception,
         "Variant snapshot has no sections");

   const auto& sections = o["sections"];
   EOS_ASSERT(sections.is_array(), snapshot_validation_exception, "Variant snapshot sections is not an array");

   const auto& section_array = sections.get_array();
   for( const auto& section: section_array ) {
      EOS_ASSERT(section.is_object(), snapshot_validation_exception, "Variant snapshot section is not an object");

      const auto& so = section.get_object();
      EOS_ASSERT(so.contains("name"), snapshot_validation_exception,
            "Variant snapshot section has no name");

      EOS_ASSERT(so["name"].is_string(), snapshot_validation_exception,
                 "Variant snapshot section name is not a string");

      EOS_ASSERT(so.contains("rows"), snapshot_validation_exception,
                 "Variant snapshot section has no rows");

      EOS_ASSERT(so["rows"].is_array(), snapshot_validation_exception,
                 "Variant snapshot section rows is not an array");
   }
}

bool variant_snapshot_reader::has_section( const string& section_name ) {
   const auto& sections = snapshot["sections"].get_array();
   for( const auto& section: sections ) {
      if (section["name"].as_string() == section_name) {
         return true;
      }
   }

   return false;
}

void variant_snapshot_reader::set_section( const string& section_name ) {
   const auto& sections = snapshot["sections"].get_array();
   for( const auto& section: sections ) {
      if (section["name"].as_string() == section_name) {
         cur_section = &section.get_object();
         return;
      }
   }

   EOS_THROW(snapshot_exception, "Variant snapshot has no section named {n}", ("n", section_name));
}

bool variant_snapshot_reader::read_row( detail::abstract_snapshot_row_reader& row_reader ) {
   const auto& rows = (*cur_section)["rows"].get_array();
   row_reader.provide(rows.at(cur_row++));
   return cur_row < rows.size();
}

bool variant_snapshot_reader::empty ( ) {
   const auto& rows = (*cur_section)["rows"].get_array();
   return rows.empty();
}

void variant_snapshot_reader::clear_section() {
   cur_section = nullptr;
   cur_row = 0;
}

void variant_snapshot_reader::return_to_header() {
   clear_section();
}

ostream_snapshot_writer::ostream_snapshot_writer(std::ostream& snapshot)
:snapshot(snapshot)
,header_pos(snapshot.tellp())
,section_pos(-1)
,row_count(0)
{
   // write magic number
   auto totem = magic_number;
   snapshot.write((char*)&totem, sizeof(totem));

   // write version
   auto version = current_snapshot_version;
   snapshot.write((char*)&version, sizeof(version));
}

void ostream_snapshot_writer::write_start_section( const std::string& section_name )
{
   EOS_ASSERT(section_pos == std::streampos(-1), snapshot_exception, "Attempting to write a new section without closing the previous section");
   section_pos = snapshot.tellp();
   row_count = 0;

   uint64_t placeholder = std::numeric_limits<uint64_t>::max();

   // write a placeholder for the section size
   snapshot.write((char*)&placeholder, sizeof(placeholder));

   // write placeholder for row count
   snapshot.write((char*)&placeholder, sizeof(placeholder));

   // write the section name (null terminated)
   snapshot.write(section_name.data(), section_name.size());
   snapshot.put(0);
}

void ostream_snapshot_writer::write_row( const detail::abstract_snapshot_row_writer& row_writer ) {
   auto restore = snapshot.tellp();
   try {
      row_writer.write(snapshot);
   } catch (...) {
      snapshot.seekp(restore);
      throw;
   }
   row_count++;
}

void ostream_snapshot_writer::write_end_section( ) {
   auto restore = snapshot.tellp();

   uint64_t section_size = restore - section_pos - sizeof(uint64_t);

   snapshot.seekp(section_pos);

   // write a the section size
   snapshot.write((char*)&section_size, sizeof(section_size));

   // write the row count
   snapshot.write((char*)&row_count, sizeof(row_count));

   snapshot.seekp(restore);

   section_pos = std::streampos(-1);
   row_count = 0;
}

void ostream_snapshot_writer::finalize() {
   uint64_t end_marker = std::numeric_limits<uint64_t>::max();

   // write a placeholder for the section size
   snapshot.write((char*)&end_marker, sizeof(end_marker));
}

ostream_json_snapshot_writer::ostream_json_snapshot_writer(std::ostream& snapshot)
      :snapshot(snapshot)
      ,row_count(0)
{
   snapshot << "{\n";
   // write magic number
   auto totem = magic_number;
   snapshot << "\"magic_number\":" << fc::json::to_string(totem, fc::time_point::maximum()) << "\n";

   // write version
   auto version = current_snapshot_version;
   snapshot << ",\"version\":" << fc::json::to_string(version, fc::time_point::maximum()) << "\n";
}

void ostream_json_snapshot_writer::write_start_section( const std::string& section_name )
{
   row_count = 0;
   snapshot.inner << "," << fc::json::to_string(section_name, fc::time_point::maximum()) << ":{\n\"rows\":[\n";
}

void ostream_json_snapshot_writer::write_row( const detail::abstract_snapshot_row_writer& row_writer ) {
   const auto yield = [&](size_t s) {};

   if(row_count != 0) snapshot.inner << ",";
   snapshot.inner << fc::json::to_string(row_writer.to_variant(), yield) << "\n";
   ++row_count;
}

void ostream_json_snapshot_writer::write_end_section( ) {
   snapshot.inner << "],\n\"num_rows\":" << row_count << "\n}\n";
   row_count = 0;
}

void ostream_json_snapshot_writer::finalize() {
   snapshot.inner << "}\n";
   snapshot.inner.flush();
}

json_snapshot_reader::json_snapshot_reader(const std::string& snapshot_path, bool validate_chain_id)
:num_rows(0)
,cur_row(0)
,assert_chain_id(validate_chain_id)
{
   FILE* fp = fopen(snapshot_path.c_str(), "r");
   EOS_ASSERT(fp, snapshot_exception, "Failed to open {file}", ("file", snapshot_path));
   // Make sure fp is closed in any cases
   auto close_fp = fc::make_scoped_exit([&fp](){fclose(fp);});

   char read_buffer[65536];
   rapidjson::FileReadStream read_stream(fp, read_buffer, sizeof(read_buffer));

   rapidjson::ParseResult ok = snapshot.ParseStream(read_stream);
   EOS_ASSERT(ok, snapshot_exception, "JSON parse error, error code: {code}, offset: {offset}", ("code", rapidjson::GetParseError_En(ok.Code())) ("offset", ok.Offset()));
}

void json_snapshot_reader::validate() const {
   // validate totem
   EOS_ASSERT(snapshot.HasMember("magic_number"), snapshot_exception, "JSON snapshot does not have magic number");
   EOS_ASSERT(snapshot["magic_number"].IsInt(), snapshot_exception, "JSON snapshot's magic number is not an integer");
   auto expected_totem = ostream_json_snapshot_writer::magic_number;
   decltype(expected_totem) actual_totem;
   actual_totem = snapshot["magic_number"].GetInt();
   EOS_ASSERT(actual_totem == expected_totem, snapshot_exception, "JSON snapshot has unexpected magic number. Expected: {expected}, Got: {actual}", ("expected", expected_totem)("actual", actual_totem));

   // validate version
   EOS_ASSERT(snapshot.HasMember("version"), snapshot_exception, "JSON snapshot does not have version");
   EOS_ASSERT(snapshot["version"].IsInt(), snapshot_exception, "JSON snapshot's version is not an integer");
   auto expected_version = current_snapshot_version;
   decltype(expected_version) actual_version;
   actual_version = snapshot["version"].GetInt();
   EOS_ASSERT(actual_version == expected_version, snapshot_exception,
              "JSON snapshot is an unsupported version. Expected: {expected}, Got: {actual}",
              ("expected", expected_version)("actual", actual_version));
}

bool json_snapshot_reader::has_section( const string& section_name ) {
   return snapshot.HasMember(section_name.c_str());
}

void json_snapshot_reader::set_section( const string& section_name ) {
   EOS_ASSERT(snapshot.HasMember(section_name.c_str()), snapshot_exception, "JSON snapshot does not have {sect}", ("sect", section_name));
   EOS_ASSERT(snapshot[section_name.c_str()].HasMember("num_rows"), snapshot_exception, "JSON snapshot {sect} does not have num_rows", ("sect", section_name));
   EOS_ASSERT(snapshot[section_name.c_str()].HasMember("rows"), snapshot_exception, "JSON snapshot {sect} does not have rows", ("sect", section_name));
   EOS_ASSERT(snapshot[section_name.c_str()]["rows"].IsArray(), snapshot_exception, "JSON snapshot {sect}'s rows is not a list", ("sect_name", section_name));

   sect_name = section_name;
   num_rows = snapshot[sect_name.c_str()]["num_rows"].GetInt();
   ilog("reading {section_name}, num_rows: {num_rows}", ("section_name", section_name) ("num_rows", num_rows));
}

bool json_snapshot_reader::read_row( detail::abstract_snapshot_row_reader& row_reader ) {
   EOS_ASSERT(cur_row < num_rows, snapshot_exception, "JSON snapshot {sect}'s cur_row {cur_row} >= num_rows {num_rows}", ("sect_name", sect_name) ("cur_row", cur_row) ("num_rows", num_rows));

   const rapidjson::Value& rows = snapshot[sect_name.c_str()]["rows"];

   // convert row from DOM to string representation
   rapidjson::StringBuffer sb;
   rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
   rows[cur_row].Accept(writer);

   // convert string representation to variant
   const auto& row = fc::json::from_string(sb.GetString());
   row_reader.provide(row);

   cur_row++;
   return cur_row < num_rows;
}

bool json_snapshot_reader::empty ( ) {
   return num_rows == 0;
}

void json_snapshot_reader::clear_section ( ) {
   num_rows = 0;
   cur_row  = 0;
   sect_name = "";
}

void json_snapshot_reader::return_to_header ( ) {
   clear_section();
}

istream_snapshot_reader::istream_snapshot_reader(std::istream& snapshot, bool validate_chain_id)
:snapshot(snapshot)
,header_pos(snapshot.tellg())
,num_rows(0)
,cur_row(0)
,assert_chain_id(validate_chain_id)
{

}

void istream_snapshot_reader::validate() const {
   // make sure to restore the read pos
   auto restore_pos = fc::make_scoped_exit([this,pos=snapshot.tellg(),ex=snapshot.exceptions()](){
      snapshot.seekg(pos);
      snapshot.exceptions(ex);
   });

   snapshot.exceptions(std::istream::failbit|std::istream::eofbit);

   try {
      // validate totem
      auto expected_totem = ostream_snapshot_writer::magic_number;
      decltype(expected_totem) actual_totem;
      snapshot.read((char*)&actual_totem, sizeof(actual_totem));
      EOS_ASSERT(actual_totem == expected_totem, snapshot_exception,
                 "Binary snapshot has unexpected magic number!");

      // validate version
      auto expected_version = current_snapshot_version;
      decltype(expected_version) actual_version;
      snapshot.read((char*)&actual_version, sizeof(actual_version));
      EOS_ASSERT(actual_version == expected_version, snapshot_exception,
                 "Binary snapshot is an unsupported version.  Expected : {expected}, Got: {actual}",
                 ("expected", expected_version)("actual", actual_version));

      while (validate_section()) {}
   } catch( const std::exception& e ) {  \
      snapshot_exception fce(FC_LOG_MESSAGE( warn, "Binary snapshot validation threw IO exception ({what})",("what",e.what())));
      throw fce;
   }
}

bool istream_snapshot_reader::validate_section() const {
   uint64_t section_size = 0;
   snapshot.read((char*)&section_size,sizeof(section_size));

   // stop when we see the end marker
   if (section_size == std::numeric_limits<uint64_t>::max()) {
      return false;
   }

   // seek past the section
   snapshot.seekg(snapshot.tellg() + std::streamoff(section_size));

   return true;
}

bool istream_snapshot_reader::has_section( const string& section_name ) {
   auto restore_pos = fc::make_scoped_exit([this,pos=snapshot.tellg()](){
      snapshot.seekg(pos);
   });

   const std::streamoff header_size = sizeof(ostream_snapshot_writer::magic_number) + sizeof(current_snapshot_version);

   auto next_section_pos = header_pos + header_size;

   while (true) {
      snapshot.seekg(next_section_pos);
      uint64_t section_size = 0;
      snapshot.read((char*)&section_size,sizeof(section_size));
      if (section_size == std::numeric_limits<uint64_t>::max()) {
         break;
      }

      next_section_pos = snapshot.tellg() + std::streamoff(section_size);

      uint64_t ignore = 0;
      snapshot.read((char*)&ignore,sizeof(ignore));

      bool match = true;
      for(auto c : section_name) {
         if(snapshot.get() != c) {
            match = false;
            break;
         }
      }

      if (match && snapshot.get() == 0) {
         return true;
      }
   }

   return false;
}

void istream_snapshot_reader::set_section( const string& section_name ) {
   auto restore_pos = fc::make_scoped_exit([this,pos=snapshot.tellg()](){
      snapshot.seekg(pos);
   });

   const std::streamoff header_size = sizeof(ostream_snapshot_writer::magic_number) + sizeof(current_snapshot_version);

   auto next_section_pos = header_pos + header_size;

   while (true) {
      snapshot.seekg(next_section_pos);
      uint64_t section_size = 0;
      snapshot.read((char*)&section_size,sizeof(section_size));
      if (section_size == std::numeric_limits<uint64_t>::max()) {
         break;
      }

      next_section_pos = snapshot.tellg() + std::streamoff(section_size);

      uint64_t row_count = 0;
      snapshot.read((char*)&row_count,sizeof(row_count));

      bool match = true;
      for(auto c : section_name) {
         if(snapshot.get() != c) {
            match = false;
            break;
         }
      }

      if (match && snapshot.get() == 0) {
         cur_row = 0;
         num_rows = row_count;

         // leave the stream at the right point
         restore_pos.cancel();
         return;
      }
   }

   EOS_THROW(snapshot_exception, "Binary snapshot has no section named {n}", ("n", section_name));
}

bool istream_snapshot_reader::read_row( detail::abstract_snapshot_row_reader& row_reader ) {
   row_reader.provide(snapshot);
   return ++cur_row < num_rows;
}

bool istream_snapshot_reader::empty ( ) {
   return num_rows == 0;
}

void istream_snapshot_reader::clear_section() {
   num_rows = 0;
   cur_row = 0;
}

void istream_snapshot_reader::return_to_header() {
   snapshot.seekg( header_pos );
   clear_section();
}

integrity_hash_snapshot_writer::integrity_hash_snapshot_writer(fc::sha256::encoder& enc)
:enc(enc)
{
}

void integrity_hash_snapshot_writer::write_start_section( const std::string& )
{
   // no-op for structural details
}

void integrity_hash_snapshot_writer::write_row( const detail::abstract_snapshot_row_writer& row_writer ) {
   row_writer.write(enc);
}

void integrity_hash_snapshot_writer::write_end_section( ) {
   // no-op for structural details
}

void integrity_hash_snapshot_writer::finalize() {
   // no-op for structural details
}

}}

#include "dbgx/mcp/json_writer.hpp"
#include "dbgx/mcp/json.hpp"

namespace dbgx::mcp {

std::string JsonWriter::Escape(std::string_view s) {
  return dbgx::json::Escape(s);
}

}  // namespace dbgx::mcp
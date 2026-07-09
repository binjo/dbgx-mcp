#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "dbgx/mcp/http_server.hpp"

namespace dbgx::mcp {

struct RequestIoMeta {
  bool parseable = false;
  bool has_rpc_method = false;
  bool has_rpc_id = false;
  bool has_tool_name = false;
  std::string rpc_method;
  std::string rpc_id_raw;
  std::string tool_name;
  std::string detail_info;
};

struct IoTraceContext {
  std::string trace_id;
  std::string stage;
  std::string rpc_method;
  std::string rpc_id;
  std::string tool_name;
  std::string outcome;
  std::uint64_t duration_ms = 0;
  std::string detail_info;
};

RequestIoMeta ParseRequestIoMeta(const HttpRequest& request);
std::string BuildLifecycleIoSummary(const IoTraceContext& trace_context, std::string_view message);

std::string BuildRequestIoSummary(const HttpRequest& request);
std::string BuildRequestIoSummary(const HttpRequest& request, const IoTraceContext& trace_context);
std::string BuildResponseIoSummary(const HttpResponse& response);
std::string BuildResponseIoSummary(const HttpResponse& response, const IoTraceContext& trace_context);

}  // namespace dbgx::mcp

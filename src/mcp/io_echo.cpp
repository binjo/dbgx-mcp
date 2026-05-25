#include "dbgx/mcp/io_echo.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "dbgx/mcp/json.hpp"

namespace dbgx::mcp {

namespace {

constexpr std::size_t kSummaryValueLimit = 160;
constexpr std::string_view kTruncatedSuffix = "...(truncated)";

struct ResponseIoMeta {
  bool parseable = false;
  bool has_rpc_id = false;
  std::string rpc_id_raw;
  bool has_error = false;
  std::string error_raw;
  bool has_result = false;
  std::string result_raw;
  std::string rpc_outcome = "unknown";
};

std::string ToLowerAscii(std::string_view value) {
  std::string lowered;
  lowered.reserve(value.size());
  for (const unsigned char ch : value) {
    lowered.push_back(static_cast<char>(std::tolower(ch)));
  }
  return lowered;
}

bool IsSensitiveHeaderName(std::string_view header_name) {
  const std::string lowered = ToLowerAscii(header_name);
  return lowered == "authorization" || lowered == "proxy-authorization" || lowered == "x-api-key";
}

bool IsJsonTrueLiteral(std::string_view raw) {
  return json::Trim(raw) == "true";
}

std::string SanitizeSingleLine(std::string_view value) {
  std::string sanitized;
  sanitized.reserve(value.size());

  for (const char ch : value) {
    if (ch == '\r' || ch == '\n' || ch == '\t') {
      sanitized.push_back(' ');
      continue;
    }
    sanitized.push_back(ch);
  }

  return sanitized;
}

std::string TruncateForSummary(std::string_view value) {
  const std::string sanitized = SanitizeSingleLine(value);
  if (sanitized.size() <= kSummaryValueLimit) {
    return sanitized;
  }

  std::string truncated = sanitized.substr(0, kSummaryValueLimit);
  truncated += kTruncatedSuffix;
  return truncated;
}

std::string JoinValues(const std::vector<std::string>& values) {
  if (values.empty()) {
    return {};
  }

  std::string joined = values.front();
  for (std::size_t i = 1; i < values.size(); ++i) {
    joined += ",";
    joined += values[i];
  }
  return joined;
}

std::string BuildSensitiveHeadersSummary(const HttpRequest& request) {
  std::vector<std::string> masked_headers;
  masked_headers.reserve(request.headers.size());

  for (const auto& [header_name, header_value] : request.headers) {
    if (!IsSensitiveHeaderName(header_name)) {
      continue;
    }

    const std::string lower_name = ToLowerAscii(header_name);
    if (header_value.empty()) {
      masked_headers.push_back(lower_name + "=<masked>");
      continue;
    }

    masked_headers.push_back(lower_name + "=<masked>");
  }

  std::sort(masked_headers.begin(), masked_headers.end());

  if (masked_headers.empty()) {
    return "sensitive_headers=none";
  }

  return "sensitive_headers=" + JoinValues(masked_headers);
}

RequestIoMeta ParseRequestIoMetaFromBody(std::string_view request_body) {
  RequestIoMeta meta;

  json::FieldMap root_fields;
  std::string parse_error;
  if (!json::ParseObjectFields(request_body, &root_fields, &parse_error)) {
    return meta;
  }

  meta.parseable = true;
  if (json::TryGetStringField(root_fields, "method", &meta.rpc_method)) {
    meta.has_rpc_method = true;
  }
  if (json::TryGetRawField(root_fields, "id", &meta.rpc_id_raw)) {
    meta.has_rpc_id = true;
  }

  if (!meta.has_rpc_method || meta.rpc_method != "tools/call") {
    return meta;
  }

  json::FieldMap params_fields;
  if (!json::TryGetObjectField(root_fields, "params", &params_fields, &parse_error)) {
    return meta;
  }

  if (json::TryGetStringField(params_fields, "name", &meta.tool_name)) {
    meta.has_tool_name = true;

    json::FieldMap arguments_fields;
    if (json::TryGetObjectField(params_fields, "arguments", &arguments_fields, &parse_error)) {
      if (meta.tool_name == "windbg.eval") {
        std::string command;
        if (json::TryGetStringField(arguments_fields, "command", &command)) {
          meta.detail_info = "command=\"" + command + "\"";
        }
      } else if (meta.tool_name == "windbg.dx") {
        std::string expression;
        if (json::TryGetStringField(arguments_fields, "expression", &expression)) {
          meta.detail_info = "expression=\"" + expression + "\"";
        }
      } else if (meta.tool_name == "windbg.search_catalog") {
        std::string query;
        if (json::TryGetStringField(arguments_fields, "query", &query)) {
          meta.detail_info = "query=\"" + query + "\"";
        }
      } else if (meta.tool_name == "windbg.read_memory") {
        std::string address;
        if (json::TryGetStringField(arguments_fields, "address", &address)) {
          meta.detail_info = "address=" + address;
        }
      }
    }
  }
  return meta;
}

ResponseIoMeta ParseResponseIoMeta(std::string_view response_body) {
  ResponseIoMeta meta;

  json::FieldMap root_fields;
  std::string parse_error;
  if (!json::ParseObjectFields(response_body, &root_fields, &parse_error)) {
    return meta;
  }

  meta.parseable = true;
  if (json::TryGetRawField(root_fields, "id", &meta.rpc_id_raw)) {
    meta.has_rpc_id = true;
  }

  if (json::TryGetRawField(root_fields, "error", &meta.error_raw)) {
    meta.has_error = true;
    meta.rpc_outcome = "error";
    return meta;
  }

  if (json::TryGetRawField(root_fields, "result", &meta.result_raw)) {
    meta.has_result = true;
    meta.rpc_outcome = "success";

    json::FieldMap result_fields;
    if (json::ParseObjectFields(meta.result_raw, &result_fields, &parse_error)) {
      std::string is_error_raw;
      if (json::TryGetRawField(result_fields, "isError", &is_error_raw) && IsJsonTrueLiteral(is_error_raw)) {
        meta.rpc_outcome = "error";
      }
    }
    return meta;
  }

  return meta;
}

void AppendTraceContext(const IoTraceContext* trace_context, std::string* summary) {
  if (trace_context == nullptr) {
    return;
  }

  if (!trace_context->trace_id.empty()) {
    *summary += " trace_id=" + TruncateForSummary(trace_context->trace_id);
  }
  if (!trace_context->stage.empty()) {
    *summary += " stage=" + TruncateForSummary(trace_context->stage);
  }
  *summary += " duration_ms=" + std::to_string(trace_context->duration_ms);
  if (!trace_context->detail_info.empty()) {
    *summary += " " + trace_context->detail_info;
  }
}

void AppendRpcRequestMeta(
    const RequestIoMeta& request_meta,
    const IoTraceContext* trace_context,
    std::string* summary) {
  std::string rpc_method = "(missing)";
  if (trace_context != nullptr && !trace_context->rpc_method.empty()) {
    rpc_method = trace_context->rpc_method;
  } else if (request_meta.has_rpc_method) {
    rpc_method = request_meta.rpc_method;
  }
  *summary += " rpc_method=" + TruncateForSummary(rpc_method);

  std::string rpc_id = "(missing)";
  if (trace_context != nullptr && !trace_context->rpc_id.empty()) {
    rpc_id = trace_context->rpc_id;
  } else if (request_meta.has_rpc_id) {
    rpc_id = request_meta.rpc_id_raw;
  }
  *summary += " rpc_id=" + TruncateForSummary(rpc_id);

  std::string tool_name;
  if (trace_context != nullptr && !trace_context->tool_name.empty()) {
    tool_name = trace_context->tool_name;
  } else if (request_meta.has_tool_name) {
    tool_name = request_meta.tool_name;
  }

  if (!tool_name.empty() || rpc_method == "tools/call") {
    *summary += " tool=" + TruncateForSummary(tool_name.empty() ? "(missing)" : tool_name);
  }

  std::string detail_info;
  if (trace_context != nullptr && !trace_context->detail_info.empty()) {
    detail_info = trace_context->detail_info;
  } else if (!request_meta.detail_info.empty()) {
    detail_info = request_meta.detail_info;
  }
  if (!detail_info.empty()) {
    *summary += " " + detail_info;
  }
}

void AppendRpcResponseMeta(
    const ResponseIoMeta& response_meta,
    const IoTraceContext* trace_context,
    std::string* summary) {
  std::string rpc_id;
  if (trace_context != nullptr && !trace_context->rpc_id.empty()) {
    rpc_id = trace_context->rpc_id;
  } else if (response_meta.has_rpc_id) {
    rpc_id = response_meta.rpc_id_raw;
  }
  if (!rpc_id.empty()) {
    *summary += " rpc_id=" + TruncateForSummary(rpc_id);
  }

  std::string rpc_outcome;
  if (trace_context != nullptr && !trace_context->outcome.empty()) {
    rpc_outcome = trace_context->outcome;
  } else {
    rpc_outcome = response_meta.rpc_outcome;
  }
  *summary += " rpc_outcome=" + TruncateForSummary(rpc_outcome.empty() ? "unknown" : rpc_outcome);

  if (trace_context != nullptr && !trace_context->tool_name.empty()) {
    *summary += " tool=" + TruncateForSummary(trace_context->tool_name);
  }

  if (response_meta.has_error) {
    *summary += " error=" + TruncateForSummary(response_meta.error_raw);
    return;
  }

  if (response_meta.has_result) {
    *summary += " result=" + TruncateForSummary(response_meta.result_raw);
  }
}

}  // namespace

std::string BuildRequestIoSummary(const HttpRequest& request) {
  return BuildRequestIoSummary(request, IoTraceContext{});
}

std::string BuildRequestIoSummary(const HttpRequest& request, const IoTraceContext& trace_context) {
  std::string summary = "mcp.request method=" + TruncateForSummary(request.method);
  AppendTraceContext(&trace_context, &summary);
  summary += " path=" + TruncateForSummary(request.path);

  const RequestIoMeta request_meta = ParseRequestIoMetaFromBody(request.body);
  if (request_meta.parseable) {
    AppendRpcRequestMeta(request_meta, &trace_context, &summary);
  } else {
    summary += " rpc_meta=unparseable";
    if (!trace_context.rpc_method.empty()) {
      summary += " rpc_method=" + TruncateForSummary(trace_context.rpc_method);
    }
    if (!trace_context.rpc_id.empty()) {
      summary += " rpc_id=" + TruncateForSummary(trace_context.rpc_id);
    }
    if (!trace_context.tool_name.empty()) {
      summary += " tool=" + TruncateForSummary(trace_context.tool_name);
    }
  }

  summary += " body_bytes=" + std::to_string(request.body.size());
  summary += " " + BuildSensitiveHeadersSummary(request);
  return summary;
}

RequestIoMeta ParseRequestIoMeta(const HttpRequest& request) {
  return ParseRequestIoMetaFromBody(request.body);
}

std::string BuildLifecycleIoSummary(const IoTraceContext& trace_context, std::string_view message) {
  std::string summary = "mcp.stage";
  AppendTraceContext(&trace_context, &summary);

  if (!trace_context.rpc_method.empty()) {
    summary += " rpc_method=" + TruncateForSummary(trace_context.rpc_method);
  }
  if (!trace_context.rpc_id.empty()) {
    summary += " rpc_id=" + TruncateForSummary(trace_context.rpc_id);
  }
  if (!trace_context.tool_name.empty()) {
    summary += " tool=" + TruncateForSummary(trace_context.tool_name);
  }
  if (!trace_context.outcome.empty()) {
    summary += " outcome=" + TruncateForSummary(trace_context.outcome);
  }
  if (!message.empty()) {
    summary += " msg=" + TruncateForSummary(message);
  }
  return summary;
}

std::string BuildResponseIoSummary(const HttpResponse& response) {
  return BuildResponseIoSummary(response, IoTraceContext{});
}

std::string BuildResponseIoSummary(const HttpResponse& response, const IoTraceContext& trace_context) {
  std::string summary = "mcp.response status=" + std::to_string(response.status_code);
  AppendTraceContext(&trace_context, &summary);
  summary += response.has_body ? " has_body=true" : " has_body=false";

  if (!response.has_body) {
    if (!trace_context.rpc_id.empty()) {
      summary += " rpc_id=" + TruncateForSummary(trace_context.rpc_id);
    }
    if (!trace_context.outcome.empty()) {
      summary += " rpc_outcome=" + TruncateForSummary(trace_context.outcome);
    }
    if (!trace_context.tool_name.empty()) {
      summary += " tool=" + TruncateForSummary(trace_context.tool_name);
    }
    return summary;
  }

  const ResponseIoMeta response_meta = ParseResponseIoMeta(response.body);
  if (response_meta.parseable) {
    AppendRpcResponseMeta(response_meta, &trace_context, &summary);
    return summary;
  }

  summary += " rpc_meta=unparseable";
  if (!trace_context.rpc_id.empty()) {
    summary += " rpc_id=" + TruncateForSummary(trace_context.rpc_id);
  }
  if (!trace_context.outcome.empty()) {
    summary += " rpc_outcome=" + TruncateForSummary(trace_context.outcome);
  }
  if (!trace_context.tool_name.empty()) {
    summary += " tool=" + TruncateForSummary(trace_context.tool_name);
  }
  summary += " body=" + TruncateForSummary(response.body.empty() ? "(empty)" : response.body);
  return summary;
}

}  // namespace dbgx::mcp

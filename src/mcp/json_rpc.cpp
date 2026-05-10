#include "dbgx/mcp/json_rpc.hpp"

#include <utility>

#include "dbgx/mcp/json.hpp"

namespace dbgx::mcp {

namespace {

constexpr const char* kProtocolVersion = "2024-11-05";

struct MethodOutcome {
  bool ok = false;
  std::string result_json;
  int error_code = -32603;
  std::string error_message = "Internal error";
  int http_status_on_error = 200;
};

std::string BuildJsonRpcSuccess(std::string_view id_raw, std::string_view result_json) {
  std::string body = "{";
  body += "\"jsonrpc\":\"2.0\",";
  body += "\"id\":";
  body += id_raw;
  body += ",\"result\":";
  body += result_json;
  body += "}";
  return body;
}

std::string BuildJsonRpcError(std::string_view id_raw, int code, std::string_view message) {
  std::string body = "{";
  body += "\"jsonrpc\":\"2.0\",";
  body += "\"id\":";
  body += id_raw;
  body += ",\"error\":{";
  body += "\"code\":";
  body += std::to_string(code);
  body += ",\"message\":\"";
  body += json::Escape(message);
  body += "\"}}";
  return body;
}

MethodOutcome HandleInitialize(const json::FieldMap& root_fields) {
  std::string requested_version = kProtocolVersion;
  json::FieldMap params_fields;
  std::string parse_error;
  if (json::TryGetObjectField(root_fields, "params", &params_fields, &parse_error)) {
    json::TryGetStringField(params_fields, "protocolVersion", &requested_version);
  }

  MethodOutcome outcome;
  outcome.ok = true;
  outcome.result_json =
      "{"
      "\"protocolVersion\":\"" + json::Escape(requested_version) + "\","
      "\"capabilities\":{\"tools\":{\"listChanged\":false,\"availableTools\":[\"windbg.eval\"]}},"
      "\"serverInfo\":{\"name\":\"dbgx-mcp\",\"version\":\"" DBGX_VERSION_STRING "\"}"
      "}";
  return outcome;
}

MethodOutcome HandleInitializedNotification() {
  MethodOutcome outcome;
  outcome.ok = true;
  outcome.result_json = "{}";
  return outcome;
}

MethodOutcome HandleToolsList() {
  MethodOutcome outcome;
  outcome.ok = true;
  outcome.result_json =
      "{"
      "\"tools\":["
      "{"
      "\"name\":\"windbg.eval\","
      "\"description\":\"Execute WinDbg command. Results returned as filtered/truncated text.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"command\":{\"type\":\"string\",\"description\":\"WinDbg command to execute\"},"
      "\"max_lines\":{\"type\":\"integer\",\"description\":\"Max lines to return (default 100)\"},"
      "\"pattern\":{\"type\":\"string\",\"description\":\"Optional substring filter\"}"
      "},"
      "\"required\":[\"command\"],"
      "\"additionalProperties\":false"
      "}"
      "}"
      "]"
      "}";
  return outcome;
}

MethodOutcome HandleToolsCall(const json::FieldMap& root_fields, windbg::IWinDbgCommandExecutor* executor) {
  MethodOutcome outcome;

  if (executor == nullptr) {
    outcome.error_code = -32603;
    outcome.error_message = "Command executor is not available";
    return outcome;
  }

  json::FieldMap params_fields;
  std::string parse_error;
  if (!json::TryGetObjectField(root_fields, "params", &params_fields, &parse_error)) {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: params must be an object";
    return outcome;
  }

  std::string tool_name;
  if (!json::TryGetStringField(params_fields, "name", &tool_name)) {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: missing tool name";
    return outcome;
  }

  if (tool_name != "windbg.eval") {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: unknown tool name";
    return outcome;
  }

  json::FieldMap arguments_fields;
  if (!json::TryGetObjectField(params_fields, "arguments", &arguments_fields, &parse_error)) {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: arguments must be an object";
    return outcome;
  }

  std::string command;
  if (!json::TryGetStringField(arguments_fields, "command", &command) || command.empty()) {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: command must be a non-empty string";
    return outcome;
  }

  windbg::CommandExecutionOptions options;
  json::TryGetIntField(arguments_fields, "max_lines", &options.max_lines);
  json::TryGetStringField(arguments_fields, "pattern", &options.pattern);

  const windbg::CommandExecutionResult execution = executor->Execute(command, options);

  const std::string payload_text = execution.success
                                       ? (execution.output.empty() ? "(no output)" : execution.output)
                                       : (execution.error_message.empty() ? "Command execution failed"
                                                                          : execution.error_message);

  outcome.ok = true;
  outcome.result_json =
      "{\"content\":[{\"type\":\"text\",\"text\":\"" + json::Escape(payload_text) +
      "\"}],\"isError\":" + (execution.success ? "false" : "true") + "}";

  return outcome;
}

MethodOutcome DispatchMethod(
    std::string_view method,
    const json::FieldMap& root_fields,
    windbg::IWinDbgCommandExecutor* executor) {
  if (method == "notifications/initialized" || method == "initialized") {
    return HandleInitializedNotification();
  }
  if (method == "initialize") {
    return HandleInitialize(root_fields);
  }
  if (method == "tools/list") {
    return HandleToolsList();
  }
  if (method == "tools/call") {
    return HandleToolsCall(root_fields, executor);
  }

  MethodOutcome outcome;
  outcome.error_code = -32601;
  outcome.error_message = "Method not found";
  return outcome;
}

}  // namespace

JsonRpcRouter::JsonRpcRouter(windbg::IWinDbgCommandExecutor* executor) : executor_(executor) {}

JsonRpcHttpResult JsonRpcRouter::HandleJsonRpcPost(std::string_view request_body) const {
  JsonRpcHttpResult http_result;

  json::FieldMap root_fields;
  std::string parse_error;
  if (!json::ParseObjectFields(request_body, &root_fields, &parse_error)) {
    http_result.status_code = 400;
    http_result.body = BuildJsonRpcError("null", -32700, "Parse error: " + parse_error);
    return http_result;
  }

  std::string jsonrpc;
  if (!json::TryGetStringField(root_fields, "jsonrpc", &jsonrpc) || jsonrpc != "2.0") {
    http_result.status_code = 200;
    std::string id_raw = "null";
    json::TryGetRawField(root_fields, "id", &id_raw);
    http_result.body = BuildJsonRpcError(id_raw, -32600, "Invalid Request: jsonrpc must be 2.0");
    return http_result;
  }

  std::string id_raw = "null";
  const bool has_id = json::TryGetRawField(root_fields, "id", &id_raw);
  if (!has_id) {
    id_raw = "null";
  }

  std::string method;
  if (!json::TryGetStringField(root_fields, "method", &method)) {
    if (!has_id) {
      http_result.status_code = 202;
      http_result.has_body = false;
      http_result.body.clear();
      return http_result;
    }

    http_result.body = BuildJsonRpcError(id_raw, -32600, "Invalid Request: missing method");
    return http_result;
  }

  const MethodOutcome outcome = DispatchMethod(method, root_fields, executor_);
  if (outcome.ok) {
    if (!has_id) {
      http_result.status_code = 202;
      http_result.has_body = false;
      http_result.body.clear();
      return http_result;
    }

    http_result.status_code = 200;
    http_result.body = BuildJsonRpcSuccess(id_raw, outcome.result_json);
    return http_result;
  }

  if (!has_id) {
    http_result.status_code = outcome.http_status_on_error;
    http_result.body = BuildJsonRpcError("null", outcome.error_code, outcome.error_message);
    return http_result;
  }

  http_result.status_code = outcome.http_status_on_error;
  http_result.body = BuildJsonRpcError(id_raw, outcome.error_code, outcome.error_message);
  return http_result;
}

}  // namespace dbgx::mcp

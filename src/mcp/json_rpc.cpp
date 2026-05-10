#include "dbgx/mcp/json_rpc.hpp"

#include <cstdlib>
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
      "\"capabilities\":{\"tools\":{\"listChanged\":false,\"availableTools\":[\"windbg.eval\",\"windbg.dx\",\"windbg.get_context\",\"windbg.read_memory\",\"windbg.search\"]}},"
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
      "\"description\":\"Execute WinDbg command. Results returned as filtered/truncated text. NOTE: WinDbg is inherently single-threaded for command execution; clients MUST run calls serially and wait for each call to finish before sending the next.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"command\":{\"type\":\"string\",\"description\":\"WinDbg command to execute. Because the debugger engine is single-threaded, clients should send commands one by one and wait for completion before the next command.\"},"
      "\"max_lines\":{\"type\":\"integer\",\"description\":\"Max lines to return (default 100)\"},"
      "\"pattern\":{\"type\":\"string\",\"description\":\"Optional substring filter\"}"
      "},"
      "\"required\":[\"command\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.dx\","
      "\"description\":\"Evaluate WinDbg Data Model expression and return as structured JSON.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"expression\":{\"type\":\"string\",\"description\":\"Data Model expression (e.g. @$curprocess)\"},"
      "\"max_depth\":{\"type\":\"integer\",\"description\":\"Max recursion depth (default 5)\"}"
      "},"
      "\"required\":[\"expression\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_context\","
      "\"description\":\"Get a comprehensive snapshot of the current debugger state (registers, stack). \","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.read_memory\","
      "\"description\":\"Read virtual memory and return as hex string.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address to read from\"},"
      "\"length\":{\"type\":\"integer\",\"description\":\"Number of bytes to read\"}"
      "},"
      "\"required\":[\"address\",\"length\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.search\","
      "\"description\":\"Search virtual memory for a byte pattern.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"start_address\":{\"type\":\"string\",\"description\":\"Hex start address\"},"
      "\"end_address\":{\"type\":\"string\",\"description\":\"Hex end address\"},"
      "\"pattern\":{\"type\":\"string\",\"description\":\"Hex pattern to search for (e.g. '41 42 43')\"}"
      "},"
      "\"required\":[\"start_address\",\"end_address\",\"pattern\"],"
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

  json::FieldMap arguments_fields;
  if (!json::TryGetObjectField(params_fields, "arguments", &arguments_fields, &parse_error)) {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: arguments must be an object";
    return outcome;
  }

  windbg::CommandExecutionResult execution;
  bool is_json_output = false;

  if (tool_name == "windbg.eval") {
    std::string command;
    if (!json::TryGetStringField(arguments_fields, "command", &command) || command.empty()) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: command must be a non-empty string";
      return outcome;
    }
    windbg::CommandExecutionOptions options;
    json::TryGetIntField(arguments_fields, "max_lines", &options.max_lines);
    json::TryGetStringField(arguments_fields, "pattern", &options.pattern);
    execution = executor->Execute(command, options);
  } else if (tool_name == "windbg.dx") {
    std::string expression;
    if (!json::TryGetStringField(arguments_fields, "expression", &expression) || expression.empty()) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: expression must be a non-empty string";
      return outcome;
    }
    int max_depth = 5;
    json::TryGetIntField(arguments_fields, "max_depth", &max_depth);
    execution = executor->EvaluateModel(expression, max_depth);
    is_json_output = true;
  } else if (tool_name == "windbg.get_context") {
    execution = executor->GetContextSnapshot();
    is_json_output = true;
  } else if (tool_name == "windbg.read_memory") {
    std::string addr_str;
    int length = 0;
    if (!json::TryGetStringField(arguments_fields, "address", &addr_str) ||
        !json::TryGetIntField(arguments_fields, "length", &length)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: address and length are required";
      return outcome;
    }
    uint64_t address = strtoull(addr_str.c_str(), nullptr, 16);
    execution = executor->ReadMemory(address, (uint32_t)length);
  } else if (tool_name == "windbg.search") {
    std::string start_str, end_str, pattern;
    if (!json::TryGetStringField(arguments_fields, "start_address", &start_str) ||
        !json::TryGetStringField(arguments_fields, "end_address", &end_str) ||
        !json::TryGetStringField(arguments_fields, "pattern", &pattern)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: start_address, end_address, and pattern are required";
      return outcome;
    }
    uint64_t start = strtoull(start_str.c_str(), nullptr, 16);
    uint64_t end = strtoull(end_str.c_str(), nullptr, 16);
    execution = executor->SearchMemory(start, end, pattern);
    is_json_output = true;
  } else {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: unknown tool name";
    return outcome;
  }

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

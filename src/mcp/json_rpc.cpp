#include "dbgx/mcp/json_rpc.hpp"
#include "dbgx/windbg/catalog.hpp"
#include <algorithm>
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

std::string PrettyPrintJson(std::string_view json) {
  std::string pretty;
  int indent = 0;
  bool in_quote = false;
  bool escape = false;
  for (size_t i = 0; i < json.size(); ++i) {
    char c = json[i];
    if (escape) {
      pretty.push_back(c);
      escape = false;
      continue;
    }
    if (c == '\\') {
      pretty.push_back(c);
      escape = true;
      continue;
    }
    if (c == '"') {
      pretty.push_back(c);
      in_quote = !in_quote;
      continue;
    }
    if (in_quote) {
      pretty.push_back(c);
      continue;
    }

    if (c == '{' || c == '[') {
      pretty.push_back(c);
      pretty.push_back('\n');
      indent += 2;
      pretty.append(indent, ' ');
    } else if (c == '}' || c == ']') {
      pretty.push_back('\n');
      indent = (std::max)(0, indent - 2);
      pretty.append(indent, ' ');
      pretty.push_back(c);
    } else if (c == ',') {
      pretty.push_back(c);
      pretty.push_back('\n');
      pretty.append(indent, ' ');
    } else if (c == ':') {
      pretty.push_back(c);
      pretty.push_back(' ');
    } else if (!isspace(static_cast<unsigned char>(c))) {
      pretty.push_back(c);
    }
  }
  return pretty;
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
      "\"capabilities\":{\"tools\":{\"listChanged\":false,\"availableTools\":[\"windbg.eval\",\"windbg.dx\",\"windbg.get_context\",\"windbg.read_memory\",\"windbg.carve_pe\",\"windbg.search\",\"windbg.get_execution_state\",\"windbg.interrupt\",\"windbg.search_catalog\",\"windbg.get_command_docs\",\"windbg.get_session_metadata\",\"windbg.write_memory\",\"windbg.get_threads\"]}},"
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
      "\"description\":\"Evaluate WinDbg Data Model expression and return as structured JSON. NOTE: If a key/property contains non-identifier characters (like hyphens, spaces, or dots), query it using the @\\\"key\\\" syntax, e.g., Parent.@\\\"key-name\\\".\","
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
      "\"name\":\"windbg.carve_pe\","
      "\"description\":\"Carve and reconstruct a Portable Executable (PE) image (DLL/EXE) directly from the target's virtual memory back into standard disk layout, resolving section offsets dynamically.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex base address of the mapped PE image in memory\"},"
      "\"length\":{\"type\":\"integer\",\"description\":\"Estimated virtual size of the image to read (e.g. 40960 for 40KB)\"}"
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
      "},"
      "{"
      "\"name\":\"windbg.get_execution_state\","
      "\"description\":\"Query the current debugger execution state before deciding whether to interrupt or execute a command.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.interrupt\","
      "\"description\":\"Request a debugger break into the currently running target and wait until debugger commands are accepted again.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.search_catalog\","
      "\"description\":\"Search the offline debugger command catalog (bp, dt, k, r, etc.) for exact syntax, parameters, and examples.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"query\":{\"type\":\"string\",\"description\":\"Keyword or token to search for\"},"
      "\"limit\":{\"type\":\"integer\",\"description\":\"Maximum number of results to return (default 10)\"}"
      "},"
      "\"required\":[\"query\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_command_docs\","
      "\"description\":\"Get full offline documentation for a specific command ID.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"id\":{\"type\":\"string\",\"description\":\"Catalog entry ID (e.g., 'bp_bu_bm_set_breakpoint')\"}"
      "},"
      "\"required\":[\"id\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_session_metadata\","
      "\"description\":\"Get metadata for the current WinDbg session, such as process ID, architecture (e.g. x64, x86, arm64), debuggee class (user/kernel mode), executable name, and target info.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.write_memory\","
      "\"description\":\"Write virtual memory in the target process. Safe way to patch code, edit variables, or write memory structures directly.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address to write to\"},"
      "\"data\":{\"type\":\"string\",\"description\":\"Hexadecimal representation of bytes to write (e.g. '9090' to write two NOP instructions)\"}"
      "},"
      "\"required\":[\"address\",\"data\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_threads\","
      "\"description\":\"List all active threads in the current target process, including WinDbg index, system thread ID (TID), and whether it is the currently selected thread.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
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
  } else if (tool_name == "windbg.carve_pe") {
    std::string addr_str;
    int length = 0;
    if (!json::TryGetStringField(arguments_fields, "address", &addr_str) ||
        !json::TryGetIntField(arguments_fields, "length", &length)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: address and length are required";
      return outcome;
    }
    uint64_t address = strtoull(addr_str.c_str(), nullptr, 16);
    execution = executor->CarvePE(address, (uint32_t)length);
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
  } else if (tool_name == "windbg.get_execution_state") {
    auto state = executor->GetExecutionState();
    std::string json_out = "{";
    json_out += "\"raw_status\":" + std::to_string(state.raw_status) + ",";
    json_out += "\"status_name\":\"" + json::Escape(state.status_name) + "\",";
    json_out += "\"running\":" + std::string(state.running ? "true" : "false") + ",";
    json_out += "\"busy\":" + std::string(state.busy ? "true" : "false") + ",";
    json_out += "\"ready_for_commands\":" + std::string(state.ready_for_commands ? "true" : "false") + ",";
    json_out += "\"summary\":\"" + json::Escape(state.summary) + "\"";
    json_out += "}";

    execution.success = true;
    execution.output = json_out;
    is_json_output = true;
  } else if (tool_name == "windbg.interrupt") {
    bool success = executor->InterruptTarget();
    std::string json_out = "{\"success\":" + std::string(success ? "true" : "false") + "}";

    execution.success = true;
    execution.output = json_out;
    is_json_output = true;
  } else if (tool_name == "windbg.search_catalog") {
    std::string query;
    json::TryGetStringField(arguments_fields, "query", &query);
    int limit = 10;
    json::TryGetIntField(arguments_fields, "limit", &limit);

    auto results = windbg::Catalog::Search(query, limit);
    std::string json_out = "[";
    for (size_t i = 0; i < results.size(); ++i) {
      if (i > 0) json_out += ",";
      json_out += "{";
      json_out += "\"id\":\"" + json::Escape(results[i].id) + "\",";
      json_out += "\"title\":\"" + json::Escape(results[i].title) + "\",";
      json_out += "\"summary\":\"" + json::Escape(results[i].summary) + "\",";

      json_out += "\"tokens\":[";
      for (size_t t = 0; t < results[i].tokens.size(); ++t) {
        if (t > 0) json_out += ",";
        json_out += "\"" + json::Escape(results[i].tokens[t]) + "\"";
      }
      json_out += "],";

      json_out += "\"syntax\":\"" + json::Escape(results[i].syntax) + "\"";
      json_out += "}";
    }
    json_out += "]";

    execution.success = true;
    execution.output = json_out;
    is_json_output = true;
  } else if (tool_name == "windbg.get_command_docs") {
    std::string entry_id;
    if (!json::TryGetStringField(arguments_fields, "id", &entry_id) || entry_id.empty()) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: missing id";
      return outcome;
    }

    auto entry = windbg::Catalog::GetById(entry_id);
    if (!entry.has_value()) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: command ID not found in catalog";
      return outcome;
    }

    std::string json_out = "{";
    json_out += "\"id\":\"" + json::Escape(entry->id) + "\",";
    json_out += "\"title\":\"" + json::Escape(entry->title) + "\",";
    json_out += "\"summary\":\"" + json::Escape(entry->summary) + "\",";

    json_out += "\"tokens\":[";
    for (size_t t = 0; t < entry->tokens.size(); ++t) {
      if (t > 0) json_out += ",";
      json_out += "\"" + json::Escape(entry->tokens[t]) + "\"";
    }
    json_out += "],";

    json_out += "\"syntax\":\"" + json::Escape(entry->syntax) + "\",";
    json_out += "\"documentation\":\"" + json::Escape(entry->documentation) + "\"";
    json_out += "}";

    execution.success = true;
    execution.output = json_out;
    is_json_output = true;
  } else if (tool_name == "windbg.get_session_metadata") {
    auto meta = executor->GetSessionMetadata();
    std::string json_out = "{";
    json_out += "\"process_id\":" + std::to_string(meta.process_id) + ",";
    json_out += "\"executable_name\":\"" + json::Escape(meta.executable_name) + "\",";
    json_out += "\"target_info\":\"" + json::Escape(meta.target_info) + "\",";
    json_out += "\"architecture\":\"" + json::Escape(meta.architecture) + "\",";
    json_out += "\"debuggee_class\":\"" + json::Escape(meta.debuggee_class) + "\"";
    json_out += "}";

    execution.success = true;
    execution.output = json_out;
    is_json_output = true;
  } else if (tool_name == "windbg.write_memory") {
    std::string addr_str, hex_data;
    if (!json::TryGetStringField(arguments_fields, "address", &addr_str) ||
        !json::TryGetStringField(arguments_fields, "data", &hex_data)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: address and data are required";
      return outcome;
    }
    uint64_t address = strtoull(addr_str.c_str(), nullptr, 16);
    execution = executor->WriteMemory(address, hex_data);
    is_json_output = true;
  } else if (tool_name == "windbg.get_threads") {
    execution = executor->GetThreads();
    is_json_output = true;
  } else {
    outcome.error_code = -32602;
    outcome.error_message = "Invalid params: unknown tool name";
    return outcome;
  }

  const std::string payload_text = execution.success
                                       ? (execution.output.empty() ? "(no output)" :
                                           (is_json_output ? PrettyPrintJson(execution.output) : execution.output))
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

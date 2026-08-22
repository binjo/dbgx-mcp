#include "dbgx/mcp/json_rpc.hpp"
#include "dbgx/windbg/catalog.hpp"
#include "dbgx/mcp/syntypes_js.hpp"
#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <utility>
#include <filesystem>
#include <fstream>
#include <windows.h>

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
      "\"capabilities\":{\"tools\":{\"listChanged\":false,\"availableTools\":[\"windbg.eval\",\"windbg.dx\",\"windbg.get_context\",\"windbg.read_memory\",\"windbg.carve_pe\",\"windbg.search\",\"windbg.get_execution_state\",\"windbg.interrupt\",\"windbg.search_catalog\",\"windbg.get_command_docs\",\"windbg.get_session_metadata\",\"windbg.write_memory\",\"windbg.get_threads\",\"windbg.apply_synthetic_type\",\"windbg.write_file\",\"windbg.apply_struct\"]}},"
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
      "},"
      "{"
      "\"name\":\"windbg.apply_synthetic_type\","
      "\"description\":\"Apply a synthetic C-style structure definition (loaded from a header file) onto a virtual memory address, returning a fully structured, field-attributed view of the memory.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"header_path\":{\"type\":\"string\",\"description\":\"Path to the C-style header (.h) file containing the struct definition\"},"
      "\"struct_name\":{\"type\":\"string\",\"description\":\"Name of the struct definition to apply (e.g., 'ACPI_MCFG')\"},"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address or expression representing the target memory location\"},"
      "\"module_name\":{\"type\":\"string\",\"description\":\"The module name to bind the type to (default: 'bootmgr')\"},"
      "\"syntypes_path\":{\"type\":\"string\",\"description\":\"Optional path to the SynTypes.js extension (default: '%TEMP%\\\\SynTypes.js')\"}"
      "},"
      "\"required\":[\"header_path\",\"struct_name\",\"address\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.write_file\","
      "\"description\":\"Write a text file directly onto the Windows guest VM file system. Dynamically creates directories and resolves environment variables (like %TEMP% or %USERPROFILE%). Excellent for transferring custom C-struct headers or SynTypes.js scripts from the host to the guest VM.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"path\":{\"type\":\"string\",\"description\":\"Absolute path on the guest VM to write the file to (supports Windows environment variables like '%TEMP%\\\\mcfg.h')\"},"
      "\"content\":{\"type\":\"string\",\"description\":\"Content of the file to write\"}"
      "},"
      "\"required\":[\"path\",\"content\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.apply_struct\","
      "\"description\":\"Apply an inline C-style struct definition directly onto a virtual memory address, returning a structured JSON view of the memory fields on-the-fly. Highly agentic: allows the agent to construct custom structures dynamically without needing any filesystem preparation.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"struct_definition\":{\"type\":\"string\",\"description\":\"The C-style struct definition to apply (e.g., 'struct Header { char sig[4]; int len; };')\"},"
      "\"struct_name\":{\"type\":\"string\",\"description\":\"The name of the struct inside the definition to instantiate (e.g., 'Header')\"},"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address or expression representing the target memory location\"},"
      "\"module_name\":{\"type\":\"string\",\"description\":\"The module name to bind the type to (default: 'bootmgr')\"}"
      "},"
      "\"required\":[\"struct_definition\",\"struct_name\",\"address\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_modules\","
      "\"description\":\"List all loaded PE modules with base address, size, checksum, timestamp, and symbol status in structured JSON format.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.get_breakpoints\","
      "\"description\":\"List all set breakpoints with ID, address, symbol, command, enabled status, and hit count in structured JSON format.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.disassemble\","
      "\"description\":\"Disassemble code at specified address for N instructions, returning structured JSON array of instructions.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address to disassemble from\"},"
      "\"count\":{\"type\":\"integer\",\"description\":\"Number of instructions to disassemble (default 10, max 200)\"}"
      "},"
      "\"required\":[\"address\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.read_string\","
      "\"description\":\"Read ASCII or UTF-16 string at specified virtual memory address.\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"address\":{\"type\":\"string\",\"description\":\"Hex address of string in virtual memory\"},"
      "\"max_length\":{\"type\":\"integer\",\"description\":\"Maximum characters to read (default 256, max 4096)\"},"
      "\"wide\":{\"type\":\"boolean\",\"description\":\"True for UTF-16 (wchar_t), false for ASCII/UTF-8 (default false)\"}"
      "},"
      "\"required\":[\"address\"],"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.step\","
      "\"description\":\"Step execution. Set step_over=true (default) to step over ('p'), or false to step in ('t').\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"step_over\":{\"type\":\"boolean\",\"description\":\"True to step over ('p'), false to step into ('t'). Default true.\"}"
      "},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.continue\","
      "\"description\":\"Continue target execution ('g').\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{},"
      "\"additionalProperties\":false"
      "}"
      "},"
      "{"
      "\"name\":\"windbg.set_breakpoint\","
      "\"description\":\"Set a breakpoint at specified expression/address ('bp').\","
      "\"inputSchema\":{"
      "\"type\":\"object\","
      "\"properties\":{"
      "\"expression\":{\"type\":\"string\",\"description\":\"Address or symbol expression for breakpoint (e.g. 'main' or '0x7ff7a8811000')\"}"
      "},"
      "\"required\":[\"expression\"],"
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
  } else if (tool_name == "windbg.apply_synthetic_type") {
    std::string header_path, struct_name, address_str;
    if (!json::TryGetStringField(arguments_fields, "header_path", &header_path) ||
        !json::TryGetStringField(arguments_fields, "struct_name", &struct_name) ||
        !json::TryGetStringField(arguments_fields, "address", &address_str)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: header_path, struct_name, and address are required";
      return outcome;
    }
    std::string module_name = "bootmgr";
    json::TryGetStringField(arguments_fields, "module_name", &module_name);
    std::string syntypes_path = "%TEMP%\\SynTypes.js";
    json::TryGetStringField(arguments_fields, "syntypes_path", &syntypes_path);

    // Expand environment variables dynamically in syntypes_path (e.g. %TEMP% to C:\Users\...)
    char expanded_syntypes[MAX_PATH];
    DWORD syntypes_size = ExpandEnvironmentStringsA(syntypes_path.c_str(), expanded_syntypes, MAX_PATH);
    std::string resolved_syntypes = (syntypes_size > 0 && syntypes_size <= MAX_PATH) ? std::string(expanded_syntypes) : syntypes_path;

    // 1. Automatically unpack/write the embedded SynTypes.js script onto the Windows guest filesystem
    try {
      std::filesystem::path syntypes_file(resolved_syntypes);
      if (syntypes_file.has_parent_path()) {
        std::filesystem::create_directories(syntypes_file.parent_path());
      }
      std::ofstream out(syntypes_file, std::ios::out | std::ios::binary);
      if (out) {
        out.write(kSynTypesJsCodeView.data(), kSynTypesJsCodeView.size());
        out.close();
      }
    } catch (...) {
      // Ignore failures if directory is write-protected but file is already there
    }

    // 2. Try to load SynTypes.js (ignore failure if already loaded or not found immediately)
    executor->Execute(".scriptload \"" + resolved_syntypes + "\"");

    // Expand environment variables dynamically in header_path
    char expanded_header_path[MAX_PATH];
    DWORD header_size = ExpandEnvironmentStringsA(header_path.c_str(), expanded_header_path, MAX_PATH);
    std::string resolved_header = (header_size > 0 && header_size <= MAX_PATH) ? std::string(expanded_header_path) : header_path;

    // 2. Escape backslashes in resolved_header for the JS string literal inside evaluate model
    std::string escaped_header = "";
    for (char c : resolved_header) {
      if (c == '\\') {
        escaped_header += "\\\\";
      } else {
        escaped_header += c;
      }
    }

    // 3. Read the header file definition
    std::string read_expr = "Debugger.Utility.Analysis.SyntheticTypes.ReadHeader(\"" + escaped_header + "\", \"" + module_name + "\")";
    executor->EvaluateModel(read_expr);

    // 4. Create the synthetic structure instance and serialize it to structured JSON
    std::string instance_expr = "Debugger.Utility.Analysis.SyntheticTypes.CreateInstance(\"" + struct_name + "\", " + address_str + ")";
    execution = executor->EvaluateModel(instance_expr);
    is_json_output = true;
  } else if (tool_name == "windbg.apply_struct") {
    std::string struct_def, struct_name, address_str;
    if (!json::TryGetStringField(arguments_fields, "struct_definition", &struct_def) ||
        !json::TryGetStringField(arguments_fields, "struct_name", &struct_name) ||
        !json::TryGetStringField(arguments_fields, "address", &address_str)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: struct_definition, struct_name, and address are required";
      return outcome;
    }
    std::string module_name = "bootmgr";
    json::TryGetStringField(arguments_fields, "module_name", &module_name);

    // 1. Resolve unique %TEMP%\synthetic_inline_<PID>_<SEQ>.h path on guest
    static std::atomic<uint64_t> s_inline_header_seq{0};
    std::string temp_var = "%TEMP%\\synthetic_inline_" + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(++s_inline_header_seq) + ".h";
    char expanded_temp[MAX_PATH];
    DWORD temp_size = ExpandEnvironmentStringsA(temp_var.c_str(), expanded_temp, MAX_PATH);
    std::string inline_h_path = (temp_size > 0 && temp_size <= MAX_PATH) ? std::string(expanded_temp) : "C:\\temp\\synthetic_inline.h";

    // 2. Write the struct_definition inline to %TEMP%\synthetic_inline.h
    try {
      std::filesystem::path h_file(inline_h_path);
      if (h_file.has_parent_path()) {
        std::filesystem::create_directories(h_file.parent_path());
      }
      std::ofstream out(h_file, std::ios::out | std::ios::binary);
      if (!out) {
        outcome.error_code = -32603;
        outcome.error_message = "Failed to create inline header file: " + inline_h_path;
        return outcome;
      }
      out.write(struct_def.data(), struct_def.size());
      out.close();
    } catch (const std::exception& e) {
      outcome.error_code = -32603;
      outcome.error_message = std::string("Filesystem exception creating inline header: ") + e.what();
      return outcome;
    }

    // 3. Resolve %TEMP%\SynTypes.js path on guest
    char expanded_syntypes[MAX_PATH];
    DWORD syntypes_size = ExpandEnvironmentStringsA("%TEMP%\\SynTypes.js", expanded_syntypes, MAX_PATH);
    std::string resolved_syntypes = (syntypes_size > 0 && syntypes_size <= MAX_PATH) ? std::string(expanded_syntypes) : "C:\\temp\\SynTypes.js";

    // 4. Automatically unpack/write the embedded SynTypes.js script onto the Windows guest filesystem
    try {
      std::filesystem::path syntypes_file(resolved_syntypes);
      if (syntypes_file.has_parent_path()) {
        std::filesystem::create_directories(syntypes_file.parent_path());
      }
      std::ofstream out(syntypes_file, std::ios::out | std::ios::binary);
      if (out) {
        out.write(kSynTypesJsCodeView.data(), kSynTypesJsCodeView.size());
        out.close();
      }
    } catch (...) {}

    // 5. Try to load SynTypes.js (ignore failure if already loaded)
    executor->Execute(".scriptload \"" + resolved_syntypes + "\"");

    // 6. Escape backslashes in inline_h_path for the JS string literal inside evaluate model
    std::string escaped_header = "";
    for (char c : inline_h_path) {
      if (c == '\\') {
        escaped_header += "\\\\";
      } else {
        escaped_header += c;
      }
    }

    // 7. Read the header file definition
    std::string read_expr = "Debugger.Utility.Analysis.SyntheticTypes.ReadHeader(\"" + escaped_header + "\", \"" + module_name + "\")";
    executor->EvaluateModel(read_expr);

    // 8. Create the synthetic structure instance and serialize it to structured JSON
    std::string instance_expr = "Debugger.Utility.Analysis.SyntheticTypes.CreateInstance(\"" + struct_name + "\", " + address_str + ")";
    execution = executor->EvaluateModel(instance_expr);
    is_json_output = true;
  } else if (tool_name == "windbg.write_file") {
    std::string path_str, content_str;
    if (!json::TryGetStringField(arguments_fields, "path", &path_str) ||
        !json::TryGetStringField(arguments_fields, "content", &content_str)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: path and content are required";
      return outcome;
    }

    // Resolve any Windows environment variables dynamically (e.g. %TEMP%)
    char expanded_path[MAX_PATH];
    DWORD size = ExpandEnvironmentStringsA(path_str.c_str(), expanded_path, MAX_PATH);
    std::string target_path = (size > 0 && size <= MAX_PATH) ? std::string(expanded_path) : path_str;

    try {
      std::filesystem::path fs_path(target_path);
      // Create parent directories if they don't exist
      if (fs_path.has_parent_path()) {
        std::filesystem::create_directories(fs_path.parent_path());
      }

      // Write text contents to file
      std::ofstream out_file(fs_path, std::ios::out | std::ios::binary);
      if (!out_file) {
        execution.success = false;
        execution.error_message = "Failed to open guest file for writing: " + target_path;
      } else {
        out_file.write(content_str.data(), content_str.size());
        out_file.close();
        execution.success = true;
        execution.output = "{\"success\":true,\"resolved_path\":\"" + json::Escape(target_path) + "\",\"bytes_written\":" + std::to_string(content_str.size()) + "}";
      }
    } catch (const std::exception& e) {
      execution.success = false;
      execution.error_message = std::string("Filesystem exception: ") + e.what();
    }
    is_json_output = true;
  } else if (tool_name == "windbg.get_modules") {
    execution = executor->GetModules();
    is_json_output = true;
  } else if (tool_name == "windbg.get_breakpoints") {
    execution = executor->GetBreakpoints();
    is_json_output = true;
  } else if (tool_name == "windbg.disassemble") {
    std::string addr_str;
    if (!json::TryGetStringField(arguments_fields, "address", &addr_str)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: address is required";
      return outcome;
    }
    int count = 10;
    json::TryGetIntField(arguments_fields, "count", &count);
    uint64_t address = strtoull(addr_str.c_str(), nullptr, 16);
    execution = executor->Disassemble(address, (uint32_t)count);
    is_json_output = true;
  } else if (tool_name == "windbg.read_string") {
    std::string addr_str;
    if (!json::TryGetStringField(arguments_fields, "address", &addr_str)) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: address is required";
      return outcome;
    }
    int max_length = 256;
    json::TryGetIntField(arguments_fields, "max_length", &max_length);
    bool wide = false;
    json::TryGetBoolField(arguments_fields, "wide", &wide);
    uint64_t address = strtoull(addr_str.c_str(), nullptr, 16);
    execution = executor->ReadString(address, (uint32_t)max_length, wide);
    is_json_output = true;
  } else if (tool_name == "windbg.step") {
    bool step_over = true;
    json::TryGetBoolField(arguments_fields, "step_over", &step_over);
    execution = executor->Step(step_over);
  } else if (tool_name == "windbg.continue") {
    execution = executor->ContinueTarget();
  } else if (tool_name == "windbg.set_breakpoint") {
    std::string expr;
    if (!json::TryGetStringField(arguments_fields, "expression", &expr) || expr.empty()) {
      outcome.error_code = -32602;
      outcome.error_message = "Invalid params: expression is required";
      return outcome;
    }
    execution = executor->SetBreakpoint(expr);
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

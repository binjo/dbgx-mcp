#include <DbgEng.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dbgx/mcp/http_server.hpp"
#include "dbgx/mcp/io_echo.hpp"
#include "dbgx/mcp/json.hpp"
#include "dbgx/mcp/json_rpc.hpp"
#include "dbgx/mcp/pipe_server.hpp"
#include "dbgx/windbg/dbgeng_command_executor.hpp"

namespace {

constexpr std::uint16_t kDefaultPort = 5678;

struct RequestTraceState {
  std::string trace_id;
  std::string rpc_method;
  std::string rpc_id;
  std::string tool_name;
  std::string detail_info;
  std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();
};

struct ExtensionState {
  std::mutex mutex;
  std::unique_ptr<dbgx::windbg::DbgEngCommandExecutor> executor;
  std::unique_ptr<dbgx::mcp::JsonRpcRouter> router;
  std::unique_ptr<dbgx::mcp::HttpServer> http_server;
  std::unique_ptr<dbgx::mcp::PipeServer> pipe_server;
  std::atomic<std::uint64_t> next_local_trace_id{1};
  std::string registered_file_path;
  std::uint16_t bound_port = 0;
  std::string bound_pipe_name;
  std::vector<std::string> active_transports;
};

DWORD g_MainThreadId = 0;

ExtensionState& State() {
  static ExtensionState state;
  return state;
}

void LogMessage(const std::string& message) {
  const std::string text = "[windbg-mcp] " + message;

  if (GetCurrentThreadId() == g_MainThreadId) {
    IDebugClient* debug_client = nullptr;
    if (SUCCEEDED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(&debug_client))) &&
        debug_client != nullptr) {
      IDebugControl* debug_control = nullptr;
      if (SUCCEEDED(debug_client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&debug_control))) &&
          debug_control != nullptr) {
        std::string line = text + "\n";
        debug_control->Output(DEBUG_OUTPUT_NORMAL, "%s", line.c_str());
        debug_control->Release();
      }
      debug_client->Release();
    }
  }

  std::string fallback_line = text + "\n";
  OutputDebugStringA(fallback_line.c_str());

  // Write to log file in Temp directory
  char temp_path[MAX_PATH];
  if (GetTempPathA(MAX_PATH, temp_path) != 0) {
    std::string log_file = std::string(temp_path) + "dbgx-mcp-extension.log";
    std::ofstream f(log_file, std::ios::app);
    if (f.is_open()) {
      f << "[" << std::time(nullptr) << "] " << message << "\n";
    }
  }
}

std::string GetRegistryDir() {
  char temp_path[MAX_PATH];
  if (GetTempPathA(MAX_PATH, temp_path) == 0) {
    return "";
  }
  std::filesystem::path path = std::filesystem::path(temp_path) / "dbgx-mcp-registry";
  std::filesystem::create_directories(path);
  return path.string();
}

void RegisterSession(std::uint16_t port, const std::string& pipe_name, const std::vector<std::string>& transports) {
  std::string dir = GetRegistryDir();
  if (dir.empty())
    return;

  std::thread([port, pipe_name, transports, dir]() {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ExtensionState& state = State();
    dbgx::windbg::SessionMetadata meta;
    {
      std::lock_guard<std::mutex> lock(state.mutex);
      if (state.executor) {
        meta = state.executor->GetSessionMetadata();
      }
    }

    std::string filename =
        (port != 0 ? std::to_string(port) : ("pipe_" + std::to_string(GetCurrentProcessId()))) + ".json";
    std::filesystem::path file_path = std::filesystem::path(dir) / filename;
    std::ofstream f(file_path);
    if (f.is_open()) {
      f << "{\"port\":" << port << ",\"pipe_name\":\"" << dbgx::json::Escape(pipe_name) << "\""
        << ",\"transports\":[";
      for (size_t i = 0; i < transports.size(); ++i) {
        if (i > 0)
          f << ",";
        f << "\"" << dbgx::json::Escape(transports[i]) << "\"";
      }
      f << "],\"pid\":" << GetCurrentProcessId() << ",\"target_pid\":" << meta.process_id << ",\"executable\":\""
        << dbgx::json::Escape(meta.executable_name.empty() ? "WinDbg Session" : meta.executable_name) << "\""
        << ",\"info\":\"" << dbgx::json::Escape(meta.target_info.empty() ? "Live Session" : meta.target_info) << "\""
        << ",\"architecture\":\"" << dbgx::json::Escape(meta.architecture.empty() ? "unknown" : meta.architecture)
        << "\""
        << ",\"debuggee_class\":\"" << dbgx::json::Escape(meta.debuggee_class.empty() ? "user" : meta.debuggee_class)
        << "\""
        << ",\"is_ttd\":" << (meta.is_ttd ? "true" : "false")
        << ",\"target_type\":\"" << dbgx::json::Escape(meta.target_type.empty() ? "unknown" : meta.target_type) << "\""
        << "}";
      std::lock_guard<std::mutex> lock(state.mutex);
      state.registered_file_path = file_path.string();
    }
  }).detach();
}

void UnregisterSession() {
  ExtensionState& state = State();
  if (!state.registered_file_path.empty()) {
    std::error_code ec;
    std::filesystem::remove(state.registered_file_path, ec);
    state.registered_file_path.clear();
  }
}

std::uint64_t ElapsedMillis(const RequestTraceState& trace_state) {
  const auto now = std::chrono::steady_clock::now();
  if (now <= trace_state.started_at) {
    return 0;
  }
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now - trace_state.started_at).count());
}

dbgx::mcp::IoTraceContext BuildTraceContext(const RequestTraceState& trace_state, std::string_view stage,
                                            std::string_view outcome = std::string_view()) {
  dbgx::mcp::IoTraceContext context;
  context.trace_id = trace_state.trace_id;
  context.stage = std::string(stage);
  context.rpc_method = trace_state.rpc_method;
  context.rpc_id = trace_state.rpc_id;
  context.tool_name = trace_state.tool_name;
  context.outcome = std::string(outcome);
  context.detail_info = trace_state.detail_info;
  context.duration_ms = ElapsedMillis(trace_state);
  return context;
}

std::string BuildTraceIdFromRpcId(std::string_view rpc_id_raw) {
  return "rpc:" + std::string(rpc_id_raw);
}

RequestTraceState BuildRequestTraceState(const dbgx::mcp::HttpRequest& request) {
  RequestTraceState trace_state;
  trace_state.started_at = std::chrono::steady_clock::now();

  const dbgx::mcp::RequestIoMeta request_meta = dbgx::mcp::ParseRequestIoMeta(request);
  if (request_meta.has_rpc_method) {
    trace_state.rpc_method = request_meta.rpc_method;
  }
  if (request_meta.has_rpc_id) {
    trace_state.rpc_id = request_meta.rpc_id_raw;
    trace_state.trace_id = BuildTraceIdFromRpcId(request_meta.rpc_id_raw);
  }
  if (request_meta.has_tool_name) {
    trace_state.tool_name = request_meta.tool_name;
  }
  if (!request_meta.detail_info.empty()) {
    trace_state.detail_info = request_meta.detail_info;
  }

  if (trace_state.trace_id.empty()) {
    const std::uint64_t sequence = State().next_local_trace_id.fetch_add(1);
    trace_state.trace_id = "local-" + std::to_string(sequence);
  }

  return trace_state;
}

void LogStageEcho(const RequestTraceState& trace_state, std::string_view stage, std::string_view outcome,
                  std::string_view message) noexcept {
  try {
    const dbgx::mcp::IoTraceContext trace_context = BuildTraceContext(trace_state, stage, outcome);
    LogMessage(dbgx::mcp::BuildLifecycleIoSummary(trace_context, message));
  } catch (...) {
    LogMessage("mcp.stage echo unavailable");
  }
}

void LogRequestEcho(const dbgx::mcp::HttpRequest& request, const RequestTraceState& trace_state) noexcept {
  try {
    const dbgx::mcp::IoTraceContext trace_context = BuildTraceContext(trace_state, "request_received");
    LogMessage(dbgx::mcp::BuildRequestIoSummary(request, trace_context));
  } catch (...) {
    LogMessage("mcp.request echo unavailable");
  }
}

void LogResponseEcho(const dbgx::mcp::HttpResponse& response, const RequestTraceState& trace_state,
                     std::string_view stage) noexcept {
  try {
    const dbgx::mcp::IoTraceContext trace_context = BuildTraceContext(trace_state, stage);
    LogMessage(dbgx::mcp::BuildResponseIoSummary(response, trace_context));
  } catch (...) {
    LogMessage("mcp.response echo unavailable");
  }
}

dbgx::mcp::HttpResponse FinishMcpRequest(dbgx::mcp::HttpResponse response, const RequestTraceState& trace_state) {
  LogResponseEcho(response, trace_state, "response_sent");
  return response;
}

bool IsProcessAlive(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (process == nullptr) {
    return GetLastError() == ERROR_ACCESS_DENIED;
  }

  DWORD exit_code = 0;
  if (GetExitCodeProcess(process, &exit_code)) {
    CloseHandle(process);
    return exit_code == STILL_ACTIVE;
  }

  CloseHandle(process);
  return false;
}

dbgx::mcp::HttpResponse HandleSessionsRequest(const dbgx::mcp::HttpRequest& request) {
  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.content_type = "application/json";

  std::string dir = GetRegistryDir();
  std::string json = "[";
  bool first = true;

  if (!dir.empty() && std::filesystem::exists(dir)) {
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
      if (entry.path().extension() == ".json") {
        std::ifstream f(entry.path());
        if (f.is_open()) {
          std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
          f.close();

          size_t pid_pos = content.find("\"pid\":");
          while (pid_pos != std::string::npos) {
            if (pid_pos == 0 || content[pid_pos - 1] != '_') {
              break;
            }
            pid_pos = content.find("\"pid\":", pid_pos + 6);
          }

          if (pid_pos != std::string::npos) {
            size_t val_start = pid_pos + 6;
            size_t val_end = content.find_first_not_of("0123456789", val_start);
            if (val_end != std::string::npos && val_end > val_start) {
              std::string pid_str = content.substr(val_start, val_end - val_start);
              DWORD host_pid = static_cast<DWORD>(std::stoul(pid_str));

              if (!IsProcessAlive(host_pid)) {
                std::error_code ec;
                std::filesystem::remove(entry.path(), ec);
                continue;
              }
            }
          }

          if (!first)
            json += ",";
          json += content;
          first = false;
        }
      }
    }
  }
  json += "]";
  response.body = json;
  return response;
}

dbgx::mcp::HttpResponse HandleHttpRequest(const dbgx::mcp::HttpRequest& request) {
  if (request.path == "/sessions") {
    return HandleSessionsRequest(request);
  }

  dbgx::mcp::HttpResponse response;
  const RequestTraceState trace_state = BuildRequestTraceState(request);

  if (request.path != "/mcp") {
    response.status_code = 404;
    response.body = "{\"error\":\"Not Found\"}";
    return response;
  }

  LogRequestEcho(request, trace_state);

  const auto origin_it = request.headers.find("origin");
  if (origin_it != request.headers.end() && !dbgx::mcp::IsOriginAllowed(origin_it->second)) {
    response.status_code = 403;
    response.body = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"Forbidden origin\"}}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  const auto protocol_header_it = request.headers.find("mcp-protocol-version");
  if (protocol_header_it != request.headers.end()) {
    const std::string& protocol = protocol_header_it->second;
    if (protocol != "2025-11-25" && protocol != "2025-03-26") {
      response.status_code = 400;
      response.body =
          "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Unsupported MCP protocol "
          "version\"}}";
      return FinishMcpRequest(std::move(response), trace_state);
    }
  }

  if (request.method == "GET") {
    response.status_code = 405;
    response.body = "{\"error\":\"GET stream is not implemented in this MVP\"}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  if (request.method != "POST") {
    response.status_code = 405;
    response.body = "{\"error\":\"Method Not Allowed\"}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  LogStageEcho(trace_state, "route_dispatch", "in_progress", "dispatching JSON-RPC request");
  if (trace_state.rpc_method == "tools/call") {
    LogStageEcho(trace_state, "tool_execute_start", "in_progress", "entering tool executor");
  }

  ExtensionState& state = State();
  dbgx::mcp::JsonRpcRouter* router = nullptr;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    router = state.router.get();
  }

  if (router == nullptr) {
    response.status_code = 500;
    response.body = "{\"error\":\"Router is not initialized\"}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  const dbgx::mcp::JsonRpcHttpResult rpc_result = router->HandleJsonRpcPost(request.body);
  response.status_code = rpc_result.status_code;
  response.content_type = rpc_result.content_type;
  response.has_body = rpc_result.has_body;
  response.body = rpc_result.body;
  if (trace_state.rpc_method == "tools/call") {
    LogResponseEcho(response, trace_state, "tool_execute_end");
  }
  return FinishMcpRequest(std::move(response), trace_state);
}

std::string HandlePipeJsonRpcRequest(const std::string& request_line) {
  ExtensionState& state = State();
  dbgx::mcp::JsonRpcRouter* router = nullptr;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    router = state.router.get();
  }

  if (router == nullptr) {
    return "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"Router is not initialized\"}}";
  }

  const dbgx::mcp::JsonRpcHttpResult rpc_result = router->HandleJsonRpcPost(request_line);
  return rpc_result.body;
}

void Cleanup() {
  ExtensionState& state = State();
  std::lock_guard<std::mutex> lock(state.mutex);

  if (state.pipe_server != nullptr) {
    state.pipe_server->Stop();
    state.pipe_server.reset();
  }

  if (state.http_server != nullptr) {
    state.http_server->Stop();
    state.http_server.reset();
  }

  state.router.reset();
  state.executor.reset();
  state.active_transports.clear();
}

}  // namespace

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags) {
  g_MainThreadId = GetCurrentThreadId();

  if (version != nullptr) {
    *version = DEBUG_EXTENSION_VERSION(1, 0);
  }
  if (flags != nullptr) {
    *flags = 0;
  }

  ExtensionState& state = State();
  std::lock_guard<std::mutex> lock(state.mutex);

  if ((state.http_server != nullptr && state.http_server->IsRunning()) ||
      (state.pipe_server != nullptr && state.pipe_server->IsRunning())) {
    return S_OK;
  }

  state.executor = std::make_unique<dbgx::windbg::DbgEngCommandExecutor>();
  state.router = std::make_unique<dbgx::mcp::JsonRpcRouter>(state.executor.get());

  // Determine requested transport: "http", "pipe", or "both" (default: "both")
  char transport_buf[64] = {0};
  std::string transport_mode = "both";
  if (GetEnvironmentVariableA("WINDBG_MCP_TRANSPORT", transport_buf, sizeof(transport_buf)) > 0) {
    transport_mode = transport_buf;
    std::transform(transport_mode.begin(), transport_mode.end(), transport_mode.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  }

  bool enable_http = (transport_mode == "http" || transport_mode == "both" || transport_mode == "all");
  bool enable_pipe = (transport_mode == "pipe" || transport_mode == "both" || transport_mode == "all");

  std::uint16_t initial_port = kDefaultPort;
  char port_buf[32] = {0};
  if (GetEnvironmentVariableA("WINDBG_MCP_PORT", port_buf, sizeof(port_buf)) > 0) {
    try {
      initial_port = static_cast<std::uint16_t>(std::stoul(port_buf));
    } catch (...) {
    }
  }

  char bind_addr_buf[256];
  std::string bind_host = "127.0.0.1";
  if (GetEnvironmentVariableA("WINDBG_MCP_BIND", bind_addr_buf, sizeof(bind_addr_buf)) > 0) {
    bind_host = bind_addr_buf;
  }

  state.active_transports.clear();
  state.bound_port = 0;
  state.bound_pipe_name.clear();

  // 1. Start HTTP Server if enabled
  if (enable_http) {
    state.http_server = std::make_unique<dbgx::mcp::HttpServer>();
    std::string http_error;
    dbgx::mcp::HttpServerStartReport start_report;
    if (state.http_server->Start(bind_host, initial_port, HandleHttpRequest, &http_error, &start_report)) {
      state.bound_port = state.http_server->BoundPort();
      state.active_transports.push_back("http");
      LogMessage("HTTP MCP server listening on http://" + bind_host + ":" + std::to_string(state.bound_port) +
                 "/mcp (Keep-Alive enabled)");
    } else {
      LogMessage("HTTP server start failed: " + http_error);
      if (!enable_pipe) {
        state.http_server.reset();
        state.router.reset();
        state.executor.reset();
        return E_FAIL;
      }
    }
  }

  // 2. Start Named Pipe Server if enabled
  if (enable_pipe) {
    state.pipe_server = std::make_unique<dbgx::mcp::PipeServer>();
    std::string pipe_name;
    char pipe_buf[256] = {0};
    if (GetEnvironmentVariableA("WINDBG_MCP_PIPE_NAME", pipe_buf, sizeof(pipe_buf)) > 0) {
      pipe_name = pipe_buf;
    } else {
      std::uint16_t port_id = (state.bound_port != 0) ? state.bound_port : initial_port;
      pipe_name = "dbgx-mcp-" + std::to_string(port_id);
    }

    std::string pipe_error;
    if (state.pipe_server->Start(pipe_name, HandlePipeJsonRpcRequest, &pipe_error)) {
      state.bound_pipe_name = pipe_name;
      state.active_transports.push_back("pipe");
      LogMessage("Named Pipe MCP server listening on \\\\.\\pipe\\" + pipe_name + " (High-Speed Local IPC)");
    } else {
      LogMessage("Named Pipe server start failed: " + pipe_error);
      if (!enable_http || state.active_transports.empty()) {
        state.pipe_server.reset();
        state.router.reset();
        state.executor.reset();
        return E_FAIL;
      }
    }
  }

  RegisterSession(state.bound_port, state.bound_pipe_name, state.active_transports);

  LogMessage("  * Background request logs are written to %TEMP%\\dbgx-mcp-extension.log to prevent UI deadlocks.");
  LogMessage("  * AI background tool executions will display '[Background Job]' status indicators in this window.");
  return S_OK;
}

extern "C" HRESULT CALLBACK DebugExtensionCanUnload(void) {
  return S_OK;
}

extern "C" void CALLBACK DebugExtensionUninitialize(void) {
  UnregisterSession();
  Cleanup();
}

extern "C" void CALLBACK DebugExtensionUnload(void) {
  UnregisterSession();
  Cleanup();
}

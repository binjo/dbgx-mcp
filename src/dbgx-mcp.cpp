#include <DbgEng.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
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
  // Bearer token required on the HTTP transport. Empty => no auth (loopback only).
  std::string auth_token;

  std::mutex register_cv_mutex;
  std::condition_variable register_cv;
  bool stop_register = false;
  std::thread register_thread;
};

DWORD g_MainThreadId = 0;

ExtensionState& State() {
  static ExtensionState state;
  return state;
}

bool IsLoopbackHost(std::string_view host) {
  return host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";
}

// Constant-time-ish comparison so a timing side channel cannot be used to guess the token.
bool TokensEqual(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  unsigned char diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
}

bool IsHttpRequestAuthorized(const dbgx::mcp::HttpRequest& request, const std::string& expected_token) {
  if (expected_token.empty()) {
    return true;
  }
  const auto it = request.headers.find("authorization");
  if (it == request.headers.end()) {
    return false;
  }
  std::string_view value = it->second;
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1);
  }
  if (value.size() < 7) {
    return false;
  }
  std::string scheme(value.substr(0, 7));
  std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (scheme != "bearer ") {
    return false;
  }
  value.remove_prefix(7);
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.remove_prefix(1);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
    value.remove_suffix(1);
  }
  return TokensEqual(value, expected_token);
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

std::string ReadEnvString(const char* name) {
  const DWORD needed = GetEnvironmentVariableA(name, nullptr, 0);
  if (needed == 0) {
    return "";
  }
  std::string buf(needed, '\0');
  const DWORD written = GetEnvironmentVariableA(name, buf.data(), needed);
  if (written == 0 || written >= needed) {
    return "";
  }
  buf.resize(written);
  return buf;
}

void WriteSessionRegistryFile(std::uint16_t port, const std::string& pipe_name,
                              const std::vector<std::string>& transports, const std::string& auth_token,
                              const dbgx::windbg::SessionMetadata& meta, std::string* out_registered_path) {
  std::string dir = GetRegistryDir();
  if (dir.empty())
    return;

  std::string filename =
      (port != 0 ? std::to_string(port) : ("pipe_" + std::to_string(GetCurrentProcessId()))) + ".json";
  std::filesystem::path file_path = std::filesystem::path(dir) / filename;
  std::filesystem::path tmp_path = std::filesystem::path(dir) / (filename + ".tmp");
  std::ofstream f(tmp_path, std::ios::out | std::ios::trunc);
  if (f.is_open()) {
    f << "{\"port\":" << port << ",\"pipe_name\":\"" << dbgx::json::Escape(pipe_name) << "\""
      << ",\"transports\":[";
    for (size_t i = 0; i < transports.size(); ++i) {
      if (i > 0)
        f << ",";
      f << "\"" << dbgx::json::Escape(transports[i]) << "\"";
    }
    f << "]";
    if (!auth_token.empty()) {
      f << ",\"token\":\"" << dbgx::json::Escape(auth_token) << "\"";
    }
    f << ",\"pid\":" << GetCurrentProcessId() << ",\"target_pid\":" << meta.process_id << ",\"executable\":\""
      << dbgx::json::Escape(meta.executable_name.empty() ? "WinDbg Session" : meta.executable_name) << "\""
      << ",\"info\":\"" << dbgx::json::Escape(meta.target_info.empty() ? "Live Session" : meta.target_info) << "\""
      << ",\"architecture\":\"" << dbgx::json::Escape(meta.architecture.empty() ? "unknown" : meta.architecture)
      << "\""
      << ",\"debuggee_class\":\"" << dbgx::json::Escape(meta.debuggee_class.empty() ? "user" : meta.debuggee_class)
      << "\""
      << ",\"is_ttd\":" << (meta.is_ttd ? "true" : "false")
      << ",\"target_type\":\"" << dbgx::json::Escape(meta.target_type.empty() ? "unknown" : meta.target_type) << "\""
      << "}";
    f.close();
    std::error_code ec;
    std::filesystem::rename(tmp_path, file_path, ec);
    if (ec) {
      std::filesystem::copy_file(tmp_path, file_path, std::filesystem::copy_options::overwrite_existing, ec);
      std::filesystem::remove(tmp_path, ec);
    }
    if (out_registered_path != nullptr) {
      *out_registered_path = file_path.string();
    }
  }
}

void UnregisterSession() {
  ExtensionState& state = State();
  std::string path_to_remove;
  {
    std::lock_guard<std::mutex> lock(state.mutex);
    path_to_remove = std::move(state.registered_file_path);
    state.registered_file_path.clear();
  }
  if (!path_to_remove.empty()) {
    std::error_code ec;
    std::filesystem::remove(path_to_remove, ec);
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
  (void)request;
  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.content_type = "application/json";

  std::string dir = GetRegistryDir();
  std::string json = "[";
  bool first = true;

  if (!dir.empty() && std::filesystem::exists(dir)) {
    std::error_code iter_ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir, iter_ec)) {
      if (entry.path().extension() == ".json") {
        std::ifstream f(entry.path());
        if (f.is_open()) {
          std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
          f.close();

          dbgx::json::FieldMap parsed_session;
          std::string parse_err;
          if (!dbgx::json::ParseObjectFields(content, &parsed_session, &parse_err)) {
            continue;
          }

          int host_pid_int = 0;
          if (dbgx::json::TryGetIntField(parsed_session, "pid", &host_pid_int) && host_pid_int > 0) {
            DWORD host_pid = static_cast<DWORD>(host_pid_int);
            if (!IsProcessAlive(host_pid)) {
              std::error_code ec;
              std::filesystem::remove(entry.path(), ec);
              continue;
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

bool IsSupportedProtocolHeader(std::string_view version) {
  return version == "2024-11-05" || version == "2025-03-26" || version == "2025-06-18" || version == "2025-11-25";
}

dbgx::mcp::HttpResponse HandleHttpRequest(const dbgx::mcp::HttpRequest& request) {
  const auto origin_it = request.headers.find("origin");
  if (origin_it != request.headers.end() && !dbgx::mcp::IsOriginAllowed(origin_it->second)) {
    dbgx::mcp::HttpResponse response;
    response.status_code = 403;
    response.body = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"Forbidden origin\"}}";
    return response;
  }

  // Bearer-token gate (applies to /mcp and /sessions alike when a token is configured).
  {
    std::string expected_token;
    {
      ExtensionState& state = State();
      std::lock_guard<std::mutex> lock(state.mutex);
      expected_token = state.auth_token;
    }
    if (!IsHttpRequestAuthorized(request, expected_token)) {
      dbgx::mcp::HttpResponse denied;
      denied.status_code = 401;
      denied.body =
          "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"Unauthorized: missing or invalid "
          "bearer token. Set WINDBG_MCP_TOKEN on the client to match the value configured for WinDbg.\"}}";
      return denied;
    }
  }

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

  const auto protocol_header_it = request.headers.find("mcp-protocol-version");
  if (protocol_header_it != request.headers.end() && !protocol_header_it->second.empty()) {
    const std::string& protocol = protocol_header_it->second;
    if (!IsSupportedProtocolHeader(protocol)) {
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
  {
    std::lock_guard<std::mutex> cv_lock(state.register_cv_mutex);
    state.stop_register = true;
  }
  state.register_cv.notify_all();
  if (state.register_thread.joinable()) {
    state.register_thread.join();
  }

  std::unique_ptr<dbgx::mcp::PipeServer> pipe_server;
  std::unique_ptr<dbgx::mcp::HttpServer> http_server;
  std::unique_ptr<dbgx::mcp::JsonRpcRouter> router;
  std::unique_ptr<dbgx::windbg::DbgEngCommandExecutor> executor;

  {
    std::lock_guard<std::mutex> lock(state.mutex);
    pipe_server = std::move(state.pipe_server);
    http_server = std::move(state.http_server);
    state.active_transports.clear();
    state.auth_token.clear();
  }

  // Stop servers outside state.mutex so in-flight request handlers acquiring state.mutex cannot deadlock
  if (pipe_server != nullptr) {
    pipe_server->Stop();
    pipe_server.reset();
  }

  if (http_server != nullptr) {
    http_server->Stop();
    http_server.reset();
  }

  {
    std::lock_guard<std::mutex> lock(state.mutex);
    router = std::move(state.router);
    executor = std::move(state.executor);
  }

  router.reset();
  executor.reset();
}

}  // namespace

extern "C" HRESULT CALLBACK DebugExtensionInitialize(PULONG version, PULONG flags) {
  if (version != nullptr) {
    *version = DEBUG_EXTENSION_VERSION(1, 0);
  }
  if (flags != nullptr) {
    *flags = 0;
  }

  ExtensionState& state = State();
  std::unique_lock<std::mutex> lock(state.mutex);

  if ((state.http_server != nullptr && state.http_server->IsRunning()) ||
      (state.pipe_server != nullptr && state.pipe_server->IsRunning())) {
    return S_OK;
  }

  g_MainThreadId = GetCurrentThreadId();

  state.executor = std::make_unique<dbgx::windbg::DbgEngCommandExecutor>();
  state.router = std::make_unique<dbgx::mcp::JsonRpcRouter>(state.executor.get());

  // Determine requested transport: "http", "pipe", or "both" (default: "both")
  std::string transport_mode = ReadEnvString("WINDBG_MCP_TRANSPORT");
  if (transport_mode.empty()) {
    transport_mode = "both";
  } else {
    std::transform(transport_mode.begin(), transport_mode.end(), transport_mode.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  }

  bool enable_http = (transport_mode == "http" || transport_mode == "both" || transport_mode == "all");
  bool enable_pipe = (transport_mode == "pipe" || transport_mode == "both" || transport_mode == "all");
  if (!enable_http && !enable_pipe) {
    LogMessage("Invalid WINDBG_MCP_TRANSPORT='" + transport_mode + "'; expected 'http', 'pipe', or 'both'.");
    state.router.reset();
    state.executor.reset();
    return E_FAIL;
  }

  std::uint16_t initial_port = kDefaultPort;
  const std::string port_str = ReadEnvString("WINDBG_MCP_PORT");
  if (!port_str.empty()) {
    try {
      std::size_t idx = 0;
      unsigned long parsed = std::stoul(port_str, &idx, 10);
      if (idx == port_str.size() && parsed >= 1 && parsed <= 65535) {
        initial_port = static_cast<std::uint16_t>(parsed);
      } else {
        LogMessage("Invalid WINDBG_MCP_PORT='" + port_str + "'; falling back to " + std::to_string(kDefaultPort));
      }
    } catch (...) {
      LogMessage("Invalid WINDBG_MCP_PORT='" + port_str + "'; falling back to " + std::to_string(kDefaultPort));
    }
  }

  std::string bind_host = ReadEnvString("WINDBG_MCP_BIND");
  if (bind_host.empty()) {
    bind_host = "127.0.0.1";
  }

  // HTTP authentication is opt-in: set WINDBG_MCP_TOKEN=<secret> (on both WinDbg and the
  // bridge) to require `Authorization: Bearer <secret>` on /mcp and /sessions. Without it the
  // Origin check and the named-pipe ACL are the only access controls, which is adequate for
  // loopback and host-only VM networks.
  state.auth_token = ReadEnvString("WINDBG_MCP_TOKEN");

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
      if (!state.auth_token.empty()) {
        LogMessage("HTTP bearer token authentication enabled (WINDBG_MCP_TOKEN).");
      } else if (!IsLoopbackHost(bind_host)) {
        LogMessage("HTTP server is reachable from the network without authentication; set WINDBG_MCP_TOKEN to "
                   "require a bearer token if the network is not trusted.");
      }
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
    std::string pipe_name = ReadEnvString("WINDBG_MCP_PIPE_NAME");
    if (pipe_name.empty()) {
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
        if (state.http_server != nullptr) {
          state.http_server->Stop();
          state.http_server.reset();
        }
        state.router.reset();
        state.executor.reset();
        return E_FAIL;
      }
    }
  }

  // Write initial session registry entry immediately without calling into DbgEng (since
  // DebugExtensionInitialize holds the DbgEng engine lock until it returns).
  dbgx::windbg::SessionMetadata initial_meta;
  initial_meta.process_id = GetCurrentProcessId();
  WriteSessionRegistryFile(state.bound_port, state.bound_pipe_name, state.active_transports, state.auth_token,
                           initial_meta, &state.registered_file_path);

  const std::uint16_t bound_port = state.bound_port;
  const std::string bound_pipe_name = state.bound_pipe_name;
  const std::vector<std::string> active_transports = state.active_transports;
  const std::string auth_token = state.auth_token;

  if (state.register_thread.joinable()) {
    state.register_thread.join();
  }
  {
    std::lock_guard<std::mutex> cv_lock(state.register_cv_mutex);
    state.stop_register = false;
  }
  state.register_thread = std::thread([bound_port, bound_pipe_name, active_transports, auth_token]() {
    ExtensionState& st = State();
    {
      std::unique_lock<std::mutex> cv_lock(st.register_cv_mutex);
      if (st.register_cv.wait_for(cv_lock, std::chrono::milliseconds(500), [&st] { return st.stop_register; })) {
        return;
      }
    }
    dbgx::windbg::IWinDbgCommandExecutor* exec = nullptr;
    {
      std::lock_guard<std::mutex> st_lock(st.mutex);
      exec = st.executor.get();
    }
    if (exec == nullptr) {
      return;
    }
    dbgx::windbg::SessionMetadata enriched_meta = exec->GetSessionMetadata();
    std::string reg_path;
    WriteSessionRegistryFile(bound_port, bound_pipe_name, active_transports, auth_token, enriched_meta, &reg_path);
    if (!reg_path.empty()) {
      std::lock_guard<std::mutex> st_lock(st.mutex);
      st.registered_file_path = std::move(reg_path);
    }
  });

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

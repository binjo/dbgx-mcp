#include "dbgx/mcp/http_server.hpp"
#include "dbgx/mcp/io_echo.hpp"
#include "dbgx/mcp/json_rpc.hpp"
#include "dbgx/windbg/dbgeng_command_executor.hpp"

#include <DbgEng.h>
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace {

constexpr std::uint16_t kDefaultPort = 5678;

struct RequestTraceState {
  std::string trace_id;
  std::string rpc_method;
  std::string rpc_id;
  std::string tool_name;
  std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();
};

struct ExtensionState {
  std::mutex mutex;
  std::unique_ptr<dbgx::windbg::DbgEngCommandExecutor> executor;
  std::unique_ptr<dbgx::mcp::JsonRpcRouter> router;
  std::unique_ptr<dbgx::mcp::HttpServer> server;
  std::atomic<std::uint64_t> next_local_trace_id{1};
};

ExtensionState& State() {
  static ExtensionState state;
  return state;
}

void LogMessage(const std::string& message) {
  const std::string text = "[windbg-mcp] " + message;

  IDebugClient* debug_client = nullptr;
  if (SUCCEEDED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(&debug_client))) &&
      debug_client != nullptr) {
    IDebugControl* debug_control = nullptr;
    if (SUCCEEDED(debug_client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&debug_control))) &&
        debug_control != nullptr) {
      std::string line = text + "\n";
      debug_control->Output(DEBUG_OUTPUT_NORMAL, "%s", line.c_str());
      debug_control->Release();
      debug_client->Release();
      return;
    }

    debug_client->Release();
  }

  std::string fallback_line = text + "\n";
  OutputDebugStringA(fallback_line.c_str());
}

std::uint64_t ElapsedMillis(const RequestTraceState& trace_state) {
  const auto now = std::chrono::steady_clock::now();
  if (now <= trace_state.started_at) {
    return 0;
  }
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(now - trace_state.started_at).count());
}

dbgx::mcp::IoTraceContext BuildTraceContext(
    const RequestTraceState& trace_state,
    std::string_view stage,
    std::string_view outcome = std::string_view()) {
  dbgx::mcp::IoTraceContext context;
  context.trace_id = trace_state.trace_id;
  context.stage = std::string(stage);
  context.rpc_method = trace_state.rpc_method;
  context.rpc_id = trace_state.rpc_id;
  context.tool_name = trace_state.tool_name;
  context.outcome = std::string(outcome);
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

  if (trace_state.trace_id.empty()) {
    const std::uint64_t sequence = State().next_local_trace_id.fetch_add(1);
    trace_state.trace_id = "local-" + std::to_string(sequence);
  }

  return trace_state;
}

void LogStageEcho(
    const RequestTraceState& trace_state,
    std::string_view stage,
    std::string_view outcome,
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

void LogResponseEcho(
    const dbgx::mcp::HttpResponse& response,
    const RequestTraceState& trace_state,
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

dbgx::mcp::HttpResponse HandleRequest(const dbgx::mcp::HttpRequest& request) {
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
    response.body =
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"Forbidden origin\"}}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  const auto protocol_header_it = request.headers.find("mcp-protocol-version");
  if (protocol_header_it != request.headers.end()) {
    const std::string& protocol = protocol_header_it->second;
    if (protocol != "2025-11-25" && protocol != "2025-03-26") {
      response.status_code = 400;
      response.body =
          "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Unsupported MCP protocol version\"}}";
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
  std::lock_guard<std::mutex> lock(state.mutex);
  if (state.router == nullptr) {
    response.status_code = 500;
    response.body = "{\"error\":\"Router is not initialized\"}";
    return FinishMcpRequest(std::move(response), trace_state);
  }

  const dbgx::mcp::JsonRpcHttpResult rpc_result = state.router->HandleJsonRpcPost(request.body);
  response.status_code = rpc_result.status_code;
  response.content_type = rpc_result.content_type;
  response.has_body = rpc_result.has_body;
  response.body = rpc_result.body;
  if (trace_state.rpc_method == "tools/call") {
    LogResponseEcho(response, trace_state, "tool_execute_end");
  }
  return FinishMcpRequest(std::move(response), trace_state);
}

void Cleanup() {
  ExtensionState& state = State();
  std::lock_guard<std::mutex> lock(state.mutex);

  if (state.server != nullptr) {
    state.server->Stop();
    state.server.reset();
  }

  state.router.reset();
  state.executor.reset();
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
  std::lock_guard<std::mutex> lock(state.mutex);

  if (state.server != nullptr && state.server->IsRunning()) {
    return S_OK;
  }

  state.executor = std::make_unique<dbgx::windbg::DbgEngCommandExecutor>();
  state.router = std::make_unique<dbgx::mcp::JsonRpcRouter>(state.executor.get());
  state.server = std::make_unique<dbgx::mcp::HttpServer>();

  char bind_addr_buf[256];
  std::string bind_host = "127.0.0.1";
  if (GetEnvironmentVariableA("WINDBG_MCP_BIND", bind_addr_buf, sizeof(bind_addr_buf)) > 0) {
    bind_host = bind_addr_buf;
  }

  std::string error_message;
  dbgx::mcp::HttpServerStartReport start_report;
  if (!state.server->Start(bind_host, kDefaultPort, HandleRequest, &error_message, &start_report)) {
    LogMessage(
        "Failed to start HTTP server: " + error_message + " (bind_host=" + bind_host +
        ", initial_port=" + std::to_string(kDefaultPort) +
        ", attempts=" + std::to_string(start_report.attempt_count) +
        ", conflicts=" + std::to_string(start_report.conflict_count) + ")");
    state.server.reset();
    state.router.reset();
    state.executor.reset();
    return E_FAIL;
  }

  if (start_report.fallback_used) {
    LogMessage(
        "HTTP MCP bind fallback engaged: bind_host=" + bind_host +
        ", initial_port=" + std::to_string(start_report.initial_port) +
        ", conflicts=" + std::to_string(start_report.conflict_count) +
        ", final_port=" + std::to_string(state.server->BoundPort()));
  }
  LogMessage("HTTP MCP server listening on http://" + bind_host + ":" + std::to_string(state.server->BoundPort()) +
             "/mcp");
  return S_OK;
}

extern "C" HRESULT CALLBACK DebugExtensionCanUnload(void) {
  return S_OK;
}

extern "C" void CALLBACK DebugExtensionUninitialize(void) {
  Cleanup();
}

extern "C" void CALLBACK DebugExtensionUnload(void) {
  Cleanup();
}

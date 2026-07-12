#include "dbgx/mcp/json_rpc.hpp"
#include "dbgx/mcp/io_echo.hpp"
#include "dbgx/mcp/http_server.hpp"
#include "dbgx/mcp/json.hpp"
#include "dbgx/windbg/catalog.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

namespace json = dbgx::json;

class FakeExecutor final : public dbgx::windbg::IWinDbgCommandExecutor {
 public:
  dbgx::windbg::CommandExecutionResult Execute(const std::string& command, const dbgx::windbg::CommandExecutionOptions& options) override {
    ++call_count;
    last_command = command;
    last_options = options;
    if (should_fail) {
      return {
          false,
          "",
          failure_message,
      };
    }
    return {
        true,
        output,
        "",
    };
  }

  dbgx::windbg::SessionMetadata GetSessionMetadata() override {
    return {1234, "test.exe", "Live Session", "x64", "user"};
  }

  dbgx::windbg::CommandExecutionResult EvaluateModel(const std::string&, int) override {
    return {true, "{}", ""};
  }

  dbgx::windbg::CommandExecutionResult GetContextSnapshot() override {
    return {true, "{}", ""};
  }

  dbgx::windbg::CommandExecutionResult ReadMemory(std::uint64_t, std::uint32_t) override {
    return {true, "00", ""};
  }

  dbgx::windbg::CommandExecutionResult WriteMemory(std::uint64_t, const std::string&) override {
    return {true, "{\"bytes_written\":2}", ""};
  }

  dbgx::windbg::CommandExecutionResult SearchMemory(std::uint64_t, std::uint64_t, const std::string&) override {
    return {true, "[]", ""};
  }

  dbgx::windbg::CommandExecutionResult GetThreads() override {
    return {true, "[{\"thread_index\":0,\"system_thread_id\":9999,\"is_current\":true}]", ""};
  }

  dbgx::windbg::DebuggerExecutionState GetExecutionState() override {
    return {1, "break", false, false, true, "Broken in"};
  }

  bool InterruptTarget() override {
    return true;
  }

  bool should_fail = false;
  std::string failure_message = "failed";
  std::string output = "ok";
  std::string last_command;
  dbgx::windbg::CommandExecutionOptions last_options;
  int call_count = 0;
};

bool Contains(const std::string& text, const std::string& expected_substring) {
  return text.find(expected_substring) != std::string::npos;
}

void Expect(bool condition, const std::string& message, int* failures) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << '\n';
    ++(*failures);
  }
}

void TestTryGetIntField(int* failures) {
  dbgx::json::FieldMap fields;
  fields["int_val"] = " 42 ";
  fields["not_int"] = "\"string\"";
  fields["empty"] = "";

  int val = 0;
  Expect(dbgx::json::TryGetIntField(fields, "int_val", &val), "TryGetIntField should succeed for integer", failures);
  Expect(val == 42, "TryGetIntField should return correct integer", failures);

  Expect(!dbgx::json::TryGetIntField(fields, "not_int", &val), "TryGetIntField should fail for string", failures);
  Expect(!dbgx::json::TryGetIntField(fields, "empty", &val), "TryGetIntField should fail for empty", failures);
  Expect(!dbgx::json::TryGetIntField(fields, "missing", &val), "TryGetIntField should fail for missing", failures);
}

dbgx::mcp::HttpResponse MakeNoopHttpResponse(const dbgx::mcp::HttpRequest&) {
  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.content_type = "application/json; charset=utf-8";
  response.body = "{}";
  return response;
}

void TestHttpServerStartBindsWithoutConflict(int* failures) {
  dbgx::mcp::HttpServer server;
  dbgx::mcp::HttpServerStartReport start_report;
  std::string error_message;

  const bool started =
      server.Start("127.0.0.1", 0, MakeNoopHttpResponse, &error_message, &start_report);
  Expect(started, "server should start on an available port", failures);
  if (!started) {
    return;
  }

  Expect(start_report.attempt_count == 1, "initial available bind should use exactly one attempt", failures);
  Expect(start_report.conflict_count == 0, "initial available bind should have no conflicts", failures);
  Expect(start_report.bound_port == server.BoundPort(), "start report should expose actual bound port", failures);
  Expect(server.BoundPort() != 0, "server should report a non-zero bound port", failures);
  server.Stop();
}

void TestHttpServerFallbackAfterPortConflict(int* failures) {
  dbgx::mcp::HttpServer blocker;
  std::string blocker_error_message;
  const bool blocker_started = blocker.Start("127.0.0.1", 0, MakeNoopHttpResponse, &blocker_error_message);
  Expect(blocker_started, "blocker server should start for port-conflict test", failures);
  if (!blocker_started) {
    return;
  }

  const std::uint16_t blocked_port = blocker.BoundPort();
  dbgx::mcp::HttpServer candidate;
  dbgx::mcp::HttpServerStartOptions start_options;
  start_options.max_port_attempts = 16;
  dbgx::mcp::HttpServerStartReport start_report;
  std::string error_message;

  const bool started = candidate.Start(
      "127.0.0.1",
      blocked_port,
      MakeNoopHttpResponse,
      &error_message,
      &start_report,
      &start_options);
  Expect(started, "server should auto-fallback when initial port is occupied", failures);
  if (started) {
    Expect(start_report.conflict_count >= 1, "fallback start should report at least one address-in-use conflict", failures);
    Expect(start_report.attempt_count >= 2, "fallback start should require at least two attempts", failures);
    Expect(start_report.fallback_used, "fallback start should be flagged as fallback_used", failures);
    Expect(candidate.BoundPort() != blocked_port, "fallback start should bind a different port", failures);
    candidate.Stop();
  }

  blocker.Stop();
}

void TestHttpServerFailsAfterMaxConflictAttempts(int* failures) {
  dbgx::mcp::HttpServer blocker;
  std::string blocker_error_message;
  const bool blocker_started = blocker.Start("127.0.0.1", 0, MakeNoopHttpResponse, &blocker_error_message);
  Expect(blocker_started, "blocker server should start for max-attempts failure test", failures);
  if (!blocker_started) {
    return;
  }

  dbgx::mcp::HttpServer candidate;
  dbgx::mcp::HttpServerStartOptions start_options;
  start_options.max_port_attempts = 1;
  dbgx::mcp::HttpServerStartReport start_report;
  std::string error_message;

  const bool started = candidate.Start(
      "127.0.0.1",
      blocker.BoundPort(),
      MakeNoopHttpResponse,
      &error_message,
      &start_report,
      &start_options);

  Expect(!started, "server should fail when max port attempts are exhausted", failures);
  Expect(start_report.attempt_count == 1, "single-attempt option should only attempt one bind", failures);
  Expect(start_report.conflict_count == 1, "single-attempt conflict should report one conflict", failures);
  Expect(start_report.exhausted_conflicts, "conflict-limited failure should report exhausted_conflicts", failures);
  Expect(
      Contains(error_message, "all attempts hit address-in-use"),
      "failure message should explain conflict exhaustion",
      failures);

  blocker.Stop();
}

void TestHttpServerNonRetryableBindFailureStopsImmediately(int* failures) {
  dbgx::mcp::HttpServer server;
  dbgx::mcp::HttpServerStartOptions start_options;
  start_options.max_port_attempts = 8;
  dbgx::mcp::HttpServerStartReport start_report;
  std::string error_message;

  const bool started = server.Start(
      "203.0.113.1",
      5678,
      MakeNoopHttpResponse,
      &error_message,
      &start_report,
      &start_options);

  Expect(!started, "non-retryable bind failures should fail start", failures);
  Expect(start_report.attempt_count == 1, "non-retryable bind failures should stop after first attempt", failures);
  Expect(start_report.conflict_count == 0, "non-retryable bind failures should not be counted as conflicts", failures);
  Expect(!start_report.exhausted_conflicts, "non-retryable bind failures should not mark exhausted_conflicts", failures);
  Expect(Contains(error_message, "Bind failed on port"), "failure should identify bind error context", failures);
}

void TestInitialize(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}})");

  Expect(result.status_code == 200, "initialize should return HTTP 200", failures);
  Expect(Contains(result.body, "\"protocolVersion\":\"2025-11-25\""), "initialize should return protocol version", failures);
  Expect(Contains(result.body, "\"windbg.eval\""), "initialize should mention windbg.eval capability", failures);
  Expect(Contains(result.body, "\"version\":\"" DBGX_VERSION_STRING "\""),
         "initialize should return DBGX_VERSION_STRING in serverInfo", failures);
}

void TestToolsList(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result =
      router.HandleJsonRpcPost(R"({"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{}})");

  Expect(result.status_code == 200, "tools/list should return HTTP 200", failures);
  Expect(Contains(result.body, "\"name\":\"windbg.eval\""), "tools/list should include windbg.eval", failures);
  Expect(
      Contains(result.body, "clients MUST run calls serially"),
      "tools/list should require clients to execute windbg.eval serially",
      failures);
  Expect(
      Contains(result.body, "wait for each call to finish before sending the next"),
      "tools/list should require waiting for each call before the next one",
      failures);
  Expect(
      Contains(result.body, "send commands one by one and wait for completion before the next command"),
      "tools/list command schema should include serial command guidance",
      failures);
}

void TestToolsCallSuccess(int* failures) {
  FakeExecutor executor;
  executor.output = "eax=0x42";

  dbgx::mcp::JsonRpcRouter router(&executor);
  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"r eax"}}})");

  Expect(result.status_code == 200, "tools/call should return HTTP 200", failures);
  Expect(executor.call_count == 1, "tools/call should execute one command", failures);
  Expect(executor.last_command == "r eax", "tools/call should forward command text", failures);
  Expect(Contains(result.body, "eax=0x42"), "tools/call should return executor output", failures);
}

void TestToolsCallMissingCommand(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"windbg.eval","arguments":{}}})");

  Expect(result.status_code == 200, "missing command should still return JSON-RPC response", failures);
  Expect(Contains(result.body, "\"code\":-32602"), "missing command should return invalid params", failures);
  Expect(executor.call_count == 0, "missing command must not execute command", failures);
}

void TestUnknownMethod(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result =
      router.HandleJsonRpcPost(R"({"jsonrpc":"2.0","id":4,"method":"unknown/method","params":{}})");

  Expect(result.status_code == 200, "unknown method should return HTTP 200 with JSON-RPC error", failures);
  Expect(Contains(result.body, "\"code\":-32601"), "unknown method should return method not found", failures);
}

void TestInitializedNotification(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result =
      router.HandleJsonRpcPost(R"({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})");

  Expect(result.status_code == 202, "initialized notification should return HTTP 202", failures);
  Expect(!result.has_body, "initialized notification should return empty body", failures);
  Expect(result.body.empty(), "initialized notification payload should be empty", failures);
}

void TestParseError(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost("this-is-not-json");

  Expect(result.status_code == 400, "invalid JSON should return HTTP 400", failures);
  Expect(Contains(result.body, "\"code\":-32700"), "invalid JSON should return parse error", failures);
}

void TestIoEchoRequestSummaryMasksSensitiveHeader(int* failures) {
  dbgx::mcp::HttpRequest request;
  request.method = "POST";
  request.path = "/mcp";
  request.headers.insert_or_assign("authorization", "Bearer super-secret-token");
  request.body =
      R"({"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"r eax"}}})";

  const std::string summary = dbgx::mcp::BuildRequestIoSummary(request);

  Expect(Contains(summary, "method=POST"), "request summary should include HTTP method", failures);
  Expect(Contains(summary, "path=/mcp"), "request summary should include request path", failures);
  Expect(Contains(summary, "rpc_method=tools/call"), "request summary should include JSON-RPC method", failures);
  Expect(Contains(summary, "rpc_id=99"), "request summary should include JSON-RPC id", failures);
  Expect(Contains(summary, "authorization=<masked>"), "request summary should mask authorization header", failures);
  Expect(!Contains(summary, "super-secret-token"), "request summary must not expose authorization token", failures);
}

void TestIoEchoSummaryTruncatesLongPayload(int* failures) {
  const std::string long_text(512, 'x');

  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.body =
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + long_text +
      "\"}]}}";

  const std::string summary = dbgx::mcp::BuildResponseIoSummary(response);
  Expect(Contains(summary, "...(truncated)"), "long response summary should be truncated", failures);
}

void TestIoEchoRequestSummaryIncludesTraceContext(int* failures) {
  dbgx::mcp::HttpRequest request;
  request.method = "POST";
  request.path = "/mcp";
  request.body =
      R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"g"}}})";

  dbgx::mcp::IoTraceContext trace_context;
  trace_context.trace_id = "rpc:7";
  trace_context.stage = "tool_execute_start";
  trace_context.rpc_method = "tools/call";
  trace_context.rpc_id = "7";
  trace_context.tool_name = "windbg.eval";
  trace_context.duration_ms = 12;

  const std::string summary = dbgx::mcp::BuildRequestIoSummary(request, trace_context);
  Expect(Contains(summary, "trace_id=rpc:7"), "request summary should include trace id", failures);
  Expect(Contains(summary, "stage=tool_execute_start"), "request summary should include stage", failures);
  Expect(Contains(summary, "duration_ms=12"), "request summary should include duration", failures);
  Expect(Contains(summary, "tool=windbg.eval"), "request summary should include tool name", failures);
}

void TestIoEchoParseRequestMetaMissingId(int* failures) {
  dbgx::mcp::HttpRequest request;
  request.method = "POST";
  request.path = "/mcp";
  request.body =
      R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"g"}}})";

  const dbgx::mcp::RequestIoMeta meta = dbgx::mcp::ParseRequestIoMeta(request);
  Expect(meta.parseable, "request meta should parse valid JSON", failures);
  Expect(meta.has_rpc_method && meta.rpc_method == "tools/call", "request meta should include tools/call method", failures);
  Expect(!meta.has_rpc_id, "request meta should detect missing id", failures);
  Expect(meta.has_tool_name && meta.tool_name == "windbg.eval", "request meta should include tool name", failures);
}

void TestIoEchoLocalTraceIdConsistencyAcrossStages(int* failures) {
  dbgx::mcp::HttpRequest request;
  request.method = "POST";
  request.path = "/mcp";
  request.body =
      R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"g"}}})";

  dbgx::mcp::IoTraceContext request_context;
  request_context.trace_id = "local-42";
  request_context.stage = "request_received";
  request_context.rpc_method = "tools/call";
  request_context.tool_name = "windbg.eval";
  request_context.duration_ms = 0;

  const std::string request_summary = dbgx::mcp::BuildRequestIoSummary(request, request_context);
  Expect(Contains(request_summary, "trace_id=local-42"), "request summary should include local trace id", failures);

  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.body =
      R"({"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"ok"}],"isError":false}})";

  dbgx::mcp::IoTraceContext response_context = request_context;
  response_context.stage = "response_sent";
  response_context.duration_ms = 25;

  const std::string response_summary = dbgx::mcp::BuildResponseIoSummary(response, response_context);
  Expect(Contains(response_summary, "trace_id=local-42"), "response summary should include same local trace id", failures);
  Expect(Contains(response_summary, "stage=response_sent"), "response summary should include response stage", failures);
}

void TestIoEchoResponseSummaryCoversSuccessAndError(int* failures) {
  dbgx::mcp::HttpResponse success_response;
  success_response.status_code = 200;
  success_response.body =
      "{\"jsonrpc\":\"2.0\",\"id\":10,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"ok\"}]}}";

  const std::string success_summary = dbgx::mcp::BuildResponseIoSummary(success_response);
  Expect(Contains(success_summary, "rpc_outcome=success"), "success response should be marked as success", failures);

  dbgx::mcp::HttpResponse error_response;
  error_response.status_code = 200;
  error_response.body =
      "{\"jsonrpc\":\"2.0\",\"id\":10,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}";

  const std::string error_summary = dbgx::mcp::BuildResponseIoSummary(error_response);
  Expect(Contains(error_summary, "rpc_outcome=error"), "error response should be marked as error", failures);
  Expect(Contains(error_summary, "-32600"), "error response summary should include JSON-RPC error code", failures);
}

void TestIoEchoResponseSummaryTreatsToolIsErrorAsError(int* failures) {
  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.body =
      R"({"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"failed"}],"isError":true}})";

  const std::string summary = dbgx::mcp::BuildResponseIoSummary(response);
  Expect(Contains(summary, "rpc_outcome=error"), "result.isError=true should be treated as error outcome", failures);
}

void TestIoEchoBlockingLocatabilityStageOrder(int* failures) {
  dbgx::mcp::IoTraceContext execute_start_context;
  execute_start_context.trace_id = "rpc:5";
  execute_start_context.stage = "tool_execute_start";
  execute_start_context.rpc_method = "tools/call";
  execute_start_context.rpc_id = "5";
  execute_start_context.tool_name = "windbg.eval";
  execute_start_context.outcome = "in_progress";
  execute_start_context.duration_ms = 0;

  dbgx::mcp::IoTraceContext response_context = execute_start_context;
  response_context.stage = "response_sent";
  response_context.outcome.clear();
  response_context.duration_ms = 40;

  dbgx::mcp::HttpResponse response;
  response.status_code = 200;
  response.body =
      R"({"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}})";

  std::vector<std::string> logs;
  logs.push_back(dbgx::mcp::BuildLifecycleIoSummary(execute_start_context, "entering tool executor"));
  logs.push_back(dbgx::mcp::BuildResponseIoSummary(response, response_context));

  Expect(Contains(logs[0], "stage=tool_execute_start"), "first log should indicate tool execution start", failures);
  Expect(Contains(logs[1], "stage=response_sent"), "second log should indicate response stage", failures);
  Expect(Contains(logs[0], "trace_id=rpc:5"), "first log should include request trace id", failures);
  Expect(Contains(logs[1], "trace_id=rpc:5"), "second log should include same request trace id", failures);
}

void TestToolsCallWithOptions(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"windbg.eval","arguments":{"command":"lm","max_lines":5,"pattern":"ntdll"}}})");

  Expect(result.status_code == 200, "tools/call with options should return HTTP 200", failures);
  Expect(executor.call_count == 1, "tools/call with options should execute command", failures);
  Expect(executor.last_command == "lm", "tools/call should forward command", failures);
  Expect(executor.last_options.max_lines == 5, "tools/call should forward max_lines", failures);
  Expect(executor.last_options.pattern == "ntdll", "tools/call should forward pattern", failures);
}

void TestCatalogSearch(int* failures) {
  auto results = dbgx::windbg::Catalog::Search("bp");
  Expect(!results.empty(), "Catalog search for bp should return matches", failures);
  Expect(results[0].tokens[0] == "bp", "First search match should be bp breakpoint set", failures);

  auto entry = dbgx::windbg::Catalog::GetById("bp_bu_bm_set_breakpoint");
  Expect(entry.has_value(), "Lookup by ID should return valid entry", failures);
  Expect(entry->tokens[0] == "bp", "Token should be bp", failures);
}

void TestToolsCallGetSessionMetadata(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"windbg.get_session_metadata","arguments":{}}})");

  Expect(result.status_code == 200, "get_session_metadata should return HTTP 200", failures);
  Expect(Contains(result.body, "process_id"), "get_session_metadata should return process_id", failures);
  Expect(Contains(result.body, "test.exe"), "get_session_metadata should return executable name", failures);
  Expect(Contains(result.body, "x64"), "get_session_metadata should return x64 architecture", failures);
  Expect(Contains(result.body, "user"), "get_session_metadata should return user debuggee_class", failures);
}

void TestToolsCallWriteMemory(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"windbg.write_memory","arguments":{"address":"0x1000","data":"9090"}}})");

  Expect(result.status_code == 200, "write_memory should return HTTP 200", failures);
  Expect(Contains(result.body, "bytes_written"), "write_memory should return bytes_written", failures);
}

void TestToolsCallGetThreads(int* failures) {
  FakeExecutor executor;
  dbgx::mcp::JsonRpcRouter router(&executor);

  const dbgx::mcp::JsonRpcHttpResult result = router.HandleJsonRpcPost(
      R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"windbg.get_threads","arguments":{}}})");

  Expect(result.status_code == 200, "get_threads should return HTTP 200", failures);
  Expect(Contains(result.body, "thread_index"), "get_threads should return thread_index", failures);
  Expect(Contains(result.body, "system_thread_id"), "get_threads should return system_thread_id", failures);
  Expect(Contains(result.body, "is_current"), "get_threads should return is_current", failures);
}

}  // namespace

int main() {
  int failures = 0;

  TestTryGetIntField(&failures);
  TestInitialize(&failures);
  TestToolsList(&failures);
  TestToolsCallSuccess(&failures);
  TestToolsCallMissingCommand(&failures);
  TestToolsCallWithOptions(&failures);
  TestUnknownMethod(&failures);
  TestInitializedNotification(&failures);
  TestParseError(&failures);
  TestHttpServerStartBindsWithoutConflict(&failures);
  TestHttpServerFallbackAfterPortConflict(&failures);
  TestHttpServerFailsAfterMaxConflictAttempts(&failures);
  TestHttpServerNonRetryableBindFailureStopsImmediately(&failures);
  TestIoEchoRequestSummaryMasksSensitiveHeader(&failures);
  TestIoEchoSummaryTruncatesLongPayload(&failures);
  TestIoEchoRequestSummaryIncludesTraceContext(&failures);
  TestIoEchoParseRequestMetaMissingId(&failures);
  TestIoEchoLocalTraceIdConsistencyAcrossStages(&failures);
  TestIoEchoResponseSummaryCoversSuccessAndError(&failures);
  TestIoEchoResponseSummaryTreatsToolIsErrorAsError(&failures);
  TestIoEchoBlockingLocatabilityStageOrder(&failures);
  TestCatalogSearch(&failures);
  TestToolsCallGetSessionMetadata(&failures);
  TestToolsCallWriteMemory(&failures);
  TestToolsCallGetThreads(&failures);

  if (failures == 0) {
    std::cout << "All unit tests passed.\n";
    return 0;
  }

  std::cerr << failures << " test(s) failed.\n";
  return 1;
}

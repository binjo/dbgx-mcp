# WinDbg MCP HTTP Extension (MVP)

Language: English | [简体中文](README.zh-CN.md)

## Project Overview

This project provides a C++ WinDbg extension DLL that exposes an MCP-compatible HTTP endpoint (`/mcp`) and a suite of structured tools for high-performance debugger inspection and agentic automation.

### Why use it

- Run WinDbg commands through a local MCP interface.
- Integrate debugger operations into MCP clients and agent workflows.
- Validate WinDbg + MCP integration with a small, dependency-light implementation.

### Who it is for

- Engineers building MCP tooling around Windows debugging.
- Teams that want scripted or agent-driven WinDbg command execution.
- Contributors who need a small reference implementation before scaling features.

### Typical scenarios

- Execute `windbg.get_context` to get a structured snapshot of registers and the call stack.
- Use `windbg.dx` to evaluate Data Model expressions and receive structured JSON instead of text tables.
- Read and search virtual memory directly via `windbg.read_memory` and `windbg.search`.

## Quick Start

### Prerequisites

- Windows
- CMake 3.12+
- MSVC toolchain (Visual Studio 2017+)
- WinDbg SDK headers/libs (`DbgEng.h`, `dbgeng.lib`)

### 1. Build the extension

```powershell
mkdir build
cd build
cmake -G "Ninja" ..
cmake --build .
```

The configuration command (`cmake -G "Ninja" ..`) breaks down as follows:
- `mkdir build`: Creates the directory for build artifacts.
- `cd build`: Moves into that directory.
- `-G "Ninja"`: Use the [Ninja](https://ninja-build.org/) build generator for high-performance builds. If you don't have Ninja, you can use `"Visual Studio 15 2017"` for VS 2017.
- `..`: Points to the source code in the parent directory.

Expected result:
- Build succeeds.
- `build/Debug/dbgx-mcp.dll` is generated.

### 2. Load the extension in WinDbg

```text
.load "D:/Repos/Project/AI-Native/dbgx-mcp/build/Debug/dbgx-mcp.dll"
```

Expected result:
- `.load` succeeds without `Win32 error`.
- The extension first tries `http://127.0.0.1:5678/mcp`.
- If port `5678` is occupied, it automatically retries subsequent ports until one is available.
- WinDbg output always includes the final listening endpoint.

Important:
- Use forward slashes in `.load` paths.
- In debugger command contexts, backslashes may be treated as escapes, which can cause `Win32 error 0n2`.
- For all MCP calls below, use the final port shown in WinDbg logs if fallback occurred.

### 3. Verify extension presence

```text
.chain
```

Expected result:
- `dbgx-mcp` appears in the extension chain output.

### 4. Send the first MCP request (`initialize`)

```powershell
$req = @{
  jsonrpc = "2.0"
  id = 1
  method = "initialize"
  params = @{ protocolVersion = "2025-11-25" }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://127.0.0.1:5678/mcp" -Method Post -ContentType "application/json" -Body $req
```

Expected result:
- Response contains `jsonrpc`, matching `id`, and `result`.

### 5. Run a debugger command via MCP (`tools/call`)

```powershell
$req = @{
  jsonrpc = "2.0"
  id = 2
  method = "tools/call"
  params = @{
    name = "windbg.eval"
    arguments = @{ command = "r eax" }
  }
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Uri "http://127.0.0.1:5678/mcp" -Method Post -ContentType "application/json" -Body $req
```

Expected result:
- Response returns command output text from WinDbg.

### Testing with `curl` (cmd.exe)

If you prefer using `curl` from a standard Windows Command Prompt, ensure you escape the double quotes in the JSON body:

```cmd
# initialize
curl -X POST http://127.0.0.1:5678/mcp -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}"

# tools/list
curl -X POST http://127.0.0.1:5678/mcp -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}"

# tools/call (windbg.eval)
curl -X POST http://127.0.0.1:5678/mcp -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"windbg.eval\",\"arguments\":{\"command\":\"r eax\"}}}"
```

## WinDbg Bridge Gateway

The `windbg-bridge.py` script acts as a proxy between Stdio-based MCP clients (like Claude Desktop or Zed) and the remote WinDbg session. It handles multi-session discovery and protocol translation.

### Usage

1. Start one or more WinDbg sessions and load the extension.
2. Run the bridge:
   ```powershell
   python windbg-bridge.py
   ```
3. Use the `windbg.list_sessions` tool to discover available debuggers and their ports.

### Configuration

Every bridge setting is resolved as **environment variable → env file → default**:

| Setting | Env var | Default |
|---|---|---|
| WinDbg host (guest VM IP) | `WINDBG_MCP_HOST` (alias `WINDBG_MCP_BIND`) | `127.0.0.1` |
| Base port | `WINDBG_MCP_PORT` | `5678` |
| Transport | `WINDBG_MCP_TRANSPORT` (`auto`/`pipe`/`http`) | `auto` |
| Bearer token | `WINDBG_MCP_TOKEN` | unset |
| Allow non-private hosts in `set_guest_host` | `WINDBG_MCP_ALLOW_PUBLIC_HOST` | `0` |
| Env file location | `WINDBG_MCP_ENV_FILE` | `~/.windbg-mcp.env` |

The env file is plain `KEY=VALUE` lines. You normally never edit it by hand — see below.

### Pointing the bridge at a VM whose IP changed (`windbg.set_guest_host`)

When WinDbg runs in a VM on a host-only/NAT network its IP can change between boots. Instead of
editing the MCP client config and restarting, just tell the agent:

> "WinDbg is at 192.168.56.101 now"

The agent calls `windbg.set_guest_host({"host": "192.168.56.101"})`. The bridge validates the host
(loopback/private/link-local only, unless `WINDBG_MCP_ALLOW_PUBLIC_HOST=1`), drops cached
connections, rediscovers sessions and returns them, and emits `notifications/tools/list_changed`.
Add `"persist": true` to have it written to the env file so the next bridge start remembers it
(the result carries a `warnings` entry if `WINDBG_MCP_HOST` in the client config would shadow it).
`windbg.list_sessions` always reports the `guest_host`/`transport` the bridge is currently using.
The token is deliberately *not* settable through the tool.

If nobody knows the VM's IP, `windbg.discover_guests` (or `set_guest_host({"host": "auto"})`)
sweeps this machine's private `/24` subnets — VirtualBox host-only, VMware vmnet, Hyper-V default
switch — with cheap TCP probes on the base port, asks responders for `/sessions`, and returns the
candidates. The sweep is capped at 1024 hosts and only ever touches private/link-local ranges.

### What the bridge does for the agent

| Behaviour | Why |
|---|---|
| `initialize` returns `instructions` describing the workflow (list sessions → set host → prefer structured tools) | Clients inject it into the model's system prompt. |
| Every tool carries MCP `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`) | Clients auto-approve reads and confirm writes. One table ([`TOOL_TRAITS`](windbg-bridge.py)) also drives caching and retry rules. |
| Tool-level failures are `isError` results with `error`, `message`, `next_steps` (e.g. `command_blocked`, `backend_unreachable`, `backend_timeout`, `unknown_session`) | The model reads and recovers instead of seeing an opaque protocol error. JSON-RPC errors are reserved for malformed requests. |
| `notifications/progress` every 10 s while a long command (`.reload /f`, `!analyze -v`) is in flight, when the client sent a `progressToken` | Keeps spec-compliant clients from timing out before WinDbg answers. |
| Never re-sends a request that may have executed: retries only on connect failure, or on a stale keep-alive for read-only/idempotent calls; timeouts are reported, not retried | Prevents a second `p`/`g`/`write_memory` after a slow first one. |
| Read-only `eval` results (`r`, `k`, `lm`, `version`…) are cached briefly per *session* (`port:pid`) and flushed by any mutating call (`step`, `continue`, `r rax=…`, `.reload`, …) | Fast polling without ever serving pre-step state. |
| Unreachable host at `initialize` answers synthetically at once | A dead VM IP no longer stalls the client's handshake for 60 s. |

## Troubleshooting `.load` Failures

1. Confirm the DLL path exists and is absolute.
2. Verify required exports are present:

```powershell
cmake --build build --config Debug --target check_windbg_exports
```

3. Run export checks in test flow:

```powershell
ctest --test-dir build -C Debug --output-on-failure -R verify_windbg_exports
```

4. If loading still fails, inspect dependent modules:

```powershell
dumpbin /dependents build\Debug\dbgx-mcp.dll
```

Common errors:
- `Win32 error 0n2`: wrong path or path separators were parsed incorrectly.
- `Win32 error 0n126`: dependent module not found in the current environment.

Port conflict behavior:
- If startup logs include `HTTP MCP bind fallback engaged`, the server moved from the default port to another available port.
- Use the `HTTP MCP server listening on http://127.0.0.1:<port>/mcp` line as the source of truth for requests.

## WinDbg Debug Log Guide

The extension emits lifecycle-aware debug logs in WinDbg output for each `/mcp` request.

### Key fields

- `trace_id`: Request correlation key. Uses `rpc:<id>` when JSON-RPC `id` exists, otherwise `local-<seq>`.
- `stage`: Lifecycle phase (`request_received`, `route_dispatch`, `tool_execute_start`, `tool_execute_end`, `response_sent`).
- `duration_ms`: Elapsed milliseconds since request start.
- `rpc_method` / `rpc_id` / `tool`: Core RPC context fields for troubleshooting.
- `rpc_outcome`: Parsed result status (`success`, `error`, `unknown`).

### Example: successful `tools/call`

```text
[windbg-mcp] mcp.request method=POST trace_id=rpc:2 stage=request_received duration_ms=0 path=/mcp rpc_method=tools/call rpc_id=2 tool=windbg.eval body_bytes=...
[windbg-mcp] mcp.stage trace_id=rpc:2 stage=route_dispatch duration_ms=0 rpc_method=tools/call rpc_id=2 tool=windbg.eval outcome=in_progress msg=dispatching JSON-RPC request
[windbg-mcp] mcp.stage trace_id=rpc:2 stage=tool_execute_start duration_ms=0 rpc_method=tools/call rpc_id=2 tool=windbg.eval outcome=in_progress msg=entering tool executor
[windbg-mcp] mcp.response status=200 trace_id=rpc:2 stage=tool_execute_end duration_ms=4 has_body=true rpc_id=2 rpc_outcome=success tool=windbg.eval result=...
[windbg-mcp] mcp.response status=200 trace_id=rpc:2 stage=response_sent duration_ms=4 has_body=true rpc_id=2 rpc_outcome=success tool=windbg.eval result=...
```

### Example: invalid params failure

```text
[windbg-mcp] mcp.request method=POST trace_id=rpc:3 stage=request_received duration_ms=0 path=/mcp rpc_method=tools/call rpc_id=3 tool=windbg.eval body_bytes=...
[windbg-mcp] mcp.response status=200 trace_id=rpc:3 stage=tool_execute_end duration_ms=1 has_body=true rpc_id=3 rpc_outcome=error tool=windbg.eval error={"code":-32602,...}
[windbg-mcp] mcp.response status=200 trace_id=rpc:3 stage=response_sent duration_ms=1 has_body=true rpc_id=3 rpc_outcome=error tool=windbg.eval error={"code":-32602,...}
```

### Blocking diagnosis signal

If you see `stage=tool_execute_start` for a `trace_id` but never see `stage=tool_execute_end` or `stage=response_sent` with the same `trace_id`, the request is stalled inside command execution (not in HTTP routing).

Safety behavior remains unchanged:
- Sensitive headers are masked (`authorization=<masked>`).
- Long values are truncated with `...(truncated)`.

## Manual Validation Checklist (Log Readability)

1. Success path:
- Send a normal `tools/call` (for example `r eax`).
- Verify stage order: `request_received` -> `tool_execute_start` -> `tool_execute_end` -> `response_sent`.
- Verify `rpc_outcome=success` and consistent `trace_id`.

2. Failure path:
- Send `tools/call` without `arguments.command`.
- Verify response remains JSON-RPC error (`-32602`).
- Verify logs include `rpc_outcome=error` with matching `trace_id`.

3. Blocking observability path:
- Send a long-running command (for example `g`) in a suitable debug session.
- Verify `tool_execute_start` appears before completion.
- If no `tool_execute_end`/`response_sent` appears for the same `trace_id`, diagnose as execution-stage stall.

4. Port fallback path:
- Occupy `127.0.0.1:5678` before loading the extension.
- Load the extension and verify logs show bind fallback and a non-5678 final port.
- Send `initialize` to the final port and verify `/mcp` is reachable.

## MCP Request Reference

### `initialize`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-11-25"
  }
}
```

### `tools/list`

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/list",
  "params": {}
}
```

### `tools/call` (`windbg.eval`)

```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "tools/call",
  "params": {
    "name": "windbg.eval",
    "arguments": {
      "command": "r eax"
    }
  }
}
```

### `tools/call` (`windbg.dx`)

```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/call",
  "params": {
    "name": "windbg.dx",
    "arguments": {
      "expression": "@$curprocess",
      "max_depth": 3
    }
  }
}
```

### `tools/call` (`windbg.get_context`)

```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "windbg.get_context",
    "arguments": {}
  }
}
```

### `tools/call` (`windbg.read_memory`)

```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "tools/call",
  "params": {
    "name": "windbg.read_memory",
    "arguments": {
      "address": "0x00401000",
      "length": 64
    }
  }
}
```

### `tools/call` (`windbg.get_session_metadata`)

```json
{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "tools/call",
  "params": {
    "name": "windbg.get_session_metadata",
    "arguments": {}
  }
}
```

### `tools/call` (`windbg.write_memory`)

```json
{
  "jsonrpc": "2.0",
  "id": 8,
  "method": "tools/call",
  "params": {
    "name": "windbg.write_memory",
    "arguments": {
      "address": "0x00401000",
      "data": "9090"
    }
  }
}
```

### `tools/call` (`windbg.get_threads`)

```json
{
  "jsonrpc": "2.0",
  "id": 9,
  "method": "tools/call",
  "params": {
    "name": "windbg.get_threads",
    "arguments": {}
  }
}
```

## Security Notes

- HTTP binds to `127.0.0.1` by default (`WINDBG_MCP_BIND` overrides).
- Validates `Origin` when present, allowing only `http://localhost...` and `http://127.0.0.1...`.
- **Optional bearer token on HTTP.** Set `WINDBG_MCP_TOKEN=<secret>` in both WinDbg's and the
  bridge's environment to require `Authorization: Bearer <secret>` on `/mcp` and `/sessions`
  (HTTP 401 otherwise). Off by default — on loopback or a host-only VM network the Origin check
  and pipe ACL are usually sufficient. The bridge also honours a per-session `token` field from
  the local session registry.
- **Named pipe ACL.** `\\.\pipe\dbgx-mcp-<port>` is created with a DACL limited to the current
  user, SYSTEM and Administrators; when WinDbg runs elevated a High-integrity mandatory label is
  added so a medium-IL process cannot drive an elevated debugger.
- **Server-side guardrails.** `windbg.eval` rejects session-killing commands (`q`, `.kill`,
  `.restart`, `.reboot`, `.shell`, `.server`, `.unload`, ...) and command-file sourcing (`$<`,
  `$$<`) regardless of which client is talking to the DLL; the bridge applies the same list.
- **Read-only mode.** Set `WINDBG_MCP_READONLY=1` before loading to reject every mutating tool
  (`eval`, `write_memory`, `write_file`, `continue`, `step`, `set/clear_breakpoint`,
  `apply_struct`, `apply_synthetic_type`, TTD seeks). Inspection tools and `interrupt` remain
  available.
- Supports HTTP `POST /mcp` for JSON-RPC.
- `GET /mcp` returns 405 (no SSE stream yet).

## Build and Test Details

Run unit tests:

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

Unit test policy (MVP):
- Test pure logic first: JSON parsing and JSON-RPC routing.
- Keep WinDbg and socket operations in thin adapters.
- Every key behavior in the spec maps to at least one test.

### Spec-to-test mapping

| Spec scenario | Unit test |
| --- | --- |
| Initialize request succeeds | `TestInitialize` |
| Tools list request succeeds | `TestToolsList` |
| Command execution succeeds | `TestToolsCallSuccess` |
| Missing command argument | `TestToolsCallMissingCommand` |
| Unknown method is rejected | `TestUnknownMethod` |
| MCP request summary includes RPC metadata and masks sensitive headers | `TestIoEchoRequestSummaryMasksSensitiveHeader` |
| Request summary includes trace/stage/tool fields | `TestIoEchoRequestSummaryIncludesTraceContext` |
| Missing JSON-RPC id is detected from request metadata | `TestIoEchoParseRequestMetaMissingId` |
| Local trace id stays consistent across lifecycle logs | `TestIoEchoLocalTraceIdConsistencyAcrossStages` |
| MCP response summary covers both success and error outcomes | `TestIoEchoResponseSummaryCoversSuccessAndError` |
| Tool result with `isError=true` is reported as error outcome | `TestIoEchoResponseSummaryTreatsToolIsErrorAsError` |
| Blocking diagnosis uses execution-before-response stage ordering | `TestIoEchoBlockingLocatabilityStageOrder` |
| Long MCP summaries are truncated with marker | `TestIoEchoSummaryTruncatesLongPayload` |
| Export symbol check passes | `verify_windbg_exports` |
| Missing export is blocked | `verify_windbg_exports_missing_symbol` (WILL_FAIL) |
| Load command path format is reusable | `Load in WinDbg` command examples |
| Load failure has diagnostics | `Troubleshooting .load failures` section |
| Invalid JSON handling | `TestParseError` |

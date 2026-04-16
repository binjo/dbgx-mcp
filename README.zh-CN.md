# WinDbg MCP HTTP 扩展（MVP）

Language: [English](README.md) | 简体中文

## 项目概览

本项目提供一个最小化的 C++ WinDbg 扩展 DLL，对外暴露兼容 MCP 的 HTTP 端点（`/mcp`）以及基础工具 `windbg.eval`。

### 为什么使用它

- 通过本地 MCP 接口执行 WinDbg 命令。
- 将调试动作接入 MCP 客户端和智能体工作流。
- 以小而清晰、依赖最少的实现验证 WinDbg + MCP 集成。

### 适用人群

- 构建 Windows 调试相关 MCP 工具的工程师。
- 需要脚本化或智能体驱动 WinDbg 命令执行的团队。
- 想先基于小型参考实现再扩展能力的贡献者。

### 典型场景

- 从 MCP 客户端调用 `windbg.eval` 查看寄存器/内存状态。
- 验证 WinDbg 工具的 JSON-RPC 路由能力。
- 检查扩展加载、导出符号与 WinDbg 内请求/响应可见性。

## Quick Start

### 前置条件

- Windows
- CMake 3.12+
- MSVC 工具链（Visual Studio 2017+）
- WinDbg SDK 头文件与库（`DbgEng.h`, `dbgeng.lib`）

### 1. 构建扩展

```powershell
mkdir build
cd build
cmake -G "Ninja" ..
cmake --build .
```

配置命令的详细说明：
- `mkdir build`：创建用于存放构建产物的目录。
- `cd build`：进入该目录。
- `-G "Ninja"`：使用 [Ninja](https://ninja-build.org/) 生成器以获得高性能构建。若环境中没有 Ninja，可使用 `"Visual Studio 15 2017"` 来匹配 VS 2017。
- `..`：指向上一级目录中的源代码。

预期结果：
- 构建成功。
- 生成 `build/Debug/dbgx-mcp.dll`。

### 2. 在 WinDbg 中加载扩展

```text
.load "D:/Repos/Project/AI-Native/dbgx-mcp/build/Debug/dbgx-mcp.dll"
```

预期结果：
- `.load` 成功，不出现 `Win32 error`。
- 扩展优先尝试 `http://127.0.0.1:5678/mcp`。
- 若 `5678` 已被占用，会自动按顺序尝试后续端口直到成功。
- WinDbg 输出会明确给出最终监听端点。

重要说明：
- `.load` 路径请使用正斜杠 `/`。
- 在调试器命令上下文中，反斜杠可能被当作转义字符，导致 `Win32 error 0n2`。
- 下文所有 MCP 示例若与默认端口不一致，请以 WinDbg 日志中的最终端口为准。

### 3. 验证扩展已加载

```text
.chain
```

预期结果：
- 扩展链输出中出现 `dbgx-mcp`。

### 4. 发送首个 MCP 请求（`initialize`）

```powershell
$req = @{
  jsonrpc = "2.0"
  id = 1
  method = "initialize"
  params = @{ protocolVersion = "2025-11-25" }
} | ConvertTo-Json -Depth 4

Invoke-RestMethod -Uri "http://127.0.0.1:5678/mcp" -Method Post -ContentType "application/json" -Body $req
```

预期结果：
- 响应包含 `jsonrpc`、匹配的 `id` 和 `result`。

### 5. 通过 MCP 执行调试命令（`tools/call`）

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

预期结果：
- 响应返回 WinDbg 命令输出文本。

## `.load` 失败排查

1. 确认 DLL 路径存在且为绝对路径。
2. 验证必需导出符号：

```powershell
cmake --build build --config Debug --target check_windbg_exports
```

3. 在测试流程中执行导出检查：

```powershell
ctest --test-dir build -C Debug --output-on-failure -R verify_windbg_exports
```

4. 若仍加载失败，检查依赖模块：

```powershell
dumpbin /dependents build\Debug\dbgx-mcp.dll
``` 

常见错误：
- `Win32 error 0n2`：路径错误，或路径分隔符被错误解析。
- `Win32 error 0n126`：当前环境缺少依赖模块。

端口冲突行为：
- 若启动日志出现 `HTTP MCP bind fallback engaged`，表示服务已从默认端口回退到其他可用端口。
- 发送请求时请以 `HTTP MCP server listening on http://127.0.0.1:<port>/mcp` 这行日志为准。

## WinDbg 调试日志说明

扩展会在 WinDbg 输出中为每个 `/mcp` 请求打印带生命周期语义的调试日志，便于快速关联与排障。

### 关键字段

- `trace_id`：请求关联键。有 JSON-RPC `id` 时使用 `rpc:<id>`，否则使用 `local-<seq>`。
- `stage`：生命周期阶段（`request_received`、`route_dispatch`、`tool_execute_start`、`tool_execute_end`、`response_sent`）。
- `duration_ms`：从请求开始到当前日志点的耗时（毫秒）。
- `rpc_method` / `rpc_id` / `tool`：用于定位问题的核心 RPC 上下文字段。
- `rpc_outcome`：解析后的结果状态（`success`、`error`、`unknown`）。

### 示例：`tools/call` 成功

```text
[windbg-mcp] mcp.request method=POST trace_id=rpc:2 stage=request_received duration_ms=0 path=/mcp rpc_method=tools/call rpc_id=2 tool=windbg.eval body_bytes=...
[windbg-mcp] mcp.stage trace_id=rpc:2 stage=route_dispatch duration_ms=0 rpc_method=tools/call rpc_id=2 tool=windbg.eval outcome=in_progress msg=dispatching JSON-RPC request
[windbg-mcp] mcp.stage trace_id=rpc:2 stage=tool_execute_start duration_ms=0 rpc_method=tools/call rpc_id=2 tool=windbg.eval outcome=in_progress msg=entering tool executor
[windbg-mcp] mcp.response status=200 trace_id=rpc:2 stage=tool_execute_end duration_ms=4 has_body=true rpc_id=2 rpc_outcome=success tool=windbg.eval result=...
[windbg-mcp] mcp.response status=200 trace_id=rpc:2 stage=response_sent duration_ms=4 has_body=true rpc_id=2 rpc_outcome=success tool=windbg.eval result=...
```

### 示例：参数错误失败

```text
[windbg-mcp] mcp.request method=POST trace_id=rpc:3 stage=request_received duration_ms=0 path=/mcp rpc_method=tools/call rpc_id=3 tool=windbg.eval body_bytes=...
[windbg-mcp] mcp.response status=200 trace_id=rpc:3 stage=tool_execute_end duration_ms=1 has_body=true rpc_id=3 rpc_outcome=error tool=windbg.eval error={"code":-32602,...}
[windbg-mcp] mcp.response status=200 trace_id=rpc:3 stage=response_sent duration_ms=1 has_body=true rpc_id=3 rpc_outcome=error tool=windbg.eval error={"code":-32602,...}
```

### 阻塞定位信号

如果同一 `trace_id` 只出现 `stage=tool_execute_start`，但一直没有 `stage=tool_execute_end` 或 `stage=response_sent`，则可判断请求停滞在命令执行阶段，而非 HTTP 路由阶段。

安全行为保持不变：
- 敏感请求头会被掩码（例如 `authorization=<masked>`）。
- 超长文本会被截断并标注 `...(truncated)`。

## 人工验收清单（日志可读性）

1. 成功路径：
- 发送正常 `tools/call`（例如 `r eax`）。
- 验证阶段顺序：`request_received` -> `tool_execute_start` -> `tool_execute_end` -> `response_sent`。
- 验证 `rpc_outcome=success` 且 `trace_id` 一致。

2. 失败路径：
- 发送不带 `arguments.command` 的 `tools/call`。
- 验证响应仍是 JSON-RPC 参数错误（`-32602`）。
- 验证日志包含 `rpc_outcome=error` 且 `trace_id` 对应一致。

3. 阻塞可观测路径：
- 在合适调试会话中发送长时间命令（例如 `g`）。
- 验证完成前可先看到 `tool_execute_start`。
- 若同一 `trace_id` 无 `tool_execute_end`/`response_sent`，可据此判定执行阶段阻塞。

4. 端口回退路径：
- 在加载扩展前先占用 `127.0.0.1:5678`。
- 加载扩展后确认日志出现端口回退信息，且最终端口不为 `5678`。
- 对最终端口发送 `initialize`，验证 `/mcp` 可访问。

## MCP 请求参考

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

### `tools/call`（`windbg.eval`）

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

## 安全说明（MVP）

- 仅绑定到 `127.0.0.1`。
- 当请求包含 `Origin` 时进行校验，仅允许 `http://localhost...` 与 `http://127.0.0.1...`。
- 支持 HTTP `POST /mcp` 的 JSON-RPC 调用。
- 当前 MVP 中 `GET /mcp` 返回 405（暂不支持 SSE 流）。

## 构建与测试细节

运行单元测试：

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

单元测试策略（MVP）：
- 优先测试纯逻辑：JSON 解析与 JSON-RPC 路由。
- 将 WinDbg 与 socket 操作保持为轻量适配层。
- 规范中的每个关键行为至少映射一个测试。

### 规范与测试映射

| 规范场景 | 单元测试 |
| --- | --- |
| 初始化请求成功 | `TestInitialize` |
| 工具列表请求成功 | `TestToolsList` |
| 命令执行成功 | `TestToolsCallSuccess` |
| 缺少命令参数 | `TestToolsCallMissingCommand` |
| 未知方法被拒绝 | `TestUnknownMethod` |
| MCP 请求摘要包含 RPC 元信息且掩码敏感头 | `TestIoEchoRequestSummaryMasksSensitiveHeader` |
| 请求摘要包含 trace/stage/tool 字段 | `TestIoEchoRequestSummaryIncludesTraceContext` |
| 缺失 JSON-RPC id 能从请求元信息中识别 | `TestIoEchoParseRequestMetaMissingId` |
| 本地 trace id 在生命周期日志中保持一致 | `TestIoEchoLocalTraceIdConsistencyAcrossStages` |
| MCP 响应摘要覆盖成功与错误路径 | `TestIoEchoResponseSummaryCoversSuccessAndError` |
| `isError=true` 的工具结果会被标记为错误 | `TestIoEchoResponseSummaryTreatsToolIsErrorAsError` |
| 阻塞定位依赖执行阶段先于响应阶段的顺序 | `TestIoEchoBlockingLocatabilityStageOrder` |
| 超长 MCP 摘要会被截断并带标记 | `TestIoEchoSummaryTruncatesLongPayload` |
| 导出符号检查通过 | `verify_windbg_exports` |
| 缺失导出被阻断 | `verify_windbg_exports_missing_symbol` (WILL_FAIL) |
| 加载命令路径写法可复用 | `Load in WinDbg` command examples |
| 加载失败有诊断指引 | `.load` 失败排查章节 |
| 非法 JSON 处理 | `TestParseError` |

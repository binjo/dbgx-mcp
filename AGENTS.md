# AGENTS.md

This file provides guidance to AI coding agents (Zed, Codex, Claude Code, etc.) when working with code in this repository.

## Project Overview

`dbgx-mcp` is a C++ WinDbg extension DLL that exposes an MCP (Model Context Protocol) HTTP endpoint at `/mcp` alongside `windbg-bridge.py` for Stdio-to-HTTP gateway translation. It provides a suite of 24 structured tools (`windbg.eval`, `windbg.dx`, `windbg.get_context`, `windbg.get_modules`, `windbg.get_breakpoints`, `windbg.disassemble`, `windbg.read_string`, `windbg.apply_struct`, `windbg.step`, `windbg.continue`, `windbg.set_breakpoint`, `windbg.list_sessions`, etc.) for agentic debugging and reverse engineering.

Zero third-party dependencies — only Windows SDK and WinDbg SDK.

## Build & Deploy

**Target platform:** Windows only (MSVC toolchain). Requires CMake 3.20+, WinDbg SDK (`DbgEng.h`, `dbgeng.lib`), Ninja.

### Recommended Build & Deploy Command (x64 & x86)

```powershell
powershell -ExecutionPolicy Bypass -File deploy.ps1 -Arch all -BuildType Debug
```

This compiles both x64 and x86 targets and deploys the binaries directly to:
- `%LOCALAPPDATA%\dbg\EngineExtensions\dbgx-mcp.dll` (x64)
- `%LOCALAPPDATA%\dbg\EngineExtensions32\dbgx-mcp.dll` (x86)

### Manual CMake Build & Test

```powershell
# Build x64
cmake -S . -B build/x64 -G "Ninja" -DCMAKE_BUILD_TYPE=Debug
cmake --build build/x64

# Run C++ Unit Tests
./build/x64/unit_tests.exe

# Run Python Bridge Tests
python -m unittest tests/test_bridge.py
```

## Architecture

```
windbg-bridge.py      -- Stdio-to-HTTP proxy gateway for MCP clients (Zed / Claude / Cursor)
  ├── Session Watcher  -- Background thread emitting notifications/tools/list_changed
  ├── Guardrails       -- Blacklists session-killing commands (.reboot, qd, etc.)
  └── Multi-Session    -- Route calls via session_id parameter to target ports

dbgx-mcp.dll          -- Native WinDbg Extension DLL
  ├── src/dbgx-mcp.cpp            -- Extension lifecycle (DebugExtensionInitialize / Unload)
  ├── mcp/http_server            -- Winsock HTTP server with socket timeouts & port fallback
  ├── mcp/json_rpc               -- JSON-RPC 2.0 router & 24 tool handlers
  ├── mcp/json                   -- Lightweight hand-rolled JSON parser & FieldMap
  ├── mcp/syntypes_js.hpp        -- Embedded SynTypes.js C-struct synthesizer engine
  └── windbg/
      ├── command_executor.hpp   -- IWinDbgCommandExecutor interface
      └── dbgeng_command_executor-- Dedicated COM worker thread isolated DbgEng implementation
```

## Key Design Patterns & Guidelines

- **COM & DbgEng Thread Safety**: All DbgEng COM interface calls (`IDebugClient`, `IDebugControl`, `IDebugRegisters`, `IModelObject`, etc.) **must** run isolated on `worker_thread_` inside `DbgEngCommandExecutor`. HTTP handler threads post tasks via `DispatchToWorker`.
- **Target Execution State**: All command/memory inspection operations verify that the target is broken in (`DEBUG_STATUS_BREAK`).
- **Dynamic Session Metadata**: `RegisterSession()` writes target metadata (`x86`/`x64`, target PID, executable name) asynchronously to `%TEMP%\dbgx-mcp-registry\<port>.json`. Stale files are purged automatically by verifying host process liveness (`pid`).
- **Bridge Gateway**: `windbg-bridge.py` acts as stdio proxy for Zed. It emits `notifications/tools/list_changed` when WinDbg sessions come online/offline so tools auto-activate in Zed without needing user toggle.

## Conventions

- C++20, namespaces: `dbgx::mcp`, `dbgx::windbg`, `dbgx::json`.
- Headers in `include/dbgx/`, sources in `src/`, tests in `tests/`.
- DLL exports defined in `src/dbgx-mcp.def` — must remain aligned with `DebugExtensionInitialize`, `DebugExtensionCanUnload`, `DebugExtensionUninitialize`, `DebugExtensionUnload`.
- Hand-rolled test harness in `tests/unit_tests.cpp` (no external test frameworks).

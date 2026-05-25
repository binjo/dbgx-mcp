# dbgx-mcp Async Execution & Command Catalog Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 
1. **Asynchronous Execution & Safe Target Interruption**: Move debugger command execution to a background worker thread to prevent blocking the HTTP server thread. Expose tools to check execution state and explicitly interrupt (`break`) the target debuggee.
2. **Offline Command Catalog RAG Assistance**: Package a static WinDbg command documentation database within the DLL and expose search tools so AI agents can query exact debugger command syntax offline before execution, preventing hallucinations.

**Tech Stack:** C++17, Winsock, Windows SDK (DbgEng COM interfaces), MSVC

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `include/dbgx/windbg/command_executor.hpp` | Add `GetExecutionStatus`, `Interrupt`, and catalog structures to interface. |
| Modify | `include/dbgx/windbg/dbgeng_command_executor.hpp` | Define background worker thread, command queue, and state tracking fields. |
| Modify | `src/windbg/dbgeng_command_executor.cpp` | Implement background thread worker, `SetInterrupt` COM calls, and virtual memory APIs. |
| Create | `include/dbgx/windbg/catalog.hpp` | Structs and search helpers for the command catalog. |
| Create | `src/windbg/catalog.cpp` | Static dictionary payload of debugger commands (`bp`, `dt`, `k`, `r`, etc.) and string-matching scoring algorithms. |
| Modify | `src/mcp/json_rpc.cpp` | Route JSON-RPC calls for `windbg.get_execution_state`, `windbg.interrupt`, `windbg.search_catalog`, and `windbg.get_command_docs`. |
| Modify | `tests/unit_tests.cpp` | Add unit tests verifying async execution, interruption flow, and catalog searches. |

---

## Chunk 1: Async worker thread & Target Interruption

Currently, running command evaluations blocks the HTTP server thread. By running a dedicated worker thread, the HTTP server can remain highly responsive, allowing non-blocking state checks and target breaks.

### Task 0: Create a new git branch

- [ ] **Step 1: Create and checkout a new branch**
  Before making changes, create a new branch `feature/async-execution-and-catalog`:
  ```bash
  git checkout -b feature/async-execution-and-catalog
  ```

---

### Task 1: Extend interface for execution state and interruption

**Files:**
- Modify: `include/dbgx/windbg/command_executor.hpp`

- [ ] **Step 1: Add status enum and method prototypes to interface**
  Add `DebuggerExecutionState` struct definition and virtual functions for state query and interruption inside `dbgx::windbg` namespace:
  ```cpp
  struct DebuggerExecutionState {
    std::uint32_t raw_status = 0;
    std::string status_name;
    bool running = false;
    bool busy = false;
    bool ready_for_commands = false;
    std::string summary;
  };

  // In IWinDbgCommandExecutor class:
  virtual DebuggerExecutionState GetExecutionState() = 0;
  virtual bool InterruptTarget() = 0;
  ```

- [ ] **Step 2: Commit changes**
  ```bash
  git add include/dbgx/windbg/command_executor.hpp
  git commit -m "feat: add DebuggerExecutionState and interruption methods to IWinDbgCommandExecutor"
  ```

---

### Task 2: Implement async queue & status tracking in DbgEngCommandExecutor

**Files:**
- Modify: `include/dbgx/windbg/dbgeng_command_executor.hpp`
- Modify: `src/windbg/dbgeng_command_executor.cpp`

- [ ] **Step 1: Define queue, thread, and condition variable in header**
  In `DbgEngCommandExecutor` class, add:
  ```cpp
  #include <thread>
  #include <queue>
  #include <mutex>
  #include <condition_variable>
  #include <future>

  private:
   struct ExecutionTask {
     std::string command;
     CommandExecutionOptions options;
     std::promise<CommandExecutionResult> promise;
   };

   std::thread worker_thread_;
   std::mutex queue_mutex_;
   std::condition_variable cv_;
   std::queue<ExecutionTask> task_queue_;
   bool shutdown_ = false;

   void WorkerThreadProc();
   static DebuggerExecutionState ParseRawStatus(std::uint32_t raw_status);
  ```

- [ ] **Step 2: Initialize worker thread in constructor**
  In `DbgEngCommandExecutor`'s constructor, start the background worker thread:
  ```cpp
  DbgEngCommandExecutor::DbgEngCommandExecutor() {
    worker_thread_ = std::thread(&DbgEngCommandExecutor::WorkerThreadProc, this);
  }
  ```

- [ ] **Step 3: Shut down worker thread in destructor**
  Ensure the thread is gracefully joined on destruct:
  ```cpp
  DbgEngCommandExecutor::~DbgEngCommandExecutor() {
    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      shutdown_ = true;
    }
    cv_.notify_one();
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }
  ```

- [ ] **Step 4: Implement `Execute` via promise/future pipeline**
  Change `Execute` implementation to push tasks into the queue and block waiting for the future:
  ```cpp
  CommandExecutionResult DbgEngCommandExecutor::Execute(const std::string& command, const CommandExecutionOptions& options) {
    std::promise<CommandExecutionResult> promise;
    std::future<CommandExecutionResult> future = promise.get_future();

    {
      std::lock_guard<std::mutex> lock(queue_mutex_);
      task_queue_.push(ExecutionTask{command, options, std::move(promise)});
    }
    cv_.notify_one();
    return future.get();
  }
  ```

- [ ] **Step 5: Implement `WorkerThreadProc` loop**
  The proc consumes tasks and evaluates them using the existing synchronous logic:
  ```cpp
  void DbgEngCommandExecutor::WorkerThreadProc() {
    while (true) {
      ExecutionTask task;
      {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        cv_.wait(lock, [this] { return shutdown_ || !task_queue_.empty(); });
        if (shutdown_ && task_queue_.empty()) {
          break;
        }
        task = std::move(task_queue_.front());
        task_queue_.pop();
      }

      // Run command evaluation (using existing synchronous IDebugControl logic)
      CommandExecutionResult result = ExecuteSynchronously(task.command, task.options);
      task.promise.set_value(result);
    }
  }
  ```

---

### Task 3: Implement execution status query and SetInterrupt break-in

**Files:**
- Modify: `src/windbg/dbgeng_command_executor.cpp`

- [ ] **Step 1: Implement `GetExecutionState` via `GetExecutionStatus`**
  Query `IDebugControl::GetExecutionStatus` to map the status cleanly:
  ```cpp
  DebuggerExecutionState DbgEngCommandExecutor::GetExecutionState() {
    Microsoft::WRL::ComPtr<IDebugClient> client;
    if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
      return {};
    }
    Microsoft::WRL::ComPtr<IDebugControl> control;
    if (FAILED(client.As(&control))) {
      return {};
    }

    ULONG raw_status = 0;
    if (FAILED(control->GetExecutionStatus(&raw_status))) {
      return {};
    }
    return ParseRawStatus(raw_status);
  }
  ```

- [ ] **Step 2: Implement status parser helpers**
  Map raw execution states (`DEBUG_STATUS_GO`, `DEBUG_STATUS_BREAK`, etc.) to readable metadata:
  ```cpp
  DebuggerExecutionState DbgEngCommandExecutor::ParseRawStatus(std::uint32_t raw_status) {
    DebuggerExecutionState state;
    state.raw_status = raw_status;
    
    switch (raw_status) {
      case DEBUG_STATUS_GO:
        state.status_name = "go";
        state.running = true;
        state.summary = "The target is running.";
        break;
      case DEBUG_STATUS_BREAK:
        state.status_name = "break";
        state.ready_for_commands = true;
        state.summary = "The target is broken in and ready for commands.";
        break;
      case DEBUG_STATUS_NO_DEBUGGEE:
        state.status_name = "no_debuggee";
        state.summary = "No debuggee is active.";
        break;
      default:
        state.status_name = "busy";
        state.busy = true;
        state.summary = "The debugger is busy or processing events.";
        break;
    }
    return state;
  }
  ```

- [ ] **Step 3: Implement `InterruptTarget` using `SetInterrupt`**
  Trigger debugger breaks using active interrupt parameters:
  ```cpp
  bool DbgEngCommandExecutor::InterruptTarget() {
    Microsoft::WRL::ComPtr<IDebugClient> client;
    if (FAILED(DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(client.GetAddressOf())))) {
      return false;
    }
    Microsoft::WRL::ComPtr<IDebugControl> control;
    if (FAILED(client.As(&control))) {
      return false;
    }

    return SUCCEEDED(control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE));
  }
  ```

- [ ] **Step 4: Commit Chunk 1 changes**
  ```bash
  git add include/dbgx/windbg/dbgeng_command_executor.hpp src/windbg/dbgeng_command_executor.cpp
  git commit -m "feat: implement background worker queue and SetInterrupt controls"
  ```

---

## Chunk 2: Static WinDbg Command Catalog & Search

Providing documentation inside the DLL prevents AI clients from generating invalid arguments or executing commands with wrong parameters.

### Task 4: Define catalog data structure

**Files:**
- Create: `include/dbgx/windbg/catalog.hpp`

- [ ] **Step 1: Implement `CatalogEntry` and `Catalog` class structures**
  ```cpp
  #pragma once

  #include <string>
  #include <vector>
  #include <optional>

  namespace dbgx::windbg {

  struct CatalogEntry {
    std::string id;
    std::string title;
    std::string summary;
    std::vector<std::string> tokens;
    std::string syntax;
    std::string documentation;
  };

  class Catalog {
   public:
    static const std::vector<CatalogEntry>& GetEntries();
    static std::vector<CatalogEntry> Search(const std::string& query, size_t limit = 10);
    static std::optional<CatalogEntry> GetById(const std::string& id);
  };

  } // namespace dbgx::windbg
  ```

---

### Task 5: Populate documentation catalog payload & search logic

**Files:**
- Create: `src/windbg/catalog.cpp`

- [ ] **Step 1: Populate core command catalog**
  Populate `GetEntries()` with high-frequency WinDbg command metadata (e.g., `bp`, `dt`, `r`, `k`, `u`):
  ```cpp
  #include "dbgx/windbg/catalog.hpp"
  #include <algorithm>
  #include <cctype>

  namespace dbgx::windbg {

  const std::vector<CatalogEntry>& Catalog::GetEntries() {
    static const std::vector<CatalogEntry> entries = {
      {
        "bp_set_breakpoint",
        "bp, bu, bm (Set Breakpoint)",
        "Sets a software breakpoint at a specified address or symbol.",
        {"bp", "bu", "bm"},
        "bp [ID] [Options] [Address [Passes]] [\"CommandString\"]",
        "Parameters:\n"
        " - ID: Unique breakpoint identifier (integer)\n"
        " - Address: The virtual memory offset or symbol to break on\n"
        " - CommandString: Command list executed automatically on break"
      },
      {
        "dt_display_type",
        "dt (Display Type)",
        "Displays information about a local variable, global variable, or data type structure.",
        {"dt"},
        "dt [Module!]Name [Field] [Address] [-r[Depth]]",
        "Parameters:\n"
        " - Module!Name: Name of structure or class, optionally prefixed by module\n"
        " - Address: Memory location of instance to dump"
      },
      {
        "k_display_stack",
        "k, kp, kb (Display Stack Backtrace)",
        "Displays the call stack of the current thread.",
        {"k", "kp", "kb", "kv"},
        "k[p|b|v] [FrameCount]",
        "Subcommands:\n"
        " - kp: Shows full parameter details for stack frames\n"
        " - kb: Shows first three arguments passed to each function"
      }
    };
    return entries;
  }
  ```

- [ ] **Step 2: Implement search token-scoring algorithm**
  Write substring/token-based matching to score and sort results:
  ```cpp
  std::vector<CatalogEntry> Catalog::Search(const std::string& query, size_t limit) {
    std::string needle = query;
    std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);

    std::vector<std::pair<int, CatalogEntry>> scored;
    for (const auto& entry : GetEntries()) {
      int score = 0;
      if (entry.id == needle) score += 100;
      for (const auto& token : entry.tokens) {
        if (token == needle) score += 80;
      }
      
      std::string title = entry.title;
      std::transform(title.begin(), title.end(), title.begin(), ::tolower);
      if (title.find(needle) != std::string::npos) score += 40;

      if (score > 0) {
        scored.push_back({score, entry});
      }
    }

    std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
      return a.first > b.first;
    });

    std::vector<CatalogEntry> results;
    for (size_t i = 0; i < (std::min)(limit, scored.size()); ++i) {
      results.push_back(scored[i].second);
    }
    return results;
  }

  std::optional<CatalogEntry> Catalog::GetById(const std::string& id) {
    for (const auto& entry : GetEntries()) {
      if (entry.id == id) return entry;
    }
    return std::nullopt;
  }

  } // namespace dbgx::windbg
  ```

- [ ] **Step 3: Commit catalog additions**
  ```bash
  git add include/dbgx/windbg/catalog.hpp src/windbg/catalog.cpp
  git commit -m "feat: implement static WinDbg command catalog and scoring search"
  ```

---

## Chunk 3: Wire JSON-RPC Routes & Test

Finally, map the new C++ components to JSON-RPC routing handlers and add testing assertions.

### Task 6: Update CMakeLists.txt to compile catalog

**Files:**
- Modify: `CMakeLists.txt`

- [ ] **Step 1: Append new source file**
  Add `src/windbg/catalog.cpp` to `add_library(dbgx-mcp SHARED ...)` and `add_executable(unit_tests ...)`:
  ```cmake
  # Inside add_library(dbgx-mcp) and add_executable(unit_tests):
  src/windbg/catalog.cpp
  ```

---

### Task 7: Wire up JSON-RPC Tools

**Files:**
- Modify: `src/mcp/json_rpc.cpp`

- [ ] **Step 1: Update `HandleToolsList` tool discovery payload**
  Advertise `windbg.get_execution_state`, `windbg.interrupt`, `windbg.search_catalog`, and `windbg.get_command_docs`:
  ```cpp
  // In HandleToolsList() JSON schema payload, append new tools:
  "{"
  "\"name\":\"windbg.get_execution_state\","
  "\"description\":\"Get current debugger execution status.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
  "},"
  "{"
  "\"name\":\"windbg.interrupt\","
  "\"description\":\"Send active interrupt break-in to target debuggee.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
  "},"
  "{"
  "\"name\":\"windbg.search_catalog\","
  "\"description\":\"Search the static debugger command catalog.\","
  "\"inputSchema\":{"
  "\"type\":\"object\","
  "\"properties\":{"
  "\"query\":{\"type\":\"string\",\"description\":\"Term to search\"}"
  "},"
  "\"required\":[\"query\"]"
  "}"
  "}"
  ```

- [ ] **Step 2: Dispatch routing in `HandleToolsCall`**
  Implement dispatch branches calling the executor and catalog:
  ```cpp
  // Inside HandleToolsCall():
  if (tool_name == "windbg.get_execution_state") {
    auto state = executor->GetExecutionState();
    outcome.ok = true;
    outcome.result_json = "{\"state_name\":\"" + state.status_name + "\",\"running\":" + (state.running ? "true" : "false") + "}";
  } else if (tool_name == "windbg.interrupt") {
    bool success = executor->InterruptTarget();
    outcome.ok = true;
    outcome.result_json = "{\"success\":" + std::string(success ? "true" : "false") + "}";
  } else if (tool_name == "windbg.search_catalog") {
    std::string query;
    json::TryGetStringField(arguments_fields, "query", &query);
    auto matches = windbg::Catalog::Search(query);
    // Build serialized JSON list array...
  }
  ```

---

### Task 8: Implement integration unit tests

**Files:**
- Modify: `tests/unit_tests.cpp`

- [ ] **Step 1: Add assertions validating catalog search**
  Add test case validating matches:
  ```cpp
  void TestCatalogSearch(std::vector<std::string>& failures) {
    auto results = dbgx::windbg::Catalog::Search("bp");
    Expect(!results.empty(), "catalog search for bp should yield matches", failures);
    Expect(results[0].tokens[0] == "bp", "first match should be software breakpoints", failures);
  }
  ```

- [ ] **Step 2: Build and verify unit tests**
  Verify CMake configuration compiles successfully and tests pass:
  ```bash
  cmake --build build
  ctest --test-dir build --output-on-failure
  ```

- [ ] **Step 3: Commit integration updates**
  ```bash
  git add src/mcp/json_rpc.cpp tests/unit_tests.cpp
  git commit -m "feat: integrate mcp tools routes and catalog unit tests"
  ```

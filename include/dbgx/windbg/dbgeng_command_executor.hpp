#pragma once
#include <DbgEng.h>
#include <wrl/client.h>

#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

#include "dbgx/windbg/command_executor.hpp"

namespace dbgx::windbg {

class DbgEngCommandExecutor final : public IWinDbgCommandExecutor {
public:
  DbgEngCommandExecutor();
  ~DbgEngCommandExecutor() override;

  CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) override;
  CommandExecutionResult EvaluateModel(const std::string& expression, int max_depth = 5) override;
  CommandExecutionResult GetContextSnapshot(bool include_all_registers = false) override;
  CommandExecutionResult ReadMemory(std::uint64_t address, std::uint32_t length) override;
  CommandExecutionResult WriteMemory(std::uint64_t address, const std::string& hex_data) override;
  CommandExecutionResult CarvePE(std::uint64_t address, std::uint32_t length) override;
  CommandExecutionResult SearchMemory(std::uint64_t start_address, std::uint64_t end_address,
                                      const std::string& pattern) override;
  CommandExecutionResult GetThreads() override;
  SessionMetadata GetSessionMetadata() override;
  DebuggerExecutionState GetExecutionState() override;
  bool InterruptTarget() override;
  CommandExecutionResult GetModules() override;
  CommandExecutionResult GetBreakpoints() override;
  CommandExecutionResult Disassemble(std::uint64_t address, std::uint32_t count = 10) override;
  CommandExecutionResult ReadString(std::uint64_t address, std::uint32_t max_length = 256, bool wide = false) override;
  CommandExecutionResult Step(bool step_over = true, bool reverse = false, std::uint32_t count = 1) override;
  CommandExecutionResult ContinueTarget(bool reverse = false) override;
  CommandExecutionResult SetBreakpoint(const std::string& expression) override;
  CommandExecutionResult ClearBreakpoint(const std::string& id) override;
  CommandExecutionResult ResolveSymbol(const std::string& expression) override;
  CommandExecutionResult GetOrSetTTDPosition(const std::string& target_position = "") override;
  std::optional<std::uint64_t> ResolveAddress(const std::string& expression) override;

private:
  using TaskFunction = std::function<CommandExecutionResult()>;

  struct ExecutionTask {
    TaskFunction func;
    std::promise<CommandExecutionResult> promise;
    bool has_promise = true;
  };

  std::thread worker_thread_;
  std::mutex queue_mutex_;
  std::condition_variable cv_;
  std::queue<ExecutionTask> task_queue_;
  bool shutdown_ = false;

  Microsoft::WRL::ComPtr<IDebugControl> interrupt_control_;

  // Worker-thread local cached COM interfaces
  Microsoft::WRL::ComPtr<IDebugClient> worker_client_;
  Microsoft::WRL::ComPtr<IDebugControl> worker_control_;
  Microsoft::WRL::ComPtr<IDebugDataSpaces> worker_data_;
  Microsoft::WRL::ComPtr<IDebugSymbols3> worker_symbols_;
  Microsoft::WRL::ComPtr<IDebugRegisters> worker_registers_;
  Microsoft::WRL::ComPtr<IDebugSystemObjects> worker_systems_;

  void WorkerThreadProc();
  CommandExecutionResult DispatchToWorker(TaskFunction func, bool check_ready = true);
  CommandExecutionResult ExecuteSynchronously(const std::string& command, const CommandExecutionOptions& options);
  CommandExecutionResult EvaluateModelSynchronously(const std::string& expression, int max_depth);
  CommandExecutionResult GetContextSnapshotSynchronously(bool include_all_registers);
  CommandExecutionResult ReadMemorySynchronously(std::uint64_t address, std::uint32_t length);
  CommandExecutionResult WriteMemorySynchronously(std::uint64_t address, const std::string& hex_data);
  CommandExecutionResult CarvePESynchronously(std::uint64_t address, std::uint32_t length);
  CommandExecutionResult SearchMemorySynchronously(std::uint64_t start_address, std::uint64_t end_address,
                                                   const std::string& pattern);
  CommandExecutionResult GetThreadsSynchronously();
  CommandExecutionResult GetModulesSynchronously();
  CommandExecutionResult GetBreakpointsSynchronously();
  CommandExecutionResult DisassembleSynchronously(std::uint64_t address, std::uint32_t count);
  CommandExecutionResult ReadStringSynchronously(std::uint64_t address, std::uint32_t max_length, bool wide);
  CommandExecutionResult ResolveSymbolSynchronously(const std::string& expression);
  CommandExecutionResult GetOrSetTTDPositionSynchronously(const std::string& target_position);
  std::optional<std::uint64_t> ResolveAddressSynchronously(const std::string& expression);
  static DebuggerExecutionState ParseRawStatus(std::uint32_t raw_status);
};

}  // namespace dbgx::windbg

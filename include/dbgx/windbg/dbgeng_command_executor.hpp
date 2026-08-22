#pragma once
#include "dbgx/windbg/command_executor.hpp"
#include <functional>
#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <DbgEng.h>
#include <wrl/client.h>

namespace dbgx::windbg {

class DbgEngCommandExecutor final : public IWinDbgCommandExecutor {
 public:
  DbgEngCommandExecutor();
  ~DbgEngCommandExecutor() override;

  CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) override;
  CommandExecutionResult EvaluateModel(const std::string& expression, int max_depth = 5) override;
  CommandExecutionResult GetContextSnapshot() override;
  CommandExecutionResult ReadMemory(std::uint64_t address, std::uint32_t length) override;
  CommandExecutionResult WriteMemory(std::uint64_t address, const std::string& hex_data) override;
  CommandExecutionResult CarvePE(std::uint64_t address, std::uint32_t length) override;
  CommandExecutionResult SearchMemory(
      std::uint64_t start_address,
      std::uint64_t end_address,
      const std::string& pattern) override;
  CommandExecutionResult GetThreads() override;
  SessionMetadata GetSessionMetadata() override;
  DebuggerExecutionState GetExecutionState() override;
  bool InterruptTarget() override;
  CommandExecutionResult GetModules() override;
  CommandExecutionResult GetBreakpoints() override;
  CommandExecutionResult Disassemble(std::uint64_t address, std::uint32_t count = 10) override;
  CommandExecutionResult ReadString(std::uint64_t address, std::uint32_t max_length = 256, bool wide = false) override;
  CommandExecutionResult Step(bool step_over = true) override;
  CommandExecutionResult ContinueTarget() override;
  CommandExecutionResult SetBreakpoint(const std::string& expression) override;

 private:
  using TaskFunction = std::function<CommandExecutionResult()>;

  struct ExecutionTask {
    TaskFunction func;
    std::promise<CommandExecutionResult> promise;
  };

  std::thread worker_thread_;
  std::mutex queue_mutex_;
  std::condition_variable cv_;
  std::queue<ExecutionTask> task_queue_;
  bool shutdown_ = false;

  Microsoft::WRL::ComPtr<IDebugClient> client_;
  Microsoft::WRL::ComPtr<IDebugControl> control_;
  Microsoft::WRL::ComPtr<IDebugControl> interrupt_control_;

  void WorkerThreadProc();
  CommandExecutionResult DispatchToWorker(TaskFunction func, bool check_ready = true);
  CommandExecutionResult ExecuteSynchronously(const std::string& command, const CommandExecutionOptions& options);
  CommandExecutionResult EvaluateModelSynchronously(const std::string& expression, int max_depth);
  CommandExecutionResult GetContextSnapshotSynchronously();
  CommandExecutionResult ReadMemorySynchronously(std::uint64_t address, std::uint32_t length);
  CommandExecutionResult WriteMemorySynchronously(std::uint64_t address, const std::string& hex_data);
  CommandExecutionResult CarvePESynchronously(std::uint64_t address, std::uint32_t length);
  CommandExecutionResult SearchMemorySynchronously(std::uint64_t start_address, std::uint64_t end_address, const std::string& pattern);
  CommandExecutionResult GetThreadsSynchronously();
  CommandExecutionResult GetModulesSynchronously();
  CommandExecutionResult GetBreakpointsSynchronously();
  CommandExecutionResult DisassembleSynchronously(std::uint64_t address, std::uint32_t count);
  CommandExecutionResult ReadStringSynchronously(std::uint64_t address, std::uint32_t max_length, bool wide);
  static DebuggerExecutionState ParseRawStatus(std::uint32_t raw_status);
};

}  // namespace dbgx::windbg

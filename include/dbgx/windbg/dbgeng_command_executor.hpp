#pragma once
#include "dbgx/windbg/command_executor.hpp"
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

  Microsoft::WRL::ComPtr<IDebugClient> client_;
  Microsoft::WRL::ComPtr<IDebugControl> control_;
  Microsoft::WRL::ComPtr<IDebugControl> interrupt_control_;

  void WorkerThreadProc();
  CommandExecutionResult ExecuteSynchronously(const std::string& command, const CommandExecutionOptions& options);
  static DebuggerExecutionState ParseRawStatus(std::uint32_t raw_status);
};

}  // namespace dbgx::windbg

#pragma once

#include "dbgx/windbg/command_executor.hpp"

namespace dbgx::windbg {

class DbgEngCommandExecutor final : public IWinDbgCommandExecutor {
 public:
  CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) override;
  CommandExecutionResult EvaluateModel(const std::string& expression, int max_depth = 5) override;
  CommandExecutionResult GetContextSnapshot() override;
  CommandExecutionResult ReadMemory(std::uint64_t address, std::uint32_t length) override;
  CommandExecutionResult SearchMemory(
      std::uint64_t start_address,
      std::uint64_t end_address,
      const std::string& pattern) override;
  SessionMetadata GetSessionMetadata() override;
};

}  // namespace dbgx::windbg

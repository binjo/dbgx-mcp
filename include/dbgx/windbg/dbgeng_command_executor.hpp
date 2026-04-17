#pragma once

#include "dbgx/windbg/command_executor.hpp"

namespace dbgx::windbg {

class DbgEngCommandExecutor final : public IWinDbgCommandExecutor {
 public:
  CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) override;
  SessionMetadata GetSessionMetadata() override;
};

}  // namespace dbgx::windbg

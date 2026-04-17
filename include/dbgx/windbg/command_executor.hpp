#pragma once

#include <string>

namespace dbgx::windbg {

struct CommandExecutionResult {
  bool success = false;
  std::string output;
  std::string error_message;
};

struct CommandExecutionOptions {
  int max_lines = 100;
  std::string pattern;
};

struct SessionMetadata {
  std::uint32_t process_id = 0;
  std::string executable_name;
  std::string target_info;
};

class IWinDbgCommandExecutor {
 public:
  virtual ~IWinDbgCommandExecutor() = default;
  virtual CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) = 0;
  virtual SessionMetadata GetSessionMetadata() = 0;
};

}  // namespace dbgx::windbg

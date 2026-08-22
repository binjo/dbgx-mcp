#pragma once

#include <cstdint>
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
  std::string architecture;
  std::string debuggee_class;
};

struct DebuggerExecutionState {
  std::uint32_t raw_status = 0;
  std::string status_name;
  bool running = false;
  bool busy = false;
  bool ready_for_commands = false;
  std::string summary;
};

class IWinDbgCommandExecutor {
 public:
  virtual ~IWinDbgCommandExecutor() = default;
  virtual CommandExecutionResult Execute(const std::string& command, const CommandExecutionOptions& options = {}) = 0;
  virtual CommandExecutionResult EvaluateModel(const std::string& expression, int max_depth = 5) = 0;
  virtual CommandExecutionResult GetContextSnapshot() = 0;
  virtual CommandExecutionResult ReadMemory(std::uint64_t address, std::uint32_t length) = 0;
  virtual CommandExecutionResult WriteMemory(std::uint64_t address, const std::string& hex_data) = 0;
  virtual CommandExecutionResult CarvePE(std::uint64_t address, std::uint32_t length) = 0;
  virtual CommandExecutionResult SearchMemory(std::uint64_t start_address, std::uint64_t end_address, const std::string& pattern) = 0;
  virtual CommandExecutionResult GetThreads() = 0;
  virtual SessionMetadata GetSessionMetadata() = 0;
  virtual DebuggerExecutionState GetExecutionState() = 0;
  virtual bool InterruptTarget() = 0;
  virtual CommandExecutionResult GetModules() = 0;
  virtual CommandExecutionResult GetBreakpoints() = 0;
  virtual CommandExecutionResult Disassemble(std::uint64_t address, std::uint32_t count = 10) = 0;
  virtual CommandExecutionResult ReadString(std::uint64_t address, std::uint32_t max_length = 256, bool wide = false) = 0;
  virtual CommandExecutionResult Step(bool step_over = true) = 0;
  virtual CommandExecutionResult ContinueTarget() = 0;
  virtual CommandExecutionResult SetBreakpoint(const std::string& expression) = 0;
};

}  // namespace dbgx::windbg

#pragma once

#include <cstdint>
#include <optional>
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
  bool is_ttd = false;
  std::string target_type;
};

// Result of classifying IDebugControl::GetDebuggeeType(&Class, &Qualifier).
struct DebuggeeClassification {
  std::string debuggee_class;
  std::string target_type;
  bool is_ttd = false;
};

// Pure mapping from DbgEng (Class, Qualifier) to the session metadata fields. Kept free of
// DbgEng.h so it can be unit-tested; the numeric values mirror the DbgEng.h constants:
//   Class:     DEBUG_CLASS_KERNEL = 1, DEBUG_CLASS_USER_WINDOWS = 2
//   Qualifier: DEBUG_USER_WINDOWS_PROCESS = 0, DEBUG_USER_WINDOWS_PROCESS_SERVER = 1,
//              DEBUG_USER_WINDOWS_IDNA = 2 (Time Travel Debugging trace),
//              dump qualifiers start at DEBUG_DUMP_SMALL = 1024 (user: *_SMALL_DUMP / *_DUMP,
//              kernel: *_SMALL_DUMP / *_DUMP / *_FULL_DUMP / *_ACTIVE_DUMP).
inline DebuggeeClassification ClassifyDebuggee(std::uint32_t debug_class, std::uint32_t qualifier) {
  constexpr std::uint32_t kClassKernel = 1;
  constexpr std::uint32_t kClassUserWindows = 2;
  constexpr std::uint32_t kUserWindowsIdna = 2;
  constexpr std::uint32_t kDumpQualifierBase = 1024;

  DebuggeeClassification result;
  if (debug_class == kClassUserWindows) {
    result.debuggee_class = "user";
    if (qualifier == kUserWindowsIdna) {
      result.is_ttd = true;
      result.target_type = "ttd_trace";
    } else if (qualifier >= kDumpQualifierBase) {
      result.target_type = "dump_user";
    } else {
      result.target_type = "live_user";
    }
  } else if (debug_class == kClassKernel) {
    result.debuggee_class = "kernel";
    result.target_type = qualifier >= kDumpQualifierBase ? "dump_kernel" : "live_kernel";
  } else {
    result.debuggee_class = "other (" + std::to_string(debug_class) + ")";
    result.target_type = "other";
  }
  return result;
}

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
  virtual CommandExecutionResult GetContextSnapshot(bool include_all_registers = false) = 0;
  virtual CommandExecutionResult ReadMemory(std::uint64_t address, std::uint32_t length) = 0;
  virtual CommandExecutionResult WriteMemory(std::uint64_t address, const std::string& hex_data) = 0;
  virtual CommandExecutionResult CarvePE(std::uint64_t address, std::uint32_t length) = 0;
  virtual CommandExecutionResult SearchMemory(std::uint64_t start_address, std::uint64_t end_address,
                                              const std::string& pattern) = 0;
  virtual CommandExecutionResult GetThreads() = 0;
  virtual SessionMetadata GetSessionMetadata() = 0;
  virtual DebuggerExecutionState GetExecutionState() = 0;
  virtual bool InterruptTarget() = 0;
  virtual CommandExecutionResult GetModules() = 0;
  virtual CommandExecutionResult GetBreakpoints() = 0;
  virtual CommandExecutionResult Disassemble(std::uint64_t address, std::uint32_t count = 10) = 0;
  virtual CommandExecutionResult ReadString(std::uint64_t address, std::uint32_t max_length = 256,
                                            bool wide = false) = 0;
  virtual CommandExecutionResult Step(bool step_over = true, bool reverse = false, std::uint32_t count = 1) = 0;
  virtual CommandExecutionResult ContinueTarget(bool reverse = false) = 0;
  virtual CommandExecutionResult SetBreakpoint(const std::string& expression) = 0;
  virtual CommandExecutionResult ClearBreakpoint(const std::string& id) = 0;
  virtual CommandExecutionResult ResolveSymbol(const std::string& expression) = 0;
  virtual CommandExecutionResult GetOrSetTTDPosition(const std::string& target_position = "") = 0;
  virtual std::optional<std::uint64_t> ResolveAddress(const std::string& expression) = 0;
};

}  // namespace dbgx::windbg

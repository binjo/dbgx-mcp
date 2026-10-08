#pragma once

#include <string>
#include <string_view>

// Server-side safety guardrails. These mirror (and are the authoritative
// counterpart to) the checks performed by windbg-bridge.py so that clients
// talking to the HTTP/pipe endpoint directly -- without the bridge -- get the
// same protection against session-killing commands.
namespace dbgx::mcp {

// Returns true if the debugger command may be executed via windbg.eval.
// Rejects session-terminating commands (q, .kill, .restart, .reboot, ...),
// shell escapes (.shell / !shell), remote-server commands, and command-file
// sourcing ($<, $$<, $>, $$>). Chained commands ("r; q") are split on ';'
// (quote-aware) and every sub-command is checked.
bool ValidateDebuggerCommand(std::string_view command, std::string* error_message);

// Returns true for tools that mutate target state or the guest file system
// (write_memory, write_file, continue, step, set/clear_breakpoint, apply_*,
// ttd_position seek, eval). Used to enforce read-only mode.
bool IsMutatingTool(std::string_view tool_name);

// Read-only mode is enabled by setting the environment variable
// WINDBG_MCP_READONLY to a non-empty value other than "0"/"false" before the
// extension loads. In this mode every mutating tool is rejected.
bool IsReadOnlyModeEnabled();

// Normalises "windbg_xyz" -> "windbg.xyz" (same rule as the tools/call router).
std::string NormalizeToolName(std::string_view tool_name);

}  // namespace dbgx::mcp

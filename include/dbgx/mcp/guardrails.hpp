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

// Like ValidateDebuggerCommand, but also reports which token tripped the
// guardrail (e.g. ".kill", "$<") so the caller can look up an alternative.
bool ValidateDebuggerCommandDetail(std::string_view command, std::string* blocked_token,
                                   std::string* error_message);

// What the agent should do instead of a blocked command token. Empty if unknown.
std::string GuardrailAlternative(std::string_view blocked_token);

// MCP tool annotations (spec 2025-03-26). Clients use them to decide which
// calls need confirmation; keep in sync with TOOL_TRAITS in windbg-bridge.py.
struct ToolAnnotations {
  bool read_only = false;
  bool destructive = false;
  bool idempotent = false;
  bool open_world = false;
};

// Looks up annotations for a tool. Returns false for unknown tools.
bool GetToolAnnotations(std::string_view tool_name, ToolAnnotations* out);

// Serialises annotations as the MCP JSON object
// {"readOnlyHint":..,"destructiveHint":..,"idempotentHint":..,"openWorldHint":..}.
std::string ToolAnnotationsJson(const ToolAnnotations& annotations);

// Inserts "annotations":{...} after every "name":"windbg.*" entry of a
// tools/list result document that lacks one. Unknown tools are left untouched.
std::string InjectToolAnnotations(std::string tools_list_json);

// Guidance returned in the `instructions` field of the initialize result.
std::string_view ServerInstructions();

// Builds a tools/call result that reports a policy refusal (guardrail,
// read-only mode) as an isError content block the model can read:
// {"content":[{"type":"text","text":"{\"error\":..,\"message\":..,\"next_steps\":[..]}"}],"isError":true}
std::string BuildRefusalResult(std::string_view error_kind, std::string_view message,
                               std::string_view next_step);

}  // namespace dbgx::mcp

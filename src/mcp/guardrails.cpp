#include "dbgx/mcp/guardrails.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

#include "dbgx/mcp/json.hpp"

namespace dbgx::mcp {

namespace {

// Keep in sync with DANGEROUS_COMMANDS in windbg-bridge.py.
constexpr std::array<std::string_view, 15> kDangerousCommands = {
    // Session exit / termination
    "q", "qq", "qd", ".kill", ".detach", ".abandon", ".restart", ".reboot", ".crash",
    // Shell escapes
    ".shell", "!shell",
    // Networking / remote server commands
    ".server", ".endsrv", ".remote",
    // Unloading ourselves mid-request would deadlock the engine.
    ".unload",
};

// windbg.interrupt is intentionally absent: breaking in is required to observe
// a running target. windbg.ttd_position is only mutating when seeking; the
// router checks the `position` argument before applying read-only mode.
constexpr std::array<std::string_view, 11> kMutatingTools = {
    "windbg.eval",           "windbg.write_memory",    "windbg.write_file",
    "windbg.continue",       "windbg.step",            "windbg.set_breakpoint",
    "windbg.clear_breakpoint", "windbg.apply_struct",  "windbg.apply_synthetic_type",
    "windbg.ttd_position",   "windbg.time_travel",
};

std::string ToLower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return out;
}

std::string_view Trim(std::string_view text) {
  while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front()))) {
    text.remove_prefix(1);
  }
  while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back()))) {
    text.remove_suffix(1);
  }
  return text;
}

// Splits on ';' while respecting single and double quotes (mirrors the bridge's
// split_commands_safe()).
std::vector<std::string_view> SplitCommandsSafe(std::string_view command) {
  std::vector<std::string_view> parts;
  char in_quote = 0;
  std::size_t start = 0;
  for (std::size_t i = 0; i < command.size(); ++i) {
    const char c = command[i];
    if (in_quote != 0) {
      if (c == in_quote) {
        in_quote = 0;
      }
    } else if (c == '"' || c == '\'') {
      in_quote = c;
    } else if (c == ';') {
      std::string_view part = Trim(command.substr(start, i - start));
      if (!part.empty()) {
        parts.push_back(part);
      }
      start = i + 1;
    }
  }
  std::string_view tail = Trim(command.substr(start));
  if (!tail.empty()) {
    parts.push_back(tail);
  }
  return parts;
}

std::string_view FirstToken(std::string_view text) {
  text = Trim(text);
  std::size_t end = 0;
  while (end < text.size() && !std::isspace(static_cast<unsigned char>(text[end]))) {
    ++end;
  }
  return text.substr(0, end);
}

}  // namespace

bool ValidateDebuggerCommandDetail(std::string_view command, std::string* blocked_token,
                                   std::string* error_message) {
  // Reject sourcing/nesting command files from disk ($<, $$<, $>, $$>, $$>a<, ...).
  if (command.find("$<") != std::string_view::npos || command.find("$>") != std::string_view::npos ||
      command.find("$$<") != std::string_view::npos || command.find("$$>") != std::string_view::npos) {
    if (blocked_token != nullptr) {
      *blocked_token = "$<";
    }
    if (error_message != nullptr) {
      *error_message =
          "Sourcing or nesting command files (using '$<' or '$$<') is prohibited to prevent unauthorized disk "
          "file execution.";
    }
    return false;
  }

  for (std::string_view sub : SplitCommandsSafe(command)) {
    const std::string base = ToLower(FirstToken(sub));
    if (base.empty()) {
      continue;
    }
    for (std::string_view dangerous : kDangerousCommands) {
      if (base == dangerous) {
        if (blocked_token != nullptr) {
          *blocked_token = base;
        }
        if (error_message != nullptr) {
          *error_message = "The command '" + base +
                           "' is prohibited by the server guardrails to prevent accidental termination or "
                           "corruption of the debugging session.";
        }
        return false;
      }
    }
  }
  return true;
}

bool ValidateDebuggerCommand(std::string_view command, std::string* error_message) {
  return ValidateDebuggerCommandDetail(command, nullptr, error_message);
}

std::string NormalizeToolName(std::string_view tool_name) {
  std::string name(tool_name);
  if (name.rfind("windbg_", 0) == 0) {
    name = "windbg." + name.substr(7);
  }
  return name;
}

bool IsMutatingTool(std::string_view tool_name) {
  const std::string name = NormalizeToolName(tool_name);
  return std::find(kMutatingTools.begin(), kMutatingTools.end(), name) != kMutatingTools.end();
}

bool IsReadOnlyModeEnabled() {
  char buf[16] = {};
  const DWORD len = GetEnvironmentVariableA("WINDBG_MCP_READONLY", buf, sizeof(buf));
  if (len == 0 || len >= sizeof(buf)) {
    return false;
  }
  const std::string value = ToLower(Trim(std::string_view(buf, len)));
  return !(value.empty() || value == "0" || value == "false" || value == "no" || value == "off");
}

namespace {

constexpr std::string_view kLifecycleAlternative =
    "Target lifecycle is reserved for the user; use windbg.continue / windbg.interrupt to control execution.";
constexpr std::string_view kQuitAlternative =
    "Ending the debugger session is reserved for the user; leave the target as it is.";
constexpr std::string_view kShellAlternative =
    "Shell escapes are blocked; use windbg.write_file for file output or ask the user to run host commands.";
constexpr std::string_view kRemoteAlternative = "Remote debugging setup is reserved for the user.";

struct AlternativeEntry {
  std::string_view token;
  std::string_view alternative;
};

constexpr std::array<AlternativeEntry, 16> kGuardrailAlternatives = {{
    {"q", kQuitAlternative},
    {"qq", kQuitAlternative},
    {"qd", kQuitAlternative},
    {".kill", kLifecycleAlternative},
    {".detach", kLifecycleAlternative},
    {".abandon", kLifecycleAlternative},
    {".restart", "Target lifecycle is reserved for the user; ask them to restart the target if needed."},
    {".reboot", "Target lifecycle is reserved for the user; ask them to reboot the target if needed."},
    {".crash", "Target lifecycle is reserved for the user."},
    {".shell", kShellAlternative},
    {"!shell", kShellAlternative},
    {".server", kRemoteAlternative},
    {".endsrv", kRemoteAlternative},
    {".remote", kRemoteAlternative},
    {".unload", "The MCP extension cannot unload itself mid-request; ask the user to run .unload in WinDbg."},
    {"$<", "Inline the commands in windbg.eval (separate with ';') instead of sourcing a script file."},
}};

struct AnnotationEntry {
  std::string_view tool;
  ToolAnnotations annotations;
};

constexpr ToolAnnotations kReadOnly{true, false, true, false};
constexpr ToolAnnotations kControl{false, false, false, false};
constexpr ToolAnnotations kIdempotentWrite{false, false, true, false};
constexpr ToolAnnotations kDestructiveIdempotent{false, true, true, false};

// Keep in sync with TOOL_TRAITS in windbg-bridge.py (tests/test_schema_drift.py checks it).
constexpr std::array<AnnotationEntry, 28> kToolAnnotations = {{
    {"windbg.eval", ToolAnnotations{false, true, false, false}},
    {"windbg.dx", kReadOnly},
    {"windbg.get_context", kReadOnly},
    {"windbg.get_modules", kReadOnly},
    {"windbg.get_breakpoints", kReadOnly},
    {"windbg.disassemble", kReadOnly},
    {"windbg.read_memory", kReadOnly},
    {"windbg.write_memory", kDestructiveIdempotent},
    {"windbg.search", kReadOnly},
    {"windbg.read_string", kReadOnly},
    {"windbg.carve_pe", kReadOnly},
    {"windbg.get_threads", kReadOnly},
    {"windbg.get_execution_state", kReadOnly},
    {"windbg.interrupt", kIdempotentWrite},
    {"windbg.step", kControl},
    {"windbg.continue", kControl},
    {"windbg.set_breakpoint", kControl},
    {"windbg.clear_breakpoint", kIdempotentWrite},
    {"windbg.resolve", kReadOnly},
    {"windbg.ttd_position", kIdempotentWrite},
    {"windbg.time_travel", kIdempotentWrite},
    {"windbg.search_catalog", kReadOnly},
    {"windbg.get_command_docs", kReadOnly},
    {"windbg.get_catalog_entry", kReadOnly},
    {"windbg.apply_struct", kIdempotentWrite},
    {"windbg.apply_synthetic_type", kIdempotentWrite},
    {"windbg.write_file", kDestructiveIdempotent},
    {"windbg.get_session_metadata", kReadOnly},
}};

constexpr std::string_view kServerInstructions =
    "dbgx-mcp WinDbg server. Prefer structured tools (get_context, get_modules, get_breakpoints, disassemble, "
    "read_memory, resolve, dx) over raw windbg.eval; use eval for anything else. WinDbg executes commands "
    "serially: wait for each call to finish before sending the next. step / continue / write_memory / "
    "set_breakpoint / ttd_position(position=...) change target state; call windbg.get_execution_state before "
    "issuing commands if a continue may still be running, and windbg.interrupt to break in. Policy refusals "
    "come back as isError results with `error`, `message` and `next_steps` fields: read them and adapt instead "
    "of retrying. Session lifecycle commands (q, .kill, .detach, .restart, .shell, .unload) are blocked; ask "
    "the user instead.";

std::string JsonBool(bool value) { return value ? "true" : "false"; }

}  // namespace

std::string GuardrailAlternative(std::string_view blocked_token) {
  const std::string token = ToLower(blocked_token);
  for (const AlternativeEntry& entry : kGuardrailAlternatives) {
    if (entry.token == token) {
      return std::string(entry.alternative);
    }
  }
  return "";
}

bool GetToolAnnotations(std::string_view tool_name, ToolAnnotations* out) {
  const std::string name = NormalizeToolName(tool_name);
  for (const AnnotationEntry& entry : kToolAnnotations) {
    if (entry.tool == name) {
      if (out != nullptr) {
        *out = entry.annotations;
      }
      return true;
    }
  }
  return false;
}

std::string ToolAnnotationsJson(const ToolAnnotations& annotations) {
  return "{\"readOnlyHint\":" + JsonBool(annotations.read_only) +
         ",\"destructiveHint\":" + JsonBool(annotations.destructive) +
         ",\"idempotentHint\":" + JsonBool(annotations.idempotent) +
         ",\"openWorldHint\":" + JsonBool(annotations.open_world) + "}";
}

std::string InjectToolAnnotations(std::string tools_list_json) {
  // Inside JSON string values a quote is always escaped (\"), so the raw byte
  // sequence "name":" can only occur as an object key at tool level.
  static constexpr std::string_view kNameKey = "\"name\":\"";
  std::size_t pos = 0;
  while ((pos = tools_list_json.find(kNameKey, pos)) != std::string::npos) {
    const std::size_t name_start = pos + kNameKey.size();
    const std::size_t name_end = tools_list_json.find('"', name_start);
    if (name_end == std::string::npos) {
      break;
    }
    const std::string_view name(tools_list_json.data() + name_start, name_end - name_start);
    std::size_t insert_at = name_end + 1;  // just past the closing quote
    ToolAnnotations annotations;
    if (GetToolAnnotations(name, &annotations)) {
      const std::string fragment = ",\"annotations\":" + ToolAnnotationsJson(annotations);
      tools_list_json.insert(insert_at, fragment);
      insert_at += fragment.size();
    }
    pos = insert_at;
  }
  return tools_list_json;
}

std::string_view ServerInstructions() { return kServerInstructions; }

std::string BuildRefusalResult(std::string_view error_kind, std::string_view message,
                               std::string_view next_step) {
  std::string payload = "{\"error\":\"" + json::Escape(error_kind) + "\",\"message\":\"" + json::Escape(message) + "\"";
  if (!next_step.empty()) {
    payload += ",\"next_steps\":[\"" + json::Escape(next_step) + "\"]";
  }
  payload += "}";
  return "{\"content\":[{\"type\":\"text\",\"text\":\"" + json::Escape(payload) + "\"}],\"isError\":true}";
}

}  // namespace dbgx::mcp

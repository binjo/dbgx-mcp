#include "dbgx/mcp/guardrails.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

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

bool ValidateDebuggerCommand(std::string_view command, std::string* error_message) {
  // Reject sourcing/nesting command files from disk ($<, $$<, $>, $$>, $$>a<, ...).
  if (command.find("$<") != std::string_view::npos || command.find("$>") != std::string_view::npos ||
      command.find("$$<") != std::string_view::npos || command.find("$$>") != std::string_view::npos) {
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

}  // namespace dbgx::mcp

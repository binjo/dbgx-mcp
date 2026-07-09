#include "dbgx/windbg/catalog.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace dbgx::windbg {

namespace {

std::string ToLower(std::string_view text) {
  std::string copy(text);
  std::transform(copy.begin(), copy.end(), copy.begin(), [](unsigned char c) {
    return std::tolower(c);
  });
  return copy;
}

std::vector<std::string> SplitWords(const std::string& text) {
  std::vector<std::string> words;
  std::string lower = ToLower(text);
  std::string word;
  for (char c : lower) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '$' || c == '?' || c == '!') {
      word.push_back(c);
    } else if (!word.empty()) {
      words.push_back(word);
      word.clear();
    }
  }
  if (!word.empty()) {
    words.push_back(word);
  }
  return words;
}

} // namespace

const std::vector<CatalogEntry>& Catalog::GetEntries() {
  static const std::vector<CatalogEntry> entries = {
    {
      "bp_bu_bm_set_breakpoint",
      "bp, bu, bm (Set Breakpoint)",
      "Sets a software breakpoint at a specified address or symbol.",
      {"bp", "bu", "bm"},
      "bp [ID] [Options] [Address [Passes]] [\"CommandString\"]\nbu [ID] [Options] [Address [Passes]] [\"CommandString\"]",
      "Syntax & Subcommands:\n"
      " - bp: Set an unresolved breakpoint on raw addresses or existing symbols\n"
      " - bu: Set an unresolved/deferred breakpoint on a symbolic name (evaluated when loaded)\n"
      " - bm: Set breakpoints on matching symbol wildcards (e.g., bm mymodule!Func*)\n\n"
      "Parameters:\n"
      " - ID: Breakpoint index (optional, if omitted automatically assigned)\n"
      " - Address: Virtual address, expression, or symbol name\n"
      " - CommandString: Debugger commands executed automatically when the breakpoint is hit"
    },
    {
      "bl_list_breakpoints",
      "bl (List Breakpoints)",
      "Lists all active breakpoints with their status, ID, addresses, and hit counts.",
      {"bl"},
      "bl",
      "Description:\n"
      " Displays a table of all current breakpoints. Includes breakpoint ID, state (e=enabled, d=disabled), virtual address, hit count, and associated command strings."
    },
    {
      "bc_bd_be_clear_breakpoints",
      "bc, bd, be (Clear / Disable / Enable Breakpoints)",
      "Clears, disables, or enables specified breakpoints by ID.",
      {"bc", "bd", "be"},
      "bc <IDs>\nbd <IDs>\nbe <IDs>",
      "Subcommands:\n"
      " - bc: Clear (permanently delete) breakpoints\n"
      " - bd: Disable breakpoints (keeps ID but does not trigger)\n"
      " - be: Enable breakpoints\n\n"
      "Parameters:\n"
      " - IDs: Breakpoint index numbers. Can be list (e.g., bc 0 1 2), range (e.g., bd 0-4), or * (e.g., be *)"
    },
    {
      "g_go_continue",
      "g (Go / Continue)",
      "Starts or resumes execution of the target process.",
      {"g"},
      "g [= StartAddress] [BreakAddress ...]",
      "Parameters:\n"
      " - StartAddress: Address where execution should resume (if omitted, resumes from current EIP/RIP)\n"
      " - BreakAddress: Set one or more temporary breakpoints during the resume run"
    },
    {
      "p_t_step",
      "p, t (Step Over / Step Into)",
      "Executes a single instruction or assembly step.",
      {"p", "t"},
      "p [= StartAddress] [Count] [\"CommandString\"]\nt [= StartAddress] [Count] [\"CommandString\"]",
      "Subcommands:\n"
      " - p: Step over (executes functions/calls as a single step)\n"
      " - t: Step into (enters functions/calls)\n\n"
      "Parameters:\n"
      " - Count: Number of steps to execute sequentially\n"
      " - CommandString: Command to execute after each step completes"
    },
    {
      "r_registers",
      "r (Registers)",
      "Displays or modifies CPU registers and flags.",
      {"r"},
      "r [RegisterName [= Value]]",
      "Description:\n"
      " - If called without arguments, displays all primary registers (eax/rax, ebx/rbx, eip/rip, efl/rflags, etc.) and the unassembled instruction at RIP.\n"
      " - To modify: r rax=0x100"
    },
    {
      "k_callstack",
      "k, kp, kb, kv (Display Call Stack)",
      "Displays the call stack backtrace for the current thread.",
      {"k", "kp", "kb", "kv"},
      "k [FrameCount]\nkp [FrameCount]\nkb [FrameCount]\nkv [FrameCount]",
      "Subcommands:\n"
      " - k: Basic backtrace listing child return address and child EBP/RSP\n"
      " - kp: Displays full parameter details for functions (requires private symbols)\n"
      " - kb: Shows the first three arguments passed to each stack function\n"
      " - kv: Shows frame pointer omission (FPO) info and calling convention"
    },
    {
      "d_display_memory",
      "d, da, db, dw, dd, dp, dq (Display Memory)",
      "Displays contents of virtual memory in various formats.",
      {"d", "da", "db", "dw", "dd", "dp", "dq"},
      "d[Format] [Address] [Length]",
      "Formats:\n"
      " - db: Byte display (hex + ASCII representations)\n"
      " - dw: Word display (16-bit unsigned integers)\n"
      " - dd: Dword display (32-bit unsigned integers)\n"
      " - dq: Qword display (64-bit unsigned integers)\n"
      " - dp: Pointer-sized display (32-bit or 64-bit hex depending on architecture)\n"
      " - da: ASCII string representation\n\n"
      "Parameters:\n"
      " - Address: The virtual offset where display starts\n"
      " - Length: Number of items to display"
    },
    {
      "e_edit_memory",
      "e, ea, eb, ew, ed, ep, eq (Edit Memory)",
      "Writes values or strings to virtual memory.",
      {"e", "ea", "eb", "ew", "ed", "ep", "eq"},
      "e[Format] Address [Values]",
      "Formats:\n"
      " - eb: Write byte values\n"
      " - ed: Write 32-bit dword values\n"
      " - eq: Write 64-bit qword values\n"
      " - ea: Write an ASCII string (terminated automatically with NUL)\n\n"
      "Example:\n"
      " eb 0x00401000 90 90 90 90"
    },
    {
      "s_search_memory",
      "s (Search Memory)",
      "Searches virtual memory for a specific byte pattern, integer, or string.",
      {"s"},
      "s -[Format] Range Pattern",
      "Formats:\n"
      " - -b: Search for byte values (e.g., s -b 0x00400000 L?0x1000 41 42 43)\n"
      " - -a: Search for ASCII strings (e.g., s -a 0x00400000 L?0x1000 \"flag\")\n"
      " - -w: Search for wide Unicode strings"
    },
    {
      "x_examine_symbols",
      "x (Examine Symbols)",
      "Searches for symbols in modules matching a wildcard string.",
      {"x"},
      "x [Module!]Pattern",
      "Example:\n"
      " x ntdll!*Create*\n"
      " x *!main"
    },
    {
      "dt_display_type",
      "dt (Display Type)",
      "Displays structured data fields, type definitions, structures, or classes.",
      {"dt"},
      "dt [Module!]TypeName [FieldName] [Address] [-r[Depth]]",
      "Parameters:\n"
      " - TypeName: Name of struct or union (e.g., _PEB)\n"
      " - FieldName: Optional filter to show only specific fields\n"
      " - Address: Offset of the structure instance to read fields from\n"
      " - -r: Recursively dump sub-structures up to a specified depth"
    },
    {
      "lm_list_modules",
      "lm (List Modules)",
      "Lists loaded modules and their virtual memory start/end ranges.",
      {"lm"},
      "lm [Options]",
      "Options:\n"
      " - l: List only modules with loaded symbol files\n"
      " - v: Verbose details (includes symbol path, version, timestamps)\n"
      " - m: Filter by name wildcard (e.g., lm m ntdll*)"
    },
    {
      "uf_unassemble_function",
      "uf (Unassemble Function)",
      "Displays an assembly disassembly listing for an entire function.",
      {"uf"},
      "uf [AddressOrSymbol]",
      "Description:\n"
      " Unassembles instruction blocks belonging to the function containing the target address or symbol. Automatically resolves basic block branch paths rather than linear code."
    },
    {
      "peb_process_environment_block",
      "!peb (Display PEB)",
      "Displays a high-level structured breakdown of the Process Environment Block.",
      {"!peb"},
      "!peb [Address]",
      "Description:\n"
      " Shows basic environment parameters, loaded module list base, loader data pointers, session ID, and heap listings."
    },
    {
      "teb_thread_environment_block",
      "!teb (Display TEB)",
      "Displays a high-level structured breakdown of the Thread Environment Block.",
      {"!teb"},
      "!teb [Address]",
      "Description:\n"
      " Shows Thread Local Storage (TLS) details, exception list heads, stack limits, and current thread IDs."
    }
  };
  return entries;
}

std::vector<CatalogEntry> Catalog::Search(const std::string& query, size_t limit) {
  std::string needle = ToLower(query);
  if (needle.empty()) {
    auto entries = GetEntries();
    if (entries.size() > limit) {
      return std::vector<CatalogEntry>(entries.begin(), entries.begin() + limit);
    }
    return entries;
  }

  std::vector<std::string> query_words = SplitWords(query);
  std::vector<std::pair<int, CatalogEntry>> scored;

  for (const auto& entry : GetEntries()) {
    int score = 0;
    std::string entry_id = ToLower(entry.id);

    // Exact match scores
    if (entry_id == needle) {
      score += 120;
    }

    for (const auto& token : entry.tokens) {
      std::string lower_token = ToLower(token);
      if (lower_token == needle) {
        score += 100;
      }
    }

    std::string entry_title = ToLower(entry.title);
    if (entry_title.find(needle) != std::string::npos) {
      score += 40;
    }

    std::string entry_summary = ToLower(entry.summary);
    if (entry_summary.find(needle) != std::string::npos) {
      score += 20;
    }

    // Word-token matches
    for (const auto& word : query_words) {
      if (entry_id == word) {
        score += 50;
      } else if (entry_id.find(word) != std::string::npos) {
        score += 10;
      }

      for (const auto& token : entry.tokens) {
        std::string lower_token = ToLower(token);
        if (lower_token == word) {
          score += 60;
        }
      }

      if (entry_title.find(word) != std::string::npos) {
        score += 15;
      }

      if (entry_summary.find(word) != std::string::npos) {
        score += 10;
      }
    }

    if (score > 0) {
      scored.push_back({score, entry});
    }
  }

  std::sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
    if (a.first != b.first) {
      return a.first > b.first; // Higher score first
    }
    return a.second.id < b.second.id; // Alphabetical fallback
  });

  std::vector<CatalogEntry> results;
  size_t max_res = (std::min)(limit, scored.size());
  for (size_t i = 0; i < max_res; ++i) {
    results.push_back(scored[i].second);
  }
  return results;
}

std::optional<CatalogEntry> Catalog::GetById(const std::string& id) {
  std::string target = ToLower(id);
  for (const auto& entry : GetEntries()) {
    if (ToLower(entry.id) == target) {
      return entry;
    }
  }
  return std::nullopt;
}

} // namespace dbgx::windbg

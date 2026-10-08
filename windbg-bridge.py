"""Bridge Gateway for WinDbg Model Context Protocol (MCP).

This script acts as a proxy between MCP clients (like Zed or Claude Desktop)
and a remote or local WinDbg session running the dbgx-mcp extension. It handles
Stdio-to-HTTP/Pipe translation, multi-session discovery, protocol stability,
command guardrails, smart TTL caching, and error enrichment.
"""

import atexit
import concurrent.futures
import http.client
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# ====================================================================
# CONFIGURATION
#
# Precedence for every setting: explicit environment variable (as launched by the
# MCP client) > optional env file (WINDBG_MCP_ENV_FILE, default ~/.windbg-mcp.env,
# KEY=VALUE lines) > built-in default. The env file exists so the agent can make a
# guest host "stick" across bridge restarts via windbg.set_guest_host(persist=true)
# without anyone editing the MCP client's config.
# ====================================================================


def _env_lookup(names, default=""):
    """Case-insensitive lookup of the first matching environment variable."""
    wanted = {n.lower() for n in names}
    for k, v in os.environ.items():
        if k.lower() in wanted:
            return v
    return default


ENV_FILE = _env_lookup(("windbg_mcp_env_file",)) or os.path.expanduser("~/.windbg-mcp.env")


def load_env_file(path: str) -> dict:
    """Parses a KEY=VALUE file into a dict with lower-cased keys. Missing file -> {}."""
    values = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                values[k.strip().lower()] = v.strip().strip("\"'")
    except FileNotFoundError:
        pass
    except Exception as e:  # malformed file must never prevent the bridge from starting
        sys.stderr.write(f"[windbg-bridge] ignoring unreadable env file {path}: {e}\n")
    return values


def _setting(names, default=""):
    env_value = _env_lookup(names, None)
    if env_value is not None:
        return env_value
    for n in names:
        if n.lower() in _FILE_SETTINGS:
            return _FILE_SETTINGS[n.lower()]
    return default


_FILE_SETTINGS = load_env_file(ENV_FILE)

# Remote WinDbg MCP guest IP (defaults to 127.0.0.1 for local WinDbg)
GUEST_IP = _setting(("windbg_mcp_host", "windbg_mcp_bind"), "127.0.0.1")
# Transport mode: "auto" (prefers Named Pipe if local Windows, otherwise HTTP), "pipe", or "http"
TRANSPORT_MODE = _setting(("windbg_mcp_transport",), "auto").lower()
# Well-known base port for the WinDbg MCP server
try:
    BASE_PORT = int(_setting(("windbg_mcp_port",), "5678"))
except ValueError:
    BASE_PORT = 5678
# Optional bearer token for the HTTP transport (opt-in). Must match WINDBG_MCP_TOKEN set in
# WinDbg's environment; leave unset when the DLL was loaded without a token.
AUTH_TOKEN = _setting(("windbg_mcp_token",), "")
# windbg.set_guest_host only accepts loopback / private / link-local hosts unless this is set,
# so a prompt-injected "connect to <public host>" cannot redirect the bridge off the lab network.
ALLOW_PUBLIC_HOST = _setting(("windbg_mcp_allow_public_host",), "0").lower() not in ("", "0", "false", "no")
# Path to the diagnostic log file
LOG_FILE = os.path.join(tempfile.gettempdir(), "windbg-bridge.log")

# Guards runtime reconfiguration (GUEST_IP / BASE_PORT) and the pools that depend on it.
_config_lock = threading.RLock()

_HOST_CHARS = re.compile(r"^[A-Za-z0-9.\-_:\[\]]+$")


def is_lab_host(host: str) -> bool:
    """True if host is loopback, private (RFC1918/ULA) or link-local, resolving names if needed."""
    h = host.strip().lower().strip("[]")
    if h in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(h, None)
    except OSError:
        return False
    addrs = [ipaddress.ip_address(info[4][0]) for info in infos]
    return bool(addrs) and all(a.is_loopback or a.is_private or a.is_link_local for a in addrs)


def validate_guest_host(host: str) -> str:
    """Normalises and validates a host for set_guest_host. Raises ValueError when rejected."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("host must be a non-empty string (IP address or hostname)")
    h = host.strip()
    if "://" in h or "/" in h or not _HOST_CHARS.match(h):
        raise ValueError("host must be a bare IP address or hostname (no scheme, port or path)")
    if not ALLOW_PUBLIC_HOST and not is_lab_host(h):
        raise ValueError(
            f"host '{h}' is not a loopback/private/link-local address. Debugger VMs normally live on a "
            "host-only or NAT network; set WINDBG_MCP_ALLOW_PUBLIC_HOST=1 to override."
        )
    return h


def auth_headers(session=None) -> dict:
    """Returns the Authorization header for a session (per-session token wins over env)."""
    token = ""
    if isinstance(session, dict):
        token = session.get("token") or ""
    if not token:
        token = AUTH_TOKEN
    return {"Authorization": f"Bearer {token}"} if token else {}

# Global state to track the currently selected backend port and sessions
_current_port = BASE_PORT
_current_pipe_name = None
_session_map = {}  # { port: session_dict }
_session_map_lock = threading.Lock()

# Threading locks and pools
_stdout_lock = threading.Lock()
_connections_lock = threading.Lock()
_conn_locks_lock = threading.Lock()
_cache_lock = threading.Lock()

_connections = {}
_conn_locks = {}

# Standard library thread pool for processing requests concurrently
_request_executor = concurrent.futures.ThreadPoolExecutor(max_workers=16)

# ====================================================================
# CACHE AND GUARDRAIL CONFIGURATIONS
# ====================================================================

# Simple memory cache: { (session_key, command_str): (timestamp, result_dict) }
# session_key is "port:pid" so a WinDbg restart on the same port never serves stale results.
_command_cache = {}

# Restrict commands that can brick or kill the debugger session
DANGEROUS_COMMANDS = {
    # Session exit / termination
    "q", "qq", "qd", ".kill", ".detach", ".abandon", ".restart", ".reboot", ".crash",
    # Shell escapes
    ".shell", "!shell",
    # Networking / remote server commands
    ".server", ".endsrv", ".remote"
}

# What the agent should do instead when a guardrail fires (keyed by the blocked token).
GUARDRAIL_ALTERNATIVES = {
    "q": "Ending the debugger session is reserved for the user; leave the target as it is.",
    "qq": "Ending the debugger session is reserved for the user; leave the target as it is.",
    "qd": "Ending the debugger session is reserved for the user; leave the target as it is.",
    ".kill": "Target lifecycle is reserved for the user; use windbg.continue / windbg.interrupt to control execution.",
    ".detach": "Target lifecycle is reserved for the user; use windbg.continue / windbg.interrupt to control execution.",
    ".abandon": "Target lifecycle is reserved for the user; use windbg.continue / windbg.interrupt to control execution.",
    ".restart": "Target lifecycle is reserved for the user; ask them to restart the target if needed.",
    ".reboot": "Target lifecycle is reserved for the user; ask them to reboot the target if needed.",
    ".crash": "Target lifecycle is reserved for the user.",
    ".shell": "Shell escapes are blocked; use windbg.write_file for file output or ask the user to run host commands.",
    "!shell": "Shell escapes are blocked; use windbg.write_file for file output or ask the user to run host commands.",
    ".server": "Remote debugging setup is reserved for the user.",
    ".endsrv": "Remote debugging setup is reserved for the user.",
    ".remote": "Remote debugging setup is reserved for the user.",
    "$<": "Inline the commands in windbg.eval (separate with ';') instead of sourcing a script file.",
}

# ---- Command classification (first-token based; never substring matching) ----

# Debugger commands that only read target state. Everything else is treated as potentially
# mutating and invalidates the per-session cache. Being conservative here only costs cache hits.
_READ_ONLY_TOKENS = {
    # memory / data display
    "d", "da", "db", "dc", "dd", "dD", "df", "dp", "dq", "du", "dw", "dW", "dyb", "dyd", "ds", "dS",
    "dda", "ddp", "dds", "dpa", "dpp", "dps", "dqa", "dqp", "dqs", "dt", "dv", "dx", "dl", "dg", "dG",
    # disassembly / symbols
    "u", "ub", "uf", "up", "ur", "ln", "ls", "lsa", "lsc", "lsf", "x", "ld",
    # module / stack / thread listing
    "lm", "k", "kb", "kc", "kd", "kp", "kP", "kv", "kn", "kL", "kM", "kf", "bl",
    # evaluation / info
    "?", "??", "version", "vertarget", "vercommand", "s", ".lastevent", ".exr", ".formats", ".time",
    ".ttime", ".echo", ".printf", ".chain", ".help", ".symopt", ".tlist", ".dumpdebug", ".frame",
    # extension reads
    "!peb", "!teb", "!object", "!address", "!handle", "!dlls", "!vm", "!heap", "!analyze", "!process",
    "!thread", "!pte", "!vad", "!dh", "!lmi", "!chkimg", "!sym", "!error", "!gle", "!exchain",
    "!runaway", "!locks", "!cs", "!dso", "!uniqstack", "!findstack", "!gflag", "!envvar", "!std_map",
    "!for_each_process", "!for_each_thread", "!for_each_module", "!for_each_frame", "!list", "!dp",
    "!pool", "!poolused", "!drvobj", "!devobj", "!irp", "!stacks", "!running", "!ready", "!idt", "!gdt",
    "!pcr", "!prcb", "!tz", "!wmitrace", "!ttdext.calls",
}
# Read-only only when used without arguments (with arguments they change debugger context/paths).
_READ_ONLY_WHEN_BARE = {"r", ".sympath", ".srcpath", ".exepath", ".effmach", ".symopt", ".frame",
                        ".process", ".thread", ".context", ".cxr", ".ecxr"}
# Tokens whose variants carry a suffix (lmv, lmf, kvn...). Checked with startswith after exact lookup.
_READ_ONLY_PREFIX_FAMILIES = ("lm", "k", "dp", "dq", "dd", "dw", "db", "da", "du", "dy")
_READ_ONLY_TOKENS = {t.lower() for t in _READ_ONLY_TOKENS}

# Cacheable read-only commands and their TTL (seconds). First token only; any arguments other
# than for 'x'/'lm' families drop the command out of the cache.
_CACHEABLE_TOKENS = {
    "version": 300.0, "vertarget": 300.0, ".effmach": 300.0,
    "lm": 120.0, "x": 120.0,
    "!peb": 30.0, "!teb": 30.0, "!object": 30.0,
    "r": 5.0, "k": 5.0, "kb": 5.0, "kp": 5.0, "kv": 5.0, "kn": 5.0, "kc": 5.0,
}


def _first_token(subcommand: str) -> str:
    """Leading command token of a single (already ';'-split) command, lower-cased.

    Handles WinDbg's glued forms: 'r@rax', 'dd@rsp', '~1s', '|0s', 'k=rbp'.
    """
    s = subcommand.strip()
    if not s:
        return ""
    m = re.match(r"^([.!$]?[A-Za-z_][A-Za-z0-9_.]*|\?\??|~|\||\$[<>]+)", s)
    tok = m.group(1) if m else s.split()[0]
    return tok.lower()


def _is_read_only_subcommand(sub: str) -> bool:
    sub = sub.strip()
    tok = _first_token(sub)
    if not tok:
        return True
    rest = sub[len(tok):].strip()
    if tok == "r":
        return "=" not in rest  # 'r rax=5' writes; 'r', 'r rax', 'r @rax' read
    if tok in ("~", "|"):
        # Bare '~'/'|' list threads/processes, '~*k' walks stacks; '~1s' / '|1s' switch context.
        return not rest or re.match(r"^[*.#0-9a-fA-F]*\s*k", rest) is not None
    if tok in _READ_ONLY_WHEN_BARE:
        return not rest
    if tok in _READ_ONLY_TOKENS:
        return True
    return any(tok.startswith(p) and tok[len(p):].isalpha() for p in _READ_ONLY_PREFIX_FAMILIES)


def command_mutates(command: str) -> bool:
    """True if any sub-command of a windbg.eval command may change target or debugger state."""
    subs = split_commands_safe(command)
    if not subs:
        return False
    return not all(_is_read_only_subcommand(s) for s in subs)


def get_cache_ttl(command: str) -> float:
    """TTL in seconds for caching a windbg.eval command (0 = never cache)."""
    subs = split_commands_safe(command)
    if len(subs) != 1:
        return 0.0
    sub = subs[0]
    tok = _first_token(sub)
    rest = sub[len(tok):].strip()
    if tok.startswith("lm") and tok[2:].isalpha():
        tok = "lm"
    ttl = _CACHEABLE_TOKENS.get(tok, 0.0)
    if ttl <= 0.0:
        return 0.0
    if "=" in rest:
        return 0.0  # register write
    if tok in ("version", "vertarget", ".effmach", "!peb", "!teb") and rest:
        return 0.0
    if tok == "x" and not rest:
        return 0.0
    return ttl


def split_commands_safe(command: str) -> list[str]:
    """Splits commands by semicolon while respecting single and double quotes."""
    parts = []
    current = []
    in_quote = None
    for c in command:
        if in_quote:
            if c == in_quote:
                in_quote = None
            current.append(c)
        elif c in ('"', "'"):
            in_quote = c
            current.append(c)
        elif c == ';':
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(c)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def validate_command_detail(command: str) -> dict | None:
    """Returns None if the command is allowed, else {blocked, reason, alternative}."""
    # Guardrail: Reject sourcing/nesting commands from disk files to prevent arbitrary code/file execution
    if any(pattern in command for pattern in ["$<", "$>", "$$<", "$$>"]):
        return {
            "blocked": "$<",
            "reason": (
                "Sourcing or nesting command files (using '$<' or '$$<') is prohibited "
                "to prevent unauthorized disk file execution."
            ),
            "alternative": GUARDRAIL_ALTERNATIVES["$<"],
        }

    # Split by semicolon to check each individual subcommand
    for sub in split_commands_safe(command):
        base_cmd = _first_token(sub)
        if base_cmd in DANGEROUS_COMMANDS:
            return {
                "blocked": base_cmd,
                "reason": (
                    f"The command '{base_cmd}' is prohibited by the gateway "
                    "guardrails to prevent accidental termination or corruption of the "
                    "debugging session."
                ),
                "alternative": GUARDRAIL_ALTERNATIVES.get(base_cmd, ""),
            }
    return None


def validate_command(command: str) -> tuple[bool, str]:
    """Checks if a command is safe to execute. Returns (is_safe, error_message)."""
    detail = validate_command_detail(command)
    if detail is None:
        return True, ""
    return False, detail["reason"]


# Timeouts for windbg.eval by first token (seconds). Order matters: first match wins.
_EVAL_TIMEOUT_RULES = (
    # (predicate(token, rest), timeout)
    (lambda t, r: t == ".reload" and re.search(r"(^|\s)[/-]f\b", r) is not None, 1200.0),
    (lambda t, r: t in (".reload", ".sympath", ".symfix"), 300.0),
    (lambda t, r: t == "!process" and re.match(r"^0\s+(0|7|1f)\b", r) is not None, 480.0),
    (lambda t, r: t in ("!for_each_process", "!for_each_thread", "!for_each_module"), 900.0),
    (lambda t, r: t == "!analyze" and "-v" in r.split(), 300.0),
    (lambda t, r: t in ("!thread", "!process") and r.split()[:1] == ["-1"], 300.0),
    (lambda t, r: t.startswith("lm") or t in ("!dlls", "!handle", "!vm", "!address"), 180.0),
    (lambda t, r: t in ("version", "vertarget", ".effmach", "?", "??", "r", ".help", ".echo"), 10.0),
    (lambda t, r: t in ("!analyze", "!thread", "!process"), 120.0),
    (lambda t, r: t in ("s",) or t.startswith(("dd", "dq", "dp", "da", "du", "db", "dw", "dy", "dt", "dx", "u")), 90.0),
    (lambda t, r: t in ("g", "gu", "gh", "gn", "p", "pa", "pc", "pt", "t", "ta", "tc", "tt", "wt", "bp", "bu", "bm", "ba", "bc", "bd", "be"), 60.0),
)


def get_timeout_for_request(req_data) -> float:
    """Determine appropriate timeout in seconds for a request based on method, tool, and command."""
    method = req_data.get("method")
    if method != "tools/call":
        return 60.0

    params = req_data.get("params", {})
    tool_name = params.get("name", "")
    if tool_name.startswith("windbg_"):
        tool_name = "windbg." + tool_name[7:]
    tool_args = params.get("arguments", {})

    if tool_name == "windbg.eval":
        command = tool_args.get("command", "")
        timeout = 0.0
        # A chained command gets the longest timeout of its parts.
        for sub in split_commands_safe(command) or [""]:
            tok = _first_token(sub)
            rest = sub.strip()[len(tok):].strip().lower()
            sub_timeout = 60.0
            for predicate, value in _EVAL_TIMEOUT_RULES:
                if predicate(tok, rest):
                    sub_timeout = value
                    break
            timeout = max(timeout, sub_timeout)
        return timeout or 60.0

    elif tool_name == "windbg.carve_pe":
        return 300.0  # 5 minutes for PE extraction

    elif tool_name == "windbg.search":
        return 120.0  # 2 minutes for memory search

    elif tool_name == "windbg.read_memory":
        return 90.0   # 1.5 minutes for reading memory

    elif tool_name in ("windbg.ttd_position", "windbg.time_travel"):
        return 60.0   # 1 minute for TTD trace position seeks

    elif tool_name == "windbg.resolve":
        return 30.0   # 30 seconds for symbol resolution

    elif tool_name == "windbg.clear_breakpoint":
        return 10.0   # 10 seconds for clearing breakpoint

    elif tool_name == "windbg.step":
        count = tool_args.get("count", 1)
        return min(300.0, 10.0 + count * 2.0)

    elif tool_name == "windbg.continue":
        return 180.0  # 3 minutes for continue / reverse continue

    return 60.0


# ====================================================================
# TOOL TRAITS (single source for MCP annotations, cache invalidation and retry safety)
# ====================================================================
#
# readOnly:   never changes target or debugger state (safe to auto-approve, safe to retry)
# destructive: changes target memory/files irreversibly
# idempotent: re-sending the same call has no additional effect
# "dynamic" tools (eval, ttd_position) are classified per call by tool_mutates().
_RO = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
_CTRL = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}
_DESTRUCTIVE_IDEMPOTENT = {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False}

TOOL_TRAITS = {
    "windbg.eval": {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
    "windbg.dx": _RO,
    "windbg.get_context": _RO,
    "windbg.get_modules": _RO,
    "windbg.get_breakpoints": _RO,
    "windbg.disassemble": _RO,
    "windbg.read_memory": _RO,
    "windbg.write_memory": _DESTRUCTIVE_IDEMPOTENT,
    "windbg.search": _RO,
    "windbg.read_string": _RO,
    "windbg.carve_pe": _RO,
    "windbg.get_threads": _RO,
    "windbg.get_execution_state": _RO,
    "windbg.interrupt": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.step": _CTRL,
    "windbg.continue": _CTRL,
    # 'bp' at an already-breakpointed address creates a duplicate, so a retry is not harmless.
    "windbg.set_breakpoint": _CTRL,
    "windbg.clear_breakpoint": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.resolve": _RO,
    "windbg.ttd_position": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.search_catalog": _RO,
    "windbg.get_command_docs": _RO,
    "windbg.get_catalog_entry": _RO,
    "windbg.apply_struct": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.apply_synthetic_type": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.write_file": _DESTRUCTIVE_IDEMPOTENT,
    "windbg.get_session_metadata": _RO,
    "windbg.list_sessions": _RO,
    "windbg.set_guest_host": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    "windbg.discover_guests": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True},
}


def tool_mutates(tool_name: str, tool_args: dict) -> bool:
    """True if this specific call may change target/debugger state (drives cache invalidation)."""
    if tool_name == "windbg.eval":
        return command_mutates(tool_args.get("command", "") or "")
    if tool_name == "windbg.ttd_position":
        return bool(tool_args.get("position"))
    traits = TOOL_TRAITS.get(tool_name)
    if traits is None:
        return True  # unknown tool: assume the worst
    return not traits["readOnlyHint"]


def tool_is_retry_safe(tool_name: str, tool_args: dict) -> bool:
    """True if the request may be transparently re-sent after a transport failure.

    A request is retry-safe only when re-executing it cannot change the target a second time:
    read-only calls, and idempotent non-control calls (set/clear breakpoint, write_memory with
    the same bytes). step/continue/eval-with-side-effects are never retried.
    """
    if tool_name == "windbg.eval":
        return not command_mutates(tool_args.get("command", "") or "")
    if tool_name == "windbg.ttd_position":
        return True  # seeking to an absolute position twice lands in the same place
    traits = TOOL_TRAITS.get(tool_name)
    if traits is None:
        return False
    return traits["readOnlyHint"] or traits["idempotentHint"]


def annotate_tool(tool: dict) -> dict:
    """Adds MCP tool annotations (spec 2025-03-26) in place when we know the tool."""
    name = tool.get("name", "")
    if name.startswith("windbg_"):
        name = "windbg." + name[7:]
    traits = TOOL_TRAITS.get(name)
    if traits is not None and "annotations" not in tool:
        tool["annotations"] = dict(traits)
    return tool


def enrich_error_response(command: str, error_message: str) -> list[str]:
    """Generates actionable workflow recovery hints for agents based on typical failures."""
    suggestions = []
    low_err = error_message.lower()
    cmd = command.lower().strip()

    if "not found" in low_err or "unresolved" in low_err:
        suggestions.append("Verify the symbol/expression spelling.")
        suggestions.append("Check loaded symbols using 'lm' or try reloading symbols using '.reload'.")
    elif "access denied" in low_err or "privilege" in low_err:
        suggestions.append("Ensure you are running the target with administrative privileges.")
        suggestions.append("Verify current thread and process context.")
    elif "syntax" in low_err:
        suggestions.append("Consult the internal WinDbg catalog tool 'windbg.search_catalog' for syntax specs.")

    if cmd.startswith("bp") or cmd.startswith("bu"):
        suggestions.append("To inspect breakpoints after setting them, use the 'bl' command.")

    return suggestions

# ====================================================================
# GATEWAY LOGISTICS
# ====================================================================

LOG_MAX_BYTES = 5 * 1024 * 1024
_log_lock = threading.Lock()


def log(msg):
    """Logs a diagnostic message to the temporary log file (rotated at LOG_MAX_BYTES)."""
    try:
        with _log_lock:
            try:
                if os.path.getsize(LOG_FILE) > LOG_MAX_BYTES:
                    os.replace(LOG_FILE, LOG_FILE + ".1")
            except OSError:
                pass
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except IOError:
        pass


def _stdout_broken():
    """The client went away: nothing we send can be read anymore, so stop the process."""
    log("stdout closed by client; shutting down bridge")
    release_global_mutex()
    os._exit(0)


def send_response(output_stream, data):
    """Serializes and sends a JSON-RPC response to stdout thread-safely."""
    try:
        line = json.dumps(data)
    except (TypeError, ValueError) as e:
        log(f"SEND ERROR (serialize): {e}")
        return
    try:
        with _stdout_lock:
            output_stream.write(line + "\n")
            output_stream.flush()
        log(f"SENT: {line[:200]}...")
    except (BrokenPipeError, ValueError):  # ValueError: I/O operation on closed file
        _stdout_broken()
    except IOError as e:
        log(f"SEND ERROR: {e}")


def send_notification(output_stream, method, params=None):
    """Sends a JSON-RPC notification to stdout thread-safely."""
    try:
        data = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            data["params"] = params
        line = json.dumps(data)
        with _stdout_lock:
            output_stream.write(line + "\n")
            output_stream.flush()
        log(f"NOTIFICATION SENT: {method}")
    except (BrokenPipeError, ValueError):
        _stdout_broken()
    except Exception as e:
        log(f"NOTIFICATION ERROR: {e}")


PROGRESS_INTERVAL_SECONDS = 10.0


class ProgressHeartbeat:
    """Emits notifications/progress while a forwarded request is in flight.

    MCP clients that honour progressToken reset their per-call timeout on every progress
    notification, which is what lets a 20-minute '.reload /f' survive a 60 s client deadline.
    No token in the request -> no-op.
    """

    def __init__(self, output_stream, req_data, label: str, total_seconds: float):
        meta = (req_data.get("params") or {}).get("_meta") or {}
        self.token = meta.get("progressToken")
        self.output_stream = output_stream
        self.label = label
        self.total = max(total_seconds, 1.0)
        self.started = time.time()
        self._stop = threading.Event()
        self._thread = None

    def __enter__(self):
        if self.token is not None:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        return False

    def _run(self):
        while not self._stop.wait(PROGRESS_INTERVAL_SECONDS):
            elapsed = time.time() - self.started
            send_notification(
                self.output_stream,
                "notifications/progress",
                {
                    "progressToken": self.token,
                    "progress": round(min(elapsed, self.total), 1),
                    "total": round(self.total, 1),
                    "message": f"{self.label} still running ({int(elapsed)}s elapsed, timeout {int(self.total)}s)",
                },
            )


_last_known_sessions = None

def session_watcher_loop(output_stream):
    """Monitors active WinDbg sessions and notifies Zed when sessions come online/offline."""
    global _last_known_sessions, _current_port, _current_pipe_name
    check_count = 0
    while True:
        try:
            time.sleep(2.0)
            check_count += 1

            current_sessions = get_sessions()
            curr_ports = sorted([f"{s.get('port', 9999)}:{s.get('pid', 0)}" for s in current_sessions])

            if _last_known_sessions is not None and curr_ports != _last_known_sessions:
                log(f"Session list changed: {_last_known_sessions} -> {curr_ports}. Sending notifications/tools/list_changed.")
                with _cache_lock:
                    _command_cache.clear()
                if current_sessions:
                    _current_port = current_sessions[0].get("port", BASE_PORT)
                    _current_pipe_name = current_sessions[0].get("pipe_name")
                send_notification(output_stream, "notifications/tools/list_changed")
            _last_known_sessions = curr_ports
        except Exception as e:
            log(f"Session watcher error: {e}")


def get_connection(host, port, timeout=60.0):
    """Retrieves or creates a persistent HTTP connection (thread-safe)."""
    key = f"{host}:{port}"
    with _connections_lock:
        conn = _connections.get(key)
        if conn is None:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
            _connections[key] = conn
        else:
            conn.timeout = timeout
        return conn


def get_connection_lock(key):
    """Retrieves a lock dedicated to serializing writes/reads on a specific connection."""
    with _conn_locks_lock:
        lock = _conn_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _conn_locks[key] = lock
        return lock


_pipe_handles: dict[str, int] = {}
_pipe_handles_lock = threading.Lock()

# Win32 error codes that mean the server side of the pipe went away.
_PIPE_RECONNECT_ERRORS = {
    109,  # ERROR_BROKEN_PIPE
    232,  # ERROR_NO_DATA (pipe being closed)
    233,  # ERROR_PIPE_NOT_CONNECTED
    6,    # ERROR_INVALID_HANDLE
}


def _pipe_full_path(pipe_name: str) -> str:
    if not pipe_name.startswith(r"\\.\pipe"):
        return r"\\.\pipe" + "\\" + pipe_name
    return pipe_name


def _open_pipe_handle(full_pipe_path: str, timeout: float):
    """Opens a client handle to the named pipe, waiting for a free instance."""
    import ctypes
    from ctypes import wintypes

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    OPEN_EXISTING = 3
    ERROR_PIPE_BUSY = 231
    ERROR_FILE_NOT_FOUND = 2

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    CreateFileW.restype = wintypes.HANDLE

    WaitNamedPipeW = ctypes.windll.kernel32.WaitNamedPipeW
    WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    WaitNamedPipeW.restype = wintypes.BOOL

    invalid = wintypes.HANDLE(-1).value
    deadline = time.time() + timeout
    while time.time() < deadline:
        h = CreateFileW(full_pipe_path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if h != invalid and h != 0:
            return h

        err = ctypes.windll.kernel32.GetLastError()
        if err == ERROR_PIPE_BUSY:
            WaitNamedPipeW(full_pipe_path, 1000)
            continue
        elif err == ERROR_FILE_NOT_FOUND:
            time.sleep(0.05)
            continue
        else:
            raise IOError(f"Failed to open named pipe '{full_pipe_path}' (Error {err})")

    raise IOError(f"Timeout waiting for named pipe '{full_pipe_path}'")


def _close_pipe_handle(full_pipe_path: str):
    """Closes and forgets the cached handle for a pipe (if any)."""
    import ctypes

    with _pipe_handles_lock:
        handle = _pipe_handles.pop(full_pipe_path, None)
    if handle is not None:
        try:
            ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass


def _get_pipe_handle(full_pipe_path: str, timeout: float):
    with _pipe_handles_lock:
        handle = _pipe_handles.get(full_pipe_path)
    if handle is not None:
        return handle
    handle = _open_pipe_handle(full_pipe_path, timeout)
    with _pipe_handles_lock:
        _pipe_handles[full_pipe_path] = handle
    return handle


def _pipe_round_trip(handle, full_pipe_path: str, body_bytes: bytes) -> bytes:
    """Writes one newline-delimited request and reads one newline-delimited response."""
    import ctypes
    from ctypes import wintypes

    ReadFile = ctypes.windll.kernel32.ReadFile
    WriteFile = ctypes.windll.kernel32.WriteFile

    msg = body_bytes if body_bytes.endswith(b"\n") else body_bytes + b"\n"
    written = wintypes.DWORD(0)
    if not WriteFile(handle, msg, len(msg), ctypes.byref(written), None):
        err = ctypes.windll.kernel32.GetLastError()
        raise OSError(err, f"WriteFile failed on pipe '{full_pipe_path}' (Error {err})")

    resp_buf = bytearray()
    chunk = ctypes.create_string_buffer(4096)
    read_bytes = wintypes.DWORD(0)
    while True:
        if not ReadFile(handle, chunk, 4096, ctypes.byref(read_bytes), None):
            err = ctypes.windll.kernel32.GetLastError()
            raise OSError(err, f"ReadFile failed on pipe '{full_pipe_path}' (Error {err})")
        if read_bytes.value == 0:
            raise OSError(109, f"Pipe '{full_pipe_path}' closed by server")
        resp_buf.extend(chunk.raw[:read_bytes.value])
        if b"\n" in resp_buf:
            break
    return bytes(resp_buf).strip()


def forward_pipe(pipe_name, body_bytes, timeout=60.0):
    """Forwards a JSON-RPC request over a persistent local Windows Named Pipe connection.

    One handle is kept open per pipe and all requests to that pipe are serialized
    with a dedicated lock (WinDbg's engine is single-threaded anyway). If the
    server side disconnects, the handle is reopened and the request retried once.
    """
    if sys.platform != "win32":
        raise NotImplementedError("Named Pipe transport is only supported on Windows")

    full_pipe_path = _pipe_full_path(pipe_name)
    lock = get_connection_lock("pipe:" + full_pipe_path)
    with lock:
        for attempt in range(2):
            handle = _get_pipe_handle(full_pipe_path, timeout)
            try:
                return _pipe_round_trip(handle, full_pipe_path, body_bytes), 200
            except OSError as e:
                _close_pipe_handle(full_pipe_path)
                if attempt == 0 and e.errno in _PIPE_RECONNECT_ERRORS:
                    log(f"Pipe '{full_pipe_path}' disconnected (Error {e.errno}). Reconnecting.")
                    continue
                raise IOError(str(e)) from e
    raise IOError(f"Pipe dispatch to '{full_pipe_path}' failed")


class BackendTimeout(IOError):
    """The server accepted the request but did not answer within the deadline."""


def _drop_connection(key, conn):
    try:
        conn.close()
    except Exception:
        pass
    with _connections_lock:
        if _connections.get(key) is conn:
            del _connections[key]


def forward_post(host, port, path, body_bytes, timeout=60.0, extra_headers=None, retry_safe=False):
    """Forwards a POST over a persistent keep-alive connection.

    Retry policy (the request may have side effects on a live debugger, so we must never
    execute it twice by accident):
      * failure while *sending* (connect refused, reset before the body was written) -> the
        server never saw it -> always retry once on a fresh connection;
      * stale keep-alive (server closed the idle socket, RemoteDisconnected before any status
        line) -> retry once only when retry_safe (read-only / idempotent call);
      * timeout waiting for the response -> never retry; raise BackendTimeout so the caller can
        tell the agent the command may still be running.
    """
    key = f"{host}:{port}"
    lock = get_connection_lock(key)
    headers = {
        "Content-Type": "application/json",
        "Connection": "keep-alive",
    }
    if extra_headers:
        headers.update(extra_headers)

    with lock:
        conn = get_connection(host, port, timeout=timeout)
        reused = conn.sock is not None
        phase = "send"
        try:
            conn.request("POST", path, body=body_bytes, headers=headers)
            phase = "receive"
            resp = conn.getresponse()
            data = resp.read()
            return data, resp.status
        except socket.timeout as e:
            _drop_connection(key, conn)
            if phase == "send":
                raise IOError(f"connect to {host}:{port} timed out") from e
            raise BackendTimeout(f"no response from {host}:{port} within {timeout:.0f}s") from e
        except (http.client.HTTPException, IOError) as e:
            _drop_connection(key, conn)
            stale_keepalive = reused and isinstance(e, (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError))
            if phase == "send" or (stale_keepalive and retry_safe):
                log(f"Connection error to {host}:{port} during {phase}: {e}. Retrying once on a new connection.")
            else:
                raise
        # Single retry on a fresh connection; any failure here propagates.
        conn = get_connection(host, port, timeout=timeout)
        try:
            conn.request("POST", path, body=body_bytes, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            return data, resp.status
        except socket.timeout as e:
            _drop_connection(key, conn)
            raise BackendTimeout(f"no response from {host}:{port} within {timeout:.0f}s") from e
        except (http.client.HTTPException, IOError):
            _drop_connection(key, conn)
            raise


def current_endpoint() -> tuple[str, int]:
    """Consistent (host, base_port) snapshot; never read the globals separately on a hot path."""
    with _config_lock:
        return GUEST_IP, BASE_PORT


def forward_mcp_message(session, body_bytes, timeout=60.0, retry_safe=False):
    """Dispatches a JSON-RPC message to the session via Named Pipe or HTTP based on availability and settings."""
    host, base_port = current_endpoint()
    pipe_name = session.get("pipe_name") if isinstance(session, dict) else None
    port = session.get("port", base_port) if isinstance(session, dict) else session

    use_pipe = (
        sys.platform == "win32"
        and host == "127.0.0.1"
        and TRANSPORT_MODE in ("auto", "pipe")
        and pipe_name is not None
    )

    if use_pipe:
        try:
            return forward_pipe(pipe_name, body_bytes, timeout=timeout)
        except Exception as e:
            log(f"Pipe dispatch to '{pipe_name}' failed ({e}). Falling back to HTTP.")
            if TRANSPORT_MODE == "pipe":
                raise

    return forward_post(host, port, "/mcp", body_bytes, timeout=timeout, extra_headers=auth_headers(session), retry_safe=retry_safe)


def is_process_alive(pid: int) -> bool:
    """Checks if a process ID is currently running on the system."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return ctypes.windll.kernel32.GetLastError() == 5  # Access Denied means alive
        exit_code = wintypes.DWORD(0)
        if ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            ctypes.windll.kernel32.CloseHandle(handle)
            return exit_code.value == 259  # STILL_ACTIVE
        ctypes.windll.kernel32.CloseHandle(handle)
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Exists but owned by another user
        except (OSError, ProcessLookupError):
            return False


def scan_port(port, host=None, timeout=0.3):
    """Scans a single host:port for active WinDbg MCP guest sessions."""
    if host is None:
        host, _ = current_endpoint()
    url = f"http://{host}:{port}/sessions"
    try:
        req = urllib.request.Request(url, method="GET", headers=auth_headers())
        with urllib.request.urlopen(req, timeout=timeout) as f:
            if f.getcode() == 200:
                data = json.loads(f.read().decode("utf-8"))
                if isinstance(data, list):
                    return data
    except urllib.error.HTTPError as e:
        if e.code == 401:
            log(f"Session scan of {url} rejected (401): set WINDBG_MCP_TOKEN to the token shown in WinDbg.")
    except Exception:
        pass
    return []


def session_key(session: dict) -> str:
    """Stable identity of a session: port plus the WinDbg process id (changes when WinDbg restarts)."""
    return f"{session.get('port', 0)}:{session.get('pid', 0)}"


def _publish_sessions(sessions: list) -> list:
    for s in sessions:
        if isinstance(s, dict):
            s.setdefault("session_key", session_key(s))
    with _session_map_lock:
        for s in sessions:
            if "port" in s:
                _session_map[s["port"]] = s
    return sorted(sessions, key=lambda x: x.get("port", 9999))


def get_sessions():
    """Discover all active WinDbg MCP sessions (instant local registry read or remote HTTP scan)."""
    host, base_port = current_endpoint()

    # Fast local filesystem registry discovery (< 0.1 ms)
    if host == "127.0.0.1":
        registry_dir = os.path.join(tempfile.gettempdir(), "dbgx-mcp-registry")
        if os.path.exists(registry_dir):
            sessions = []
            try:
                for entry in os.listdir(registry_dir):
                    if entry.endswith(".json"):
                        fpath = os.path.join(registry_dir, entry)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                data = json.load(f)
                            if isinstance(data, dict):
                                host_pid = data.get("pid")
                                if host_pid and not is_process_alive(host_pid):
                                    try:
                                        os.remove(fpath)
                                    except Exception:
                                        pass
                                    continue
                                sessions.append(data)
                        except Exception:
                            pass
                if sessions:
                    return _publish_sessions(sessions)
            except Exception as e:
                log(f"Local registry scan error: {e}")

    # Fallback to parallel HTTP scanning for remote VMs
    ports_to_try = list(range(base_port, base_port + 11))
    unique_sessions = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports_to_try)) as executor:
        results = executor.map(lambda p: scan_port(p, host=host), ports_to_try)
        for res in results:
            for s in res:
                if isinstance(s, dict) and "port" in s:
                    unique_sessions[s["port"]] = s

    return _publish_sessions(list(unique_sessions.values()))


# ---- Guest auto-discovery (host-only / NAT lab networks) ----

DISCOVERY_MAX_HOSTS = 1024        # hard budget: at most four /24s per sweep
DISCOVERY_CONNECT_TIMEOUT = 0.25  # seconds per TCP probe


def local_lab_networks() -> list:
    """IPv4 /24 networks of this machine's private/link-local interfaces (VM host-only adapters live here)."""
    nets = {}
    addrs = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    # Interfaces without a hostname mapping: learn the egress address toward a few well-known lab ranges.
    for probe in ("192.168.56.1", "192.168.0.1", "10.0.0.1", "172.16.0.1"):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.05)
            s.connect((probe, 9))
            addrs.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            continue
        if ip.is_loopback or not (ip.is_private or ip.is_link_local):
            continue
        net = ipaddress.ip_network(f"{a}/24", strict=False)
        nets[str(net)] = net
    return list(nets.values())


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_guests(port=None, networks=None) -> dict:
    """Sweeps the local lab /24s for dbgx-mcp servers listening on `port` and returns candidates.

    Only TCP-connects (cheap, ~0.25 s worst case per host, fully parallel) and then asks the
    responders for /sessions so the agent can pick the right machine without guessing IPs.
    """
    _, base_port = current_endpoint()
    port = port or base_port
    nets = networks if networks is not None else local_lab_networks()
    hosts = []
    for net in nets:
        for h in net.hosts():
            hosts.append(str(h))
            if len(hosts) >= DISCOVERY_MAX_HOSTS:
                break
        if len(hosts) >= DISCOVERY_MAX_HOSTS:
            break

    started = time.time()
    candidates = []
    if hosts:
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
            open_flags = list(executor.map(lambda h: _tcp_open(h, port, DISCOVERY_CONNECT_TIMEOUT), hosts))
        for h, is_open in zip(hosts, open_flags):
            if not is_open:
                continue
            sessions = scan_port(port, host=h, timeout=1.0)
            candidates.append({"host": h, "port": port, "sessions": sessions, "is_dbgx_mcp": bool(sessions)})
    candidates.sort(key=lambda c: (not c["is_dbgx_mcp"], c["host"]))
    return {
        "scanned_networks": [str(n) for n in nets],
        "hosts_probed": len(hosts),
        "port": port,
        "elapsed_seconds": round(time.time() - started, 2),
        "candidates": candidates,
    }


def get_default_tools_list():
    """Returns the full static tool definition catalog to ensure Zed registers all tools immediately."""
    tools = [
        {"name": "windbg.eval", "description": "Execute WinDbg command. Results returned as filtered/truncated text. Supports optional max_lines and pattern filters.", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}, "max_lines": {"type": "integer"}, "pattern": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["command"]}},
        {"name": "windbg.dx", "description": "Evaluate WinDbg C++ Data Model expressions (dx) and serialize directly to structured JSON.", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "max_depth": {"type": "integer"}, "session_id": {"type": "integer"}}, "required": ["expression"]}},
        {"name": "windbg.get_context", "description": "Get structured CPU register snapshot, current instruction, call stack frames with symbol resolution, and TTD position.", "inputSchema": {"type": "object", "properties": {"include_all_registers": {"type": "boolean", "description": "True to include all vector/debug/segment registers (default false, primary GPRs only)"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.get_modules", "description": "Get structured list of all loaded modules, base addresses, sizes, checksums, and symbol statuses.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.get_breakpoints", "description": "Get structured list of all active breakpoints, offsets, hit counts, and commands.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.disassemble", "description": "Disassemble instructions at given address or current instruction pointer (if omitted/empty).", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "count": {"type": "integer"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.read_memory", "description": "Read raw memory block at virtual address, symbol, or expression as hex string.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "length": {"type": "integer"}, "session_id": {"type": "integer"}}, "required": ["address"]}},
        {"name": "windbg.write_memory", "description": "Write raw bytes from hex string to virtual address or symbol.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "data": {"type": "string", "description": "Hexadecimal representation of bytes to write (e.g. '9090')"}, "session_id": {"type": "integer"}}, "required": ["address", "data"]}},
        {"name": "windbg.search", "description": "Search virtual memory range for byte pattern.", "inputSchema": {"type": "object", "properties": {"start_address": {"type": "string"}, "end_address": {"type": "string"}, "pattern": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["start_address", "end_address", "pattern"]}},
        {"name": "windbg.read_string", "description": "Read ASCII or UTF-16 wide string from memory address or symbol.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "max_length": {"type": "integer"}, "wide": {"type": "boolean"}, "session_id": {"type": "integer"}}, "required": ["address"]}},
        {"name": "windbg.carve_pe", "description": "Reconstruct and carve mapped PE image from memory back to file-aligned raw bytes.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "length": {"type": "integer", "description": "Estimated virtual size of the image to read"}, "session_id": {"type": "integer"}}, "required": ["address", "length"]}},
        {"name": "windbg.get_threads", "description": "Get list of all target threads with thread IDs and current active thread flag.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.get_execution_state", "description": "Check if target is running, busy, or broken in and ready for commands.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.interrupt", "description": "Send interrupt signal to break into running target.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.step", "description": "Step execution forward or backward in time (TTD).", "inputSchema": {"type": "object", "properties": {"step_over": {"type": "boolean"}, "reverse": {"type": "boolean"}, "count": {"type": "integer"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.continue", "description": "Resume target execution forward ('g') or backward in time ('g-' in TTD).", "inputSchema": {"type": "object", "properties": {"reverse": {"type": "boolean"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.set_breakpoint", "description": "Set breakpoint at symbol or expression ('bp').", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["expression"]}},
        {"name": "windbg.clear_breakpoint", "description": "Clear breakpoint by ID or '*' for all breakpoints ('bc'). Defaults to '*'.", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.resolve", "description": "Resolve symbol expression to address or address to nearest symbol and module.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["query"]}},
        {"name": "windbg.ttd_position", "description": "Query current Time Travel Debugging (TTD) position and thread positions or seek to a position (e.g. '1B:0').", "inputSchema": {"type": "object", "properties": {"position": {"type": "string"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.search_catalog", "description": "Search built-in WinDbg command documentation catalog.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]}},
        {"name": "windbg.get_command_docs", "description": "Retrieve full documentation for command by ID.", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
        {"name": "windbg.get_catalog_entry", "description": "Retrieve full documentation for command by ID (alias for get_command_docs).", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
        {"name": "windbg.apply_struct", "description": "Dynamically apply C struct definition to memory address.", "inputSchema": {"type": "object", "properties": {"struct_definition": {"type": "string"}, "struct_name": {"type": "string"}, "address": {"type": "string"}, "module_name": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["struct_definition", "struct_name", "address"]}},
        {"name": "windbg.apply_synthetic_type", "description": "Apply a synthetic C-style struct definition loaded from a header file on the guest onto a memory address.", "inputSchema": {"type": "object", "properties": {"header_path": {"type": "string"}, "struct_name": {"type": "string"}, "address": {"type": "string"}, "module_name": {"type": "string"}, "syntypes_path": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["header_path", "struct_name", "address"]}},
        {"name": "windbg.write_file", "description": "Write file directly onto Windows filesystem.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
        {"name": "windbg.get_session_metadata", "description": "Get metadata about active debugging target.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
    ]
    tools.extend(BRIDGE_LOCAL_TOOLS)
    return tools


# Tools implemented by the bridge itself (never forwarded to the DLL).
BRIDGE_LOCAL_TOOLS = [
    {
        "name": "windbg.list_sessions",
        "description": (
            "List all active WinDbg MCP sessions reachable from the bridge, plus the guest host the "
            "bridge is currently pointed at. If this is empty and the user mentioned a VM IP, call "
            "windbg.set_guest_host."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "windbg.set_guest_host",
        "description": (
            "Point the bridge at a different WinDbg host (e.g. the debugger VM's current IP on a host-only "
            "network) without restarting. Clears cached connections, rediscovers sessions and returns them. "
            "Use when windbg.list_sessions is empty or calls fail with 'unreachable' and the user has told "
            "you where WinDbg is running. Only loopback/private/link-local hosts are accepted by default."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "IP address or hostname of the machine running WinDbg (e.g. '192.168.56.101' or '127.0.0.1'), or 'auto' to sweep the local host-only/NAT subnets for a dbgx-mcp server and use the first one found"},
                "port": {"type": "integer", "description": "Base HTTP port of the dbgx-mcp extension (default 5678)"},
                "persist": {"type": "boolean", "description": "Also save to the bridge env file so the setting survives restarts (default false)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "windbg.discover_guests",
        "description": (
            "Sweep this machine's private /24 subnets (VirtualBox host-only, VMware vmnet, Hyper-V default "
            "switch) for machines with a dbgx-mcp server listening and return them with their sessions. "
            "Takes a few seconds. Use when the user has not told you the debugger VM's IP; then call "
            "windbg.set_guest_host with the chosen host."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "description": "Port to probe (default: the bridge's base port, 5678)"},
            },
        },
    },
]
for _t in BRIDGE_LOCAL_TOOLS:
    annotate_tool(_t)

# Injected into the MCP initialize result; clients surface it to the model as server guidance.
SERVER_INSTRUCTIONS = (
    "WinDbg bridge. Workflow: (1) call windbg.list_sessions; if `sessions` is empty, ask the user for the "
    "debugger VM's IP or call windbg.discover_guests, then windbg.set_guest_host. (2) Prefer structured "
    "tools (get_context, get_modules, get_breakpoints, disassemble, read_memory, resolve, dx) over raw "
    "windbg.eval; use eval for anything else. (3) step / continue / write_memory / set_breakpoint / "
    "ttd_position(position=...) change target state; check windbg.get_execution_state before issuing "
    "commands if a continue may still be running. (4) Tool failures come back as isError results with "
    "`error` and `next_steps` fields: read them and recover instead of retrying blindly. (5) Session "
    "lifecycle commands (q, .kill, .detach, .restart, .shell) are blocked; ask the user instead. Pass "
    "session_id (a port from list_sessions) to target a specific WinDbg instance."
)


def _tool_text_result(req_id, payload, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": json.dumps(payload, indent=2)}]}
    if is_error:
        result["isError"] = True
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _tool_failure(req_id, error: str, message: str, next_steps=None, **extra) -> dict:
    """Tool-level failure as an MCP isError result (the model can read it), not a JSON-RPC error."""
    payload = {"error": error, "message": message}
    if next_steps:
        payload["next_steps"] = list(next_steps)
    payload.update(extra)
    return _tool_text_result(req_id, payload, is_error=True)


def _rpc_error(req_id, code, message) -> dict:
    """Protocol-level error (malformed request, internal fault)."""
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def effective_transport() -> str:
    """Transport the bridge will actually use for GUEST_IP right now."""
    host, _ = current_endpoint()
    if sys.platform == "win32" and host == "127.0.0.1" and TRANSPORT_MODE in ("auto", "pipe"):
        return "pipe"
    return "http"


def describe_gateway() -> dict:
    host, base_port = current_endpoint()
    return {
        "guest_host": host,
        "base_port": base_port,
        "transport": effective_transport(),
        "auth": "bearer" if AUTH_TOKEN else "none",
        "env_file": ENV_FILE,
    }


def _no_sessions_next_steps(host: str, base_port: int) -> list:
    steps = []
    if host == "127.0.0.1":
        steps.append("Ask the user to load dbgx-mcp in WinDbg (.load dbgx-mcp) on this machine, or")
        steps.append("if WinDbg runs in a VM: call windbg.discover_guests, or windbg.set_guest_host(host=<vm ip>) if the user gave you the IP")
    else:
        steps.append(f"Verify WinDbg on {host} has dbgx-mcp loaded with WINDBG_MCP_BIND=0.0.0.0 (or the VM's address) and port {base_port} open in its firewall")
        steps.append("Call windbg.discover_guests if the VM's IP may have changed (DHCP on host-only adapters)")
    return steps


def handle_list_sessions(req_id):
    """Processes the windbg.list_sessions tool call."""
    sessions = get_sessions()
    payload = describe_gateway()
    payload["sessions"] = sessions
    if not sessions:
        payload["next_steps"] = _no_sessions_next_steps(payload["guest_host"], payload["base_port"])
    return _tool_text_result(req_id, payload)


def handle_discover_guests(req_id, tool_args):
    """Processes the windbg.discover_guests tool call."""
    port = tool_args.get("port")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535)):
        return _tool_failure(req_id, "invalid_argument", "port must be an integer between 1 and 65535")
    try:
        result = discover_guests(port=port)
    except Exception as e:
        log(f"DISCOVER ERROR: {e}")
        return _tool_failure(req_id, "discovery_failed", str(e))
    hits = [c for c in result["candidates"] if c["is_dbgx_mcp"]]
    if hits:
        result["next_steps"] = [f"Call windbg.set_guest_host(host='{hits[0]['host']}')" + (f", port={hits[0]['port']}" if hits[0]["port"] != BASE_PORT else "")]
    else:
        result["next_steps"] = [
            "No dbgx-mcp server answered on the scanned subnets. Ask the user for the VM's IP, confirm WINDBG_MCP_BIND "
            "is set to a reachable interface in WinDbg's environment, and that the Windows firewall allows the port.",
        ]
    return _tool_text_result(req_id, result)


def _reset_host_bound_state():
    """Drops every cache keyed by host/port after GUEST_IP or BASE_PORT changed."""
    with _connections_lock:
        for conn in _connections.values():
            try:
                conn.close()
            except Exception:
                pass
        _connections.clear()
    with _session_map_lock:
        _session_map.clear()
    with _cache_lock:
        _command_cache.clear()
    if sys.platform == "win32":
        for path in list(_pipe_handles):
            _close_pipe_handle(path)


def persist_env_setting(key: str, value: str, path: str = None) -> str:
    """Upserts KEY=VALUE in the env file (atomic rewrite). Returns the path written."""
    path = path or ENV_FILE
    key_upper = key.upper()
    lines = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        pass
    out, replaced = [], False
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip().upper()
            if k == key_upper:
                if not replaced:
                    out.append(f"{key_upper}={value}")
                    replaced = True
                continue
        out.append(line)
    if not replaced:
        out.append(f"{key_upper}={value}")
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, path)
    return path


def set_guest_host(host: str, port=None, persist: bool = False) -> dict:
    """Re-points the bridge at another WinDbg host at runtime. Raises ValueError on bad input.

    host="auto" sweeps the local lab subnets and picks the first machine running dbgx-mcp.
    """
    global GUEST_IP, BASE_PORT, _current_port, _current_pipe_name

    if port is not None:
        if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
            raise ValueError("port must be an integer between 1 and 65535")

    discovery = None
    if isinstance(host, str) and host.strip().lower() == "auto":
        discovery = discover_guests(port=port)
        hits = [c for c in discovery["candidates"] if c["is_dbgx_mcp"]]
        if not hits:
            raise ValueError(
                f"auto-discovery found no dbgx-mcp server on {discovery['scanned_networks'] or 'any local subnet'} "
                f"(port {discovery['port']}, {discovery['hosts_probed']} hosts probed). Ask the user for the VM's IP."
            )
        host = hits[0]["host"]
        port = hits[0]["port"]

    new_host = validate_guest_host(host)
    with _config_lock:
        new_port = BASE_PORT if port is None else port
        changed = (new_host != GUEST_IP) or (new_port != BASE_PORT)
        previous = (GUEST_IP, BASE_PORT)
        GUEST_IP = new_host
        BASE_PORT = new_port
        if changed:
            _reset_host_bound_state()
            _current_port = BASE_PORT
            _current_pipe_name = None
        log(f"GUEST HOST: {previous[0]}:{previous[1]} -> {GUEST_IP}:{BASE_PORT} (changed={changed}, persist={persist})")

    persisted_to = None
    warnings = []
    if persist:
        persisted_to = persist_env_setting("WINDBG_MCP_HOST", new_host)
        if port is not None:
            persist_env_setting("WINDBG_MCP_PORT", str(new_port))
        shadowing = [k for k in os.environ if k.lower() in ("windbg_mcp_host", "windbg_mcp_bind")]
        if shadowing:
            warnings.append(
                f"Environment variable {shadowing[0]} is set by the MCP client config and overrides the env file on the "
                "next bridge start; remove it from the client config for the persisted host to take effect."
            )

    sessions = get_sessions()
    if sessions:
        _current_port = sessions[0].get("port", new_port)
        _current_pipe_name = sessions[0].get("pipe_name")

    result = describe_gateway()
    result.update({
        "changed": changed,
        "persisted_to": persisted_to,
        "sessions": sessions,
    })
    if discovery is not None:
        result["discovery"] = {k: discovery[k] for k in ("scanned_networks", "hosts_probed", "elapsed_seconds")}
    if warnings:
        result["warnings"] = warnings
    if not sessions:
        result["hint"] = (
            f"No dbgx-mcp sessions answered at {new_host} (ports {new_port}-{new_port + 10}). Check that the "
            "extension is loaded in WinDbg with WINDBG_MCP_BIND set to a reachable interface and that the "
            "firewall allows the port."
        )
        result["next_steps"] = _no_sessions_next_steps(new_host, new_port)
    return result


def handle_set_guest_host(req_id, tool_args, output_stream):
    """Processes the windbg.set_guest_host tool call."""
    try:
        result = set_guest_host(
            tool_args.get("host"),
            port=tool_args.get("port"),
            persist=bool(tool_args.get("persist", False)),
        )
    except ValueError as e:
        return _tool_failure(
            req_id, "invalid_host", str(e),
            next_steps=["Ask the user for the debugger VM's IP, or call windbg.discover_guests to sweep the lab subnets."],
        )
    except Exception as e:
        log(f"SET_GUEST_HOST ERROR: {e}")
        return _tool_failure(req_id, "switch_failed", f"Failed to switch guest host: {e}")
    if result.get("changed"):
        send_notification(output_stream, "notifications/tools/list_changed")
    return _tool_text_result(req_id, result)

# ====================================================================
# MAIN STRATEGIC DISPATCH
# ====================================================================

def _normalize_tool_name(name: str) -> str:
    return "windbg." + name[7:] if name.startswith("windbg_") else name


def _cache_session_key(target_session: dict, target_port) -> str:
    return session_key(target_session) if target_session.get("pid") else f"{target_port}:0"


def _invalidate_session_cache(skey: str):
    with _cache_lock:
        for key in [k for k in _command_cache if k[0] == skey]:
            del _command_cache[key]


def _resolve_target_session(target_port) -> dict | None:
    """Session dict for a port; refreshes discovery once if the port is unknown. None if still unknown."""
    with _session_map_lock:
        session = _session_map.get(target_port)
    if session is None:
        get_sessions()
        with _session_map_lock:
            session = _session_map.get(target_port)
    return session


def _synthetic_initialize(req_id, requested_version) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": requested_version,
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "windbg-bridge-gateway", "version": "1.3.0"},
            "instructions": SERVER_INSTRUCTIONS,
        },
    }


def _handle_initialize(req_id, req_data, line, output_stream):
    global _current_port, _current_pipe_name
    params = req_data.get("params", {})
    requested_version = params.get("protocolVersion", "2024-11-05")
    log(f"initialize: requested version {requested_version}, transport {TRANSPORT_MODE}")
    sessions = get_sessions()
    if not sessions:
        # Nothing to forward to: answer immediately instead of waiting out a TCP timeout (A6).
        log("initialize: no active sessions; returning synthetic handshake")
        send_response(output_stream, _synthetic_initialize(req_id, requested_version))
        return

    active_session = sessions[0]
    _current_port = active_session.get("port", BASE_PORT)
    _current_pipe_name = active_session.get("pipe_name")
    try:
        resp_bytes, _ = forward_mcp_message(active_session, line.encode("utf-8"), timeout=15.0, retry_safe=True)
        resp_data = json.loads(resp_bytes.decode("utf-8"))
        result = resp_data.get("result")
        if isinstance(result, dict):
            result["protocolVersion"] = requested_version
            result.setdefault("capabilities", {})["tools"] = {"listChanged": True}
            result.setdefault("instructions", SERVER_INSTRUCTIONS)
            log(f"Backend init successful on :{_current_port}")
        send_response(output_stream, resp_data)
    except Exception as e:
        log(f"INIT BACKEND FAIL on :{_current_port}: {e}. Returning synthetic success.")
        send_response(output_stream, _synthetic_initialize(req_id, requested_version))


def _handle_tools_list(req_id, line, output_stream):
    sessions = get_sessions()
    tools = None
    if sessions:
        try:
            resp_bytes, _ = forward_mcp_message(sessions[0], line.encode("utf-8"), timeout=15.0, retry_safe=True)
            resp_data = json.loads(resp_bytes.decode("utf-8"))
            tools = resp_data.get("result", {}).get("tools")
        except Exception as e:
            log(f"TOOLS/LIST BACKEND FAIL on :{sessions[0].get('port')}: {e}. Returning full catalog.")
    if not isinstance(tools, list):
        tools = get_default_tools_list()
    else:
        for tool in tools:
            if tool.get("name", "").startswith(("windbg.", "windbg_")):
                props = tool.setdefault("inputSchema", {}).setdefault("properties", {})
                props["session_id"] = {
                    "type": "integer",
                    "description": "Port of target WinDbg session. Find via windbg.list_sessions.",
                }
        tools.extend(BRIDGE_LOCAL_TOOLS)
    for tool in tools:
        annotate_tool(tool)
    send_response(output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}})


def _unreachable_failure(req_id, target_port, error: str):
    host, base_port = current_endpoint()
    sessions_now = get_sessions()
    next_steps = []
    if sessions_now:
        ports = [s.get("port") for s in sessions_now]
        next_steps.append(f"Session on port {target_port} is gone; live sessions are {ports}. Pass one as session_id, or omit session_id to use the default.")
    else:
        next_steps.extend(_no_sessions_next_steps(host, base_port))
    return _tool_failure(
        req_id, "backend_unreachable", f"WinDbg session on {host}:{target_port} did not answer: {error}",
        next_steps=next_steps, guest_host=host, port=target_port, sessions_now=sessions_now,
    )


def _handle_tools_call(req_id, req_data, line, output_stream):
    params = req_data.get("params", {})
    raw_tool_name = params.get("name", "")
    tool_name = _normalize_tool_name(raw_tool_name)
    if tool_name != raw_tool_name:
        req_data["params"]["name"] = tool_name
        line = json.dumps(req_data)
    tool_args = params.get("arguments") or {}
    if not isinstance(tool_args, dict):
        send_response(output_stream, _rpc_error(req_id, -32602, "params.arguments must be an object"))
        return

    # Bridge-local tools (never forwarded)
    if tool_name in ("windbg.list_sessions", "list_sessions"):
        send_response(output_stream, handle_list_sessions(req_id))
        return
    if tool_name in ("windbg.set_guest_host", "set_guest_host"):
        send_response(output_stream, handle_set_guest_host(req_id, tool_args, output_stream))
        return
    if tool_name in ("windbg.discover_guests", "discover_guests"):
        send_response(output_stream, handle_discover_guests(req_id, tool_args))
        return

    # Session routing
    explicit_session = "session_id" in tool_args
    target_port = tool_args.pop("session_id", _current_port)
    if explicit_session:
        req_data["params"]["arguments"] = tool_args
        line = json.dumps(req_data)
        if isinstance(target_port, bool) or not isinstance(target_port, int):
            send_response(output_stream, _tool_failure(
                req_id, "invalid_session_id", "session_id must be the integer port of a session from windbg.list_sessions",
                sessions_now=get_sessions(),
            ))
            return
    target_session = _resolve_target_session(target_port)
    if target_session is None:
        if explicit_session:
            send_response(output_stream, _tool_failure(
                req_id, "unknown_session", f"No WinDbg session is listening on port {target_port}.",
                next_steps=["Call windbg.list_sessions and pass one of the returned ports as session_id."],
                sessions_now=get_sessions(),
            ))
            return
        target_session = {"port": target_port, "pipe_name": f"dbgx-mcp-{target_port}"}
    skey = _cache_session_key(target_session, target_port)

    # Guardrail + cache (eval only)
    command = ""
    if tool_name == "windbg.eval":
        command = tool_args.get("command", "") or ""
        detail = validate_command_detail(command)
        if detail is not None:
            log(f"GUARDRAIL BLOCKED: '{command}'")
            send_response(output_stream, _tool_failure(
                req_id, "command_blocked", detail["reason"],
                next_steps=[detail["alternative"]] if detail["alternative"] else None,
                blocked=detail["blocked"], command=command,
            ))
            return
        ttl = get_cache_ttl(command)
        if ttl > 0.0:
            with _cache_lock:
                cached_item = _command_cache.get((skey, command.strip()))
            if cached_item and time.time() - cached_item[0] < ttl:
                log(f"CACHE HIT: '{command}' on {skey}")
                resp_to_send = dict(cached_item[1])
                resp_to_send["id"] = req_id
                send_response(output_stream, resp_to_send)
                return

    mutates = tool_mutates(tool_name, tool_args)
    retry_safe = tool_is_retry_safe(tool_name, tool_args)
    req_timeout = get_timeout_for_request(req_data)
    label = f"{tool_name} {command}".strip() if command else tool_name
    log(f"FORWARD: {label!r} -> {skey} timeout={req_timeout}s mutates={mutates} retry_safe={retry_safe}")
    try:
        with ProgressHeartbeat(output_stream, req_data, label, req_timeout):
            resp_bytes, _ = forward_mcp_message(target_session, line.encode("utf-8"), timeout=req_timeout, retry_safe=retry_safe)
    except BackendTimeout as e:
        if mutates:
            _invalidate_session_cache(skey)
        send_response(output_stream, _tool_failure(
            req_id, "backend_timeout", str(e),
            next_steps=[
                "The command was delivered and may still be running in WinDbg; it was NOT retried.",
                "Call windbg.get_execution_state; if the target is running, use windbg.interrupt before issuing more commands.",
            ],
            port=target_port, timeout_seconds=req_timeout, command=command or None,
        ))
        return
    except Exception as e:
        log(f"FORWARD ERROR to target {target_port}: {e}")
        send_response(output_stream, _unreachable_failure(req_id, target_port, str(e)))
        return

    if mutates:
        _invalidate_session_cache(skey)

    if not resp_bytes:
        log(f"Empty response from :{target_port}")
        if req_id is not None:
            send_response(output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {}})
        return

    try:
        resp_json = json.loads(resp_bytes.decode("utf-8"))
    except ValueError as e:
        send_response(output_stream, _tool_failure(req_id, "bad_backend_response", f"Server on port {target_port} returned non-JSON: {e}"))
        return

    if tool_name == "windbg.eval":
        result = resp_json.get("result")
        if isinstance(result, dict) and not result.get("isError"):
            ttl = get_cache_ttl(command)
            if ttl > 0.0 and not mutates:
                with _cache_lock:
                    _command_cache[(skey, command.strip())] = (time.time(), resp_json)
                log(f"CACHED: '{command}' on {skey} (TTL: {ttl}s)")
        elif "error" in resp_json:
            err_msg = resp_json["error"].get("message", "")
            suggestions = enrich_error_response(command, err_msg)
            if suggestions:
                resp_json["error"]["suggestions"] = suggestions
                log(f"ENRICHED ERROR: '{command}' suggestions={suggestions}")

    if req_id is not None:
        send_response(output_stream, resp_json)


def _handle_passthrough(req_id, method, line, output_stream):
    """Any other method (notifications/initialized, resources/*, prompts/*...) goes to the default session."""
    target_port = _current_port
    with _session_map_lock:
        target_session = _session_map.get(target_port, {"port": target_port, "pipe_name": f"dbgx-mcp-{target_port}"})
    try:
        resp_bytes, _ = forward_mcp_message(target_session, line.encode("utf-8"), timeout=60.0, retry_safe=True)
    except Exception as e:
        log(f"FORWARD ERROR ({method}) to target {target_port}: {e}")
        if req_id is not None:
            send_response(output_stream, _rpc_error(req_id, -32000, f"Backend :{target_port} unreachable: {e}"))
        return
    if req_id is None:
        log(f"Notification '{method}' forwarded; suppressing backend reply")
        return
    if not resp_bytes:
        send_response(output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {}})
        return
    try:
        send_response(output_stream, json.loads(resp_bytes.decode("utf-8")))
    except ValueError as e:
        send_response(output_stream, _rpc_error(req_id, -32603, f"Backend returned non-JSON: {e}"))


def handle_request(line, output_stream):
    """Processes an individual JSON-RPC request from start to finish. Every request with an id gets a reply."""
    req_id = None
    try:
        req_data = json.loads(line)
        if not isinstance(req_data, dict):
            raise ValueError("JSON-RPC message must be an object")
    except ValueError as e:
        send_response(output_stream, _rpc_error(None, -32700, f"Parse error: {e}"))
        return
    try:
        req_id = req_data.get("id")
        method = req_data.get("method")
        log(f"REQ: {method} (id: {req_id})")

        if method == "ping":
            send_response(output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {}})
        elif method == "initialize":
            _handle_initialize(req_id, req_data, line, output_stream)
        elif method == "tools/list":
            _handle_tools_list(req_id, line, output_stream)
        elif method == "tools/call":
            _handle_tools_call(req_id, req_data, line, output_stream)
        else:
            _handle_passthrough(req_id, method, line, output_stream)
    except Exception as e:
        log(f"GLOBAL BRIDGE REQUEST ERROR: {e!r}")
        if req_id is not None:
            send_response(output_stream, _rpc_error(req_id, -32603, f"Bridge internal error: {e}"))


_global_mutex_handle = None
_posix_lock_file = None


def acquire_global_mutex() -> bool:
    """Acquires a system-wide single ownership lock."""
    global _global_mutex_handle, _posix_lock_file

    if sys.platform != "win32":
        try:
            import fcntl
            lock_path = os.path.join(tempfile.gettempdir(), "dbgxmcp.lock")
            _posix_lock_file = open(lock_path, "w")
            fcntl.flock(_posix_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            log(f"Acquired system-wide POSIX file lock at '{lock_path}'")
            return True
        except (IOError, BlockingIOError):
            log("POSIX lock acquisition failed: another bridge instance is running")
            if _posix_lock_file:
                try:
                    _posix_lock_file.close()
                except Exception:
                    pass
                _posix_lock_file = None
            return False
        except Exception as e:
            log(f"POSIX file locking failed: {e}")
            return True

    try:
        import ctypes
        from ctypes import wintypes

        mutex_name = "Local\\dbgxmcp"

        CreateMutex = ctypes.windll.kernel32.CreateMutexW
        CreateMutex.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        CreateMutex.restype = wintypes.HANDLE

        GetLastError = ctypes.windll.kernel32.GetLastError
        GetLastError.restype = wintypes.DWORD

        ERROR_ALREADY_EXISTS = 183

        handle = CreateMutex(None, False, mutex_name)
        if not handle:
            return False

        last_error = GetLastError()
        if last_error == ERROR_ALREADY_EXISTS:
            ctypes.windll.kernel32.CloseHandle(handle)
            return False

        _global_mutex_handle = handle
        log(f"Acquired system-wide named mutex '{mutex_name}'")
        return True
    except Exception as e:
        log(f"Mutex creation failed: {e}")
        return True


def release_global_mutex():
    """Releases the system lock on exit."""
    global _global_mutex_handle, _posix_lock_file
    if _global_mutex_handle and sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.CloseHandle(_global_mutex_handle)
            log("Released named mutex")
        except Exception:
            pass
        _global_mutex_handle = None
    elif _posix_lock_file and sys.platform != "win32":
        try:
            import fcntl
            fcntl.flock(_posix_lock_file, fcntl.LOCK_UN)
            _posix_lock_file.close()
            log("Released POSIX file lock")
        except Exception:
            pass
        _posix_lock_file = None


def main():
    """Main execution loop for the bridge gateway."""
    atexit.register(release_global_mutex)

    if not acquire_global_mutex():
        log("Notice: Another WinDbg MCP launcher mutex exists. Continuing multi-client stdio bridge session.")

    log(f"Bridge Gateway started (Guest: {GUEST_IP}, Transport: {TRANSPORT_MODE})")
    input_stream = sys.stdin
    output_stream = sys.stdout

    # Start background session watcher thread to auto-notify Zed on session changes
    watcher_thread = threading.Thread(target=session_watcher_loop, args=(output_stream,), daemon=True)
    watcher_thread.start()

    while True:
        try:
            line = input_stream.readline()
            if not line:
                log("Stdin closed")
                break

            line = line.strip()
            if not line:
                continue

            # Process request asynchronously in the thread pool to avoid blocking the main reader
            _request_executor.submit(handle_request, line, output_stream)
        except Exception as e:
            log(f"Stdin read loop error: {e}")
            break

    # The client is gone: nothing in flight can be delivered, so do not wait for long-running
    # forwards (a 20-minute .reload would otherwise keep a zombie bridge alive).
    _request_executor.shutdown(wait=False, cancel_futures=True)
    release_global_mutex()
    log("Bridge Gateway stopped")
    os._exit(0)


if __name__ == "__main__":
    main()

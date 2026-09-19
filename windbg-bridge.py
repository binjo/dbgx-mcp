"""Bridge Gateway for WinDbg Model Context Protocol (MCP).

This script acts as a proxy between MCP clients (like Zed or Claude Desktop)
and a remote or local WinDbg session running the dbgx-mcp extension. It handles
Stdio-to-HTTP/Pipe translation, multi-session discovery, protocol stability,
command guardrails, smart TTL caching, and error enrichment.
"""

import atexit
import concurrent.futures
import http.client
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Remote WinDbg MCP guest IP (defaults to 127.0.0.1 for local WinDbg)
GUEST_IP = next(
    (v for k, v in os.environ.items() if k.lower() in ("windbg_mcp_bind", "windbg_mcp_host")),
    "127.0.0.1",
)
# Transport mode: "auto" (prefers Named Pipe if local Windows, otherwise HTTP), "pipe", or "http"
TRANSPORT_MODE = next(
    (v.lower() for k, v in os.environ.items() if k.lower() == "windbg_mcp_transport"),
    "auto",
)
# Well-known base port for the WinDbg MCP server
BASE_PORT = 5678
# Path to the diagnostic log file
LOG_FILE = os.path.join(tempfile.gettempdir(), "windbg-bridge.log")

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

# Simple memory cache: { (port, command_str): (timestamp, result_dict) }
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

def get_cache_ttl(command: str) -> float:
    """Returns appropriate TTL in seconds based on command semantics."""
    cmd = command.lower().strip()

    # Strictly static / metadata
    if any(x in cmd for x in ["version", ".effmach", "vertarget"]):
        return 300.0  # 5 minutes

    # Moderately static
    if "lm" in cmd or cmd.startswith("x "):
        return 120.0  # 2 minutes

    # High-level structures
    if any(x in cmd for x in ["!peb", "!teb", "!object"]):
        return 30.0   # 30 seconds

    # Fast-changing execution context (Registers and stacks)
    if any(x == cmd or cmd.startswith(x + " ") for x in ["r", "k", "kb", "kp", "kv"]):
        return 5.0    # 5 seconds to cushion fast loop queries without stale reads

    return 0.0  # Bypass cache (write operations, execution control, etc.)


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


def validate_command(command: str) -> tuple[bool, str]:
    """Checks if a command is safe to execute. Returns (is_safe, error_message)."""
    # Guardrail: Reject sourcing/nesting commands from disk files to prevent arbitrary code/file execution
    if any(pattern in command for pattern in ["$<", "$>", "$$<", "$$>"]):
        return False, (
            "Sourcing or nesting command files (using '$<' or '$$<') is prohibited "
            "to prevent unauthorized disk file execution."
        )

    # Split by semicolon to check each individual subcommand
    subcommands = split_commands_safe(command)
    for sub in subcommands:
        parts = sub.strip().split()
        if not parts:
            continue
        base_cmd = parts[0].lower()
        if base_cmd in DANGEROUS_COMMANDS:
            return False, (
                f"The command '{base_cmd}' is prohibited by the gateway "
                "guardrails to prevent accidental termination or corruption of the "
                "debugging session."
            )
    return True, ""


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
        cmd_lower = command.lower().strip()

        # Extended symbol loading commands
        if any(ext_cmd in cmd_lower for ext_cmd in [".reload /f", ".reload -f"]):
            return 1200.0  # 20 minutes

        # Standard symbol operations
        if any(sym_cmd in cmd_lower for sym_cmd in [".reload", ".sympath", ".symfix"]):
            return 300.0   # 5 minutes

        # Process list commands
        if any(proc_cmd in cmd_lower for proc_cmd in ["!process 0 0", "!process 0 7", "!process 0 1f"]):
            return 480.0   # 8 minutes

        # Streaming commands
        if any(stream_cmd in cmd_lower for stream_cmd in ["!for_each_process", "!for_each_thread", "!for_each_module"]):
            return 900.0   # 15 minutes

        # Large analysis commands
        if any(large_cmd in cmd_lower for large_cmd in ["!analyze -v", "!thread -1", "!process -1"]):
            return 300.0   # 5 minutes

        # Bulk commands
        if any(bulk_cmd in cmd_lower for bulk_cmd in ["lm", "!dlls", "!handle", "!vm", "!address"]):
            return 180.0   # 3 minutes

        # Quick commands
        if any(quick_cmd in cmd_lower for quick_cmd in ["version", "help", "?", "r", ".effmach", "vertarget"]):
            return 10.0    # 10 seconds

        # Analysis commands
        if any(analysis_cmd in cmd_lower for analysis_cmd in ["!analyze", "!thread", "!process"]):
            return 120.0   # 2 minutes

        # Memory commands
        if any(memory_cmd in cmd_lower for memory_cmd in ["dd", "dq", "dp", "da", "du"]):
            return 90.0    # 1.5 minutes

        # Execution commands
        if any(exec_cmd in cmd_lower for exec_cmd in ["g", "p", "t", "bp", "bc"]):
            return 60.0    # 1 minute

        return 60.0

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

def log(msg):
    """Logs a diagnostic message to the temporary log file."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except IOError:
        pass


def send_response(output_stream, data):
    """Serializes and sends a JSON-RPC response to stdout thread-safely."""
    try:
        line = json.dumps(data)
        with _stdout_lock:
            output_stream.write(line + "\n")
            output_stream.flush()
        log(f"SENT: {line[:200]}...")
    except (TypeError, ValueError, IOError) as e:
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
    except Exception as e:
        log(f"NOTIFICATION ERROR: {e}")


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
            curr_ports = sorted([s.get("port", 9999) for s in current_sessions])

            if _last_known_sessions is not None and curr_ports != _last_known_sessions:
                log(f"Session list changed: {_last_known_sessions} -> {curr_ports}. Sending notifications/tools/list_changed.")
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


def forward_pipe(pipe_name, body_bytes, timeout=60.0):
    """Forwards a JSON-RPC request over a local Windows Named Pipe with ultra-low latency."""
    if not pipe_name.startswith(r"\\.\pipe"):
        full_pipe_path = r"\\.\pipe" + "\\" + pipe_name
    else:
        full_pipe_path = pipe_name

    if sys.platform != "win32":
        raise NotImplementedError("Named Pipe transport is only supported on Windows")

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

    CloseHandle = ctypes.windll.kernel32.CloseHandle
    ReadFile = ctypes.windll.kernel32.ReadFile
    WriteFile = ctypes.windll.kernel32.WriteFile

    deadline = time.time() + timeout
    handle = None

    while time.time() < deadline:
        h = CreateFileW(full_pipe_path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if h != wintypes.HANDLE(-1).value and h != 0:
            handle = h
            break

        err = ctypes.windll.kernel32.GetLastError()
        if err == ERROR_PIPE_BUSY:
            WaitNamedPipeW(full_pipe_path, 1000)
            continue
        elif err == ERROR_FILE_NOT_FOUND:
            time.sleep(0.05)
            continue
        else:
            raise IOError(f"Failed to open named pipe '{full_pipe_path}' (Error {err})")

    if handle is None:
        raise IOError(f"Timeout waiting for named pipe '{full_pipe_path}'")

    try:
        msg = body_bytes if body_bytes.endswith(b"\n") else body_bytes + b"\n"
        written = wintypes.DWORD(0)
        if not WriteFile(handle, msg, len(msg), ctypes.byref(written), None):
            err = ctypes.windll.kernel32.GetLastError()
            raise IOError(f"WriteFile failed on pipe '{full_pipe_path}' (Error {err})")

        resp_buf = bytearray()
        chunk = ctypes.create_string_buffer(4096)
        read_bytes = wintypes.DWORD(0)
        while True:
            if not ReadFile(handle, chunk, 4096, ctypes.byref(read_bytes), None) or read_bytes.value == 0:
                break
            resp_buf.extend(chunk.raw[:read_bytes.value])
            if b"\n" in resp_buf:
                break
        return bytes(resp_buf).strip(), 200
    finally:
        CloseHandle(handle)


def forward_post(host, port, path, body_bytes, timeout=60.0):
    """Forwards a POST request using a persistent keep-alive connection with automatic reconnect."""
    key = f"{host}:{port}"
    lock = get_connection_lock(key)
    with lock:
        conn = get_connection(host, port, timeout=timeout)
        try:
            conn.request(
                "POST",
                path,
                body=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                },
            )
            resp = conn.getresponse()
            data = resp.read()
            return data, resp.status
        except (http.client.HTTPException, IOError) as e:
            log(
                f"Connection error to {host}:{port}: {e}. Retrying with a new connection."
            )
            try:
                conn.close()
            except Exception:
                pass
            with _connections_lock:
                if key in _connections:
                    del _connections[key]
            # Retry once
            conn = get_connection(host, port, timeout=timeout)
            conn.request(
                "POST",
                path,
                body=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                },
            )
            resp = conn.getresponse()
            data = resp.read()
            return data, resp.status


def forward_mcp_message(session, body_bytes, timeout=60.0):
    """Dispatches a JSON-RPC message to the session via Named Pipe or HTTP based on availability and settings."""
    pipe_name = session.get("pipe_name") if isinstance(session, dict) else None
    port = session.get("port", BASE_PORT) if isinstance(session, dict) else session

    use_pipe = (
        sys.platform == "win32"
        and GUEST_IP == "127.0.0.1"
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

    return forward_post(GUEST_IP, port, "/mcp", body_bytes, timeout=timeout)


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
        except (OSError, ProcessLookupError):
            return False


def scan_port(port):
    """Scans a single port for active WinDbg MCP guest sessions."""
    url = f"http://{GUEST_IP}:{port}/sessions"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=0.3) as f:
            if f.getcode() == 200:
                data = json.loads(f.read().decode("utf-8"))
                if isinstance(data, list):
                    return data
    except Exception:
        pass
    return []


def get_sessions():
    """Discover all active WinDbg MCP sessions (instant local registry read or remote HTTP scan)."""
    global _session_map

    # Fast local filesystem registry discovery (< 0.1 ms)
    if GUEST_IP == "127.0.0.1":
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
                    with _session_map_lock:
                        for s in sessions:
                            if "port" in s:
                                _session_map[s["port"]] = s
                    return sorted(sessions, key=lambda x: x.get("port", 9999))
            except Exception as e:
                log(f"Local registry scan error: {e}")

    # Fallback to parallel HTTP scanning for remote VMs
    ports_to_try = [BASE_PORT] + [p for p in range(BASE_PORT + 1, BASE_PORT + 11)]
    unique_sessions = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(ports_to_try)
    ) as executor:
        results = executor.map(scan_port, ports_to_try)
        for res in results:
            for s in res:
                if isinstance(s, dict) and "port" in s:
                    unique_sessions[s["port"]] = s

    result_list = list(unique_sessions.values())
    with _session_map_lock:
        for s in result_list:
            if "port" in s:
                _session_map[s["port"]] = s
    return sorted(result_list, key=lambda x: x.get("port", 9999))


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
        {"name": "windbg.write_memory", "description": "Write raw bytes from hex string to virtual address or symbol.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "hex_data": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["address", "hex_data"]}},
        {"name": "windbg.search", "description": "Search virtual memory range for byte pattern.", "inputSchema": {"type": "object", "properties": {"start_address": {"type": "string"}, "end_address": {"type": "string"}, "pattern": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["start_address", "end_address", "pattern"]}},
        {"name": "windbg.read_string", "description": "Read ASCII or UTF-16 wide string from memory address or symbol.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "max_length": {"type": "integer"}, "wide": {"type": "boolean"}, "session_id": {"type": "integer"}}, "required": ["address"]}},
        {"name": "windbg.carve_pe", "description": "Reconstruct and carve mapped PE image from memory back to file-aligned raw bytes.", "inputSchema": {"type": "object", "properties": {"address": {"type": "string"}, "length": {"type": "integer"}, "session_id": {"type": "integer"}}, "required": ["address"]}},
        {"name": "windbg.get_threads", "description": "Get list of all target threads with thread IDs and current active thread flag.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.get_execution_state", "description": "Check if target is running, busy, or broken in and ready for commands.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.interrupt", "description": "Send interrupt signal to break into running target.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.step", "description": "Step execution forward or backward in time (TTD).", "inputSchema": {"type": "object", "properties": {"step_over": {"type": "boolean"}, "reverse": {"type": "boolean"}, "count": {"type": "integer"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.continue", "description": "Resume target execution forward ('g') or backward in time ('g-' in TTD).", "inputSchema": {"type": "object", "properties": {"reverse": {"type": "boolean"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.set_breakpoint", "description": "Set breakpoint at symbol or expression ('bp').", "inputSchema": {"type": "object", "properties": {"expression": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["expression"]}},
        {"name": "windbg.clear_breakpoint", "description": "Clear breakpoint by ID or '*' for all breakpoints ('bc').", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["id"]}},
        {"name": "windbg.resolve", "description": "Resolve symbol expression to address or address to nearest symbol and module.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["query"]}},
        {"name": "windbg.ttd_position", "description": "Query current Time Travel Debugging (TTD) position and thread positions or seek to a position (e.g. '1B:0').", "inputSchema": {"type": "object", "properties": {"position": {"type": "string"}, "session_id": {"type": "integer"}}}},
        {"name": "windbg.search_catalog", "description": "Search built-in WinDbg command documentation catalog.", "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]}},
        {"name": "windbg.get_command_docs", "description": "Retrieve full documentation for command by ID.", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
        {"name": "windbg.get_catalog_entry", "description": "Retrieve full documentation for command by ID (alias for get_command_docs).", "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}, "required": ["id"]}},
        {"name": "windbg.apply_struct", "description": "Dynamically apply C struct definition to memory address.", "inputSchema": {"type": "object", "properties": {"struct_definition": {"type": "string"}, "struct_name": {"type": "string"}, "address": {"type": "string"}, "module_name": {"type": "string"}, "session_id": {"type": "integer"}}, "required": ["struct_definition", "struct_name", "address"]}},
        {"name": "windbg.write_file", "description": "Write file directly onto Windows filesystem.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
        {"name": "windbg.get_session_metadata", "description": "Get metadata about active debugging target.", "inputSchema": {"type": "object", "properties": {"session_id": {"type": "integer"}}}},
        {"name": "windbg.list_sessions", "description": "List all active WinDbg MCP sessions in host/guest.", "inputSchema": {"type": "object", "properties": {}}}
    ]
    return tools


def handle_list_sessions(req_id):
    """Processes the windbg.list_sessions tool call."""
    sessions = get_sessions()
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(sessions, indent=2)}]
        },
    }

# ====================================================================
# MAIN STRATEGIC DISPATCH
# ====================================================================

def handle_request(line, output_stream):
    """Processes an individual JSON-RPC request from start to finish."""
    global _current_port, _current_pipe_name
    try:
        req_data = json.loads(line)
        req_id = req_data.get("id")
        method = req_data.get("method")
        params = req_data.get("params", {})
        log(f"REQ: {method} (id: {req_id})")

        # 1. Handle local gateway heartbeats
        if method == "ping":
            send_response(output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {}})
            return

        # 2. Handle Handshake/Initialization
        if method == "initialize":
            requested_version = params.get("protocolVersion", "2024-11-05")
            log(
                f"Searching for active WinDbg sessions (Requested version: {requested_version}, Transport: {TRANSPORT_MODE})..."
            )
            sessions = get_sessions()
            active_session = None
            if sessions:
                active_session = sessions[0]
                _current_port = active_session.get("port", BASE_PORT)
                _current_pipe_name = active_session.get("pipe_name")
                log(f"Found active session on port :{_current_port} (pipe: {_current_pipe_name}). Using as default.")
            else:
                log(f"No active sessions found. Falling back to base port :{BASE_PORT}")
                active_session = {"port": BASE_PORT, "pipe_name": f"dbgx-mcp-{BASE_PORT}"}

            try:
                resp_bytes, status = forward_mcp_message(
                    active_session, line.encode("utf-8"), timeout=60.0
                )
                resp_data = json.loads(resp_bytes.decode("utf-8"))
                if "result" in resp_data:
                    resp_data["result"]["protocolVersion"] = requested_version

                    if "capabilities" in resp_data["result"]:
                        caps = resp_data["result"]["capabilities"]
                        caps["tools"] = {"listChanged": True}
                        log(f"Backend init successful on :{_current_port}")

                send_response(output_stream, resp_data)
            except Exception as e:
                log(
                    f"INIT BACKEND FAIL on :{_current_port}: {e}. Returning synthetic success."
                )
                synthetic = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": requested_version,
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {
                            "name": "windbg-bridge-gateway",
                            "version": "1.2.0",
                        },
                    },
                }
                send_response(output_stream, synthetic)
            return

        # 3. Handle Tool Discovery
        if method == "tools/list":
            sessions = get_sessions()
            active_session = sessions[0] if sessions else {"port": _current_port, "pipe_name": _current_pipe_name}
            try:
                resp_bytes, status = forward_mcp_message(
                    active_session, line.encode("utf-8"), timeout=60.0
                )
                resp_data = json.loads(resp_bytes.decode("utf-8"))
                if "result" in resp_data and "tools" in resp_data["result"]:
                    for tool in resp_data["result"]["tools"]:
                        if tool["name"].startswith("windbg.") or tool["name"].startswith("windbg_"):
                            props = tool.setdefault("inputSchema", {}).setdefault(
                                "properties", {}
                            )
                            props["session_id"] = {
                                "type": "integer",
                                "description": (
                                    "Port of target WinDbg session. "
                                    "Find via windbg.list_sessions."
                                ),
                            }

                    resp_data["result"]["tools"].append(
                        {
                            "name": "windbg.list_sessions",
                            "description": (
                                "List all active WinDbg MCP sessions in the host/guest VM."
                            ),
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    )
                send_response(output_stream, resp_data)
            except Exception as e:
                log(f"TOOLS/LIST BACKEND FAIL on :{_current_port}: {e}. Returning full catalog.")
                send_response(
                    output_stream,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "tools": get_default_tools_list()
                        },
                    },
                )
            return

        # 4. Handle Execution
        if method == "tools/call":
            raw_tool_name = params.get("name", "")
            tool_name = raw_tool_name
            # Normalize tool_name if client uses underscore notation
            if tool_name.startswith("windbg_"):
                tool_name = "windbg." + tool_name[7:]
                req_data["params"]["name"] = tool_name
                line = json.dumps(req_data)

            tool_args = params.get("arguments", {})

            if tool_name in ("windbg.list_sessions", "list_sessions"):
                send_response(output_stream, handle_list_sessions(req_id))
                return

            target_port = tool_args.get("session_id", _current_port)
            if "session_id" in tool_args:
                del tool_args["session_id"]
                req_data["params"]["arguments"] = tool_args
                line = json.dumps(req_data)

            # Resolve target session metadata
            with _session_map_lock:
                target_session = _session_map.get(target_port, {"port": target_port, "pipe_name": f"dbgx-mcp-{target_port}"})

            # --- GUARDRAIL INTERCEPTOR ---
            if tool_name == "windbg.eval":
                command = tool_args.get("command", "")
                is_safe, guard_err = validate_command(command)
                if not is_safe:
                    log(f"GUARDRAIL BLOCKED: '{command}'")
                    send_response(output_stream, {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": guard_err
                        }
                    })
                    return

                # --- SMART TTL CACHE INTERCEPTOR ---
                ttl = get_cache_ttl(command)
                if ttl > 0.0:
                    cache_key = (target_port, command.strip())
                    with _cache_lock:
                        cached_item = _command_cache.get(cache_key)
                        if cached_item:
                            cache_time, cached_res = cached_item
                            if time.time() - cache_time < ttl:
                                log(f"CACHE HIT: '{command}' on :{target_port}")
                                resp_to_send = dict(cached_res)
                                resp_to_send["id"] = req_id
                                send_response(output_stream, resp_to_send)
                                return
        else:
            target_port = _current_port
            with _session_map_lock:
                target_session = _session_map.get(target_port, {"port": target_port, "pipe_name": f"dbgx-mcp-{target_port}"})

        # Forwarding to Backend via Pipe / HTTP
        try:
            req_timeout = get_timeout_for_request(req_data)
            log(f"FORWARD: using adaptive timeout {req_timeout}s for tool/command on target {target_port}")
            resp_bytes, status = forward_mcp_message(
                target_session, line.encode("utf-8"), timeout=req_timeout
            )
            if resp_bytes:
                resp_json = json.loads(resp_bytes.decode("utf-8"))

                # Intercept results to cache or enrich errors
                if method == "tools/call":
                    raw_tool_name = params.get("name", "")
                    tool_name = "windbg." + raw_tool_name[7:] if raw_tool_name.startswith("windbg_") else raw_tool_name

                    if tool_name == "windbg.eval":
                        command = tool_args.get("command", "")

                        # Populate cache on success
                        if "result" in resp_json:
                            ttl = get_cache_ttl(command)
                            if ttl > 0.0:
                                cache_key = (target_port, command.strip())
                                with _cache_lock:
                                    _command_cache[cache_key] = (time.time(), resp_json)
                                    log(f"CACHED: '{command}' on :{target_port} (TTL: {ttl}s)")

                        # Enrich syntax/runtime errors with actionable recommendations
                        elif "error" in resp_json:
                            err_msg = resp_json["error"].get("message", "")
                            suggestions = enrich_error_response(command, err_msg)
                            if suggestions:
                                resp_json["error"]["suggestions"] = suggestions
                                log(f"ENRICHED ERROR: '{command}' suggestions={suggestions}")

                send_response(output_stream, resp_json)
            else:
                log(f"Empty response from :{target_port}")
                if req_id is not None:
                    send_response(
                        output_stream,
                        {"jsonrpc": "2.0", "id": req_id, "result": {}},
                    )
        except Exception as e:
            log(f"FORWARD ERROR to target {target_port}: {e}")
            if req_id is not None:
                send_response(
                    output_stream,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": f"Backend :{target_port} unreachable: {e}",
                        },
                    },
                )

    except Exception as e:
        log(f"GLOBAL BRIDGE REQUEST ERROR: {e}")


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


if __name__ == "__main__":
    main()

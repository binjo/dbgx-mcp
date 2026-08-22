"""Bridge Gateway for WinDbg Model Context Protocol (MCP).

This script acts as a proxy between MCP clients (like Zed or Claude Desktop)
and a remote WinDbg session running the dbgx-mcp extension. It handles
Stdio-to-HTTP translation, multi-session discovery, protocol stability,
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
# Well-known base port for the WinDbg MCP server
BASE_PORT = 5678
# Path to the diagnostic log file
LOG_FILE = os.path.join(tempfile.gettempdir(), "windbg-bridge.log")

# Global state to track the currently selected backend port
_current_port = BASE_PORT

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


def validate_command(command: str) -> tuple[bool, str]:
    """Checks if a command is safe to execute. Returns (is_safe, error_message)."""
    # Guardrail: Reject sourcing/nesting commands from disk files to prevent arbitrary code/file execution
    if any(pattern in command for pattern in ["$<", "$>", "$$<", "$$>"]):
        return False, (
            "Sourcing or nesting command files (using '$<' or '$$<') is prohibited "
            "to prevent unauthorized disk file execution."
        )

    # Split by semicolon to check each individual subcommand
    subcommands = command.split(";")
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
    tool_name = params.get("name")
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
    global _last_known_sessions, _current_port
    check_count = 0
    while True:
        try:
            time.sleep(2.0)
            check_count += 1

            # Fast check: if current session is healthy, do full scan only every 6 seconds
            if _last_known_sessions and check_count % 3 != 0:
                quick_res = scan_port(_current_port)
                if quick_res:
                    continue  # Session is healthy and unchanged

            current_sessions = get_sessions()
            curr_ports = sorted([s.get("port", 9999) for s in current_sessions])

            if _last_known_sessions is not None and curr_ports != _last_known_sessions:
                log(f"Session list changed: {_last_known_sessions} -> {curr_ports}. Sending notifications/tools/list_changed.")
                if curr_ports:
                    _current_port = curr_ports[0]
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
    """Discover all active WinDbg MCP sessions in the guest VM."""
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
    return list(unique_sessions.values())


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
    global _current_port
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
                f"Searching for active WinDbg sessions (Requested version: {requested_version})..."
            )
            sessions = get_sessions()
            if sessions:
                _current_port = sorted(sessions, key=lambda x: x.get("port", 9999))[0][
                    "port"
                ]
                log(f"Found active session on port :{_current_port}. Using as default.")
            else:
                log(f"No active sessions found. Falling back to base port :{BASE_PORT}")

            try:
                resp_bytes, status = forward_post(
                    GUEST_IP, _current_port, "/mcp", line.encode("utf-8"), timeout=60.0
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
                            "version": "1.1.0",
                        },
                    },
                }
                send_response(output_stream, synthetic)
            return

        # 3. Handle Tool Discovery
        if method == "tools/list":
            try:
                resp_bytes, status = forward_post(
                    GUEST_IP, _current_port, "/mcp", line.encode("utf-8"), timeout=60.0
                )
                resp_data = json.loads(resp_bytes.decode("utf-8"))
                if "result" in resp_data and "tools" in resp_data["result"]:
                    for tool in resp_data["result"]["tools"]:
                        if tool["name"].startswith("windbg."):
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
                                "List all active WinDbg MCP sessions in the guest VM."
                            ),
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    )
                send_response(output_stream, resp_data)
            except Exception as e:
                log(f"TOOLS/LIST BACKEND FAIL on :{_current_port}: {e}")
                send_response(
                    output_stream,
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "tools": [
                                {
                                    "name": "windbg.list_sessions",
                                    "description": (
                                        "List active sessions (Backend "
                                        "currently unreachable)."
                                    ),
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {},
                                    },
                                }
                            ]
                        },
                    },
                )
            return

        # 4. Handle Execution
        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})

            if tool_name in ("windbg.list_sessions", "list_sessions"):
                send_response(output_stream, handle_list_sessions(req_id))
                return

            target_port = tool_args.get("session_id", _current_port)
            if "session_id" in tool_args:
                del tool_args["session_id"]
                req_data["params"]["arguments"] = tool_args
                line = json.dumps(req_data)

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
                                # CRITICAL FIX: Clone and swap the ID to match current request context!
                                resp_to_send = dict(cached_res)
                                resp_to_send["id"] = req_id
                                send_response(output_stream, resp_to_send)
                                return
        else:
            target_port = _current_port

        # Generic Forwarding to Backend
        try:
            req_timeout = get_timeout_for_request(req_data)
            log(f"FORWARD_POST: using adaptive timeout {req_timeout}s for tool/command")
            resp_bytes, status = forward_post(
                GUEST_IP, target_port, "/mcp", line.encode("utf-8"), timeout=req_timeout
            )
            if resp_bytes:
                resp_json = json.loads(resp_bytes.decode("utf-8"))

                # Intercept results to cache or enrich errors
                if method == "tools/call":
                    tool_name = params.get("name")

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
            log(f"FORWARD ERROR to :{target_port}: {e}")
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
    """Acquires a system-wide single ownership lock.
    
    On Windows, uses the system-wide 'Local\\dbgxmcp' named mutex.
    On macOS/Linux, uses standard POSIX fcntl file locking on a temporary file.
    
    Returns True if the lock was successfully acquired,
    otherwise False if another bridge instance is already running.
    """
    global _global_mutex_handle, _posix_lock_file

    if sys.platform != "win32":
        try:
            import fcntl
            lock_path = os.path.join(tempfile.gettempdir(), "dbgxmcp.lock")
            # Open the file for writing (create if not exists)
            _posix_lock_file = open(lock_path, "w")
            # Try to acquire an exclusive, non-blocking file lock
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
            return True  # Fallback to True if something fails unexpectedly

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
        return True  # Fallback to True if something fails unexpectedly in ctypes loading


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
    # Register the clean-up handler for the mutex lock
    atexit.register(release_global_mutex)

    if not acquire_global_mutex():
        log("Notice: Another WinDbg MCP launcher mutex exists. Continuing multi-client stdio bridge session.")

    log(f"Bridge Gateway started (Guest: {GUEST_IP})")
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

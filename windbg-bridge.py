"""Bridge Gateway for WinDbg Model Context Protocol (MCP).

This script acts as a proxy between MCP clients (like Zed or Claude Desktop)
and a remote WinDbg session running the dbgx-mcp extension. It handles
Stdio-to-HTTP translation, multi-session discovery, and protocol stability.
"""

import concurrent.futures
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

# Remote WinDbg MCP guest IP
GUEST_IP = next(
    (v for k, v in os.environ.items() if k.lower() == "windbg_mcp_bind"),
    "172.16.23.188",
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

_connections = {}
_conn_locks = {}

# Standard library thread pool for processing requests concurrently
_request_executor = concurrent.futures.ThreadPoolExecutor(max_workers=16)


def log(msg):
    """Logs a diagnostic message to the temporary log file.

    Args:
      msg: The message string to log.
    """
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
    except IOError:
        pass


def send_response(output_stream, data):
    """Serializes and sends a JSON-RPC response to stdout.

    Ensures the JSON is formatted as a single line to prevent protocol
    desynchronization in clients that expect line-buffered Stdio transport.
    Uses a mutex to ensure thread-safe output.

    Args:
      output_stream: The file-like object to write to (usually sys.stdout).
      data: The dictionary to serialize as JSON.
    """
    try:
        line = json.dumps(data)
        with _stdout_lock:
            output_stream.write(line + "\n")
            output_stream.flush()
        log(f"SENT: {line[:200]}...")
    except (TypeError, ValueError, IOError) as e:
        log(f"SEND ERROR: {e}")


def get_connection(host, port):
    """Retrieves or creates a persistent HTTP connection (thread-safe)."""
    key = f"{host}:{port}"
    with _connections_lock:
        conn = _connections.get(key)
        if conn is None:
            conn = http.client.HTTPConnection(host, port, timeout=60)
            _connections[key] = conn
        return conn


def get_connection_lock(key):
    """Retrieves a lock dedicated to serializing writes/reads on a specific connection."""
    with _conn_locks_lock:
        lock = _conn_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _conn_locks[key] = lock
        return lock


def forward_post(host, port, path, body_bytes):
    """Forwards a POST request using a persistent keep-alive connection with automatic reconnect."""
    key = f"{host}:{port}"
    lock = get_connection_lock(key)
    with lock:
        conn = get_connection(host, port)
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
            conn = get_connection(host, port)
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
    """Scans a single port for an active WinDbg MCP guest session."""
    url = f"http://{GUEST_IP}:{port}/sessions"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=0.3) as f:
            if f.getcode() == 200:
                data = json.loads(f.read().decode("utf-8"))
                if isinstance(data, list):
                    for s in data:
                        s["port"] = port
                    return data
    except Exception:
        pass
    return []


def get_sessions():
    """Discover all active WinDbg MCP sessions in the guest VM.

    Scans a range of ports starting from BASE_PORT in parallel to find active endpoints
    exposing the /sessions metadata.

    Returns:
      A list of session dictionaries, each containing process info and port.
    """
    ports_to_try = [BASE_PORT] + [p for p in range(BASE_PORT + 1, BASE_PORT + 11)]
    sessions = []
    # Scan all ports in parallel using a thread pool to avoid blocking (completes in ~0.3s)
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(ports_to_try)
    ) as executor:
        results = executor.map(scan_port, ports_to_try)
        for res in results:
            sessions.extend(res)
    return sessions


def handle_list_sessions(req_id):
    """Processes the windbg.list_sessions tool call.

    Args:
      req_id: The JSON-RPC request ID to associate with the result.

    Returns:
      A JSON-RPC response dictionary containing the session list.
    """
    sessions = get_sessions()
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(sessions, indent=2)}]
        },
    }


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
                    GUEST_IP, _current_port, "/mcp", line.encode("utf-8")
                )
                resp_data = json.loads(resp_bytes.decode("utf-8"))
                if "result" in resp_data:
                    resp_data["result"]["protocolVersion"] = requested_version

                    if "capabilities" in resp_data["result"]:
                        caps = resp_data["result"]["capabilities"]
                        if "tools" not in caps:
                            caps["tools"] = {}
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
                        "capabilities": {"tools": {}},
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
                    GUEST_IP, _current_port, "/mcp", line.encode("utf-8")
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

            if tool_name == "windbg.list_sessions" or tool_name == "list_sessions":
                send_response(output_stream, handle_list_sessions(req_id))
                return

            target_port = tool_args.get("session_id", _current_port)
            if "session_id" in tool_args:
                del tool_args["session_id"]
                req_data["params"]["arguments"] = tool_args
                line = json.dumps(req_data)
        else:
            target_port = _current_port

        # Generic Forwarding to Backend
        try:
            resp_bytes, status = forward_post(
                GUEST_IP, target_port, "/mcp", line.encode("utf-8")
            )
            if resp_bytes:
                resp_json = json.loads(resp_bytes.decode("utf-8"))
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


def main():
    """Main execution loop for the bridge gateway."""
    log(f"Bridge Gateway started (Guest: {GUEST_IP})")
    input_stream = sys.stdin
    output_stream = sys.stdout

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

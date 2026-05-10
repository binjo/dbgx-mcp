"""Bridge Gateway for WinDbg Model Context Protocol (MCP).

This script acts as a proxy between MCP clients (like Zed or Claude Desktop)
and a remote WinDbg session running the dbgx-mcp extension. It handles
Stdio-to-HTTP translation, multi-session discovery, and protocol stability.
"""

import json
import os
import sys
import tempfile
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

    Args:
      output_stream: The file-like object to write to (usually sys.stdout).
      data: The dictionary to serialize as JSON.
    """
    try:
        line = json.dumps(data)
        output_stream.write(line + "\n")
        output_stream.flush()
        log(f"SENT: {line[:200]}...")
    except (TypeError, ValueError, IOError) as e:
        log(f"SEND ERROR: {e}")


def get_sessions():
    """Discover all active WinDbg MCP sessions in the guest VM.

    Scans a range of ports starting from BASE_PORT to find active endpoints
    exposing the /sessions metadata.

    Returns:
      A list of session dictionaries, each containing process info and port.
    """
    ports_to_try = [BASE_PORT] + [p for p in range(BASE_PORT + 1, BASE_PORT + 11)]
    sessions = []
    for port in ports_to_try:
        url = f"http://{GUEST_IP}:{port}/sessions"
        try:
            # Use short timeout for scanning
            with urllib.request.urlopen(url, timeout=0.3) as f:
                if f.getcode() == 200:
                    data = json.loads(f.read().decode("utf-8"))
                    # Tag with port so client knows where it came from
                    if isinstance(data, list):
                        for s in data:
                            s["port"] = port
                        sessions.extend(data)
        except (
            urllib.error.URLError,
            json.JSONDecodeError,
            TimeoutError,
            ConnectionError,
        ):
            continue
    return sessions


def handle_list_sessions(req_id):
    """Processes the list_sessions tool call.

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


def main():
    """Main execution loop for the bridge gateway."""
    global _current_port
    log(f"Bridge Gateway started (Guest: {GUEST_IP})")
    input_stream = sys.stdin
    output_stream = sys.stdout

    while True:
        line = input_stream.readline()
        if not line:
            log("Stdin closed")
            break

        line = line.strip()
        if not line:
            continue

        try:
            req_data = json.loads(line)
            req_id = req_data.get("id")
            method = req_data.get("method")
            params = req_data.get("params", {})
            log(f"REQ: {method} (id: {req_id})")

            # 1. Handle local gateway heartbeats
            if method == "ping":
                send_response(
                    output_stream, {"jsonrpc": "2.0", "id": req_id, "result": {}}
                )
                continue

            # 2. Handle Handshake/Initialization
            if method == "initialize":
                requested_version = params.get("protocolVersion", "2024-11-05")
                # Strategy: Scan for an active session to use as the default port
                log(
                    f"Searching for active WinDbg sessions (Requested version: {requested_version})..."
                )
                sessions = get_sessions()
                if sessions:
                    # Prefer the session on the lowest port (usually 5678 or 5679)
                    _current_port = sorted(sessions, key=lambda x: x.get("port", 9999))[
                        0
                    ]["port"]
                    log(
                        f"Found active session on port :{_current_port}. Using as default."
                    )
                else:
                    log(
                        f"No active sessions found. Falling back to base port :{BASE_PORT}"
                    )

                url = f"http://{GUEST_IP}:{_current_port}/mcp"
                req = urllib.request.Request(
                    url,
                    data=line.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as f:
                        resp_data = json.loads(f.read().decode("utf-8"))
                        if "result" in resp_data:
                            # Echo requested version to satisfy client constraints
                            resp_data["result"]["protocolVersion"] = requested_version

                            if "capabilities" in resp_data["result"]:
                                caps = resp_data["result"]["capabilities"]
                                if "tools" not in caps:
                                    caps["tools"] = {}
                                log(f"Backend init successful on :{_current_port}")

                        send_response(output_stream, resp_data)
                        continue
                except (
                    urllib.error.URLError,
                    json.JSONDecodeError,
                    TimeoutError,
                    ConnectionError,
                ) as e:
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
                    continue

            # 3. Handle Tool Discovery
            if method == "tools/list":
                url = f"http://{GUEST_IP}:{_current_port}/mcp"
                req = urllib.request.Request(
                    url,
                    data=line.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as f:
                        resp_data = json.loads(f.read().decode("utf-8"))
                        if "result" in resp_data and "tools" in resp_data["result"]:
                            for tool in resp_data["result"]["tools"]:
                                if tool["name"] == "windbg.eval":
                                    props = tool.setdefault(
                                        "inputSchema", {}
                                    ).setdefault("properties", {})
                                    props["session_id"] = {
                                        "type": "integer",
                                        "description": (
                                            "Port of target WinDbg session. "
                                            "Find via list_sessions."
                                        ),
                                    }

                            resp_data["result"]["tools"].append(
                                {
                                    "name": "list_sessions",
                                    "description": (
                                        "List all active WinDbg MCP sessions "
                                        "in the guest VM."
                                    ),
                                    "inputSchema": {"type": "object", "properties": {}},
                                }
                            )
                        send_response(output_stream, resp_data)
                        continue
                except (
                    urllib.error.URLError,
                    json.JSONDecodeError,
                    TimeoutError,
                    ConnectionError,
                ) as e:
                    log(f"TOOLS/LIST BACKEND FAIL on :{_current_port}: {e}")
                    send_response(
                        output_stream,
                        {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "tools": [
                                    {
                                        "name": "list_sessions",
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
                    continue

            # 4. Handle Execution
            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})

                if tool_name == "list_sessions":
                    send_response(output_stream, handle_list_sessions(req_id))
                    continue

                target_port = tool_args.get("session_id", _current_port)
                if "session_id" in tool_args:
                    del tool_args["session_id"]
                    req_data["params"]["arguments"] = tool_args
                    line = json.dumps(req_data)
            else:
                target_port = _current_port

            # Generic Forwarding to Backend
            url = f"http://{GUEST_IP}:{target_port}/mcp"
            req = urllib.request.Request(
                url,
                data=line.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=60) as f:
                    response_raw = f.read().decode("utf-8").strip()
                    if response_raw:
                        resp_json = json.loads(response_raw)
                        send_response(output_stream, resp_json)
                    else:
                        log(f"Empty response from :{target_port}")
                        if req_id is not None:
                            send_response(
                                output_stream,
                                {"jsonrpc": "2.0", "id": req_id, "result": {}},
                            )
            except (
                urllib.error.URLError,
                json.JSONDecodeError,
                TimeoutError,
                ConnectionError,
            ) as e:
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

        except (json.JSONDecodeError, KeyError) as e:
            log(f"GLOBAL BRIDGE ERROR: {e}")


if __name__ == "__main__":
    main()

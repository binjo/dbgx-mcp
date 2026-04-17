import sys
import json
import urllib.request
import urllib.error
import time

# Remote WinDbg MCP guest IP
GUEST_IP = "172.16.23.188"
# Well-known base port
BASE_PORT = 5678
LOG_FILE = "/tmp/windbg-bridge.log"

# Global state to track selected port
_current_port = BASE_PORT

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

def get_sessions():
    """Discover all active sessions in the guest VM."""
    # Try the base port first as it is the most likely to be up
    ports_to_try = [BASE_PORT] + [p for p in range(BASE_PORT + 1, BASE_PORT + 11)]
    
    for port in ports_to_try:
        url = f"http://{GUEST_IP}:{port}/sessions"
        try:
            with urllib.request.urlopen(url, timeout=2) as f:
                if f.getcode() == 200:
                    return json.loads(f.read().decode('utf-8'))
        except:
            continue
    return []

def handle_list_sessions(req_id):
    sessions = get_sessions()
    response = {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(sessions, indent=2)}]
        }
    }
    return response

def main():
    global _current_port
    log("Bridge Gateway started")
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
            
        log(f"REQ: {line[:200]}...")
        
        try:
            req_data = json.loads(line)
            req_id = req_data.get("id")
            method = req_data.get("method")
            params = req_data.get("params", {})
            
            # Handle local gateway commands
            if method == "tools/list":
                # Forward to backend first to get real tools
                url = f"http://{GUEST_IP}:{_current_port}/mcp"
                req = urllib.request.Request(
                    url, 
                    data=line.encode('utf-8'), 
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                try:
                    with urllib.request.urlopen(req, timeout=10) as f:
                        resp_data = json.loads(f.read().decode('utf-8'))
                        if "result" in resp_data and "tools" in resp_data["result"]:
                            # Add our gateway tool
                            resp_data["result"]["tools"].append({
                                "name": "list_sessions",
                                "description": "List all active WinDbg MCP sessions in the guest VM.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {}
                                }
                            })
                            output_stream.write(json.dumps(resp_data) + "\n")
                            output_stream.flush()
                            continue
                except:
                    pass

            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                
                if tool_name == "list_sessions":
                    output_stream.write(json.dumps(handle_list_sessions(req_id)) + "\n")
                    output_stream.flush()
                    continue
                
                # If a session_id (port) is provided in arguments, use it
                target_port = tool_args.get("session_id", _current_port)
                # Remove session_id from arguments before forwarding to backend
                if "session_id" in tool_args:
                    del tool_args["session_id"]
                    # Also update req_data for forwarding
                    req_data["params"]["arguments"] = tool_args
                    line = json.dumps(req_data)
            else:
                target_port = _current_port

            # Forward to the chosen port
            url = f"http://{GUEST_IP}:{target_port}/mcp"
            
            req = urllib.request.Request(
                url, 
                data=line.encode('utf-8'), 
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=60) as f:
                status = f.getcode()
                response = f.read().decode('utf-8').strip()
                
                if response:
                    log(f"RES ({status}) from :{target_port}: {response[:200]}...")
                    output_stream.write(response + "\n")
                    output_stream.flush()
                else:
                    log(f"RES ({status}) from :{target_port}: No body")
                
        except Exception as e:
            err_msg = str(e)
            if isinstance(e, urllib.error.URLError):
                err_msg = f"Network error on port {target_port}: {e.reason}"
            
            log(f"BRIDGE ERROR: {err_msg}")
            
            try:
                req_id = json.loads(line).get("id")
                if req_id is not None:
                    error_response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32000,
                            "message": err_msg
                        }
                    }
                    output_stream.write(json.dumps(error_response) + "\n")
                    output_stream.flush()
            except:
                pass

if __name__ == "__main__":
    main()

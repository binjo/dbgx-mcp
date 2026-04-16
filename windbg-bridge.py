import sys
import json
import urllib.request
import urllib.error
import time

# Remote WinDbg MCP HTTP endpoint
URL = "http://172.16.23.188:5678/mcp"
LOG_FILE = "/tmp/windbg-bridge.log"

def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

def main():
    log("Bridge started (fixed empty-line handling)")
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
            req = urllib.request.Request(
                URL, 
                data=line.encode('utf-8'), 
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=10) as f:
                # Check the status code
                status = f.getcode()
                response = f.read().decode('utf-8').strip()
                
                if response:
                    log(f"RES ({status}): {response[:200]}...")
                    # Only write to Gemini if there is a non-empty JSON-RPC response
                    output_stream.write(response + "\n")
                    output_stream.flush()
                else:
                    log(f"RES ({status}): No body (skipping output)")
                
        except urllib.error.URLError as e:
            log(f"NET ERROR: {e.reason}")
            # Optional: Send a JSON-RPC error back to Gemini instead of just stderr
        except Exception as e:
            log(f"INTERNAL ERROR: {str(e)}")

if __name__ == "__main__":
    main()

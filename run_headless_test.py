import subprocess
import time
import urllib.request
import json
import threading

url = "http://127.0.0.1:5678/mcp"
cdb_path = r"D:\tools\windbg\nino\windbg\cdb.exe"
dmp_path = r"D:\Exclusive\tmp\FLREQ\515198003\w3wp.exe minidumps\w3wp.exe PID 7180\minidump\minidump.dmp"

def ts_print(msg, *args):
    timestamp = f"{time.strftime('%Y-%m-%d %H:%M:%S')}.{int(time.time()*1000)%1000:03d}"
    formatted = str(msg)
    if args:
        formatted += " " + " ".join(str(a) for a in args)
    print(f"[{timestamp}] {formatted}")

def send_request(payload, timeout=60):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception as e:
        return {"error": str(e)}

def run_reload():
    ts_print("[Thread 1] Sending .reload /f...")
    payload = {
        "jsonrpc": "2.0",
        "id": 1001,
        "method": "tools/call",
        "params": {
            "name": "windbg.eval",
            "arguments": {
                "command": ".reload /f"
            }
        }
    }
    res = send_request(payload)
    ts_print("[Thread 1] .reload /f finished. Response:\n" + json.dumps(res, indent=2))

def main():
    ts_print("Launching cdb.exe in the background with the user-mode dump...")
    cmd = [cdb_path, "-z", dmp_path, "-c", ".load dbgx-mcp"]
    
    # We use DEVNULL to prevent OS pipe buffers from filling up and blocking cdb.exe
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    
    try:
        # Wait 4 seconds for the HTTP server to initialize
        ts_print("Waiting 4 seconds for HTTP server to spin up...")
        time.sleep(4)
        
        # Verify the session is up
        ts_print("Verifying session status via /sessions...")
        try:
            req = urllib.request.urlopen("http://127.0.0.1:5678/sessions", timeout=2)
            ts_print("Session discovered:", req.read().decode("utf-8"))
        except Exception as e:
            ts_print("Error reaching sessions endpoint:", e)
            return

        # 1. Start the reload in the background
        ts_print("Starting reload thread...")
        t = threading.Thread(target=run_reload)
        t.start()

        # 2. Wait 2 seconds for the engine to become busy
        ts_print("Sleeping 2 seconds...")
        time.sleep(2)
        ts_print("Sleep done. Preparing to send interrupt.")

        # 3. Issue the interrupt
        ts_print("[Main] Sending windbg.interrupt...")
        interrupt_payload = {
            "jsonrpc": "2.0",
            "id": 1002,
            "method": "tools/call",
            "params": {
                "name": "windbg.interrupt",
                "arguments": {}
            }
        }
        interrupt_res = send_request(interrupt_payload)
        ts_print("[Main] Interrupt response:\n" + json.dumps(interrupt_res, indent=2))

        # 4. Immediately execute .chain
        ts_print("[Main] Sending .chain...")
        chain_payload = {
            "jsonrpc": "2.0",
            "id": 1003,
            "method": "tools/call",
            "params": {
                "name": "windbg.eval",
                "arguments": {
                    "command": ".chain"
                }
            }
        }
        chain_res = send_request(chain_payload)
        ts_print("[Main] .chain response:\n" + json.dumps(chain_res, indent=2))

        # Wait for the reload thread to join
        ts_print("Waiting for reload thread to join...")
        t.join()
        
    finally:
        ts_print("Terminating cdb.exe...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
        ts_print("Done!")

if __name__ == "__main__":
    main()

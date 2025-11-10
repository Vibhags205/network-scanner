# app.py
from flask import Flask, request, jsonify, send_from_directory
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import os

app = Flask(__name__, static_folder="static", static_url_path="/static")

# Safety limits for web UI
MAX_RANGE_SIZE = 500
DEFAULT_TIMEOUT = 0.5

def scan_port(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> tuple:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port, True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return port, False

def scan_range(host: str, start: int, end: int, workers: int = 100, timeout: float = DEFAULT_TIMEOUT):
    start_time = time.time()
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in range(start, end+1)}
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
    elapsed = time.time() - start_time
    return sorted(open_ports), elapsed

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/scan", methods=["POST"])
def scan_api():
    """
    Expect JSON body:
    { "host": "192.168.1.1", "start": 1, "end": 1024, "workers": 100, "timeout": 0.5 }
    """
    data = request.get_json() or {}
    host = (data.get("host") or "").strip()
    try:
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
    except (TypeError, ValueError):
        return jsonify({"error": "start and end must be integers"}), 400

    if not host:
        return jsonify({"error": "host is required"}), 400
    if start < 1 or end > 65535 or start > end:
        return jsonify({"error": "invalid port range; must be 1-65535 and start <= end"}), 400
    if (end - start + 1) > MAX_RANGE_SIZE:
        return jsonify({"error": f"range too large from UI (max {MAX_RANGE_SIZE} ports). Use CLI for larger scans."}), 400

    workers = int(data.get("workers", 100))
    timeout = float(data.get("timeout", DEFAULT_TIMEOUT))

    try:
        open_ports, elapsed = scan_range(host, start, end, workers=workers, timeout=timeout)
    except Exception as e:
        return jsonify({"error": f"scan failed: {str(e)}"}), 500

    return jsonify({"host": host, "start": start, "end": end, "open_ports": open_ports, "time_s": elapsed})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # debug=False in production; set to True for local dev if desired.
    app.run(host="0.0.0.0", port=port, debug=True)

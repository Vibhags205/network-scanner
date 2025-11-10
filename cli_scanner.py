# cli_scanner.py
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

def scan_port(host: str, port: int, timeout: float = 0.4) -> tuple:
    """Return (port, is_open)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return port, True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return port, False

def scan_range(host: str, start: int, end: int, workers: int = 200, timeout: float = 0.4):
    open_ports = []
    total = end - start + 1
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in range(start, end+1)}
        checked = 0
        for fut in as_completed(futures):
            port, is_open = fut.result()
            checked += 1
            if is_open:
                open_ports.append(port)
            print(f"\rChecked {checked}/{total} ports", end="", flush=True)
    elapsed = time.time() - start_time
    print()
    return sorted(open_ports), elapsed

def main():
    parser = argparse.ArgumentParser(description="Simple CLI TCP port scanner")
    parser.add_argument("host", help="target hostname or IP (e.g. 192.168.1.10 or example.com)")
    parser.add_argument("--start", type=int, default=1, help="start port (default 1)")
    parser.add_argument("--end", type=int, default=1024, help="end port (default 1024)")
    parser.add_argument("--workers", type=int, default=200, help="concurrent threads (default 200)")
    parser.add_argument("--timeout", type=float, default=0.4, help="socket timeout seconds (default 0.4)")
    args = parser.parse_args()

    print(f"Scanning {args.host} ports {args.start}-{args.end} ...")
    open_ports, elapsed = scan_range(args.host, args.start, args.end, args.workers, args.timeout)
    print(f"Done in {elapsed:.2f}s. Open ports: {open_ports if open_ports else 'None found'}")

if __name__ == "__main__":
    main()

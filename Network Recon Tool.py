import socket
import argparse
import threading
import json
import time
from queue import Queue
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False

results = {
    "target": None,
    "open_ports": [],
    "discovered_hosts": [],
    "timestamp": None
}

queue = Queue()

def discover_hosts(network):
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not installed — host discovery skipped.")
        return []

    print(f"[+] Discovering hosts on {network} ...")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered = srp(packet, timeout=2, verbose=0)[0]

    hosts = []
    for send, receive in answered:
        hosts.append(receive.psrc)

    results["discovered_hosts"] = hosts
    return hosts

def scan_tcp_port(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                sock.send(b"Hello\r\n")
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = "Unknown Service"

            print(f"[OPEN] TCP {port} | {banner}")

            results["open_ports"].append({
                "port": port,
                "protocol": "TCP",
                "service": banner
            })

        sock.close()
    except:
        pass

def scan_udp_port(target, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"", (target, port))

        try:
            data, addr = sock.recvfrom(1024)
            banner = data.decode(errors="ignore").strip()
            print(f"[OPEN] UDP {port} | {banner}")

            results["open_ports"].append({
                "port": port,
                "protocol": "UDP",
                "service": banner
            })
        except socket.timeout:
            # UDP silence means possibly open/filtered
            print(f"[?] UDP {port} (open|filtered)")

        sock.close()
    except:
        pass


def worker(target, scan_type):
    while not queue.empty():
        port = queue.get()
        if scan_type == "tcp":
            scan_tcp_port(target, port)
        elif scan_type == "udp":
            scan_udp_port(target, port)
        queue.task_done()

def run_scan(target, ports, threads, scan_type):
    results["target"] = target

    for port in ports:
        queue.put(port)

    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(target, scan_type))
        thread.daemon = True
        thread.start()

    queue.join()


def save_output(filename):
    results["timestamp"] = datetime.now().isoformat()

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n[+] Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Network Scanner & Recon Tool (Single Script)")
    parser.add_argument("--target", help="Target IP or host", required=False)
    parser.add_argument("--ports", help="Port range e.g., 1-1000", default="1-1024")
    parser.add_argument("--udp", action="store_true", help="Run UDP scan instead of TCP")
    parser.add_argument("--discover", help="Network range for host discovery (e.g., 192.168.1.0/24)")
    parser.add_argument("--threads", type=int, default=100, help="Number of scanning threads")
    parser.add_argument("--output", help="Save results to JSON file", default="results.json")

    args = parser.parse_args()

    if args.discover:
        discover_hosts(args.discover)

    if not args.target:
        print("[!] No target provided — only discovery was run.")
        return

    start, end = map(int, args.ports.split("-"))
    ports = range(start, end + 1)

    scan_type = "udp" if args.udp else "tcp"

    print(f"[+] Starting {scan_type.upper()} scan on {args.target}")
    print(f"[+] Ports: {start}-{end}")
    run_scan(args.target, ports, args.threads, scan_type)

    save_output(args.output)


if __name__ == "__main__":
    main()

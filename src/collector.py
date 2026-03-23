import psutil
import json
import time
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

try:
    from scapy.all import sniff, DNS, DNSRR
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False

# ── DNS cache (persists across cycles, avoids repeated lookups) ────────────────
_dns_cache: dict = {}

def _resolve_ip(ip: str) -> str:
    """Reverse-DNS a single IP with a hard 0.4 s timeout. Falls back to raw IP."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(socket.gethostbyaddr, ip)
            host = future.result(timeout=0.4)[0]
    except Exception:
        host = ip
    _dns_cache[ip] = host
    return host


def start_packet_sniffer():
    """Wireshark-like background packet sniffer to track actual website domains (DNS Responses)."""
    def process_packet(packet):
        try:
            if packet.haslayer(DNS) and packet.haslayer(DNSRR):
                for i in range(packet[DNS].ancount):
                    rr = packet[DNS].an[i]
                    if rr.type == 1:  # A record (IPv4)
                        domain = rr.rrname.decode('utf-8').rstrip('.')
                        ip = str(rr.rdata)
                        # Map the exact sniffed website domain to the IP
                        _dns_cache[ip] = domain
        except Exception:
            pass

    print("[Sniffer] Starting background DNS packet sniffer...")
    try:
        sniff(filter="udp port 53", prn=process_packet, store=0)
    except Exception as e:
        print(f"[Sniffer] Warning: Could not start packet sniffer: {e}")

if _SCAPY_AVAILABLE:
    threading.Thread(target=start_packet_sniffer, daemon=True).start()

def collect_network_connections() -> dict:
    """
    Returns a dict: pid -> {
        'connection_count': int,
        'remote_hosts':     [str, ...],   # resolved domain names (max 5)
        'remote_ips':       [str, ...],
        'has_web':          bool,          # any port-80 / 443 connection
        'has_dns':          bool,          # any port-53 connection
    }

    Requires: psutil (already installed).
    On Windows, reading all connections may need Administrator rights.
    If access is denied the function returns an empty dict silently.
    """
    pid_data: dict = {}

    try:
        connections = psutil.net_connections(kind='tcp')
    except (psutil.AccessDenied, PermissionError):
        # Silently skip — process data will still work without network info
        return {}

    # Collect raw IPs per PID first (avoid DNS inside the loop)
    pid_raw: dict = {}
    for conn in connections:
        if not conn.pid or not conn.raddr:
            continue
        ip   = conn.raddr.ip
        port = conn.raddr.port
        # Skip loopback and link-local
        if ip.startswith('127.') or ip.startswith('::1') or ip.startswith('169.254'):
            continue
        pid_raw.setdefault(conn.pid, []).append((ip, port))

    # Resolve IPs to hostnames in a thread pool (bounded concurrency)
    unique_ips = {ip for conns in pid_raw.values() for ip, _ in conns}
    if unique_ips:
        with ThreadPoolExecutor(max_workers=min(len(unique_ips), 20)) as ex:
            futures = {ex.submit(_resolve_ip, ip): ip for ip in unique_ips}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    _dns_cache[ip] = fut.result()
                except Exception:
                    _dns_cache[ip] = ip

    # Build per-PID summary
    for pid, conns in pid_raw.items():
        hosts = []
        ips   = []
        has_web = False
        has_dns = False
        seen_hosts: set = set()

        for ip, port in conns:
            host = _dns_cache.get(ip, ip)
            ips.append(ip)
            if host not in seen_hosts:
                seen_hosts.add(host)
                hosts.append(host)
            if port in (80, 443, 8080, 8443):
                has_web = True
            if port == 53:
                has_dns = True

        pid_data[pid] = {
            'connection_count': len(conns),
            'remote_hosts':     hosts[:25],          # Increased cap to catch all browser connections
            'remote_ips':       list(set(ips))[:25],
            'has_web':          has_web,
            'has_dns':          has_dns,
        }

    return pid_data


def collect_processes() -> list:
    """
    Captures live system process data enriched with network connections.

    Each process dict now includes:
        pid, ppid, name, cpu_percent, memory_percent, username
        connection_count  — number of active external TCP connections
        remote_hosts      — resolved domain names (e.g. ['google.com'])
        remote_ips        — raw remote IPs
        has_web           — True if process has any HTTP/HTTPS connection
        has_dns           — True if process has port-53 activity
    """
    net_data = collect_network_connections()

    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info.copy()
            try:
                info['username'] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['username'] = 'SYSTEM'

            # Merge network data
            pid = info.get('pid', -1)
            net = net_data.get(pid, {})
            info['connection_count'] = net.get('connection_count', 0)
            info['remote_hosts']     = net.get('remote_hosts', [])
            info['remote_ips']       = net.get('remote_ips', [])
            info['has_web']          = net.get('has_web', False)
            info['has_dns']          = net.get('has_dns', False)

            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return processes


def save_telemetry(data, file_path='data/gnn_baseline_data.json'):
    """Serializes telemetry data to JSON."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Captured {len(data)} processes to {file_path}")


if __name__ == "__main__":
    print("Starting Cyber Triage Data Collector (with network monitoring)...")
    while True:
        try:
            telemetry = collect_processes()
            save_telemetry(telemetry)
            # Show any processes with active web connections
            web_procs = [p for p in telemetry if p.get('has_web')]
            if web_procs:
                print(f"  Web-connected processes ({len(web_procs)}):")
                for p in web_procs[:5]:
                    print(f"    {p['name']} (PID {p['pid']}) → {p['remote_hosts']}")
            time.sleep(5)
        except KeyboardInterrupt:
            print("\nCollector stopped.")
            break

"""
Live packet capture module — Wireshark-style.
Uses scapy (already installed). Requires admin/root + Npcap on Windows.
Runs in a background daemon thread; safe to import even if scapy is missing.
"""

import threading
import time
from collections import deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── Shared state ───────────────────────────────────────────────────────────────
_buffer: deque = deque(maxlen=500)   # rolling window of last 500 packets
_lock   = threading.Lock()
_stats  = {"total": 0, "bytes": 0, "start": time.time()}
_pkt_no = 0
_running = False

# Protocol → display name mapping
_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# Well-known port → protocol label
_PORT_PROTO = {
    80: "HTTP", 8080: "HTTP",
    443: "HTTPS", 8443: "HTTPS",
    22: "SSH", 21: "FTP", 25: "SMTP",
    110: "POP3", 143: "IMAP", 587: "SMTP",
    3389: "RDP", 445: "SMB", 139: "NetBIOS",
    53: "DNS", 67: "DHCP", 68: "DHCP",
    123: "NTP", 161: "SNMP",
}


def _classify_port(port):
    return _PORT_PROTO.get(port)


def _tcp_flags(flag_int):
    names = []
    if flag_int & 0x02: names.append("SYN")
    if flag_int & 0x10: names.append("ACK")
    if flag_int & 0x01: names.append("FIN")
    if flag_int & 0x04: names.append("RST")
    if flag_int & 0x08: names.append("PSH")
    if flag_int & 0x20: names.append("URG")
    return " ".join(names) if names else "—"


def _process(pkt):
    global _pkt_no
    try:
        if not pkt.haslayer(IP):
            return
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst

        # Drop loopback
        if src_ip.startswith("127.") or dst_ip.startswith("127."):
            return

        proto  = _PROTO.get(ip.proto, str(ip.proto))
        size   = len(pkt)
        sport  = dport = None
        flags  = ""
        info   = ""

        if pkt.haslayer(TCP):
            tcp   = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = _tcp_flags(int(tcp.flags))
            label = _classify_port(dport) or _classify_port(sport)
            if label:
                proto = label
            info = flags

        elif pkt.haslayer(UDP):
            udp   = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            label = _classify_port(dport) or _classify_port(sport)
            if label:
                proto = label
            if proto == "DNS" and pkt.haslayer(DNS):
                dns = pkt[DNS]
                try:
                    if dns.qd:
                        info = f"Query: {dns.qd.qname.decode().rstrip('.')}"
                    elif dns.an:
                        info = f"Response: {dns.an.rdata}"
                except Exception:
                    pass

        elif pkt.haslayer(ICMP):
            proto = "ICMP"
            icmp  = pkt[ICMP]
            info  = f"type={icmp.type} code={icmp.code}"

        with _lock:
            _pkt_no += 1
            _stats["total"] += 1
            _stats["bytes"] += size
            _buffer.append({
                "no":    _pkt_no,
                "ts":    datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src":   src_ip,
                "dst":   dst_ip,
                "sport": sport,
                "dport": dport,
                "proto": proto,
                "size":  size,
                "flags": flags,
                "info":  info,
            })
    except Exception:
        pass


def _find_active_iface():
    """Return the interface whose IP matches the machine's default outbound address."""
    try:
        from scapy.all import get_if_list, get_if_addr
        import socket
        local_ip = socket.gethostbyname(socket.gethostname())
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    return iface
            except Exception:
                pass
    except Exception:
        pass
    return None


def start(iface=None):
    """Start capturing in a background daemon thread. Safe to call multiple times."""
    global _running
    if not SCAPY_OK:
        print("[PacketSniffer] scapy not available — skipping")
        return
    if _running:
        return
    _running = True

    # On Windows, scapy must have an explicit interface — auto-detect if not given
    target_iface = iface or _find_active_iface()
    if target_iface:
        print(f"[PacketSniffer] Capturing on: {target_iface}")
    else:
        print("[PacketSniffer] Warning: could not detect active interface, trying default")

    def _run():
        try:
            sniff(
                iface=target_iface,
                filter="ip",
                prn=_process,
                store=0,
                stop_filter=lambda _: not _running,
            )
        except Exception as e:
            print(f"[PacketSniffer] Could not capture packets: {e}")
            print("[PacketSniffer] Tip: run the server as Administrator and ensure Npcap is installed.")

    threading.Thread(target=_run, daemon=True, name="PacketSniffer").start()
    print("[PacketSniffer] Live capture started")


def stop():
    global _running
    _running = False


def get_recent(n: int = 100) -> list:
    with _lock:
        return list(_buffer)[-n:]


def get_stats() -> dict:
    with _lock:
        elapsed = max(time.time() - _stats["start"], 1.0)
        return {
            "total":  _stats["total"],
            "bytes":  _stats["bytes"],
            "pps":    round(_stats["total"] / elapsed, 1),
            "kbps":   round(_stats["bytes"] / elapsed / 1024, 2),
            "active": _running and SCAPY_OK,
        }

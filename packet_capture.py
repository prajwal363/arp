"""
NetGuard - Network Security Monitor
Live Packet Capture Module

Captures all packets in real-time and emits them to the dashboard
via SocketIO so the user can see a live network traffic feed
with protocol-level details (TCP, UDP, ICMP, ARP).
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether, Raw
import time
from collections import defaultdict
import threading

# Protocol statistics counters
proto_stats = defaultdict(int)
proto_stats_lock = threading.Lock()

# Total bytes captured per protocol
proto_bytes = defaultdict(int)


def parse_packet(packet):
    """
    Parse a raw Scapy packet into a structured dict for the dashboard.
    Returns a dict with protocol details or None if uninteresting.
    """
    info = {
        "time": time.strftime("%H:%M:%S"),
        "proto": "OTHER",
        "src": "-",
        "dst": "-",
        "sport": "-",
        "dport": "-",
        "length": len(packet),
        "flags": "-",
        "info": "",
        "color": "muted"
    }

    # ── ARP ──────────────────────────────────────────────────────
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op_name = "Request" if arp.op == 1 else "Reply"
        info.update({
            "proto": "ARP",
            "src": arp.psrc or "-",
            "dst": arp.pdst or "-",
            "info": f"ARP {op_name}: {arp.hwsrc} → {arp.hwdst}",
            "color": "purple"
        })
        with proto_stats_lock:
            proto_stats["ARP"] += 1
            proto_bytes["ARP"] += info["length"]
        return info

    # ── IP layer ─────────────────────────────────────────────────
    if not packet.haslayer(IP):
        return None  # skip non-IP, non-ARP packets

    ip = packet[IP]
    info["src"] = ip.src
    info["dst"] = ip.dst
    info["length"] = ip.len

    # ── TCP ──────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags_map = {
            0x01: "FIN", 0x02: "SYN", 0x04: "RST",
            0x08: "PSH", 0x10: "ACK", 0x20: "URG",
            0x12: "SYN-ACK", 0x11: "FIN-ACK", 0x18: "PSH-ACK",
        }
        flag_str = flags_map.get(int(tcp.flags), str(tcp.flags))

        # Infer application layer
        app = _infer_app(tcp.sport, tcp.dport)

        info.update({
            "proto": "TCP",
            "sport": str(tcp.sport),
            "dport": str(tcp.dport),
            "flags": flag_str,
            "info": f"{app} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack}",
            "color": "blue"
        })
        with proto_stats_lock:
            proto_stats["TCP"] += 1
            proto_bytes["TCP"] += info["length"]
        return info

    # ── UDP ──────────────────────────────────────────────────────
    if packet.haslayer(UDP):
        udp = packet[UDP]
        app = _infer_app(udp.sport, udp.dport)
        info.update({
            "proto": "UDP",
            "sport": str(udp.sport),
            "dport": str(udp.dport),
            "flags": "-",
            "info": f"{app} Len={udp.len}",
            "color": "green"
        })
        with proto_stats_lock:
            proto_stats["UDP"] += 1
            proto_bytes["UDP"] += info["length"]
        return info

    # ── ICMP ─────────────────────────────────────────────────────
    if packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {
            0: "Echo Reply", 3: "Dest Unreachable",
            5: "Redirect ⚠️", 8: "Echo Request",
            11: "Time Exceeded"
        }
        type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
        info.update({
            "proto": "ICMP",
            "info": f"{type_name} (code={icmp.code})",
            "color": "yellow"
        })
        with proto_stats_lock:
            proto_stats["ICMP"] += 1
            proto_bytes["ICMP"] += info["length"]
        return info

    return None


def _infer_app(sport, dport):
    """Map well-known ports to application names."""
    port_map = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
        23: "Telnet", 25: "SMTP", 53: "DNS", 110: "POP3",
        143: "IMAP", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        67: "DHCP", 68: "DHCP", 123: "NTP",
        4444: "Metasploit⚠️", 31337: "BackOrifice⚠️", 12345: "NetBus⚠️"
    }
    return port_map.get(dport) or port_map.get(sport) or f"Port {sport}→{dport}"


def get_proto_stats():
    """Return a snapshot of protocol statistics."""
    with proto_stats_lock:
        return {
            "counts": dict(proto_stats),
            "bytes": dict(proto_bytes)
        }


def start_packet_capture(interface=None, socketio=None, max_rate=30, stop_event=None):
    """
    Start live packet capture and emit each packet to the dashboard.

    Args:
        interface: Network interface to capture on (None = default)
        socketio: Flask-SocketIO instance for emitting events
        max_rate: Max packets per second to emit to avoid flooding the UI
        stop_event: threading.Event — when set, the sniffer exits cleanly.
    """
    print(f"[Packet Capture] Starting live capture on: {interface or 'default'}")
    last_emit = [0.0]
    packet_buffer = []
    EMIT_INTERVAL = 1.0 / max_rate  # seconds between emits

    def handle_packet(pkt):
        parsed = parse_packet(pkt)
        if parsed is None:
            return

        now = time.time()
        packet_buffer.append(parsed)

        # Rate-limit emissions to avoid flooding the browser
        if now - last_emit[0] >= EMIT_INTERVAL:
            if socketio:
                # Emit up to 5 buffered packets at once
                for p in packet_buffer[-5:]:
                    socketio.emit('live_packet', p)
                # Also emit updated protocol stats every ~1s
                if int(now) != int(last_emit[0]):
                    socketio.emit('proto_stats', get_proto_stats())
            last_emit[0] = now
            packet_buffer.clear()

    while not (stop_event and stop_event.is_set()):
        sniff(
            iface=interface,
            prn=handle_packet,
            store=False,
            filter="ip or arp",
            timeout=1   # Re-checks stop_event every second
        )
    print("[Packet Capture] Stopped.")

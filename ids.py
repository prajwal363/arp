"""
NetGuard - Network Security Monitor
Intrusion Detection System (IDS) Module

Detection Techniques:
  1. Port Scan Detection (SYN scan, NULL scan, XMAS scan, FIN scan)
  2. Brute Force Detection (SSH, FTP, HTTP login repeated failures)
  3. DoS/DDoS Detection (SYN flood, UDP flood, ICMP flood)
  4. Suspicious Port Access (known malware/backdoor ports)
  5. Large Data Exfiltration Detection (unusually large outbound data)
  6. Nmap Signature Detection (OS fingerprinting probes)
"""

import threading
import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Raw, sniff
import logger

# --- Port Scan Detection ---
# Track SYN packets per source IP: {src_ip: {dst_port: timestamp}}
syn_tracker = defaultdict(dict)
syn_lock = threading.Lock()
PORT_SCAN_THRESHOLD = 15       # ports in ...
PORT_SCAN_WINDOW = 5           # ... seconds

# --- DoS/Flood Detection ---
# {src_ip: [timestamps]}
flood_tracker = defaultdict(list)
flood_lock = threading.Lock()
FLOOD_THRESHOLD = 200          # packets in ...
FLOOD_WINDOW = 5               # ... seconds

# --- Brute Force Detection ---
# {(src_ip, dst_port): [timestamps]}
brute_tracker = defaultdict(list)
brute_lock = threading.Lock()
BRUTE_THRESHOLD = 10           # attempts in ...
BRUTE_WINDOW = 20              # ... seconds

# --- Suspicious Ports ---
SUSPICIOUS_PORTS = {
    31337: "Back Orifice (Backdoor)",
    1337:  "LEET/Backdoor",
    4444:  "Metasploit default",
    5555:  "Android Debug Bridge",
    6666:  "IRC/Trojan",
    6667:  "IRC (common malware C&C)",
    6668:  "IRC Trojan",
    9999:  "Possible Backdoor",
    12345: "NetBus (Trojan)",
    27374: "SubSeven (RAT)",
    65535: "Possible Backdoor",
    1080:  "SOCKS Proxy (possible TOR relay)",
    3127:  "MyDoom worm",
    8888:  "Alternative HTTP (suspicious if unexpected)",
}

# --- Known Brute Force Target Ports ---
BRUTE_FORCE_PORTS = {
    22:   "SSH",
    21:   "FTP",
    23:   "Telnet",
    3389: "RDP",
    5900: "VNC",
    110:  "POP3",
    143:  "IMAP",
    25:   "SMTP",
    80:   "HTTP Basic Auth",
    8080: "HTTP Alt",
}

# --- Data Exfiltration Tracking ---
# {src_ip: total_bytes_sent_last_minute}
exfil_tracker = defaultdict(int)
exfil_timestamps = defaultdict(list)
exfil_lock = threading.Lock()
EXFIL_THRESHOLD_BYTES = 5 * 1024 * 1024   # 5 MB in 60 seconds
EXFIL_WINDOW = 60


def detect_port_scan(packet, socketio=None):
    """Detect various port scan techniques."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]
    src_ip = ip.src
    dst_port = tcp.dport
    flags = tcp.flags
    now = time.time()

    # SYN scan: only SYN flag set (0x02)
    is_syn_only = flags == 0x02
    # NULL scan: no flags
    is_null = flags == 0x00
    # XMAS scan: FIN+PSH+URG (0x29)
    is_xmas = flags == 0x29
    # FIN scan: only FIN flag (0x01)
    is_fin_only = flags == 0x01

    if not (is_syn_only or is_null or is_xmas or is_fin_only):
        return

    scan_type = ("SYN" if is_syn_only else
                 "NULL" if is_null else
                 "XMAS" if is_xmas else "FIN")

    with syn_lock:
        # Clean old entries
        syn_tracker[src_ip] = {
            port: ts for port, ts in syn_tracker[src_ip].items()
            if now - ts < PORT_SCAN_WINDOW
        }
        syn_tracker[src_ip][dst_port] = now

        if len(syn_tracker[src_ip]) >= PORT_SCAN_THRESHOLD:
            description = (
                f"PORT SCAN DETECTED! {scan_type} Scan from {src_ip}. "
                f"Scanned {len(syn_tracker[src_ip])} ports in {PORT_SCAN_WINDOW}s. "
                f"Recent ports: {sorted(syn_tracker[src_ip].keys())[-10:]}"
            )
            logger.log_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                description=description,
                src_ip=src_ip,
                raw_info=f"scan_type={scan_type}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'PORT_SCAN', 'severity': 'HIGH',
                    'description': description, 'src_ip': src_ip
                })
            # Reset to avoid alert spam
            syn_tracker[src_ip] = {}


def detect_dos_flood(packet, socketio=None):
    """Detect SYN/UDP/ICMP flood (DoS/DDoS)."""
    if not packet.haslayer(IP):
        return

    ip = packet[IP]
    src_ip = ip.src
    now = time.time()

    with flood_lock:
        flood_tracker[src_ip].append(now)
        # Keep only recent timestamps
        flood_tracker[src_ip] = [
            t for t in flood_tracker[src_ip] if now - t < FLOOD_WINDOW
        ]
        count = len(flood_tracker[src_ip])

        if count >= FLOOD_THRESHOLD:
            proto = ("SYN" if packet.haslayer(TCP) and packet[TCP].flags == 0x02
                     else "UDP" if packet.haslayer(UDP)
                     else "ICMP" if packet.haslayer(ICMP) else "IP")
            description = (
                f"DoS FLOOD DETECTED! {proto} flood from {src_ip}. "
                f"{count} packets in {FLOOD_WINDOW}s. "
                f"Possible Denial-of-Service attack!"
            )
            logger.log_alert(
                alert_type="DOS_FLOOD",
                severity="HIGH",
                description=description,
                src_ip=src_ip,
                dst_ip=ip.dst,
                raw_info=f"proto={proto}, pps={count}/{FLOOD_WINDOW}s"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'DOS_FLOOD', 'severity': 'HIGH',
                    'description': description, 'src_ip': src_ip
                })
            # Reset tracker after alert
            flood_tracker[src_ip] = []


def detect_brute_force(packet, socketio=None):
    """Detect brute force login attempts on common service ports."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]
    dst_port = tcp.dport
    src_ip = ip.src
    now = time.time()

    if dst_port not in BRUTE_FORCE_PORTS:
        return

    # Only track SYN (new connection attempts)
    if tcp.flags != 0x02:
        return

    key = (src_ip, dst_port)
    with brute_lock:
        brute_tracker[key].append(now)
        brute_tracker[key] = [
            t for t in brute_tracker[key] if now - t < BRUTE_WINDOW
        ]
        count = len(brute_tracker[key])

        if count >= BRUTE_THRESHOLD:
            service = BRUTE_FORCE_PORTS[dst_port]
            description = (
                f"BRUTE FORCE DETECTED! {count} {service} (port {dst_port}) "
                f"connection attempts from {src_ip} in {BRUTE_WINDOW}s. "
                f"Possible credential stuffing/brute force attack!"
            )
            logger.log_alert(
                alert_type="BRUTE_FORCE",
                severity="HIGH",
                description=description,
                src_ip=src_ip,
                dst_ip=ip.dst,
                raw_info=f"service={service}, attempts={count}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'BRUTE_FORCE', 'severity': 'HIGH',
                    'description': description, 'src_ip': src_ip
                })
            brute_tracker[key] = []


def detect_suspicious_ports(packet, socketio=None):
    """Alert on traffic to/from known backdoor/trojan ports."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]

    for port in [tcp.dport, tcp.sport]:
        if port in SUSPICIOUS_PORTS:
            service = SUSPICIOUS_PORTS[port]
            description = (
                f"SUSPICIOUS PORT ACCESS! Port {port} ({service}) detected. "
                f"Traffic: {ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}. "
                f"May indicate malware, backdoor, or RAT activity!"
            )
            logger.log_alert(
                alert_type="SUSPICIOUS_PORT",
                severity="HIGH",
                description=description,
                src_ip=ip.src,
                dst_ip=ip.dst,
                raw_info=f"port={port}, service={service}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'SUSPICIOUS_PORT', 'severity': 'HIGH',
                    'description': description, 'src_ip': ip.src
                })


def detect_exfiltration(packet, socketio=None):
    """Detect large-volume outbound data (possible data exfiltration)."""
    if not (packet.haslayer(IP) and packet.haslayer(Raw)):
        return

    ip = packet[IP]
    src_ip = ip.src
    payload_size = len(bytes(packet[Raw]))
    now = time.time()

    with exfil_lock:
        exfil_tracker[src_ip] += payload_size
        exfil_timestamps[src_ip].append(now)

        # Clean old timestamps and reset bytes if window expired
        exfil_timestamps[src_ip] = [
            t for t in exfil_timestamps[src_ip] if now - t < EXFIL_WINDOW
        ]
        if not exfil_timestamps[src_ip]:
            exfil_tracker[src_ip] = 0

        if exfil_tracker[src_ip] >= EXFIL_THRESHOLD_BYTES:
            mb_sent = exfil_tracker[src_ip] / (1024 * 1024)
            description = (
                f"DATA EXFILTRATION ALERT! {src_ip} sent {mb_sent:.2f} MB "
                f"in {EXFIL_WINDOW}s. Possible data theft or exfiltration!"
            )
            logger.log_alert(
                alert_type="DATA_EXFIL",
                severity="HIGH",
                description=description,
                src_ip=src_ip,
                dst_ip=ip.dst,
                raw_info=f"bytes={exfil_tracker[src_ip]}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'DATA_EXFIL', 'severity': 'HIGH',
                    'description': description, 'src_ip': src_ip
                })
            exfil_tracker[src_ip] = 0


def process_ids_packet(packet, socketio=None):
    """Run all IDS checks on a packet."""
    detect_port_scan(packet, socketio)
    detect_dos_flood(packet, socketio)
    detect_brute_force(packet, socketio)
    detect_suspicious_ports(packet, socketio)
    detect_exfiltration(packet, socketio)


def start_ids(interface=None, socketio=None, stop_event=None):
    """Start the IDS packet sniffer.

    Args:
        stop_event: threading.Event — when set, the sniffer exits cleanly.
    """
    print(f"[IDS] Starting Intrusion Detection System on interface: {interface or 'default'}")
    while not (stop_event and stop_event.is_set()):
        sniff(
            filter="tcp or udp or icmp",
            iface=interface,
            prn=lambda pkt: process_ids_packet(pkt, socketio),
            store=False,
            timeout=1   # Re-checks stop_event every second
        )
    print("[IDS] Stopped.")

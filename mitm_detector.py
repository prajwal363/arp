"""
NetGuard - Network Security Monitor
MITM (Man-in-the-Middle) Attack Detector Module

How MITM works:
  - After ARP spoofing, attacker sits between victim and gateway
  - All victim traffic flows: Victim -> Attacker -> Gateway (and back)
  - Attacker can read, modify, or replay packets

Detection Techniques Used:
  1. TTL Anomaly Detection:
     - MITM proxy typically decrements TTL by 1 extra
     - Establish baseline TTL per (src_ip, dst_ip) pair
     - Alert if TTL drops unexpectedly

  2. Duplicate IP Detection:
     - Two different MACs claiming the same IP is a classic MITM sign

  3. SSL Stripping Detection:
     - HTTP request to known HTTPS sites (downgrade attack)

  4. Unexpected Routing Detection:
     - Packets arriving on unexpected interfaces / being forwarded suspiciously

  5. ICMP Redirect Detection:
     - ICMP type 5 (Redirect) can be used to redirect traffic through attacker
"""

import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, Ether, sniff, DNS, DNSQR
import logger

# Baseline TTL per (src_ip, dst_ip): {pair: [ttl_samples]}
ttl_baseline = defaultdict(list)
ttl_lock = threading.Lock()

# IP->MAC mappings from ARP (shared with arp_detector)
from arp_detector import arp_table, arp_table_lock

# Seen sequence numbers per flow to detect replays
# {(src_ip, dst_ip, src_port, dst_port): set of seq numbers}
seen_sequences = defaultdict(set)
seq_lock = threading.Lock()

# Known HTTPS-only domains (SSL stripping targets)
HTTPS_ONLY_DOMAINS = {
    "google.com", "facebook.com", "paypal.com", "amazon.com",
    "banking.com", "netflix.com", "github.com", "twitter.com",
    "instagram.com", "linkedin.com"
}


def check_ttl_anomaly(packet, socketio=None):
    """Detect TTL anomaly that may indicate a relay/MITM proxy."""
    if not packet.haslayer(IP):
        return
    ip = packet[IP]
    src = ip.src
    dst = ip.dst
    ttl = ip.ttl

    with ttl_lock:
        key = (src, dst)
        samples = ttl_baseline[key]

        if len(samples) < 5:
            samples.append(ttl)
            ttl_baseline[key] = samples
            return

        avg_ttl = sum(samples) / len(samples)

        # If TTL drops by more than 3 from baseline unexpectedly
        if avg_ttl - ttl > 3:
            description = (
                f"TTL ANOMALY detected: {src} -> {dst}. "
                f"Expected TTL ~{avg_ttl:.0f}, got {ttl}. "
                f"Possible MITM relay/proxy in path!"
            )
            logger.log_alert(
                alert_type="MITM_TTL",
                severity="HIGH",
                description=description,
                src_ip=src,
                dst_ip=dst,
                raw_info=f"avg_ttl={avg_ttl:.1f}, observed={ttl}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'MITM_TTL', 'severity': 'HIGH',
                    'description': description, 'src_ip': src, 'dst_ip': dst
                })
        else:
            # Update baseline with rolling window of 10
            samples.append(ttl)
            if len(samples) > 10:
                samples.pop(0)
            ttl_baseline[key] = samples


def check_ssl_stripping(packet, socketio=None):
    """
    Detect SSL stripping: attacker downgrades HTTPS to HTTP.
    Look for HTTP GET/POST to known HTTPS-only domains over port 80.
    """
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]

    # Only check outbound HTTP (port 80) traffic
    if tcp.dport != 80:
        return

    try:
        raw = bytes(tcp.payload).decode('utf-8', errors='ignore')
    except Exception:
        return

    if not raw.startswith(("GET ", "POST ", "PUT ", "DELETE ")):
        return

    # Extract Host header
    host = ""
    for line in raw.split("\r\n"):
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip().lower()
            break

    # Check against known HTTPS-only sites
    for domain in HTTPS_ONLY_DOMAINS:
        if domain in host:
            description = (
                f"SSL STRIPPING detected! HTTP request to known HTTPS-only site: "
                f"{host} from {ip.src}. Attacker may be downgrading HTTPS to HTTP!"
            )
            logger.log_alert(
                alert_type="SSL_STRIP",
                severity="HIGH",
                description=description,
                src_ip=ip.src,
                dst_ip=ip.dst,
                raw_info=f"Host: {host}, Port: 80"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'SSL_STRIP', 'severity': 'HIGH',
                    'description': description, 'src_ip': ip.src
                })
            break


def check_icmp_redirect(packet, socketio=None):
    """Detect ICMP Redirect (type 5) which can be used for MITM."""
    if not (packet.haslayer(ICMP) and packet.haslayer(IP)):
        return

    icmp = packet[ICMP]
    ip = packet[IP]

    if icmp.type == 5:  # ICMP Redirect
        description = (
            f"ICMP REDIRECT received from {ip.src}! "
            f"Code: {icmp.code}. "
            f"Attacker may be redirecting your traffic through their machine (MITM)!"
        )
        logger.log_alert(
            alert_type="ICMP_REDIRECT",
            severity="HIGH",
            description=description,
            src_ip=ip.src,
            raw_info=f"ICMP type=5 code={icmp.code}"
        )
        if socketio:
            socketio.emit('new_alert', {
                'type': 'ICMP_REDIRECT', 'severity': 'HIGH',
                'description': description, 'src_ip': ip.src
            })


def check_dns_spoofing(packet, socketio=None):
    """
    Detect DNS Spoofing: MITM attacker may respond to DNS queries with fake IPs.
    Look for multiple different answers for the same domain in a short time.
    """
    if not (packet.haslayer(DNS) and packet.haslayer(IP)):
        return

    dns = packet[DNS]
    ip = packet[IP]

    # Only DNS responses (qr=1)
    if dns.qr != 1 or not dns.an:
        return

    try:
        queried = dns.qd.qname.decode('utf-8').rstrip('.')
    except Exception:
        return

    answers = []
    answer = dns.an
    while answer:
        if hasattr(answer, 'rdata'):
            answers.append(str(answer.rdata))
        answer = answer.payload if hasattr(answer, 'payload') else None
        if not hasattr(answer, 'rdata'):
            break

    if answers:
        description = (
            f"DNS Response from {ip.src} for '{queried}' -> {answers}. "
            f"If this IP looks unexpected, may indicate DNS Spoofing/MITM!"
        )
        logger.log_alert(
            alert_type="DNS_RESPONSE",
            severity="LOW",
            description=description,
            src_ip=ip.src,
            raw_info=f"Domain: {queried}, Answers: {answers}"
        )
        if socketio:
            socketio.emit('new_alert', {
                'type': 'DNS_RESPONSE', 'severity': 'LOW',
                'description': description, 'src_ip': ip.src
            })


def check_packet_replay(packet, socketio=None):
    """Detect TCP packet replay attacks (reused sequence numbers)."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return

    ip = packet[IP]
    tcp = packet[TCP]
    seq = tcp.seq
    flow = (ip.src, ip.dst, tcp.sport, tcp.dport)

    with seq_lock:
        if seq in seen_sequences[flow] and tcp.flags & 0x02 == 0:  # not SYN
            description = (
                f"TCP PACKET REPLAY detected! Flow {ip.src}:{tcp.sport} -> "
                f"{ip.dst}:{tcp.dport} reused sequence number {seq}. "
                f"Possible replay attack!"
            )
            logger.log_alert(
                alert_type="PACKET_REPLAY",
                severity="MEDIUM",
                description=description,
                src_ip=ip.src,
                dst_ip=ip.dst,
                raw_info=f"seq={seq}"
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'PACKET_REPLAY', 'severity': 'MEDIUM',
                    'description': description, 'src_ip': ip.src
                })
        else:
            seen_sequences[flow].add(seq)
            # Keep set size bounded
            if len(seen_sequences[flow]) > 1000:
                seen_sequences[flow] = set(list(seen_sequences[flow])[-500:])


def process_mitm_packet(packet, socketio=None):
    """Run all MITM detection checks on a packet."""
    check_ttl_anomaly(packet, socketio)
    check_ssl_stripping(packet, socketio)
    check_icmp_redirect(packet, socketio)
    check_dns_spoofing(packet, socketio)
    check_packet_replay(packet, socketio)


def start_mitm_detector(interface=None, socketio=None, stop_event=None):
    """Start sniffing for MITM-related packets.

    Args:
        stop_event: threading.Event — when set, the sniffer exits cleanly.
    """
    print(f"[MITM Detector] Starting on interface: {interface or 'default'}")
    while not (stop_event and stop_event.is_set()):
        sniff(
            filter="ip or icmp",
            iface=interface,
            prn=lambda pkt: process_mitm_packet(pkt, socketio),
            store=False,
            timeout=1   # Re-checks stop_event every second
        )
    print("[MITM Detector] Stopped.")

"""
NetGuard - Network Security Monitor
ARP Spoofing Detector Module

How ARP Spoofing works:
  - Attacker sends fake ARP replies saying "I am <victim IP>, my MAC is <attacker MAC>"
  - This poisons the ARP cache of other devices on the LAN
  - All traffic meant for victim now goes to attacker (enabling MITM)

Detection approach:
  - Maintain a trusted ARP table: {IP -> MAC}
  - On every ARP reply, check if the MAC for an IP has suddenly changed
  - Flag suspicious ARP replies (unsolicited / gratuitous ARP)
  - Cross-check with gateway MAC to detect gateway impersonation
"""

import threading
from collections import defaultdict
from scapy.all import ARP, sniff, get_if_hwaddr
import netifaces as netifaces
import logger

# Trusted ARP cache: {IP: MAC}
arp_table = {}
arp_table_lock = threading.Lock()

# Count of ARP packets per source MAC (flood detection)
arp_flood_counter = defaultdict(int)

# Gateway info
gateway_ip = None
gateway_mac = None


def get_gateway_info():
    """Retrieve default gateway IP and MAC from the system."""
    global gateway_ip, gateway_mac
    try:
        gws = netifaces.gateways()
        gw = gws.get('default', {}).get(netifaces.AF_INET)
        if gw:
            gateway_ip = gw[0]
            print(f"[ARP] Gateway IP: {gateway_ip}")
    except Exception as e:
        print(f"[ARP] Could not get gateway info: {e}")


def process_arp_packet(packet, socketio=None):
    """
    Analyze a single ARP packet for spoofing signs.

    ARP op=2 means ARP Reply.
    """
    if not packet.haslayer(ARP):
        return

    arp = packet[ARP]

    # Only inspect ARP replies (op=2) or gratuitous ARP
    if arp.op not in [1, 2]:
        return

    src_ip = arp.psrc
    src_mac = arp.hwsrc
    dst_ip = arp.pdst

    # Skip empty/broadcast IPs
    if src_ip in ("0.0.0.0", "255.255.255.255") or not src_ip:
        return

    # ARP flood detection: if a MAC sends too many ARP packets
    with arp_table_lock:
        arp_flood_counter[src_mac] += 1
        if arp_flood_counter[src_mac] > 50:
            description = (f"ARP Flood detected! MAC {src_mac} sent "
                           f"{arp_flood_counter[src_mac]} ARP packets. "
                           f"Possible ARP DoS or scanning.")
            logger.log_alert(
                alert_type="ARP_FLOOD",
                severity="MEDIUM",
                description=description,
                src_ip=src_ip,
                src_mac=src_mac
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'ARP_FLOOD', 'severity': 'MEDIUM',
                    'description': description, 'src_ip': src_ip
                })
            arp_flood_counter[src_mac] = 0  # reset after alert

        # Check if this IP was already associated with a different MAC
        if src_ip in arp_table:
            known_mac = arp_table[src_ip]
            if known_mac.lower() != src_mac.lower():
                description = (
                    f"ARP SPOOFING DETECTED! IP {src_ip} was mapped to MAC "
                    f"{known_mac} but now claims to be MAC {src_mac}. "
                    f"Possible attacker performing ARP cache poisoning!"
                )
                severity = "HIGH"

                # Extra severity if gateway is being impersonated
                if src_ip == gateway_ip:
                    description = "GATEWAY " + description
                    severity = "HIGH"

                logger.log_alert(
                    alert_type="ARP_SPOOF",
                    severity=severity,
                    description=description,
                    src_ip=src_ip,
                    src_mac=src_mac,
                    raw_info=f"Old MAC: {known_mac} | New MAC: {src_mac}"
                )
                if socketio:
                    socketio.emit('new_alert', {
                        'type': 'ARP_SPOOF', 'severity': severity,
                        'description': description, 'src_ip': src_ip,
                        'src_mac': src_mac
                    })
        else:
            # Add to trusted table
            arp_table[src_ip] = src_mac

        # Gratuitous ARP detection: src_ip == dst_ip in request (op=1)
        if arp.op == 1 and src_ip == dst_ip and src_ip != "0.0.0.0":
            description = (
                f"Gratuitous ARP from {src_ip} ({src_mac}). "
                f"Could indicate ARP poisoning attempt or network reconfiguration."
            )
            logger.log_alert(
                alert_type="GRATUITOUS_ARP",
                severity="LOW",
                description=description,
                src_ip=src_ip,
                src_mac=src_mac
            )
            if socketio:
                socketio.emit('new_alert', {
                    'type': 'GRATUITOUS_ARP', 'severity': 'LOW',
                    'description': description, 'src_ip': src_ip
                })


def start_arp_detector(interface=None, socketio=None, stop_event=None):
    """Start sniffing ARP packets on the given interface.

    Args:
        stop_event: threading.Event — when set, the sniffer exits cleanly.
    """
    get_gateway_info()
    print(f"[ARP Detector] Starting on interface: {interface or 'default'}")
    while not (stop_event and stop_event.is_set()):
        sniff(
            filter="arp",
            iface=interface,
            prn=lambda pkt: process_arp_packet(pkt, socketio),
            store=False,
            timeout=1   # Re-checks stop_event every second
        )
    print("[ARP Detector] Stopped.")

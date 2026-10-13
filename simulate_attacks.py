"""
NetGuard - Attack Simulator (for testing without real network attacks)
Run this SEPARATELY to generate fake alerts into the database for UI testing.

Usage:
    python simulate_attacks.py
"""

import time
import random
import logger

logger.init_db()

ATTACK_SCENARIOS = [
    {
        "alert_type": "ARP_SPOOF",
        "severity": "HIGH",
        "src_ip": "192.168.1.1",
        "dst_ip": None,
        "src_mac": "aa:bb:cc:dd:ee:ff",
        "description": "ARP SPOOFING DETECTED! IP 192.168.1.1 was mapped to MAC 00:11:22:33:44:55 but now claims to be MAC aa:bb:cc:dd:ee:ff. Possible attacker performing ARP cache poisoning!",
        "raw_info": "Old MAC: 00:11:22:33:44:55 | New MAC: aa:bb:cc:dd:ee:ff"
    },
    {
        "alert_type": "MITM_TTL",
        "severity": "HIGH",
        "src_ip": "192.168.1.105",
        "dst_ip": "8.8.8.8",
        "description": "TTL ANOMALY detected: 192.168.1.105 -> 8.8.8.8. Expected TTL ~64, got 58. Possible MITM relay/proxy in path!",
        "raw_info": "avg_ttl=64.0, observed=58"
    },
    {
        "alert_type": "PORT_SCAN",
        "severity": "HIGH",
        "src_ip": "10.0.0.55",
        "dst_ip": None,
        "description": "PORT SCAN DETECTED! SYN Scan from 10.0.0.55. Scanned 20 ports in 5s. Recent ports: [21, 22, 23, 25, 80, 443, 3306, 3389, 5900, 8080]",
        "raw_info": "scan_type=SYN"
    },
    {
        "alert_type": "SSL_STRIP",
        "severity": "HIGH",
        "src_ip": "192.168.1.200",
        "dst_ip": "172.217.14.110",
        "description": "SSL STRIPPING detected! HTTP request to known HTTPS-only site: google.com from 192.168.1.200. Attacker may be downgrading HTTPS to HTTP!",
        "raw_info": "Host: google.com, Port: 80"
    },
    {
        "alert_type": "BRUTE_FORCE",
        "severity": "HIGH",
        "src_ip": "10.0.0.99",
        "dst_ip": "192.168.1.10",
        "description": "BRUTE FORCE DETECTED! 15 SSH (port 22) connection attempts from 10.0.0.99 in 20s. Possible credential stuffing/brute force attack!",
        "raw_info": "service=SSH, attempts=15"
    },
    {
        "alert_type": "ICMP_REDIRECT",
        "severity": "HIGH",
        "src_ip": "192.168.1.1",
        "description": "ICMP REDIRECT received from 192.168.1.1! Code: 1. Attacker may be redirecting your traffic through their machine (MITM)!",
        "raw_info": "ICMP type=5 code=1"
    },
    {
        "alert_type": "DOS_FLOOD",
        "severity": "HIGH",
        "src_ip": "10.10.10.10",
        "dst_ip": "192.168.1.10",
        "description": "DoS FLOOD DETECTED! SYN flood from 10.10.10.10. 250 packets in 5s. Possible Denial-of-Service attack!",
        "raw_info": "proto=SYN, pps=250/5s"
    },
    {
        "alert_type": "SUSPICIOUS_PORT",
        "severity": "HIGH",
        "src_ip": "192.168.1.77",
        "dst_ip": "192.168.1.10",
        "description": "SUSPICIOUS PORT ACCESS! Port 4444 (Metasploit default) detected. Traffic: 192.168.1.77:52341 -> 192.168.1.10:4444. May indicate malware, backdoor, or RAT activity!",
        "raw_info": "port=4444, service=Metasploit default"
    },
    {
        "alert_type": "ARP_FLOOD",
        "severity": "MEDIUM",
        "src_ip": "192.168.1.88",
        "src_mac": "de:ad:be:ef:ca:fe",
        "description": "ARP Flood detected! MAC de:ad:be:ef:ca:fe sent 60 ARP packets. Possible ARP DoS or scanning.",
        "raw_info": None
    },
    {
        "alert_type": "GRATUITOUS_ARP",
        "severity": "LOW",
        "src_ip": "192.168.1.5",
        "src_mac": "11:22:33:44:55:66",
        "description": "Gratuitous ARP from 192.168.1.5 (11:22:33:44:55:66). Could indicate ARP poisoning attempt or network reconfiguration.",
        "raw_info": None
    },
    {
        "alert_type": "PACKET_REPLAY",
        "severity": "MEDIUM",
        "src_ip": "192.168.1.150",
        "dst_ip": "192.168.1.1",
        "description": "TCP PACKET REPLAY detected! Flow 192.168.1.150:44321 -> 192.168.1.1:80 reused sequence number 1234567890. Possible replay attack!",
        "raw_info": "seq=1234567890"
    },
    {
        "alert_type": "DATA_EXFIL",
        "severity": "HIGH",
        "src_ip": "192.168.1.200",
        "dst_ip": "185.45.67.89",
        "description": "DATA EXFILTRATION ALERT! 192.168.1.200 sent 5.30 MB in 60s. Possible data theft or exfiltration!",
        "raw_info": "bytes=5558272"
    },
]


def simulate():
    print("[Simulator] Injecting test alerts into database...")
    print("[Simulator] Open http://127.0.0.1:5000 to view the dashboard\n")

    for i, scenario in enumerate(ATTACK_SCENARIOS):
        logger.log_alert(
            alert_type=scenario["alert_type"],
            severity=scenario["severity"],
            description=scenario["description"],
            src_ip=scenario.get("src_ip"),
            dst_ip=scenario.get("dst_ip"),
            src_mac=scenario.get("src_mac"),
            dst_mac=scenario.get("dst_mac"),
            raw_info=scenario.get("raw_info")
        )
        print(f"  [{i+1}/{len(ATTACK_SCENARIOS)}] Injected: {scenario['alert_type']}")
        time.sleep(0.3)

    print(f"\n[Simulator] Done! {len(ATTACK_SCENARIOS)} test alerts injected.")
    print("[Simulator] Refresh the dashboard to see them.")


if __name__ == '__main__':
    simulate()

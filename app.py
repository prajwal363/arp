"""
NetGuard - Network Security Monitor
Main Application - Flask + SocketIO Web Dashboard
"""

import threading
import os
import platform
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import logger
import arp_detector
import mitm_detector
import ids
import packet_capture
import simulate_attacks

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netguard-secret-2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Store selected network interface
selected_interface = None
monitoring_active = False
monitor_threads = []
stop_event = threading.Event()   # Set this to cleanly stop all sniffers



# ─── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/alerts')
def get_alerts():
    limit = request.args.get('limit', 100, type=int)
    alerts = logger.get_all_alerts(limit=limit)
    return jsonify(alerts)


@app.route('/api/stats')
def get_stats():
    stats = logger.get_alert_stats()
    return jsonify(stats)


@app.route('/api/arp_table')
def get_arp_table():
    with arp_detector.arp_table_lock:
        table = dict(arp_detector.arp_table)
    return jsonify(table)


@app.route('/api/clear', methods=['POST'])
def clear_alerts():
    logger.clear_alerts()
    socketio.emit('alerts_cleared', {})
    return jsonify({'status': 'cleared'})


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    global monitoring_active, monitor_threads, selected_interface
    data = request.get_json() or {}
    iface = data.get('interface') or None
    selected_interface = iface

    if monitoring_active:
        return jsonify({'status': 'already_running'})

    monitoring_active = True

    # Start all detectors + live packet capture in daemon threads
    threads_config = [
        ("ARP Detector",    arp_detector.start_arp_detector,         {'interface': iface, 'socketio': socketio}),
        ("MITM Detector",   mitm_detector.start_mitm_detector,        {'interface': iface, 'socketio': socketio}),
        ("IDS",             ids.start_ids,                            {'interface': iface, 'socketio': socketio}),
        ("Packet Capture",  packet_capture.start_packet_capture,      {'interface': iface, 'socketio': socketio}),
    ]

    for name, func, kwargs in threads_config:
        t = threading.Thread(target=func, kwargs=kwargs, daemon=True, name=name)
        t.start()
        monitor_threads.append(t)
        print(f"[NetGuard] Started {name}")

    socketio.emit('monitoring_started', {'interface': iface or 'default'})
    return jsonify({'status': 'started', 'interface': iface or 'default'})


@app.route('/api/interfaces')
def get_interfaces():
    """Return list of available network interfaces."""
    try:
        import netifaces2 as netifaces
        ifaces = netifaces.interfaces()
        return jsonify(ifaces)
    except Exception:
        return jsonify([])


@app.route('/api/proto_stats')
def get_proto_stats():
    """Return live protocol statistics (TCP/UDP/ICMP/ARP counts)."""
    return jsonify(packet_capture.get_proto_stats())


@app.route('/api/demo/<attack_type>', methods=['POST'])
def demo_alert(attack_type):
    """
    Inject a single demo alert of the requested type and emit it via SocketIO.
    This lets you demonstrate any attack scenario without needing a real attack.

    Supported types: ARP_SPOOF, ARP_FLOOD, GRATUITOUS_ARP, MITM_TTL,
                     SSL_STRIP, ICMP_REDIRECT, DOS_FLOOD, BRUTE_FORCE,
                     PORT_SCAN, SUSPICIOUS_PORT, PACKET_REPLAY, DATA_EXFIL
    """
    attack_type = attack_type.upper()
    scenario = next(
        (s for s in simulate_attacks.ATTACK_SCENARIOS if s['alert_type'] == attack_type),
        None
    )
    if not scenario:
        return jsonify({'error': f'Unknown attack type: {attack_type}'}), 404

    logger.log_alert(
        alert_type=scenario['alert_type'],
        severity=scenario['severity'],
        description=scenario['description'],
        src_ip=scenario.get('src_ip'),
        dst_ip=scenario.get('dst_ip'),
        src_mac=scenario.get('src_mac'),
        dst_mac=scenario.get('dst_mac'),
        raw_info=scenario.get('raw_info')
    )
    # Push live to dashboard
    socketio.emit('new_alert', {
        'type': scenario['alert_type'],
        'severity': scenario['severity'],
        'description': scenario['description'],
        'src_ip': scenario.get('src_ip', ''),
        'dst_ip': scenario.get('dst_ip', '')
    })
    print(f"[Demo] Injected demo alert: {attack_type}")
    return jsonify({'status': 'injected', 'alert_type': attack_type})


@app.route('/api/demo/all', methods=['POST'])
def demo_all_alerts():
    """Inject all demo scenarios at once."""
    import time
    for scenario in simulate_attacks.ATTACK_SCENARIOS:
        logger.log_alert(
            alert_type=scenario['alert_type'],
            severity=scenario['severity'],
            description=scenario['description'],
            src_ip=scenario.get('src_ip'),
            dst_ip=scenario.get('dst_ip'),
            src_mac=scenario.get('src_mac'),
            dst_mac=scenario.get('dst_mac'),
            raw_info=scenario.get('raw_info')
        )
        socketio.emit('new_alert', {
            'type': scenario['alert_type'],
            'severity': scenario['severity'],
            'description': scenario['description'],
            'src_ip': scenario.get('src_ip', ''),
            'dst_ip': scenario.get('dst_ip', '')
        })
        time.sleep(0.2)
    return jsonify({'status': 'injected', 'count': len(simulate_attacks.ATTACK_SCENARIOS)})


@app.route('/api/modules')
def get_modules():
    """Return module info: functions and descriptions for the dashboard."""
    return jsonify({
        "ARP Detector": {
            "file": "arp_detector.py",
            "emoji": "🔍",
            "color": "#a371f7",
            "description": "Monitors ARP traffic to detect cache poisoning, spoofing, and flood attacks on the LAN.",
            "functions": [
                {
                    "name": "get_gateway_info()",
                    "desc": "Fetches default gateway IP using netifaces. Used to detect gateway impersonation (most dangerous form of ARP spoof)."
                },
                {
                    "name": "process_arp_packet(packet)",
                    "desc": "Main callback: inspects every ARP packet. Checks MAC-IP consistency, counts flood rate, and detects gratuitous ARP."
                },
                {
                    "name": "start_arp_detector(interface, socketio)",
                    "desc": "Starts Scapy sniff() with filter='arp'. Runs indefinitely in a daemon thread. Each ARP packet is passed to process_arp_packet()."
                }
            ],
            "detects": ["ARP_SPOOF", "ARP_FLOOD", "GRATUITOUS_ARP"]
        },
        "MITM Detector": {
            "file": "mitm_detector.py",
            "emoji": "🕵️",
            "color": "#f85149",
            "description": "Detects Man-in-the-Middle attacks by analyzing IP/ICMP/TCP traffic patterns, TTL changes, and DNS responses.",
            "functions": [
                {
                    "name": "check_ttl_anomaly(packet)",
                    "desc": "Builds a baseline TTL per (src→dst) pair from first 5 packets. Alerts if TTL drops >3 below baseline (indicates a relay/proxy in the path)."
                },
                {
                    "name": "check_ssl_stripping(packet)",
                    "desc": "Looks for HTTP GET/POST on port 80 with Host headers matching known HTTPS-only sites (Google, PayPal, etc.). Indicates SSL downgrade attack."
                },
                {
                    "name": "check_icmp_redirect(packet)",
                    "desc": "Detects ICMP Type 5 (Redirect) messages which attackers use to redirect victim traffic through their machine."
                },
                {
                    "name": "check_dns_spoofing(packet)",
                    "desc": "Captures all DNS responses (qr=1) and logs the resolved IPs. Suspicious if a domain resolves to an unexpected IP."
                },
                {
                    "name": "check_packet_replay(packet)",
                    "desc": "Tracks TCP sequence numbers per flow. If a sequence number is reused (and it's not a SYN), it's a replay attack."
                },
                {
                    "name": "start_mitm_detector(interface, socketio)",
                    "desc": "Starts Scapy sniff() with filter='ip or icmp'. Runs all 5 checks on every packet."
                }
            ],
            "detects": ["MITM_TTL", "SSL_STRIP", "ICMP_REDIRECT", "DNS_RESPONSE", "PACKET_REPLAY"]
        },
        "IDS": {
            "file": "ids.py",
            "emoji": "🚨",
            "color": "#f0883e",
            "description": "Intrusion Detection System that monitors TCP/UDP/ICMP traffic for port scans, brute force, DoS floods, and data exfiltration.",
            "functions": [
                {
                    "name": "detect_port_scan(packet)",
                    "desc": "Tracks SYN/NULL/XMAS/FIN packets per source IP. If ≥15 distinct ports are probed within 5s → PORT_SCAN alert."
                },
                {
                    "name": "detect_dos_flood(packet)",
                    "desc": "Counts all IP packets from each source IP within a 5s sliding window. If ≥200 packets → DoS FLOOD alert."
                },
                {
                    "name": "detect_brute_force(packet)",
                    "desc": "Tracks SYN packets to SSH(22), RDP(3389), FTP(21), Telnet(23) etc. If ≥10 attempts in 20s → BRUTE_FORCE alert."
                },
                {
                    "name": "detect_suspicious_ports(packet)",
                    "desc": "Checks every TCP packet's src/dst port against a known-malware port list (Metasploit:4444, BackOrifice:31337, NetBus:12345, etc.)."
                },
                {
                    "name": "detect_exfiltration(packet)",
                    "desc": "Sums outbound payload bytes per source IP in a 60s window. If >5MB is sent → DATA_EXFIL alert."
                },
                {
                    "name": "start_ids(interface, socketio)",
                    "desc": "Starts Scapy sniff() with filter='tcp or udp or icmp'. Runs all 5 IDS checks on every packet."
                }
            ],
            "detects": ["PORT_SCAN", "DOS_FLOOD", "BRUTE_FORCE", "SUSPICIOUS_PORT", "DATA_EXFIL"]
        },
        "Logger": {
            "file": "logger.py",
            "emoji": "🗄️",
            "color": "#58a6ff",
            "description": "SQLite-based alert persistence layer. All detectors call logger.log_alert() to save alerts with timestamp, severity, IPs, and raw info.",
            "functions": [
                {
                    "name": "init_db()",
                    "desc": "Creates the 'alerts' table in netguard.db if it doesn't exist. Called once at startup."
                },
                {
                    "name": "log_alert(alert_type, severity, description, ...)",
                    "desc": "Inserts one alert row into SQLite with timestamp, type, severity, src_ip, dst_ip, src_mac, description, and raw_info."
                },
                {
                    "name": "get_all_alerts(limit=200)",
                    "desc": "Fetches the latest N alerts from the DB ordered by newest first. Used by the /api/alerts endpoint."
                },
                {
                    "name": "get_alert_stats()",
                    "desc": "Returns counts grouped by alert_type and severity. Powers the stats cards and charts on the dashboard."
                },
                {
                    "name": "clear_alerts()",
                    "desc": "Deletes all rows from the alerts table. Triggered by the 'Clear Alerts' button."
                }
            ],
            "detects": []
        },
        "Packet Capture": {
            "file": "packet_capture.py",
            "emoji": "📡",
            "color": "#3fb950",
            "description": "Captures all network packets and streams them to the dashboard in real-time. Shows TCP, UDP, ICMP, ARP with protocol details.",
            "functions": [
                {
                    "name": "parse_packet(packet)",
                    "desc": "Converts a raw Scapy packet into a structured dict with protocol, src/dst IPs, ports, flags, and app-layer info."
                },
                {
                    "name": "_infer_app(sport, dport)",
                    "desc": "Maps well-known port numbers to application names (HTTP=80, SSH=22, DNS=53, Metasploit=4444, etc.)."
                },
                {
                    "name": "get_proto_stats()",
                    "desc": "Returns a snapshot of packet counts and byte totals per protocol (TCP/UDP/ICMP/ARP)."
                },
                {
                    "name": "start_packet_capture(interface, socketio)",
                    "desc": "Runs Scapy sniff() and emits each parsed packet as a 'live_packet' SocketIO event. Rate-limited to 30 packets/s to avoid UI overload."
                }
            ],
            "detects": []
        }
    })


# ─── SocketIO Events ──────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    print('[NetGuard] Dashboard client connected')
    socketio.emit('status', {
        'monitoring': monitoring_active,
        'interface': selected_interface or 'default'
    })


@socketio.on('disconnect')
def on_disconnect():
    print('[NetGuard] Dashboard client disconnected')


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    logger.init_db()
    print("=" * 60)
    print("  NetGuard - Network Security Monitor")
    print("  Detects: ARP Spoofing | MITM | Intrusion | Port Scan")
    print("=" * 60)
    print("  Dashboard: http://127.0.0.1:5000")
    print("  NOTE: Run as Administrator/root for packet capture!")
    print("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)

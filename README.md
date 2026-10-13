# 🛡️ NetGuard — Network Security Monitor
### Mini Project | 5th Sem CSE | Network Security

---

## 📌 Overview

**NetGuard** is a real-time network security monitoring tool that detects:

| Module | Detects |
|--------|---------|
| **ARP Spoof Detector** | ARP Cache Poisoning, Gratuitous ARP, ARP Flood |
| **MITM Detector** | TTL Anomaly, SSL Stripping, ICMP Redirect, DNS Spoofing, Packet Replay |
| **IDS** | Port Scan (SYN/NULL/XMAS/FIN), DoS Flood, Brute Force, Suspicious Ports, Data Exfiltration |

All alerts are displayed on a **real-time web dashboard** with live notifications.

---

## 🗂️ Project Structure

```
NetGuard/
├── app.py                  ← Flask + SocketIO main server
├── arp_detector.py         ← ARP Spoofing detection
├── mitm_detector.py        ← MITM attack detection
├── ids.py                  ← Intrusion Detection System
├── logger.py               ← SQLite alert logger
├── simulate_attacks.py     ← Test simulator (no real attacks needed)
├── requirements.txt        ← Dependencies
├── netguard.db             ← SQLite database (auto-created)
└── templates/
    └── dashboard.html      ← Web dashboard UI
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.9+
- **Npcap** (Windows) — required for Scapy packet capture
  - Download: https://npcap.com/#download
- Run as **Administrator** (required for raw packet capture)

### 1. Install dependencies
```bash
cd C:\Users\Hp\NetGuard
pip install -r requirements.txt
```

### 2. Start the dashboard server
```bash
# Run as Administrator!
python app.py
```

### 3. Open Dashboard
```
http://127.0.0.1:5000
```

### 4. Start Monitoring
- Select your network interface from the dropdown
- Click **▶ Start Monitoring**

---

## 🧪 Testing Without Real Attacks

Run the simulator to inject fake alerts and see the dashboard in action:
```bash
python simulate_attacks.py
```
Then refresh the dashboard — you'll see all attack types populated.

---

## 🔍 Detection Logic

### ARP Spoofing
- Maintains a trusted `{IP → MAC}` table
- Alerts when a MAC address changes for an existing IP
- Detects gratuitous ARP and ARP flood

### MITM Detection
- **TTL Anomaly**: Monitors TTL values; drops >3 from baseline = relay suspected
- **SSL Stripping**: HTTP traffic to known HTTPS-only domains flagged
- **ICMP Redirect** (Type 5): Traffic redirection attempt alert
- **DNS Spoofing**: Logs all DNS responses for inspection
- **Packet Replay**: Detects reused TCP sequence numbers

### IDS (Intrusion Detection)
- **Port Scan**: 15+ ports in 5s → SYN/NULL/XMAS/FIN scan alert
- **DoS Flood**: 200+ packets in 5s → flood alert
- **Brute Force**: 10+ connection attempts to SSH/RDP/FTP in 20s
- **Suspicious Ports**: Metasploit (4444), Back Orifice (31337), NetBus (12345), etc.
- **Data Exfiltration**: >5MB outbound data in 60s

---

## 🖥️ Dashboard Features

- 📊 **Stats Cards** — Total, HIGH/MEDIUM/LOW, ARP, MITM, Scan, Brute counts
- 🍩 **Doughnut Chart** — Alert type distribution
- 📊 **Bar Chart** — Severity breakdown
- 🚨 **Alert Table** — Filterable, real-time updates
- 📋 **ARP Cache Table** — Live IP→MAC mappings
- 📡 **Live Feed** — Real-time alert stream
- 🔔 **Toast Notifications** — Pop-up on every new alert

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, Flask-SocketIO |
| Packet Capture | Scapy |
| Database | SQLite |
| Frontend | HTML5, CSS3, Vanilla JS |
| Charts | Chart.js |
| Real-time | Socket.IO |

---

## ⚠️ Ethical Notice

> This tool is built for **educational and defensive purposes only**.
> Use only on networks you own or have explicit permission to monitor.
> Unauthorized network monitoring may be illegal.

---

## 👤 Author
5th Semester CSE Mini Project — Network Security

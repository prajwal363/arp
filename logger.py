"""
NetGuard - Network Security Monitor
Logger module: Handles alert logging to SQLite database
"""

import sqlite3
import datetime
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "netguard.db")


def init_db():
    """Initialize the SQLite database and create tables if not exists."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            description TEXT,
            raw_info TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_alert(alert_type, severity, description, src_ip=None, dst_ip=None,
              src_mac=None, dst_mac=None, raw_info=None):
    """
    Log a security alert to the database.

    Args:
        alert_type: Type of alert (ARP_SPOOF, MITM, INTRUSION, PORT_SCAN, etc.)
        severity: HIGH / MEDIUM / LOW
        description: Human-readable description of the alert
        src_ip: Source IP address (optional)
        dst_ip: Destination IP address (optional)
        src_mac: Source MAC address (optional)
        dst_mac: Destination MAC address (optional)
        raw_info: Raw packet or extra info string (optional)
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('''
        INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip,
                            src_mac, dst_mac, description, raw_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, alert_type, severity, src_ip, dst_ip,
          src_mac, dst_mac, description, raw_info))
    conn.commit()
    conn.close()
    print(f"[{severity}] [{alert_type}] {description}")


def get_all_alerts(limit=200):
    """Retrieve the latest alerts from the database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    return rows


def get_alert_stats():
    """Return counts grouped by alert_type and severity."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT alert_type, COUNT(*) as cnt FROM alerts GROUP BY alert_type")
    by_type = {row[0]: row[1] for row in c.fetchall()}

    c.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity")
    by_severity = {row[0]: row[1] for row in c.fetchall()}

    c.execute("SELECT COUNT(*) FROM alerts")
    total = c.fetchone()[0]

    conn.close()
    return {"by_type": by_type, "by_severity": by_severity, "total": total}


def clear_alerts():
    """Clear all alerts from the database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()

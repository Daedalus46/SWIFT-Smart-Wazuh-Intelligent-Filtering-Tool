"""
SWIFT Test Case Generator v2 — Realistic SOC Scenarios
=======================================================
Generates CSV test files that mirror real-world Wazuh/Kibana exports:
  - Broken/mixed headers (dot-notation, spaces, mixed case)
  - Missing values and partial columns
  - Grey-area logs (high-sev benign, low-sev malicious)
  - Signal contradiction (bad IPs benign, internal IPs compromised)
  - Attack campaign simulations
"""
import csv
import random
import os
from datetime import datetime, timedelta
from typing import List, Dict

# =====================================================================
# TEMPLATES
# =====================================================================
BENIGN = [
    {"decoder_name": "web-accesslog", "rule_description": "Normal GET request to /index.html", "rule_group": "web_traffic", "mitre_id": "None"},
    {"decoder_name": "syscheck", "rule_description": "File integrity check passed", "rule_group": "ossec", "mitre_id": "None"},
    {"decoder_name": "pam", "rule_description": "Successful SSH login", "rule_group": "authentication", "mitre_id": "None"},
    {"decoder_name": "windows", "rule_description": "System event 4624", "rule_group": "windows_auth", "mitre_id": "None"},
    {"decoder_name": "cron", "rule_description": "Cron job executed successfully", "rule_group": "system", "mitre_id": "None"},
    {"decoder_name": "postfix", "rule_description": "Mail delivery successful", "rule_group": "mail", "mitre_id": "None"},
    {"decoder_name": "iptables", "rule_description": "Firewall accepted connection", "rule_group": "firewall", "mitre_id": "None"},
    {"decoder_name": "mysql", "rule_description": "Standard DB query execution", "rule_group": "database", "mitre_id": "None"},
    {"decoder_name": "nginx", "rule_description": "Normal asset load (JS/CSS)", "rule_group": "web_traffic", "mitre_id": "None"},
    {"decoder_name": "sudo", "rule_description": "User executed allowed sudo command", "rule_group": "privilege", "mitre_id": "None"},
]

MALICIOUS = [
    {"decoder_name": "modsecurity", "rule_description": "SQL Injection attempt detected", "rule_group": "owasp_10", "mitre_id": "T1190"},
    {"decoder_name": "modsecurity", "rule_description": "Cross Site Scripting (XSS) detected", "rule_group": "owasp_10", "mitre_id": "T1190"},
    {"decoder_name": "sshd", "rule_description": "Multiple SSH authentication failures (Brute Force)", "rule_group": "authentication_failed", "mitre_id": "T1110"},
    {"decoder_name": "windows_defender", "rule_description": "Malware Execution Detected", "rule_group": "malware", "mitre_id": "T1204"},
    {"decoder_name": "suricata", "rule_description": "Lateral movement via Windows Admin Shares", "rule_group": "lateral_movement", "mitre_id": "T1021"},
    {"decoder_name": "windows", "rule_description": "Suspicious privilege escalation via token manipulation", "rule_group": "privilege_escalation", "mitre_id": "T1134"},
    {"decoder_name": "suricata", "rule_description": "Nmap port scanning detected (Reconnaissance)", "rule_group": "reconnaissance", "mitre_id": "T1046"},
    {"decoder_name": "nginx", "rule_description": "HTTP Flood Denial of Service (DoS)", "rule_group": "dos", "mitre_id": "T1498"},
    {"decoder_name": "suricata", "rule_description": "Command and Control Beaconing Detected", "rule_group": "c2", "mitre_id": "T1071"},
]

# Grey-area: high-severity benign (compliance scans, system alerts)
HIGH_SEV_BENIGN = [
    {"decoder_name": "sca", "rule_description": "SCA policy scan: CIS Benchmark compliance check completed", "rule_group": "compliance", "mitre_id": "None"},
    {"decoder_name": "syscheck", "rule_description": "High disk usage alert - /var/log at 92% capacity", "rule_group": "system_monitor", "mitre_id": "None"},
    {"decoder_name": "pam", "rule_description": "Password expiry warning for user admin (30 days remaining)", "rule_group": "authentication", "mitre_id": "None"},
    {"decoder_name": "sshd", "rule_description": "Multiple SSH authentication failures (Brute Force)", "rule_group": "authentication_failed", "mitre_id": "T1110"},
    {"decoder_name": "suricata", "rule_description": "Nmap port scanning detected (Reconnaissance)", "rule_group": "reconnaissance", "mitre_id": "T1046"},
]

# Grey-area: low-severity malicious (subtle attacks)
LOW_SEV_MALICIOUS = [
    {"decoder_name": "sshd", "rule_description": "Subtle brute force: 3 failed logins from single source", "rule_group": "authentication_failed", "mitre_id": "T1110"},
    {"decoder_name": "suricata", "rule_description": "Hidden port scan: slow SYN sweep on non-standard ports", "rule_group": "reconnaissance", "mitre_id": "T1046"},
    {"decoder_name": "pam", "rule_description": "Successful SSH login", "rule_group": "authentication", "mitre_id": "None"},
    {"decoder_name": "web-accesslog", "rule_description": "Normal GET request to /index.html", "rule_group": "web_traffic", "mitre_id": "None"},
    {"decoder_name": "suricata", "rule_description": "DNS tunneling: suspicious TXT record queries to unknown domain", "rule_group": "c2", "mitre_id": "T1071"},
]

# Severity-overlap templates (level 5-8, used in both classes)
MID_SEVERITY_SHARED = [
    {"decoder_name": "sshd", "rule_description": "Multiple failed password attempts", "rule_group": "authentication_failed", "mitre_id": "T1110"},
    {"decoder_name": "nginx", "rule_description": "Unusual traffic spike detected", "rule_group": "web_traffic", "mitre_id": "None"},
    {"decoder_name": "suricata", "rule_description": "Outbound connection to rare external IP", "rule_group": "network_monitor", "mitre_id": "None"},
    {"decoder_name": "syscheck", "rule_description": "Unexpected file modification in /etc/", "rule_group": "ossec", "mitre_id": "None"},
    {"decoder_name": "windows", "rule_description": "Service started from non-standard path", "rule_group": "windows_system", "mitre_id": "None"},
]

BAD_IPS = [
    "103.45.67.89", "45.227.254.52", "185.220.101.34", "23.129.64.15",
    "51.222.95.16", "54.39.136.194", "8.222.243.165", "47.237.24.132",
    "85.203.23.153", "77.105.160.156", "38.34.179.51", "20.121.25.154",
]

# Header variants for broken-header tests
HEADERS_CLEAN = ["timestamp", "rule_level", "decoder_name", "rule_description", "rule_group", "mitre_id", "agent_ip", "is_malicious"]
HEADERS_DOT = ["timestamp", "rule.level", "decoder.name", "rule.description", "rule.groups", "rule.mitre.id", "agent.ip", "is_malicious"]
HEADERS_SPACE = ["Timestamp", "Rule Level", "Decoder Name", "Rule Description", "Rule Group", "Mitre ID", "Agent IP", "is_malicious"]
HEADERS_MIXED = ["timestamp", "Rule.Level", "decoder_name", "rule description", "rule.groups", "MITRE_ID", "Agent IP", "is_malicious"]


def _ts(base, span=43200):
    return (base + timedelta(minutes=random.randint(0, span))).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _int_ip():
    return f"192.168.1.{random.randint(2, 254)}"

def _ext_ip():
    return random.choice(BAD_IPS) if random.random() < 0.6 else f"{random.randint(1,200)}.{random.randint(1,255)}.1.{random.randint(1,255)}"

def _row(base, t, level, ip, label):
    return [_ts(base), level, t["decoder_name"], t["rule_description"], t["rule_group"], t["mitre_id"], ip, label]

def _write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    print(f"  [OK] {os.path.basename(path):40s} ({len(rows)} rows)")


def main():
    d = os.path.dirname(os.path.abspath(__file__))
    random.seed(42)
    base = datetime(2026, 3, 25, 0, 0, 0)

    print("\nGenerating SWIFT realistic test cases...\n")

    # =====================================================================
    # 1. Clean baseline (standard headers, no noise)
    # =====================================================================
    rows = []
    for _ in range(350):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 4), _int_ip(), 0))
    for _ in range(150):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 15), _ext_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_clean_baseline.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 2. Kibana export (dot-notation headers)
    # =====================================================================
    rows = []
    for _ in range(400):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 4), _int_ip(), 0))
    for _ in range(200):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 15), _ext_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_kibana_export.csv"), HEADERS_DOT, rows)

    # =====================================================================
    # 3. Dashboard export (spaces + mixed case headers)
    # =====================================================================
    rows = []
    for _ in range(300):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 4), _int_ip(), 0))
    for _ in range(100):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 15), _ext_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_dashboard_export.csv"), HEADERS_SPACE, rows)

    # =====================================================================
    # 4. Mixed broken headers (worst-case real export)
    # =====================================================================
    rows = []
    for _ in range(250):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 4), _int_ip(), 0))
    for _ in range(250):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 15), _ext_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_broken_headers.csv"), HEADERS_MIXED, rows)

    # =====================================================================
    # 5. Partial CSV (missing agent_ip and decoder_name columns entirely)
    # =====================================================================
    rows = []
    partial_hdr = ["timestamp", "rule_level", "rule_description", "is_malicious"]
    for _ in range(200):
        t = random.choice(BENIGN)
        rows.append([_ts(base), random.randint(1, 4), t["rule_description"], 0])
    for _ in range(100):
        t = random.choice(MALICIOUS)
        rows.append([_ts(base), random.randint(8, 15), t["rule_description"], 1])
    random.shuffle(rows)
    _write(os.path.join(d, "test_partial_columns.csv"), partial_hdr, rows)

    # =====================================================================
    # 6. Null-heavy CSV (~15% missing values scattered)
    # =====================================================================
    rows = []
    for _ in range(350):
        t = random.choice(BENIGN)
        row = _row(base, t, random.randint(1, 4), _int_ip(), 0)
        for j in range(len(row) - 1):  # don't null the label
            if random.random() < 0.15:
                row[j] = ""
        rows.append(row)
    for _ in range(150):
        t = random.choice(MALICIOUS)
        row = _row(base, t, random.randint(8, 15), _ext_ip(), 1)
        for j in range(len(row) - 1):
            if random.random() < 0.15:
                row[j] = ""
        rows.append(row)
    random.shuffle(rows)
    _write(os.path.join(d, "test_null_heavy.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 7. Grey area — high-severity benign + low-severity malicious
    # =====================================================================
    rows = []
    for _ in range(150):
        t = random.choice(HIGH_SEV_BENIGN)
        rows.append(_row(base, t, random.randint(10, 12), _int_ip(), 0))
    for _ in range(150):
        t = random.choice(LOW_SEV_MALICIOUS)
        rows.append(_row(base, t, random.randint(3, 5), _int_ip(), 1))
    for _ in range(100):
        t = random.choice(MID_SEVERITY_SHARED)
        rows.append(_row(base, t, random.randint(5, 8), _int_ip(), random.choice([0, 1])))
    random.shuffle(rows)
    _write(os.path.join(d, "test_grey_area.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 8. Signal contradiction — bad IPs benign, internal IPs malicious
    # =====================================================================
    rows = []
    for _ in range(200):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 3), random.choice(BAD_IPS), 0))
    for _ in range(200):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 12), _int_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_signal_contradiction.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 9. Brute force burst (single attacker, 30-minute window)
    # =====================================================================
    burst_base = datetime(2026, 3, 25, 14, 0, 0)
    rows = []
    attacker = "103.45.67.89"
    for _ in range(250):
        rows.append([
            (burst_base + timedelta(seconds=random.randint(0, 1800))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            random.choice([10, 11, 12, 13, 14]), "sshd",
            "Multiple SSH authentication failures (Brute Force)",
            "authentication_failed", "T1110", attacker, 1
        ])
    for _ in range(50):
        t = random.choice(BENIGN)
        rows.append(_row(burst_base, t, random.randint(1, 4), _int_ip(), 0))
    rows.sort(key=lambda r: r[0])
    _write(os.path.join(d, "test_brute_force_burst.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 10. SQLi/XSS web attack campaign (6 attackers, 12-hour window)
    # =====================================================================
    web_base = datetime(2026, 3, 24, 8, 0, 0)
    rows = []
    web_attacks = [t for t in MALICIOUS if t["rule_group"] == "owasp_10"]
    attackers = random.sample(BAD_IPS, 6)
    for _ in range(300):
        t = random.choice(web_attacks)
        rows.append(_row(web_base, t, random.randint(9, 15), random.choice(attackers), 1))
    for _ in range(100):
        t = random.choice(BENIGN)
        rows.append(_row(web_base, t, random.randint(1, 4), _int_ip(), 0))
    random.shuffle(rows)
    _write(os.path.join(d, "test_sqli_xss_campaign.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 11. Lateral movement + C2 (internal pivoting, night hours)
    # =====================================================================
    lat_base = datetime(2026, 3, 23, 2, 0, 0)
    rows = []
    lateral = [t for t in MALICIOUS if t["rule_group"] in ("lateral_movement", "c2", "privilege_escalation")]
    pivots = [f"10.0.{random.randint(1,5)}.{random.randint(10,50)}" for _ in range(5)]
    for _ in range(200):
        t = random.choice(lateral)
        rows.append(_row(lat_base, t, random.randint(8, 15), random.choice(pivots), 1))
    for _ in range(150):
        t = random.choice(BENIGN)
        rows.append(_row(lat_base, t, random.randint(1, 4), _int_ip(), 0))
    rows.sort(key=lambda r: r[0])
    _write(os.path.join(d, "test_lateral_movement.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 12. Malware outbreak (8 infected hosts, 24-hour spread)
    # =====================================================================
    mal_base = datetime(2026, 3, 22, 9, 0, 0)
    rows = []
    infected = [f"10.10.{random.randint(1,3)}.{random.randint(100,200)}" for _ in range(8)]
    malware = [t for t in MALICIOUS if t["rule_group"] in ("malware", "c2")]
    for _ in range(280):
        t = random.choice(malware)
        rows.append(_row(mal_base, t, random.randint(10, 15), random.choice(infected), 1))
    for _ in range(120):
        t = random.choice(BENIGN)
        rows.append(_row(mal_base, t, random.randint(1, 4), _int_ip(), 0))
    rows.sort(key=lambda r: r[0])
    _write(os.path.join(d, "test_malware_outbreak.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 13. Recon scan (single scanner, 2-hour burst)
    # =====================================================================
    recon_base = datetime(2026, 3, 21, 0, 0, 0)
    rows = []
    scanner = "185.220.101.34"
    recon = [t for t in MALICIOUS if t["rule_group"] in ("reconnaissance", "dos")]
    for _ in range(250):
        t = random.choice(recon)
        rows.append(_row(recon_base, t, random.randint(8, 14), scanner, 1))
    for _ in range(100):
        t = random.choice(BENIGN)
        rows.append(_row(recon_base, t, random.randint(1, 4), _int_ip(), 0))
    rows.sort(key=lambda r: r[0])
    _write(os.path.join(d, "test_recon_scan.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 14. Stress test (10K rows, realistic 70/30 split)
    # =====================================================================
    rows = []
    stress_base = datetime(2026, 3, 1, 0, 0, 0)
    for _ in range(7000):
        t = random.choice(BENIGN)
        rows.append(_row(stress_base, t, random.randint(1, 4), _int_ip(), 0))
    for _ in range(3000):
        t = random.choice(MALICIOUS)
        rows.append(_row(stress_base, t, random.randint(7, 15), _ext_ip(), 1))
    random.shuffle(rows)
    _write(os.path.join(d, "test_large_stress.csv"), HEADERS_CLEAN, rows)

    # =====================================================================
    # 15. Pentest simulation — authorized scanning labeled benign
    # =====================================================================
    rows = []
    pentest_ip = "192.168.1.100"
    for _ in range(200):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(8, 12), pentest_ip, 0))  # authorized, labeled benign
    for _ in range(100):
        t = random.choice(MALICIOUS)
        rows.append(_row(base, t, random.randint(10, 15), _ext_ip(), 1))  # real attack
    for _ in range(200):
        t = random.choice(BENIGN)
        rows.append(_row(base, t, random.randint(1, 4), _int_ip(), 0))
    random.shuffle(rows)
    _write(os.path.join(d, "test_pentest_simulation.csv"), HEADERS_CLEAN, rows)

    print(f"\n[DONE] All test cases generated in: {d}")


if __name__ == "__main__":
    main()

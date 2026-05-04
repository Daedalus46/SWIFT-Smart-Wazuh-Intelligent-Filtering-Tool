"""
SWIFT SOC — Chaotic Data Generator
===================================
Simulates a realistic, messy Wazuh log export with:
  - Broken/inconsistent column headers
  - ~8% missing values (NaN injection)
  - ~3% duplicate rows
  - 10% "Grey Area" hard cases (class ambiguity)
  - Severity overlap in rule_level 5-8 for both classes
  - Signal contradiction: bad IPs doing benign things, safe IPs compromised
"""
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import urllib.request
import os

def generate_chaotic_data():
    random.seed(42)
    np.random.seed(42)

    num_records = 30000
    num_benign = int(num_records * 0.70)
    num_malicious = num_records - num_benign

    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    blocklist_path = os.path.join(PROJECT_ROOT, "firehol_level2.netset")
    raw_csv_path = os.path.join(PROJECT_ROOT, "wazuh_logs_raw.csv")

    # =====================================================================
    # TEMPLATE DEFINITIONS
    # =====================================================================

    # Standard benign (clean, low-severity, internal IPs)
    benign_templates = [
        ("web-accesslog", "Normal GET request to /index.html", "web_traffic", "None"),
        ("syscheck", "File integrity check passed", "ossec", "None"),
        ("pam", "Successful SSH login", "authentication", "None"),
        ("windows", "System event 4624", "windows_auth", "None"),
        ("cron", "Cron job executed successfully", "system", "None"),
        ("postfix", "Mail delivery successful", "mail", "None"),
        ("iptables", "Firewall accepted connection", "firewall", "None"),
        ("mysql", "Standard DB query execution", "database", "None"),
        ("nginx", "Normal asset load (JS/CSS)", "web_traffic", "None"),
        ("sudo", "User executed allowed sudo command", "privilege", "None"),
    ]

    # Standard malicious (high-severity, external/bad IPs)
    malicious_templates = [
        ("modsecurity", "SQL Injection attempt detected", "owasp_10", "T1190"),
        ("modsecurity", "Cross Site Scripting (XSS) detected", "owasp_10", "T1190"),
        ("sshd", "Multiple SSH authentication failures (Brute Force)", "authentication_failed", "T1110"),
        ("windows_defender", "Malware Execution Detected", "malware", "T1204"),
        ("suricata", "Lateral movement via Windows Admin Shares", "lateral_movement", "T1021"),
        ("windows", "Suspicious privilege escalation via token manipulation", "privilege_escalation", "T1134"),
        ("suricata", "Nmap port scanning detected (Reconnaissance)", "reconnaissance", "T1046"),
        ("nginx", "HTTP Flood Denial of Service (DoS)", "dos", "T1498"),
        ("suricata", "Command and Control Beaconing Detected", "c2", "T1071"),
    ]

    # HIGH-SEVERITY BENIGN — compliance scans, system alerts (level 8-12, is_malicious=0)
    high_sev_benign_templates = [
        ("sca", "SCA policy scan: CIS Benchmark compliance check completed", "compliance", "None"),
        ("syscheck", "High disk usage alert - /var/log at 92% capacity", "system_monitor", "None"),
        ("pam", "Password expiry warning for user admin (30 days remaining)", "authentication", "None"),
        ("sca", "Vulnerability assessment scan completed on all endpoints", "compliance", "None"),
        ("windows", "Windows Update service restarted automatically", "windows_system", "None"),
        ("syscheck", "Certificate expiration warning: SSL cert expires in 7 days", "system_monitor", "None"),
        ("sshd", "SSH key rotation completed for service account", "authentication", "None"),
        ("mysql", "Database maintenance: slow query log threshold exceeded", "database", "None"),
        # OVERLAP: same descriptions as malicious, but labeled benign
        ("sshd", "Multiple SSH authentication failures (Brute Force)", "authentication_failed", "T1110"),
        ("suricata", "Nmap port scanning detected (Reconnaissance)", "reconnaissance", "T1046"),
        ("modsecurity", "SQL Injection attempt detected", "owasp_10", "T1190"),
    ]

    # LOW-SEVERITY MALICIOUS — subtle attacks at level 3-5 (is_malicious=1)
    low_sev_malicious_templates = [
        ("sshd", "Subtle brute force: 3 failed logins from single source", "authentication_failed", "T1110"),
        ("suricata", "Hidden port scan: slow SYN sweep on non-standard ports", "reconnaissance", "T1046"),
        ("nginx", "Low-rate credential stuffing via API endpoint", "authentication_failed", "T1110"),
        ("web-accesslog", "Directory traversal probe: GET /../../etc/shadow", "owasp_10", "T1190"),
        ("suricata", "DNS tunneling: suspicious TXT record queries to unknown domain", "c2", "T1071"),
        ("pam", "Service account login from unexpected geographic region", "lateral_movement", "T1021"),
        # OVERLAP: same descriptions as benign, but labeled malicious
        ("pam", "Successful SSH login", "authentication", "None"),
        ("web-accesslog", "Normal GET request to /index.html", "web_traffic", "None"),
        ("sudo", "User executed allowed sudo command", "privilege", "None"),
    ]

    # SEVERITY-OVERLAP templates (level 5-8, appears in BOTH classes)
    mid_severity_shared = [
        ("sshd", "Multiple failed password attempts", "authentication_failed", "T1110"),
        ("nginx", "Unusual traffic spike detected", "web_traffic", "None"),
        ("suricata", "Outbound connection to rare external IP", "network_monitor", "None"),
        ("syscheck", "Unexpected file modification in /etc/", "ossec", "None"),
        ("windows", "Service started from non-standard path", "windows_system", "None"),
    ]

    # =====================================================================
    # LOAD BLOCKLIST IPs
    # =====================================================================
    print("Loading FireHOL blocklist...")
    bad_ips = []
    if os.path.exists(blocklist_path):
        with open(blocklist_path, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    ip = line.strip()
                    if '/' not in ip:
                        bad_ips.append(ip)
                    if len(bad_ips) > 5000:
                        break

    if "103.45.67.89" not in bad_ips:
        bad_ips.append("103.45.67.89")

    # =====================================================================
    # HEADER CHAOS: randomly assign one of several broken column name sets
    # =====================================================================
    # We'll use the canonical names during generation, then randomize at the end
    header_variants = [
        # Standard clean
        {"timestamp": "timestamp", "rule_level": "rule_level", "decoder_name": "decoder_name",
         "rule_description": "rule_description", "rule_group": "rule_group", "mitre_id": "mitre_id",
         "agent_ip": "agent_ip", "is_malicious": "is_malicious"},
        # Dot-notation (Kibana style)
        {"timestamp": "timestamp", "rule_level": "rule.level", "decoder_name": "decoder.name",
         "rule_description": "rule.description", "rule_group": "rule.groups", "mitre_id": "rule.mitre.id",
         "agent_ip": "agent.ip", "is_malicious": "is_malicious"},
        # Mixed case with spaces
        {"timestamp": "Timestamp", "rule_level": "Rule Level", "decoder_name": "Decoder Name",
         "rule_description": "Rule Description", "rule_group": "Rule Group", "mitre_id": "Mitre ID",
         "agent_ip": "Agent IP", "is_malicious": "is_malicious"},
    ]

    records = []
    start_time = datetime.now() - timedelta(days=30)

    def make_timestamp():
        return (start_time + timedelta(minutes=random.randint(0, 43200))).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def internal_ip():
        return f"192.168.1.{random.randint(2, 254)}"

    def external_ip():
        return random.choice(bad_ips) if (bad_ips and random.random() < 0.7) else f"{random.randint(1,223)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    # =====================================================================
    # PHASE 1: Standard benign (60% of benign, level 1-4, internal IPs)
    # =====================================================================
    phase1_count = int(num_benign * 0.60)
    print(f"Phase 1: Standard benign logs ({phase1_count})...")
    for _ in range(phase1_count):
        d, desc, grp, mid = random.choice(benign_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(1, 4),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 0
        })

    # =====================================================================
    # PHASE 2: High-severity benign (15% of benign, level 8-12, is_malicious=0)
    # =====================================================================
    phase2_count = int(num_benign * 0.15)
    print(f"Phase 2: High-severity BENIGN logs ({phase2_count})...")
    for _ in range(phase2_count):
        d, desc, grp, mid = random.choice(high_sev_benign_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(8, 12),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 0
        })

    # =====================================================================
    # PHASE 3: Severity-overlap BENIGN (10% of benign, level 5-8, is_malicious=0)
    # Same descriptions used in Phase 7 for malicious — forces class confusion
    # =====================================================================
    phase3_count = int(num_benign * 0.10)
    print(f"Phase 3: Severity-overlap BENIGN logs ({phase3_count})...")
    for _ in range(phase3_count):
        d, desc, grp, mid = random.choice(mid_severity_shared)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(5, 8),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 0
        })

    # =====================================================================
    # PHASE 4: Known-bad IPs doing benign things (8% of benign, signal contradiction)
    # =====================================================================
    phase4_count = int(num_benign * 0.08)
    print(f"Phase 4: Bad-IP benign noise ({phase4_count})...")
    for _ in range(phase4_count):
        d, desc, grp, mid = random.choice(benign_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(1, 4),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid,
            "agent_ip": random.choice(bad_ips) if bad_ips else internal_ip(),
            "is_malicious": 0
        })

    # =====================================================================
    # PHASE 5: Remaining benign to fill allocation
    # =====================================================================
    phase5_count = num_benign - phase1_count - phase2_count - phase3_count - phase4_count
    print(f"Phase 5: Filler benign ({phase5_count})...")
    for _ in range(phase5_count):
        d, desc, grp, mid = random.choice(benign_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(1, 5),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 0
        })

    # =====================================================================
    # PHASE 6: Standard malicious (60% of malicious, level 8-15, bad IPs)
    # =====================================================================
    phase6_count = int(num_malicious * 0.60)
    print(f"Phase 6: Standard malicious logs ({phase6_count})...")
    # Preserve exact-match test injection
    records.append({
        "timestamp": "2026-03-25T14:08:45.991Z", "rule_level": 12,
        "decoder_name": "sshd", "rule_description": "Multiple SSH authentication failures (Brute Force)",
        "rule_group": "authentication_failed", "mitre_id": "T1110",
        "agent_ip": "103.45.67.89", "is_malicious": 1
    })
    for _ in range(phase6_count - 1):
        d, desc, grp, mid = random.choice(malicious_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(8, 15),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": external_ip(), "is_malicious": 1
        })

    # =====================================================================
    # PHASE 7: Severity-overlap MALICIOUS (12% of malicious, level 5-8, is_malicious=1)
    # Same descriptions as Phase 3 — the model CANNOT separate these by description alone
    # =====================================================================
    phase7_count = int(num_malicious * 0.12)
    print(f"Phase 7: Severity-overlap MALICIOUS logs ({phase7_count})...")
    for _ in range(phase7_count):
        d, desc, grp, mid = random.choice(mid_severity_shared)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(5, 8),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": external_ip(), "is_malicious": 1
        })

    # =====================================================================
    # PHASE 8: Low-severity malicious (15% of malicious, level 3-5, is_malicious=1)
    # =====================================================================
    phase8_count = int(num_malicious * 0.15)
    print(f"Phase 8: Low-severity MALICIOUS logs ({phase8_count})...")
    for _ in range(phase8_count):
        d, desc, grp, mid = random.choice(low_sev_malicious_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(3, 5),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 1
        })

    # =====================================================================
    # PHASE 9: Compromised internal hosts (remaining malicious, level 8-12, safe IPs)
    # =====================================================================
    phase9_count = num_malicious - phase6_count - phase7_count - phase8_count
    print(f"Phase 9: Compromised internal hosts ({phase9_count})...")
    for _ in range(phase9_count):
        d, desc, grp, mid = random.choice(malicious_templates)
        records.append({
            "timestamp": make_timestamp(), "rule_level": random.randint(8, 12),
            "decoder_name": d, "rule_description": desc, "rule_group": grp,
            "mitre_id": mid, "agent_ip": internal_ip(), "is_malicious": 1
        })

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # =====================================================================
    # POST-PROCESSING: Inject chaos into the clean DataFrame
    # =====================================================================

    # 1. Inject ~8% NaN values across non-label columns
    print("Injecting ~8% missing values...")
    cols_to_corrupt = ['timestamp', 'rule_level', 'decoder_name', 'rule_description',
                       'rule_group', 'mitre_id', 'agent_ip']
    total_cells = len(df) * len(cols_to_corrupt)
    nan_count = int(total_cells * 0.08)
    for _ in range(nan_count):
        row_idx = random.randint(0, len(df) - 1)
        col = random.choice(cols_to_corrupt)
        df.at[row_idx, col] = np.nan

    # 2. Inject ~3% duplicate rows
    print("Injecting ~3% duplicate rows...")
    dup_count = int(len(df) * 0.03)
    dup_indices = random.sample(range(len(df)), dup_count)
    duplicates = df.iloc[dup_indices].copy()
    df = pd.concat([df, duplicates], ignore_index=True)

    # 3. Randomize column headers (pick one of the broken variants)
    chosen_headers = random.choice(header_variants)
    df.rename(columns=chosen_headers, inplace=True)

    df.to_csv(raw_csv_path, index=False)

    # =====================================================================
    # SUMMARY
    # =====================================================================
    print(f"\n{'='*50}")
    print(f"CHAOTIC DATA GENERATION COMPLETE")
    print(f"{'='*50}")
    print(f"Total records (incl. duplicates): {len(df)}")
    print(f"NaN cells injected:               {nan_count}")
    print(f"Duplicate rows injected:          {dup_count}")
    print(f"Header style used:                {list(chosen_headers.values())[:3]}...")
    print(f"Output: {raw_csv_path}")

    # Print class distribution from original (pre-NaN) data
    label_col = chosen_headers.get("is_malicious", "is_malicious")
    benign_ct = len(df[df[label_col] == 0])
    mal_ct = len(df[df[label_col] == 1])
    nan_ct = df[label_col].isna().sum()
    print(f"\nBenign:    {benign_ct}")
    print(f"Malicious: {mal_ct}")
    print(f"Label NaN: {nan_ct}")


if __name__ == "__main__":
    generate_chaotic_data()

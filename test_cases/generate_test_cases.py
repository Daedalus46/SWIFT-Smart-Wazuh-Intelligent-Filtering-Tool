"""
SWIFT Test Case Generator - Generates multiple CSV files with Wazuh log test scenarios.
"""
import csv
import random
import os
from datetime import datetime, timedelta
from typing import List, Dict

HEADER: List[str] = [
    "timestamp", "rule_level", "decoder_name",
    "rule_description", "rule_group", "mitre_id",
    "agent_ip", "is_malicious",
]

BENIGN_TEMPLATES: List[Dict[str, str]] = [
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

MALICIOUS_TEMPLATES: List[Dict[str, str]] = [
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

EDGE_CASE_TEMPLATES: List[Dict[str, str]] = [
    {"decoder_name": "auditd", "rule_description": "Unauthorized root login from remote host", "rule_group": "authentication_failed", "mitre_id": "T1078"},
    {"decoder_name": "suricata", "rule_description": "DNS Tunneling activity detected", "rule_group": "exfiltration", "mitre_id": "T1048"},
    {"decoder_name": "modsecurity", "rule_description": "Remote File Inclusion (RFI) attempt", "rule_group": "owasp_10", "mitre_id": "T1190"},
    {"decoder_name": "suricata", "rule_description": "Cryptominer traffic detected", "rule_group": "malware", "mitre_id": "T1496"},
    {"decoder_name": "windows", "rule_description": "Pass-the-Hash credential theft detected", "rule_group": "credential_access", "mitre_id": "T1550"},
    {"decoder_name": "sshd", "rule_description": "SSH key-based login from blocklisted IP", "rule_group": "authentication_failed", "mitre_id": "T1110"},
    {"decoder_name": "suricata", "rule_description": "Data exfiltration over HTTPS detected", "rule_group": "exfiltration", "mitre_id": "T1041"},
    {"decoder_name": "windows_defender", "rule_description": "Ransomware behavior pattern detected", "rule_group": "malware", "mitre_id": "T1486"},
]

BAD_IPS: List[str] = [
    "103.45.67.89", "45.227.254.52", "185.220.101.34", "23.129.64.15",
    "51.222.95.16", "54.39.136.194", "8.222.243.165", "47.237.24.132",
    "85.203.23.153", "77.105.160.156", "38.34.179.51", "20.121.25.154",
    "64.23.243.96", "51.161.65.163", "74.248.130.207", "79.141.163.38",
]


def _rand_ts(base: datetime, span_minutes: int = 43200) -> str:
    offset = timedelta(minutes=random.randint(0, span_minutes))
    return (base + offset).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _benign_ip() -> str:
    return f"192.168.1.{random.randint(2, 254)}"

def _malicious_ip() -> str:
    if random.random() < 0.6:
        return random.choice(BAD_IPS)
    return f"{random.randint(1, 200)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def _write_csv(path: str, rows: List[Dict[str, object]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [OK] {os.path.basename(path)}  ({len(rows)} rows)")


def gen_all_benign(out_dir: str, n: int = 500) -> None:
    base = datetime(2026, 3, 25, 0, 0, 0)
    rows = []
    for _ in range(n):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_all_benign.csv"), rows)

def gen_all_malicious(out_dir: str, n: int = 500) -> None:
    base = datetime(2026, 3, 25, 0, 0, 0)
    rows = []
    for _ in range(n):
        t = random.choice(MALICIOUS_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(7, 16), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_all_malicious.csv"), rows)

def gen_mixed_balanced(out_dir: str, n: int = 1000) -> None:
    base = datetime(2026, 3, 25, 0, 0, 0)
    rows = []
    half = n // 2
    for _ in range(half):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    for _ in range(half):
        t = random.choice(MALICIOUS_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(7, 16), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_mixed_balanced.csv"), rows)

def gen_realistic_skewed(out_dir: str, n: int = 2000) -> None:
    base = datetime(2026, 3, 25, 0, 0, 0)
    rows = []
    n_benign = int(n * 0.7)
    for _ in range(n_benign):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    for _ in range(n - n_benign):
        t = random.choice(MALICIOUS_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(7, 16), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_realistic_skewed.csv"), rows)

def gen_brute_force_burst(out_dir: str) -> None:
    base = datetime(2026, 3, 25, 14, 0, 0)
    attacker_ip = "103.45.67.89"
    rows = []
    for _ in range(250):
        rows.append({"timestamp": (base + timedelta(seconds=random.randint(0, 1800))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "rule_level": random.choice([10, 11, 12, 13, 14, 15]), "decoder_name": "sshd",
            "rule_description": "Multiple SSH authentication failures (Brute Force)",
            "rule_group": "authentication_failed", "mitre_id": "T1110", "agent_ip": attacker_ip, "is_malicious": 1})
    for _ in range(50):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=60), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    rows.sort(key=lambda r: r["timestamp"])
    _write_csv(os.path.join(out_dir, "test_brute_force_burst.csv"), rows)

def gen_sqli_xss_campaign(out_dir: str) -> None:
    base = datetime(2026, 3, 24, 8, 0, 0)
    rows = []
    web_attacks = [t for t in MALICIOUS_TEMPLATES if t["rule_group"] == "owasp_10"]
    attackers = random.sample(BAD_IPS, 6)
    for _ in range(300):
        t = random.choice(web_attacks)
        rows.append({"timestamp": _rand_ts(base, span_minutes=720), "rule_level": random.randint(9, 16), **t, "agent_ip": random.choice(attackers), "is_malicious": 1})
    for _ in range(100):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=720), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_sqli_xss_campaign.csv"), rows)

def gen_lateral_movement(out_dir: str) -> None:
    base = datetime(2026, 3, 23, 2, 0, 0)
    rows = []
    lateral_templates = [t for t in MALICIOUS_TEMPLATES if t["rule_group"] in ("lateral_movement", "c2", "privilege_escalation")]
    pivot_ips = [f"10.0.{random.randint(1,5)}.{random.randint(10,50)}" for _ in range(5)]
    for _ in range(200):
        t = random.choice(lateral_templates)
        rows.append({"timestamp": _rand_ts(base, span_minutes=480), "rule_level": random.randint(8, 16), **t, "agent_ip": random.choice(pivot_ips), "is_malicious": 1})
    for _ in range(150):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=480), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    rows.sort(key=lambda r: r["timestamp"])
    _write_csv(os.path.join(out_dir, "test_lateral_movement.csv"), rows)

def gen_edge_cases(out_dir: str) -> None:
    base = datetime(2026, 3, 25, 0, 0, 0)
    rows = []
    for _ in range(100):
        t = random.choice(EDGE_CASE_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(8, 16), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    for _ in range(50):
        t = random.choice(MALICIOUS_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(4, 6), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    for _ in range(50):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(7, 10), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    for _ in range(50):
        t = random.choice(MALICIOUS_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(9, 15), **t, "agent_ip": f"192.168.1.{random.randint(2, 254)}", "is_malicious": 1})
    for _ in range(50):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_edge_cases.csv"), rows)

def gen_malware_outbreak(out_dir: str) -> None:
    base = datetime(2026, 3, 22, 9, 0, 0)
    rows = []
    infected = [f"10.10.{random.randint(1,3)}.{random.randint(100,200)}" for _ in range(8)]
    malware_templates = [t for t in MALICIOUS_TEMPLATES if t["rule_group"] in ("malware", "c2")]
    for _ in range(280):
        t = random.choice(malware_templates)
        rows.append({"timestamp": _rand_ts(base, span_minutes=1440), "rule_level": random.randint(10, 16), **t, "agent_ip": random.choice(infected), "is_malicious": 1})
    for _ in range(120):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=1440), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    rows.sort(key=lambda r: r["timestamp"])
    _write_csv(os.path.join(out_dir, "test_malware_outbreak.csv"), rows)

def gen_recon_scan(out_dir: str) -> None:
    base = datetime(2026, 3, 21, 0, 0, 0)
    rows = []
    scanner_ip = "185.220.101.34"
    recon = [t for t in MALICIOUS_TEMPLATES if t["rule_group"] in ("reconnaissance", "dos")]
    for _ in range(250):
        t = random.choice(recon)
        rows.append({"timestamp": _rand_ts(base, span_minutes=120), "rule_level": random.randint(8, 14), **t, "agent_ip": scanner_ip, "is_malicious": 1})
    for _ in range(100):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=120), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    rows.sort(key=lambda r: r["timestamp"])
    _write_csv(os.path.join(out_dir, "test_recon_scan.csv"), rows)

def gen_large_stress(out_dir: str, n: int = 10000) -> None:
    base = datetime(2026, 3, 1, 0, 0, 0)
    rows = []
    n_benign = int(n * 0.7)
    for _ in range(n_benign):
        t = random.choice(BENIGN_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=43200), "rule_level": random.randint(1, 4), **t, "agent_ip": _benign_ip(), "is_malicious": 0})
    for _ in range(n - n_benign):
        t = random.choice(MALICIOUS_TEMPLATES + EDGE_CASE_TEMPLATES)
        rows.append({"timestamp": _rand_ts(base, span_minutes=43200), "rule_level": random.randint(7, 16), **t, "agent_ip": _malicious_ip(), "is_malicious": 1})
    random.shuffle(rows)
    _write_csv(os.path.join(out_dir, "test_large_stress.csv"), rows)


def main() -> None:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(script_dir, exist_ok=True)
    random.seed(42)

    print("\nGenerating SWIFT Wazuh test case CSVs...\n")

    gen_all_benign(script_dir)
    gen_all_malicious(script_dir)
    gen_mixed_balanced(script_dir)
    gen_realistic_skewed(script_dir)
    gen_brute_force_burst(script_dir)
    gen_sqli_xss_campaign(script_dir)
    gen_lateral_movement(script_dir)
    gen_edge_cases(script_dir)
    gen_malware_outbreak(script_dir)
    gen_recon_scan(script_dir)
    gen_large_stress(script_dir)

    print("\n[DONE] All test case files generated in:", script_dir)


if __name__ == "__main__":
    main()

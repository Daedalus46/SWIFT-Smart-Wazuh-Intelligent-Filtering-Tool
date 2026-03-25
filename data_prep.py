import pandas as pd
import random
from datetime import datetime, timedelta
import urllib.request
import os

def generate_data():
    num_records = 29560
    num_benign = int(num_records * 0.70)
    num_malicious = num_records - num_benign

    benign_noise = [
        ("web-accesslog", "Normal GET request to /index.html", "web_traffic", "None"),
        ("syscheck", "File integrity check passed", "ossec", "None"),
        ("pam", "Successful SSH login", "authentication", "None"),
        ("windows", "System event 4624", "windows_auth", "None"),
        ("cron", "Cron job executed successfully", "system", "None"),
        ("postfix", "Mail delivery successful", "mail", "None"),
        ("iptables", "Firewall accepted connection", "firewall", "None"),
        ("mysql", "Standard DB query execution", "database", "None"),
        ("nginx", "Normal asset load (JS/CSS)", "web_traffic", "None"),
        ("sudo", "User executed allowed sudo command", "privilege", "None")
    ]
    
    malicious_noise = [
        ("modsecurity", "SQL Injection attempt detected", "owasp_10", "T1190"),
        ("modsecurity", "Cross Site Scripting (XSS) detected", "owasp_10", "T1190"),
        ("sshd", "Multiple SSH authentication failures (Brute Force)", "authentication_failed", "T1110"),
        ("windows_defender", "Malware Execution Detected", "malware", "T1204"),
        ("suricata", "Lateral movement via Windows Admin Shares", "lateral_movement", "T1021"),
        ("windows", "Suspicious privilege escalation via token manipulation", "privilege_escalation", "T1134"),
        ("suricata", "Nmap port scanning detected (Reconnaissance)", "reconnaissance", "T1046"),
        ("nginx", "HTTP Flood Denial of Service (DoS)", "dos", "T1498"),
        ("suricata", "Command and Control Beaconing Detected", "c2", "T1071")
    ]

    blocklist_url = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset"
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    blocklist_path = os.path.join(PROJECT_ROOT, "firehol_level2.netset")
    wazuh_logs_path = os.path.join(PROJECT_ROOT, "wazuh_logs.csv")
    
    print("Downloading FireHOL blocklist...")
    try:
        urllib.request.urlretrieve(blocklist_url, blocklist_path)
    except Exception as e:
        print(f"Error downloading blocklist: {e}")
        with open(blocklist_path, 'w') as f:
            f.write("# Fallback Dummy List\n103.45.67.89\n8.8.8.8\n")
            
    bad_ips = []
    if os.path.exists(blocklist_path):
        with open(blocklist_path, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    ip = line.strip()
                    if '/' not in ip:
                        bad_ips.append(ip)
                    if len(bad_ips) > 5000: break
    
    if "103.45.67.89" not in bad_ips:
        bad_ips.append("103.45.67.89")
        
    records = []
    start_time = datetime.now() - timedelta(days=30)
    
    print("Generating benign logs (70%)...")
    for _ in range(num_benign):
        decoder, desc, r_group, m_id = random.choice(benign_noise)
        records.append({
            "timestamp": (start_time + timedelta(minutes=random.randint(0, 43200))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "rule_level": random.randint(1, 4),
            "decoder_name": decoder,
            "rule_description": desc,
            "rule_group": r_group,
            "mitre_id": m_id,
            "agent_ip": f"192.168.1.{random.randint(2, 254)}",
            "is_malicious": 0
        })
        
    print("Generating malicious logs (30%)...")
    for idx in range(num_malicious):
        decoder, desc, r_group, m_id = random.choice(malicious_noise)
        
        # Test exact match injection
        if idx == 0:
            records.append({
                "timestamp": "2026-03-25T14:08:45.991Z",
                "rule_level": 12,
                "decoder_name": "sshd",
                "rule_description": "Multiple SSH authentication failures (Brute Force)",
                "rule_group": "authentication_failed",
                "mitre_id": "T1110",
                "agent_ip": "103.45.67.89",
                "is_malicious": 1
            })
            continue
            
        records.append({
            "timestamp": (start_time + timedelta(minutes=random.randint(0, 43200))).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "rule_level": random.randint(8, 15) + random.choice([-1, 0, 1]), # dynamic variance
            "decoder_name": decoder,
            "rule_description": desc,
            "rule_group": r_group,
            "mitre_id": m_id,
            "agent_ip": random.choice(bad_ips) if (bad_ips and random.random() < 0.7) else f"{random.randint(1,200)}.{random.randint(1,255)}.1.{random.randint(1,255)}",
            "is_malicious": 1
        })
        
    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    df.to_csv(wazuh_logs_path, index=False)
    print("wazuh_logs.csv generated successfully.")
    
if __name__ == "__main__":
    generate_data()

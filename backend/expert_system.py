MITRE_MAPPING = {
    "Brute Force": {
        "tactic": "Credential Access (TA0006)",
        "owasp": "None",
        "mitigation": ["Enforce Multi-Factor Authentication (MFA)", "Implement account lockout policies", "Rotate compromised administrative passwords"]
    },
    "SQL Injection": {
        "tactic": "Initial Access (TA0001)",
        "owasp": "A03:2021-Injection",
        "mitigation": ["Deploy Web Application Firewall (WAF) rules", "Implement parameterized queries", "Sanitize all user-supplied input"]
    },
    "Cross Site Scripting": {
        "tactic": "Initial Access (TA0001)",
        "owasp": "A03:2021-Injection",
        "mitigation": ["Escape and sanitize all user input", "Implement strict Content Security Policy (CSP)", "Audit frontend rendering endpoints"]
    },
    "Reconnaissance": {
        "tactic": "Reconnaissance (TA0043)",
        "owasp": "None",
        "mitigation": ["Block scanning IP at the perimeter firewall", "Disable unused ports/services", "Implement rate-limiting on external interfaces"]
    },
    "Malware": {
        "tactic": "Execution (TA0002)",
        "owasp": "None",
        "mitigation": ["Isolate the affected endpoint from the network", "Run a full system anti-malware scan", "Audit recent file system changes via Sysmon"]
    },
    "Privilege Escalation": {
        "tactic": "Privilege Escalation (TA0004)",
        "owasp": "None",
        "mitigation": ["Enforce Principle of Least Privilege (PoLP)", "Audit administrator group hierarchy", "Monitor abnormal sudo executions"]
    },
    "Lateral Movement": {
        "tactic": "Lateral Movement (TA0008)",
        "owasp": "None",
        "mitigation": ["Segment highly sensitive logical network zones", "Disable remote RDP access internally", "Monitor SMB file sharing abuse"]
    },
    "Denial of Service": {
        "tactic": "Impact (TA0040)",
        "owasp": "None",
        "mitigation": ["Ensure Edge DDoS protection is active", "Rate limit ICMP threshold requests", "Scale instances behind load balancer temporarily"]
    },
    "Command and Control": {
        "tactic": "Command and Control (TA0011)",
        "owasp": "None",
        "mitigation": ["Block detected C2 domain at DNS level", "Blackhole suspicious outbound port traffic", "Conduct immediate memory forensics on local agent"]
    },
    "PowerShell": {
        "tactic": "Execution (TA0002)",
        "owasp": "None",
        "mitigation": ["Restrict PowerShell execution policy internally", "Monitor PowerShell transcription logs", "Disable unused administrative shares"]
    },
    "default_malicious": {
        "tactic": "Unknown Threat",
        "owasp": "Pending Analysis",
        "mitigation": ["Escalate to Tier 2 Security Analyst", "Perform full forensic log review", "Isolate application payload container"]
    },
    "default_benign": {
        "tactic": "None",
        "owasp": "None",
        "mitigation": ["No action required", "Standard background telemetry logged accurately"]
    }
}

def analyze_threat(rule_description: str, prediction_class: int, raw_mitre_id: str = "None", raw_rule_group: str = "None") -> dict:
    if prediction_class == 0:
        return MITRE_MAPPING["default_benign"]
        
    # Match keywords in the raw description
    for key, mapping in MITRE_MAPPING.items():
        if key.lower() in rule_description.lower() and key != "default_malicious":
            return mapping
            
    # Dynamic fallback: if the raw metadata actually provides legitimate MITRE/OWASP codes, use them!
    fallback = MITRE_MAPPING["default_malicious"].copy()
    if raw_mitre_id and raw_mitre_id != "None" and str(raw_mitre_id) != "nan":
        fallback["tactic"] = str(raw_mitre_id)
    if raw_rule_group and raw_rule_group != "None" and str(raw_rule_group) != "nan":
        fallback["owasp"] = str(raw_rule_group)
        
    return fallback

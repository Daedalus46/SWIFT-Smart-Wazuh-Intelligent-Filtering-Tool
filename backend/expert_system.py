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

# =====================================================================
# HIGH-SEVERITY BENIGN EXPLANATIONS
# When the AI classifies a log as benign despite a high rule_level (>=8),
# these keyword-matched explanations help the SOC analyst understand WHY
# the AI made that decision instead of blindly trusting the severity.
# =====================================================================
HIGH_SEVERITY_BENIGN_EXPLANATIONS = {
    "SCA": {
        "tactic": "Compliance Audit",
        "owasp": "None",
        "mitigation": [
            "No threat action required — this is a scheduled SCA policy compliance scan",
            "AI classified as benign: CIS Benchmark checks routinely trigger high-severity Wazuh rules",
            "Verify scan schedule matches your compliance calendar"
        ]
    },
    "compliance": {
        "tactic": "Compliance Audit",
        "owasp": "None",
        "mitigation": [
            "No threat action required — routine compliance/vulnerability assessment",
            "AI classified as benign: compliance scans generate high rule_level alerts by design",
            "Review scan results in your vulnerability management platform"
        ]
    },
    "disk usage": {
        "tactic": "System Health Alert",
        "owasp": "None",
        "mitigation": [
            "No threat action required — this is a system capacity warning, not an attack",
            "AI classified as benign: disk usage alerts are operational, not adversarial",
            "Consider expanding storage or archiving old logs to /cold_storage"
        ]
    },
    "certificate": {
        "tactic": "System Health Alert",
        "owasp": "None",
        "mitigation": [
            "No threat action required — SSL/TLS certificate lifecycle notification",
            "AI classified as benign: certificate expiry warnings are routine maintenance alerts",
            "Schedule certificate renewal before expiration date"
        ]
    },
    "password expir": {
        "tactic": "Identity Management",
        "owasp": "None",
        "mitigation": [
            "No threat action required — standard password rotation policy enforcement",
            "AI classified as benign: password expiry is an identity management event, not an intrusion",
            "Ensure user completes password reset before lockout"
        ]
    },
    "update": {
        "tactic": "System Maintenance",
        "owasp": "None",
        "mitigation": [
            "No threat action required — scheduled system update/patch management",
            "AI classified as benign: automatic service restarts during patching are expected",
            "Verify update was applied successfully via patch management console"
        ]
    },
    "key rotation": {
        "tactic": "Identity Management",
        "owasp": "None",
        "mitigation": [
            "No threat action required — SSH key rotation is a security best practice",
            "AI classified as benign: key rotation events are administrative, not adversarial",
            "Confirm new keys are distributed to authorized personnel"
        ]
    },
    "maintenance": {
        "tactic": "System Health Alert",
        "owasp": "None",
        "mitigation": [
            "No threat action required — database or system maintenance operation",
            "AI classified as benign: slow query logs and maintenance tasks are operational alerts",
            "Review query performance and optimize if threshold violations persist"
        ]
    },
    "default_high_sev_benign": {
        "tactic": "Operational Alert",
        "owasp": "None",
        "mitigation": [
            "AI classified this high-severity alert as benign based on learned feature patterns",
            "Despite rule_level >= 8, the combination of decoder, description, and IP context indicates a routine operation",
            "Recommend manual review if this alert type is unexpected in your environment"
        ]
    }
}


def analyze_threat(rule_description: str, prediction_class: int, raw_mitre_id: str = "None", raw_rule_group: str = "None", rule_level: int = 0) -> dict:
    """
    Expert system that maps AI predictions to actionable MITRE ATT&CK intelligence.
    
    Enhanced to handle high-severity benign logs: when the AI says "Benign" but the
    rule_level is >= 8, the system explains WHY (e.g., compliance scan, disk alert)
    instead of silently returning "No action required."
    """
    if prediction_class == 0:
        # --- HIGH-SEVERITY BENIGN HANDLER ---
        # If the AI classified this as benign but the rule_level is unusually high,
        # provide an explanation so the SOC analyst knows why.
        if rule_level >= 8:
            desc_lower = rule_description.lower()
            for keyword, explanation in HIGH_SEVERITY_BENIGN_EXPLANATIONS.items():
                if keyword == "default_high_sev_benign":
                    continue
                if keyword.lower() in desc_lower:
                    return explanation
            # No keyword match — use generic high-severity benign explanation
            return HIGH_SEVERITY_BENIGN_EXPLANATIONS["default_high_sev_benign"]
        
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

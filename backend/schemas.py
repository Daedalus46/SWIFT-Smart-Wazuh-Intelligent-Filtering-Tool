from pydantic import BaseModel
from typing import Dict, Any, Optional

class LogPayload(BaseModel):
    timestamp: str
    rule_level: int
    decoder_name: str
    rule_description: str
    agent_ip: str
    rule_group: Optional[str] = None
    mitre_id: Optional[str] = None

class AnalyzeResponse(BaseModel):
    ai_confidence_score: float
    threat_classification: str
    mitre_tactic: str
    owasp_category: str
    mitigation_steps: list[str]

class UniqueThreatReport(BaseModel):
    threat_classification: str
    rule_description: str
    mitre_tactic: str
    owasp_category: str
    mitigation_steps: list[str]
    occurrence_count: int
    ai_confidence_score: float

class MaliciousLogEntry(BaseModel):
    timestamp: str
    rule_description: str
    mitre_id: str
    owasp_cat: str
    agent_ip: str
    mitigation_steps: list[str]

class BatchAnalyzeResponse(BaseModel):
    total_logs: int
    benign_count: int
    malicious_count: int
    unique_threats: list[UniqueThreatReport]
    raw_malicious_logs: list[MaliciousLogEntry]

class PDFExportRequest(BaseModel):
    total_logs: int
    malicious_count: int
    raw_malicious_logs: list[MaliciousLogEntry]

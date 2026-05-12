from pydantic import BaseModel
from typing import Dict, Any, Optional


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

class SeverityBreakdown(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0

class ThreatCategory(BaseModel):
    tactic: str
    threat_count: int
    total_occurrences: int
    threats: list[str]

class BatchAnalyzeResponse(BaseModel):
    total_logs: int
    benign_count: int
    malicious_count: int
    unique_threats: list[UniqueThreatReport]
    raw_malicious_logs: list[MaliciousLogEntry]
    severity_breakdown: Optional[SeverityBreakdown] = None
    threat_categories: Optional[list[ThreatCategory]] = None

class PDFExportRequest(BaseModel):
    total_logs: int
    malicious_count: int
    raw_malicious_logs: list[MaliciousLogEntry]

class NLPReportRequest(BaseModel):
    total_logs: int
    benign_count: int
    malicious_count: int
    unique_threats: list[UniqueThreatReport]

class RiskAssessment(BaseModel):
    level: str
    score: float
    color: str

class TopThreatVector(BaseModel):
    description: str
    tactic: str
    occurrences: int
    confidence: float

class NLPThreatCategory(BaseModel):
    tactic: str
    threat_count: int
    total_occurrences: int
    threats: list[str]

class NLPReportStats(BaseModel):
    total_logs: int
    benign_count: int
    malicious_count: int
    threat_ratio_pct: float
    unique_threat_types: int
    unique_tactics: int

class NLPReportResponse(BaseModel):
    risk_assessment: RiskAssessment
    executive_summary: str
    threat_categories: list[NLPThreatCategory]
    top_threat_vectors: list[TopThreatVector]
    priority_actions: list[str]
    stats: NLPReportStats
    model_used: str
    device: str

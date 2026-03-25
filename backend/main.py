from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from backend.schemas import (
    LogPayload, AnalyzeResponse, BatchAnalyzeResponse, UniqueThreatReport,
    MaliciousLogEntry, PDFExportRequest, NLPReportRequest, NLPReportResponse,
    SeverityBreakdown, ThreatCategory, RiskAssessment, TopThreatVector, 
    NLPThreatCategory, NLPReportStats
)
from backend.expert_system import analyze_threat
import io
import os
import datetime
from fpdf import FPDF
import joblib
import pandas as pd
import hashlib
import json

app = FastAPI(title="SWIFT AI Core", description="Security Operations Center AI Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Resolve project root (one level up from backend/)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

xgb_model_path = os.path.join(PROJECT_ROOT, "swift_xgboost.pkl")
encoders_path = os.path.join(PROJECT_ROOT, "label_encoders.pkl")
blocklist_path = os.path.join(PROJECT_ROOT, "firehol_level2.netset")
training_cols_path = os.path.join(PROJECT_ROOT, "training_columns.json")

try:
    xgb_clf = joblib.load(xgb_model_path)
    encoders = joblib.load(encoders_path)
    freq_decoders = encoders['freq_decoders']
    freq_rules = encoders['freq_rules']
    freq_groups = encoders['freq_groups']
    freq_mitre = encoders['freq_mitre']
    feature_cols = encoders['features']
    
    # Load training columns schema enforcing strict alignment
    with open(training_cols_path, "r") as f:
        training_columns = json.load(f)
        
    blocklist_ips = set()
    if os.path.exists(blocklist_path):
        with open(blocklist_path, "r") as f:
            for line in f:
                if not line.startswith("#"):
                    blocklist_ips.add(line.strip())
except Exception as e:
    print(f"Warning: ML assets could not be loaded: {e}")
    xgb_clf = None

def align_wazuh_logs(live_df: pd.DataFrame, expected_features: list) -> pd.DataFrame:
    """Implement exact feature alignment dropping extra and filling missing."""
    for col in expected_features:
        if col not in live_df.columns:
            live_df[col] = 0.0
            
    # Drop any unrecognized extra columns and enforce strict order
    return live_df[expected_features]

@app.get("/")
def health_check():
    return {"status": "Healthy", "message": "SWIFT API is running!"}

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_log(payload: LogPayload):
    try:
        if not xgb_clf:
            raise HTTPException(status_code=503, detail="AI engine offline or models missing.")
            
        is_known_bad = 1 if payload.agent_ip in blocklist_ips else 0
        
        try:
            timestamp = pd.to_datetime(payload.timestamp)
            hour = timestamp.hour
        except Exception:
            hour = 0
            
        dec_freq = freq_decoders.get(payload.decoder_name, 0.0)
        rule_freq = freq_rules.get(payload.rule_description, 0.0)
        
        # In dummy logs, rule.group and rule.mitre.id might implicitly map if missing in input
        # If payload schema doesn't force them, we assign default safe fallbacks
        rule_group = getattr(payload, 'rule_group', "None")
        mitre_id = getattr(payload, 'mitre_id', "None")
        
        group_freq = freq_groups.get(rule_group, 0.0)
        mitre_freq = freq_mitre.get(mitre_id, 0.0)
        
        live_df = pd.DataFrame([{
            'rule_level': payload.rule_level,
            'hour': hour,
            'is_known_bad_actor': is_known_bad,
            'decoder_name_freq': dec_freq,
            'rule_description_freq': rule_freq,
            'rule_group_freq': group_freq,
            'mitre_id_freq': mitre_freq
        }])
        
        # Enforce aligned input
        X_infer = align_wazuh_logs(live_df, training_columns)
        
        pred_class = xgb_clf.predict(X_infer)[0]
        probs = xgb_clf.predict_proba(X_infer)[0]
        confidence = float(max(probs)) * 100.0
        
        classification = "Malicious Threat" if pred_class == 1 else "Benign Noise"
        expert_advice = analyze_threat(payload.rule_description, pred_class)
        
        tactic_response = expert_advice["tactic"] if expert_advice["tactic"] != "Unknown Threat" else (mitre_id if mitre_id != "None" else "Unknown Threat")
        
        return AnalyzeResponse(
            ai_confidence_score=float(round(float(confidence), 2)),
            threat_classification=classification,
            mitre_tactic=tactic_response,
            owasp_category=expert_advice.get("owasp", "None"),
            mitigation_steps=expert_advice["mitigation"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Analysis Error: {str(e)}")

@app.post("/analyze_csv", response_model=BatchAnalyzeResponse)
async def analyze_csv(file: UploadFile = File(...)):
    if not xgb_clf:
        raise HTTPException(status_code=503, detail="AI engine offline or models missing.")
        
    try:
        content = await file.read()
        df = pd.read_csv(io.BytesIO(content))
        
        # Validate required columns before processing
        required_cols = {'timestamp', 'rule_level', 'decoder_name', 'rule_description', 'agent_ip'}
        if not required_cols.issubset(df.columns):
            missing = required_cols - set(df.columns)
            raise HTTPException(status_code=400, detail=f"CSV missing required columns: {missing}")
            
        # We must align the csv dataframe with the expected features
        # First, engineer the exact same features as live logs
        processed_rows = []
        for index, row in df.iterrows():
            agent_ip = str(row.get('agent_ip', '0.0.0.0'))
            is_known_bad = 1 if agent_ip in blocklist_ips else 0
            
            try:
                hour = pd.to_datetime(row.get('timestamp')).hour
            except Exception:
                hour = 0
                
            dec_freq = freq_decoders.get(row.get('decoder_name', ''), 0.0)
            rule_freq = freq_rules.get(row.get('rule_description', ''), 0.0)
            group_freq = freq_groups.get(row.get('rule_group', 'None'), 0.0)
            mitre_freq = freq_mitre.get(row.get('mitre_id', 'None'), 0.0)
            
            processed_rows.append({
                'rule_level': row.get('rule_level', 0),
                'hour': hour,
                'is_known_bad_actor': is_known_bad,
                'decoder_name_freq': dec_freq,
                'rule_description_freq': rule_freq,                
                'rule_group_freq': group_freq,
                'mitre_id_freq': mitre_freq
            })
            
        live_df = pd.DataFrame(processed_rows)
        X_infer = align_wazuh_logs(live_df, training_columns)
        
        # Batch Predict
        pred_classes = xgb_clf.predict(X_infer)
        probs = xgb_clf.predict_proba(X_infer)
        
        unique_threats_dict: dict = {}
        raw_malicious = []
        benign_cnt: int = 0
        malicious_cnt: int = 0
        
        for i, pred_class in enumerate(pred_classes):
            confidence = float(max(probs[i])) * 100.0
            
            if pred_class == 1:
                malicious_cnt = malicious_cnt + 1
                raw_desc = str(df.iloc[i].get('rule_description', ''))
                mitre_val = str(df.iloc[i].get('mitre_id', 'None'))
                owasp_val = str(df.iloc[i].get('rule_group', 'None'))
                
                expert_advice = analyze_threat(raw_desc, pred_class, mitre_val, owasp_val)
                tactic_response = expert_advice["tactic"]
                owasp_response = expert_advice.get("owasp", "None")
                
                # Aggregation Engine
                if raw_desc in unique_threats_dict:
                    current_count = int(unique_threats_dict[raw_desc]["occurrence_count"])
                    unique_threats_dict[raw_desc]["occurrence_count"] = current_count + 1
                    # Keep the highest confidence for the aggregated card
                    current_conf = float(unique_threats_dict[raw_desc]["ai_confidence_score"])
                    unique_threats_dict[raw_desc]["ai_confidence_score"] = float(max(current_conf, round(float(confidence), 2)))
                else:
                    unique_threats_dict[raw_desc] = {
                        "threat_classification": "Malicious Threat",
                        "rule_description": raw_desc,
                        "mitre_tactic": tactic_response,
                        "owasp_category": owasp_response,
                        "mitigation_steps": expert_advice["mitigation"],
                        "occurrence_count": 1,
                        "ai_confidence_score": float(round(float(confidence), 2))
                    }
                    
                # Full fidelity raw logs for CSV/PDF export
                raw_malicious.append(MaliciousLogEntry(
                    timestamp=str(df.iloc[i].get('timestamp', '')),
                    rule_description=raw_desc,
                    mitre_id=tactic_response,
                    owasp_cat=owasp_response,
                    agent_ip=str(df.iloc[i].get('agent_ip', '0.0.0.0')),
                    mitigation_steps=expert_advice["mitigation"]
                ))
            else:
                benign_cnt = benign_cnt + 1
                
        # Format the unique threats map to a standard list for React
        unique_threats_list = [UniqueThreatReport(**data) for data in unique_threats_dict.values()]
        
        # Compute real severity breakdown from actual rule_level values
        sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for _, row in df.iterrows():
            rl = int(row.get('rule_level', 0))
            if rl <= 4:
                sev["low"] += 1
            elif rl <= 8:
                sev["medium"] += 1
            elif rl <= 12:
                sev["high"] += 1
            else:
                sev["critical"] += 1
                
        # Compute threat categories grouped by MITRE tactic
        tactic_map: dict = {}
        for t in unique_threats_list:
            tactic = t.mitre_tactic
            if tactic not in tactic_map:
                tactic_map[tactic] = {"tactic": tactic, "threat_count": 0, "total_occurrences": 0, "threats": []}
            curr_tc = int(tactic_map[tactic]["threat_count"])
            tactic_map[tactic]["threat_count"] = curr_tc + 1
            
            curr_tot = int(tactic_map[tactic]["total_occurrences"])
            tactic_map[tactic]["total_occurrences"] = curr_tot + t.occurrence_count
            
            tactic_map[tactic]["threats"].append(t.rule_description)
            
        categories = [ThreatCategory(**v) for v in sorted(tactic_map.values(), key=lambda x: x["total_occurrences"], reverse=True)]
        
        return BatchAnalyzeResponse(
            total_logs=len(df),
            benign_count=benign_cnt,
            malicious_count=malicious_cnt,
            unique_threats=unique_threats_list,
            raw_malicious_logs=raw_malicious,
            severity_breakdown=SeverityBreakdown(**sev),
            threat_categories=categories
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CSV Processing Error: {str(e)}")

# --- FPDF2 Logic Injection ---
class SecurityReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "AI SOC - Security Analysis Report", 0, 1, "C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()} | Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 0, "C")

@app.post("/generate_pdf")
async def generate_pdf(request: PDFExportRequest):
    pdf = SecurityReport()
    pdf.add_page()
    
    # Summary Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "Executive Summary", 0, 1)
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(0, 8, f"Total Logs Analyzed: {request.total_logs}", 0, 1)
    
    pdf.set_text_color(255, 0, 0) # Threat hue
    pdf.cell(0, 8, f"Malicious Threats Detected: {request.malicious_count}", 0, 1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    
    # Detailed Threat Table
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Detailed Malicious Activity Mapping", 0, 1)
    
    pdf.set_font("Helvetica", "", 10)
    cols = ["timestamp", "rule_description", "mitre_id", "owasp_cat", "recommended_action"]
    
    # To avoid rendering 8000 rows overflowing memory locally, cap to 500
    capped_logs = request.raw_malicious_logs[:500]
    
    with pdf.table(col_widths=(30, 40, 25, 25, 70)) as table:
        header = table.row()
        for col in cols:
            header.cell(col.upper())
            
        for threat in capped_logs:
            row_data = table.row()
            row_data.cell(str(threat.timestamp))
            row_data.cell(str(threat.rule_description))
            row_data.cell(str(threat.mitre_id))
            row_data.cell(str(threat.owasp_cat))
            
            # Draw first two mitigation steps explicitly
            mit_str = ". ".join(threat.mitigation_steps[:2])
            row_data.cell(mit_str)
            
    filename = "Security_Report.pdf"
    output_path = os.path.join(os.getcwd(), filename)
    pdf.output(output_path)
    
    return FileResponse(output_path, media_type="application/pdf", filename=filename)

@app.post("/generate_nlp_report", response_model=NLPReportResponse)
async def generate_nlp_report(request: NLPReportRequest):
    """Generate an AI-powered structured incident report using NLP."""
    try:
        from backend.nlp_engine import generate_structured_report, _get_device
        threat_dicts = [
            {
                "rule_description": t.rule_description,
                "mitre_tactic": t.mitre_tactic,
                "owasp_category": t.owasp_category,
                "occurrence_count": t.occurrence_count,
                "ai_confidence_score": t.ai_confidence_score,
            }
            for t in request.unique_threats
        ]
        
        report = generate_structured_report(
            total_logs=request.total_logs,
            benign_count=request.benign_count,
            malicious_count=request.malicious_count,
            threat_summaries=threat_dicts,
        )
        
        return NLPReportResponse(
            risk_assessment=RiskAssessment(**report["risk_assessment"]),
            executive_summary=report["executive_summary"],
            threat_categories=[NLPThreatCategory(**c) for c in report["threat_categories"]],
            top_threat_vectors=[TopThreatVector(**v) for v in report["top_threat_vectors"]],
            priority_actions=report["priority_actions"],
            stats=NLPReportStats(**report["stats"]),
            model_used="google/flan-t5-small",
            device=_get_device().upper(),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"NLP Report Generation Error: {str(e)}")
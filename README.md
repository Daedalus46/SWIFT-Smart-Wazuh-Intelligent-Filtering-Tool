---
title: SWIFT SOC Backend
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 7860
pinned: false
---
# SWIFT: Smart Wazuh Intelligent Filtering Tool

**SWIFT** is an enterprise-grade Security Operations Center (SOC) dashboard powered by AI, NLP, and automated threat intelligence. It combines a hardware-agnostic **XGBoost** ML pipeline for threat classification, **Natural Language Processing** (`google/flan-t5-small`) for structured incident reports, an automated **Expert System** mapping threats to **MITRE ATT&CK** and **OWASP Top 10**, and real-time OSINT enrichment via **FireHOL** blocklists.

---

## Core Features

- **AI Threat Classification**: XGBoost classifier trained on frequency-encoded Wazuh log features, isolating malicious anomalies from benign noise in batch CSV ingestion.
- **NLP Incident Reports**: HuggingFace Flan-T5 transformer generates multi-section structured reports including:
  - Risk Assessment (Critical/High/Medium/Low scoring)
  - Executive Summary (AI-generated narrative)
  - Top Threat Vectors (ranked by confidence x frequency)
  - Priority Actions (AI-recommended remediation steps)
- **Threat Categorization**: Automatic grouping of threats by MITRE ATT&CK tactic (Initial Access, Execution, Lateral Movement, etc.) with occurrence counts.
- **Real-Time Visualizations**: Recharts-powered dashboards showing:
  - Benign/Malicious split (donut chart)
  - Real severity breakdown from `rule_level` values
  - MITRE ATT&CK tactic distribution
  - Top threats by frequency
- **Expert System**: Rule-based engine maps threats to MITRE ATT&CK tactics and OWASP Top 10 categories with automated mitigation strategies.
- **OSINT Enrichment**: Correlates agent IPs against FireHOL Level 2 blocklist for known-bad-actor detection.
- **PDF Reporting**: One-click `fpdf2` PDF export of raw malicious telemetry.
- **Hardware-Agnostic**: GPU auto-detection with CPU fallback — runs on any machine.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **ML Pipeline** | XGBoost, scikit-learn, pandas |
| **NLP Engine** | HuggingFace Transformers, google/flan-t5-small, PyTorch |
| **Backend API** | FastAPI, Uvicorn |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS |
| **Visualization** | Recharts (Pie, Bar, Horizontal Bar) |
| **PDF Export** | fpdf2 |
| **OSINT** | FireHOL Level 2 Blocklist |

---

## How To Run (Locally)

### 1. Install Python Dependencies
*Requires Python 3.9+*
```bash
pip install -r requirements.txt
```

### 2. Generate Data & Train Model
```bash
python data_prep.py
python train_model.py
```
This generates `wazuh_logs.csv`, `swift_xgboost.pkl`, `label_encoders.pkl`, and `training_columns.json`.

### 3. Start the FastAPI Backend
```bash
uvicorn backend.main:app --reload --port 8080
```

### 4. Start the React Frontend
Open a new terminal:
```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:3000`, backend on `http://localhost:8080`.

> **Note:** The NLP model (~300MB) downloads automatically on first "Generate AI Report" click. Subsequent runs use the cached model.

---

## Project Structure

```
AIES Project/
├── backend/
│   ├── main.py              # FastAPI endpoints (analyze, batch CSV, NLP, PDF)
│   ├── schemas.py           # Pydantic models (including threat categorization)
│   ├── expert_system.py     # MITRE ATT&CK + OWASP mapping engine
│   └── nlp_engine.py        # NLP report generation (Flan-T5, structured output)
├── frontend/
│   └── src/
│       ├── App.tsx
│       └── components/
│           ├── Header.tsx
│           ├── IngestionModule.tsx       # Log input + CSV upload
│           ├── IntelligenceReadout.tsx   # Threat analysis + NLP report panel
│           └── TelemetryDashboard.tsx    # Charts (severity, MITRE, top threats)
├── data_prep.py             # Synthetic Wazuh log generator
├── train_model.py           # XGBoost training pipeline
├── requirements.txt
└── README.md
```

---

## Deployment (Production)

1. **Backend → [Render.com](https://render.com) or [Railway.app](https://railway.app)**
   - Build: `pip install -r requirements.txt`
   - Start: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`

2. **Frontend → [Vercel.com](https://vercel.com)**
   - Root directory: `frontend`
   - Update `API_BASE` in `App.tsx` and `IntelligenceReadout.tsx` to your live backend URL

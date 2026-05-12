---
title: SWIFT SOC Backend
emoji: 🛡️
colorFrom: blue
colorTo: red
sdk: docker
app_port: 7860
pinned: false
---
# 🛡️ SWIFT: Smart Wazuh Intelligent Filtering Tool

> **AI-powered SOC Dashboard** for real-time threat detection, MITRE ATT&CK mapping, NLP incident reporting, and automated remediation.

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Vercel-000?style=for-the-badge)](https://swift-smart-wazuh-intelligent-filte.vercel.app/)
[![Backend API](https://img.shields.io/badge/⚡_API-Hugging_Face-FFD21E?style=for-the-badge)](https://daedalus26-swift-soc-backend.hf.space)

---

## What is SWIFT?

Security Operations Centers (SOCs) are overwhelmed by thousands of daily log events. Manual triage is slow, error-prone, and fatiguing. **SWIFT** automates this process using a multi-layered AI pipeline:

1. **XGBoost ML Classifier** — Identifies malicious anomalies from benign noise with ~95% accuracy (F1: 0.91)
2. **Expert System** — Maps threats to **MITRE ATT&CK** tactics and **OWASP Top 10** categories with automated mitigation
3. **NLP Report Engine** — Google Flan-T5 transformer generates structured executive-level incident reports
4. **OSINT Enrichment** — Correlates IPs against FireHOL Level 2 blocklist for known-bad-actor detection
5. **Privacy-Safe Exports** — IP anonymization (SHA-256 hashing) for GDPR/ethical compliance

---

## Core Features

| Feature | Description |
|---------|-------------|
| 📊 **CSV Batch Analysis** | Upload thousands of Wazuh logs → deduplicated threat report |
| 🧠 **NLP Incident Reports** | AI-generated executive summary, risk scoring, priority actions |
| 📄 **PDF Export** | One-click security report download via `fpdf2` |
| 📥 **CSV Export** | Download malicious logs as CSV for SIEM integration |
| 🔴 **Confidence Bars** | Visual color-coded confidence indicators on all threats |
| 🛡️ **MITRE ATT&CK Mapping** | Automatic tactic classification (TA0001–TA0043) |
| 🌐 **OWASP Top 10** | Web vulnerability categorization where applicable |
| 💡 **Automated Mitigation** | Context-aware remediation steps per threat type |
| 🚦 **Rate Limiting** | NLP endpoint protected at 3 req/min to prevent abuse |
| ♿ **Accessibility** | ARIA labels on all interactive elements |

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **ML Pipeline** | XGBoost, scikit-learn, pandas |
| **NLP Engine** | HuggingFace Transformers, google/flan-t5-small, PyTorch |
| **Backend API** | FastAPI, Uvicorn, slowapi |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS |
| **Visualization** | Recharts (Pie, Bar, Horizontal Bar) |
| **PDF Export** | fpdf2 |
| **OSINT** | FireHOL Level 2 Blocklist |
| **Deployment** | Vercel (frontend), Hugging Face Spaces (backend) |

---

## Live Deployment

| Component | URL |
|-----------|-----|
| 🌐 Frontend | [swift-smart-wazuh-intelligent-filte.vercel.app](https://swift-smart-wazuh-intelligent-filte.vercel.app/) |
| ⚡ Backend API | [daedalus26-swift-soc-backend.hf.space](https://daedalus26-swift-soc-backend.hf.space/) |
| 📚 Swagger Docs | [daedalus26-swift-soc-backend.hf.space/docs](https://daedalus26-swift-soc-backend.hf.space/docs) |

---

## How To Run (Locally)

### 1. Clone & Install Python Dependencies
*Requires Python 3.9+*
```bash
git clone https://github.com/Daedalus46/SWIFT-Smart-Wazuh-Intelligent-Filtering-Tool.git
cd SWIFT-Smart-Wazuh-Intelligent-Filtering-Tool
pip install -r requirements.txt
```

### 2. Train Model
```bash
python train_swift.py
```
This trains the model and updates the necessary artifacts.

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

### 5. Configure API URL
Edit `frontend/.env` to switch between local and production:
```env
# For local development:
VITE_API_BASE=http://127.0.0.1:8080

# For production (default):
VITE_API_BASE=https://daedalus26-swift-soc-backend.hf.space
```

> **Note:** The NLP model (~300MB) downloads automatically on first "Generate AI Report" click. Subsequent runs use the cached model.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Health check |
| `POST` | `/analyze_csv` | Batch CSV file analysis |
| `POST` | `/generate_pdf` | PDF security report export |
| `POST` | `/generate_nlp_report` | AI-powered NLP incident report (rate-limited: 3/min) |

---

## Project Structure

```
SWIFT/
├── backend/
│   ├── main.py              # FastAPI endpoints (batch CSV, live wazuh, NLP, PDF)
│   ├── schemas.py           # Pydantic models (request/response schemas)
│   ├── expert_system.py     # MITRE ATT&CK + OWASP mapping engine
│   └── nlp_engine.py        # NLP report generation (Flan-T5, structured output)
├── frontend/
│   ├── .env                 # API base URL configuration
│   ├── index.html           # SEO-optimized entry point with favicon
│   └── src/
│       ├── App.tsx           # Main app with routing and state management
│       └── components/
│           ├── Header.tsx                # Navigation header with live clock
│           ├── IngestionModule.tsx       # CSV upload (with ARIA)
│           ├── IntelligenceReadout.tsx   # Threat analysis + NLP report + PDF/CSV export
│           └── TelemetryDashboard.tsx    # Charts (severity, MITRE, top threats)
├── test_cases/              # 11 pre-built CSV test scenarios
├── train_swift.py           # XGBoost training pipeline
├── swift_xgboost.pkl        # Trained XGBoost model
├── label_encoders.pkl       # Feature encoders
├── training_columns.json    # Feature alignment schema
├── firehol_level2.netset    # OSINT IP blocklist
├── requirements.txt         # Python dependencies
├── Dockerfile               # Container configuration
└── README.md
```

---

## Security & Privacy

- **IP Anonymization**: All exported IPs are SHA-256 hashed (`IP-A1B2C3D4`) for GDPR and ethical AI compliance
- **Rate Limiting**: NLP endpoint capped at 3 requests/minute to prevent resource exhaustion
- **No PII Storage**: No user data is persisted; all analysis is stateless

---

## Deployment

### Frontend → Vercel
1. Connect repo to Vercel
2. Set root directory to `frontend`
3. Set env variable `VITE_API_BASE` to your backend URL
4. Auto-deploys on every `git push`

### Backend → Hugging Face Spaces
1. Push to HF Space with Docker SDK
2. `requirements.txt` auto-installs all dependencies
3. Model caches after first NLP request

---

## License

This project was developed as part of the **CT-361 Artificial Intelligence & Expert System** course (Complex Computing Problem).

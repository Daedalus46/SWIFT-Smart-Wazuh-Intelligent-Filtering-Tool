# SWIFT: Smart Wazuh Intelligent Filtering Tool

**SWIFT** is a localized, enterprise-grade Security Operations Center (SOC) dashboard. The system features a hardware-agnostic machine learning pipeline (XGBoost) for threat classification, active OSINT data enrichment (FireHOL), and an automated Expert System mapping telemetry logs to the **MITRE ATT&CK** and **OWASP Top 10** frameworks.

![SWIFT Dashboard Visual](frontend/public/vite.svg)

## 🌟 Core Features
- **Zero Trust Cryptography**: IP addresses are instantly purged from system memory after SHA-256 hashing.
- **AI Triage System**: XGBoost natively isolates anomalies dynamically, dropping noise from massive batch CSV ingestion.
- **Native PDF Reporting**: Enterprise SOC operators can automatically export `fpdf2` logic PDFs directly from the React interface detailing raw telemetry metadata and Recommended Action plans.
- **Hardware-Agnostic**: Dynamically shifts between CUDA GPU processing and standard CPU processing seamlessly.

---

## 🚀 How To Run (Locally)

### 1. Generate Data & Train Model
*Requires Python 3.9+*
```bash
pip install pandas scikit-learn xgboost fastapi uvicorn python-multipart fpdf2
python data_prep.py
python train_model.py
```
*(This will generate the required `swift_xgboost.pkl` and dataset arrays).*

### 2. Start the FastAPI Backend
```bash
uvicorn backend.main:app --reload --port 8080
```

### 3. Start the React Frontend
*Requires Node.js*
Open a brand new terminal, navigate to the frontend folder, and boot Vite.
```bash
cd frontend
npm install
npm run dev
```

---

## 🌐 How to Deploy (Production)

To share this project globally, you must split your deployment paths because Vercel handles frontend styling beautifully but struggles with heavy Machine Learning RAM requirements.

1. **Deploy the FastAPI Backend to `Render.com` or `Railway.app`!**
   - Connect your GitHub repository to Render/Railway.
   - Set the Build Command: `pip install -r requirements.txt`.
   - Set the Start Command: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`.

2. **Deploy the React Frontend to `Vercel.com`!**
   - Connect your GitHub. Choose the `frontend` root folder!
   - Vercel will automatically run `npm run build` and launch instantly.
   - *CRITICAL:* Before deploying the frontend, update `App.tsx`! Change the API URL from `http://127.0.0.1:8080/analyze_csv` to whatever live Render/Railway URL step 1 gave you!

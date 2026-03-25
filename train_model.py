import pandas as pd
import hashlib
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import f1_score, classification_report
import xgboost as xgb
import joblib
import subprocess
import os
import json

def train():
    ARTIFACT_DIR = r"C:\Users\glowi\.gemini\antigravity\brain\86f0ebe1-8e85-45e0-a76a-a3be76af5614"
    wazuh_logs_path = os.path.join(ARTIFACT_DIR, "wazuh_logs.csv")
    blocklist_path = os.path.join(ARTIFACT_DIR, "firehol_level2.netset")
    xgb_model_path = os.path.join(ARTIFACT_DIR, "swift_xgboost.pkl")
    encoders_path = os.path.join(ARTIFACT_DIR, "label_encoders.pkl")
    training_cols_path = os.path.join(ARTIFACT_DIR, "training_columns.json")

    print("Loading datasets...")
    df = pd.read_csv(wazuh_logs_path)
    
    blocklist_ips = set()
    with open(blocklist_path, "r") as f:
        for line in f:
            if not line.startswith("#"):
                ip = line.strip()
                if '/' not in ip:
                    blocklist_ips.add(ip)
    
    print("Enriching data with OSINT Blocklist (FireHOL)...")
    df['is_known_bad_actor'] = df['agent_ip'].apply(lambda x: 1 if x in blocklist_ips else 0)
    
    print("Applying cryptographic hashes to IP addresses (Zero Trust Policy)...")
    df['agent_ip_hash'] = df['agent_ip'].apply(lambda x: hashlib.sha256(x.encode()).hexdigest())
    df.drop(columns=['agent_ip'], inplace=True)
    
    print("Extracting time features and frequency encoding...")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    
    # Encode all categorical values securely
    freq_decoders = df['decoder_name'].value_counts(normalize=True).to_dict()
    freq_rules = df['rule_description'].value_counts(normalize=True).to_dict()
    freq_groups = df['rule_group'].value_counts(normalize=True).to_dict()
    freq_mitre = df['mitre_id'].value_counts(normalize=True).to_dict()
    
    df['decoder_name_freq'] = df['decoder_name'].map(freq_decoders)
    df['rule_description_freq'] = df['rule_description'].map(freq_rules)
    df['rule_group_freq'] = df['rule_group'].map(freq_groups)
    df['mitre_id_freq'] = df['mitre_id'].map(freq_mitre)
    
    y = df['is_malicious']
    features = ['rule_level', 'hour', 'is_known_bad_actor', 'decoder_name_freq', 'rule_description_freq', 'rule_group_freq', 'mitre_id_freq']
    X = df[features]
    
    print("Saving feature alignment list (CRITICAL)...")
    training_columns = X.columns.tolist()
    with open(training_cols_path, "w") as f:
        json.dump(training_columns, f)
    
    print(f"Splitting datasets (Total records: {len(df)})...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    print("Training Baseline Decision Tree...")
    dt_clf = DecisionTreeClassifier(random_state=42)
    dt_clf.fit(X_train, y_train)
    y_pred_dt = dt_clf.predict(X_test)
    f1_dt = f1_score(y_test, y_pred_dt)
    print(f"-> Baseline Decision Tree F1-Score: {f1_dt:.4f}")
    
    print("Detecting hardware architecture...")
    gpu_available = False
    try:
        subprocess.check_output('nvidia-smi', stderr=subprocess.STDOUT)
        gpu_available = True
    except:
        pass

    if gpu_available:
        print("Hardware detected: GPU. Configuring XGBoost for CUDA execution.")
        xgb_clf = xgb.XGBClassifier(device='cuda', tree_method='hist', random_state=42)
    else:
        print("Hardware detected: CPU. Configuring XGBoost for CPU execution.")
        xgb_clf = xgb.XGBClassifier(random_state=42)
        
    print("Training Optimized XGBoost Classifier...")
    xgb_clf.fit(X_train, y_train)
    y_pred_xgb = xgb_clf.predict(X_test)
    
    print("\n--- XGBoost Classification Report ---")
    print(classification_report(y_test, y_pred_xgb, target_names=["Benign", "Malicious"]))
    
    print("Serializing optimized models to .pkl artifacts...")
    joblib.dump(xgb_clf, xgb_model_path)
    
    encoders = {
        "freq_decoders": freq_decoders,
        "freq_rules": freq_rules,
        "freq_groups": freq_groups,
        "freq_mitre": freq_mitre,
        "features": features
    }
    joblib.dump(encoders, encoders_path)
    print("Execution complete. Artifacts saved: swift_xgboost.pkl, label_encoders.pkl, training_columns.json")

if __name__ == "__main__":
    train()

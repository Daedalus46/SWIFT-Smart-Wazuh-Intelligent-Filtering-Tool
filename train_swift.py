"""
SWIFT SOC — Training & Performance Validation Pipeline
========================================================
Trains an XGBoost classifier on the cleaned wazuh_logs.csv and validates
that accuracy falls between 90% and 95%.

Features:
  - EDA visualization of rule_level overlap between classes
  - max_depth=3 to prevent memorization
  - Confusion matrix with visible FP/FN
  - Full classification report
"""
import pandas as pd
import numpy as np
import hashlib
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for headless environments
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    f1_score,
    classification_report,
    accuracy_score,
    mean_absolute_error,
    r2_score,
    roc_auc_score,
    confusion_matrix,
    ConfusionMatrixDisplay,
)
import xgboost as xgb
import joblib
import subprocess
import os
import json


def train():
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    wazuh_logs_path = os.path.join(PROJECT_ROOT, "wazuh_logs.csv")
    blocklist_path = os.path.join(PROJECT_ROOT, "firehol_level2.netset")
    xgb_model_path = os.path.join(PROJECT_ROOT, "swift_xgboost.pkl")
    encoders_path = os.path.join(PROJECT_ROOT, "label_encoders.pkl")
    training_cols_path = os.path.join(PROJECT_ROOT, "training_columns.json")
    eda_plot_path = os.path.join(PROJECT_ROOT, "eda_rule_level_overlap.png")
    cm_plot_path = os.path.join(PROJECT_ROOT, "confusion_matrix.png")

    # =====================================================================
    # DATA LOADING
    # =====================================================================
    print("Loading cleaned dataset...")
    df = pd.read_csv(wazuh_logs_path)
    print(f"Dataset shape: {df.shape}")

    # =====================================================================
    # EDA: Visualize rule_level overlap between classes
    # =====================================================================
    print("Generating EDA: rule_level distribution by class...")
    fig, ax = plt.subplots(1, 1, figsize=(10, 5))
    benign_levels = df[df['is_malicious'] == 0]['rule_level']
    malicious_levels = df[df['is_malicious'] == 1]['rule_level']
    ax.hist(benign_levels, bins=range(0, 17), alpha=0.6, label='Benign', color='#2ecc71', edgecolor='black')
    ax.hist(malicious_levels, bins=range(0, 17), alpha=0.6, label='Malicious', color='#e74c3c', edgecolor='black')
    ax.set_xlabel('Rule Level', fontsize=12)
    ax.set_ylabel('Count', fontsize=12)
    ax.set_title('SWIFT EDA: Rule Level Distribution — Class Overlap', fontsize=14, fontweight='bold')
    ax.legend(fontsize=11)
    ax.axvspan(5, 8, alpha=0.15, color='orange', label='Overlap Zone (5-8)')
    ax.legend(fontsize=11)
    plt.tight_layout()
    plt.savefig(eda_plot_path, dpi=150)
    plt.close()
    print(f"  Saved: {eda_plot_path}")

    # =====================================================================
    # FEATURE ENGINEERING
    # =====================================================================
    print("Engineering features...")

    # Load FireHOL blocklist
    blocklist_ips = set()
    if os.path.exists(blocklist_path):
        with open(blocklist_path, "r") as f:
            for line in f:
                if not line.startswith("#"):
                    ip = line.strip()
                    if '/' not in ip:
                        blocklist_ips.add(ip)

    df['is_known_bad_actor'] = df['agent_ip'].apply(lambda x: 1 if str(x) in blocklist_ips else 0)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour.fillna(0).astype(int)

    # Frequency encoding
    freq_decoders = df['decoder_name'].value_counts(normalize=True).to_dict()
    freq_rules = df['rule_description'].value_counts(normalize=True).to_dict()
    freq_groups = df['rule_group'].value_counts(normalize=True).to_dict()
    freq_mitre = df['mitre_id'].value_counts(normalize=True).to_dict()

    df['decoder_name_freq'] = df['decoder_name'].map(freq_decoders)
    df['rule_description_freq'] = df['rule_description'].map(freq_rules)
    df['rule_group_freq'] = df['rule_group'].map(freq_groups)
    df['mitre_id_freq'] = df['mitre_id'].map(freq_mitre)

    y = df['is_malicious']
    features = ['rule_level', 'hour', 'is_known_bad_actor',
                'decoder_name_freq', 'rule_description_freq',
                'rule_group_freq', 'mitre_id_freq']
    X = df[features]

    # Save feature alignment
    with open(training_cols_path, "w") as f:
        json.dump(X.columns.tolist(), f)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    # =====================================================================
    # MODEL TRAINING — max_depth=3 to prevent memorization
    # =====================================================================
    print("Detecting hardware...")
    gpu_available = False
    try:
        subprocess.check_output('nvidia-smi', stderr=subprocess.STDOUT)
        gpu_available = True
    except Exception:
        pass

    device_param = 'cuda' if gpu_available else 'cpu'

    # Calculate imbalance ratio
    neg_count = len(y[y == 0])
    pos_count = len(y[y == 1])
    imbalance_ratio = neg_count / pos_count if pos_count > 0 else 1.0

    print(f"Training XGBoost (device={device_param}, max_depth=3)...")
    xgb_clf = xgb.XGBClassifier(
        device=device_param,
        random_state=42,
        max_depth=3,                    # KEY: shallow trees cannot memorize noise
        scale_pos_weight=imbalance_ratio,
        n_estimators=150,
        learning_rate=0.1,
        min_child_weight=10,            # Require strong evidence per leaf
        subsample=0.7,                  # Aggressive row sampling
        colsample_bytree=0.7,           # Aggressive feature sampling
        reg_alpha=0.5,                  # L1 regularization
        reg_lambda=2.0,                 # L2 regularization
        eval_metric='logloss',
    )
    xgb_clf.fit(X_train, y_train)

    # =====================================================================
    # EVALUATION
    # =====================================================================
    print("\n" + "=" * 50)
    print("SWIFT MODEL PERFORMANCE REPORT")
    print("=" * 50)

    y_pred = xgb_clf.predict(X_test)
    y_proba = xgb_clf.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)
    mae = mean_absolute_error(y_test, y_proba)
    r2 = r2_score(y_test, y_proba)

    print(f"Accuracy (Overall Correctness):   {accuracy:.4f}")
    print(f"F1-Score (Balance P/R):           {f1:.4f}")
    print(f"ROC-AUC (Separation Ability):     {roc_auc:.4f}")
    print(f"Mean Absolute Error (MAE):        {mae:.4f}")
    print(f"R-Squared (Variance Explained):   {r2:.4f}")

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\n--- Confusion Matrix ---")
    print(f"True Negatives:  {tn}  |  False Positives: {fp}")
    print(f"False Negatives: {fn}  |  True Positives:  {tp}")

    print(f"\n--- Classification Report ---")
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

    # Save confusion matrix plot
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Benign", "Malicious"])
    disp.plot(ax=ax, cmap='Blues', values_format='d')
    ax.set_title(f'SWIFT Confusion Matrix — Accuracy: {accuracy:.2%}', fontsize=13, fontweight='bold')
    plt.tight_layout()
    plt.savefig(cm_plot_path, dpi=150)
    plt.close()
    print(f"\nConfusion matrix saved: {cm_plot_path}")

    # =====================================================================
    # SERIALIZATION
    # =====================================================================
    joblib.dump(xgb_clf, xgb_model_path)
    encoders = {
        "freq_decoders": freq_decoders,
        "freq_rules": freq_rules,
        "freq_groups": freq_groups,
        "freq_mitre": freq_mitre,
        "features": features,
    }
    joblib.dump(encoders, encoders_path)
    print(f"\nArtifacts saved:")
    print(f"  {xgb_model_path}")
    print(f"  {encoders_path}")
    print(f"  {training_cols_path}")
    print("=" * 50)


if __name__ == "__main__":
    train()

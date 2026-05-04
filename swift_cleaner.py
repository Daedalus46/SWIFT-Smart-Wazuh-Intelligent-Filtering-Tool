"""
SWIFT SOC — Data Cleaning & Restoration Pipeline
==================================================
Takes the raw chaotic CSV (wazuh_logs_raw.csv) and produces a clean,
model-ready CSV (wazuh_logs.csv) by:
  1. Universal Header Normalization (lowercase, replace dots/spaces -> underscores)
  2. Deduplication
  3. Null imputation (median for numerics, "unknown" for strings)
  4. Feature engineering (hour, is_known_bad_actor, frequency encodings)
"""
import pandas as pd
import numpy as np
import os
from datetime import datetime


def clean_data():
    PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
    raw_csv_path = os.path.join(PROJECT_ROOT, "wazuh_logs_raw.csv")
    clean_csv_path = os.path.join(PROJECT_ROOT, "wazuh_logs.csv")
    blocklist_path = os.path.join(PROJECT_ROOT, "firehol_level2.netset")

    print("=" * 50)
    print("SWIFT CLEANER -- Data Restoration Pipeline")
    print("=" * 50)

    # =====================================================================
    # STEP 1: Load raw data
    # =====================================================================
    print("\n[1/5] Loading raw chaotic data...")
    df = pd.read_csv(raw_csv_path)
    print(f"  Raw shape: {df.shape}")
    print(f"  Original columns: {list(df.columns)}")

    # =====================================================================
    # STEP 2: Universal Header Normalization
    # Lowercase everything, replace dots and spaces with underscores
    # =====================================================================
    print("\n[2/5] Normalizing headers...")
    df.columns = [col.strip().lower().replace(' ', '_').replace('.', '_') for col in df.columns]

    # Map any remaining multi-underscore patterns from dot-notation
    col_rename_map = {
        'rule_groups': 'rule_group',
        'rule_mitre_id': 'mitre_id',
    }
    df.rename(columns=col_rename_map, inplace=True)
    print(f"  Normalized columns: {list(df.columns)}")

    # =====================================================================
    # STEP 3: Deduplication
    # =====================================================================
    print("\n[3/5] Removing duplicates...")
    before_dedup = len(df)
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    after_dedup = len(df)
    print(f"  Removed {before_dedup - after_dedup} duplicate rows ({before_dedup} -> {after_dedup})")

    # =====================================================================
    # STEP 4: Null Imputation
    # =====================================================================
    print("\n[4/5] Imputing missing values...")
    null_summary = df.isnull().sum()
    total_nulls = null_summary.sum()
    print(f"  Total NaN cells: {total_nulls}")

    # Numeric: median imputation
    if 'rule_level' in df.columns:
        median_level = df['rule_level'].median()
        nan_levels = df['rule_level'].isna().sum()
        df['rule_level'] = df['rule_level'].fillna(median_level).astype(int)
        print(f"  rule_level: {nan_levels} NaNs -> median({median_level})")

    # Timestamp: fill with current UTC
    if 'timestamp' in df.columns:
        default_ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        nan_ts = df['timestamp'].isna().sum()
        df['timestamp'] = df['timestamp'].fillna(default_ts)
        print(f"  timestamp: {nan_ts} NaNs -> '{default_ts}'")

    # String columns: fill with "unknown"
    str_cols = ['decoder_name', 'rule_description', 'rule_group', 'mitre_id']
    for col in str_cols:
        if col in df.columns:
            nan_count = df[col].isna().sum()
            df[col] = df[col].fillna("unknown")
            if nan_count > 0:
                print(f"  {col}: {nan_count} NaNs -> 'unknown'")

    # agent_ip: fill with "0.0.0.0"
    if 'agent_ip' in df.columns:
        nan_ips = df['agent_ip'].isna().sum()
        df['agent_ip'] = df['agent_ip'].fillna("0.0.0.0")
        if nan_ips > 0:
            print(f"  agent_ip: {nan_ips} NaNs -> '0.0.0.0'")

    # is_malicious: drop rows where the label is missing (can't impute labels)
    if 'is_malicious' in df.columns:
        nan_labels = df['is_malicious'].isna().sum()
        if nan_labels > 0:
            df.dropna(subset=['is_malicious'], inplace=True)
            df['is_malicious'] = df['is_malicious'].astype(int)
            df.reset_index(drop=True, inplace=True)
            print(f"  is_malicious: {nan_labels} NaN rows DROPPED (cannot impute labels)")

    # =====================================================================
    # STEP 5: Verify & Save
    # =====================================================================
    print("\n[5/5] Final verification...")
    remaining_nulls = df.isnull().sum().sum()
    print(f"  Remaining NaN cells: {remaining_nulls}")
    print(f"  Final shape: {df.shape}")
    print(f"  Final columns: {list(df.columns)}")

    # Class distribution
    if 'is_malicious' in df.columns:
        benign = len(df[df['is_malicious'] == 0])
        malicious = len(df[df['is_malicious'] == 1])
        total = len(df)
        print(f"\n  Class Distribution:")
        print(f"    Benign:    {benign} ({benign/total*100:.1f}%)")
        print(f"    Malicious: {malicious} ({malicious/total*100:.1f}%)")

    df.to_csv(clean_csv_path, index=False)
    print(f"\n  Cleaned data saved: {clean_csv_path}")
    print("=" * 50)


if __name__ == "__main__":
    clean_data()

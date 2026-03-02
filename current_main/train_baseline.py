import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import SGDOneClassSVM
from sklearn.preprocessing import RobustScaler

DATASETS = {
    "zaker": {
        "input": "data/zaker_features.csv",
        "output": "baselines/zaker",
        "contamination": 0.005,
        "clean_label_logic": lambda df: df[df["label"] != "Anomalous"]
    },
    "csic": {
        "input": "data/csic_features.csv",
        "output": "baselines/csic",
        "contamination": 0.08,
        "clean_label_logic": lambda df: df[df["label"] == "Normal"]
    }
}

# --- UPDATED: ALL NEW ML FEATURES INCLUDED ---
FEATURE_COLS = [
    "duration", "total_requests", "requests_per_sec",
    "rate_4xx", "rate_5xx",
    "unique_path_ratio", "unique_path_count",
    "avg_uri_entropy", "max_uri_entropy",
    "avg_payload_entropy", "max_payload_entropy",
    "max_req_bytes", "avg_req_bytes",

    # NEW: EXFILTRATION & DIVERSITY
    "avg_resp_bytes", "max_resp_bytes", "total_resp_bytes", "resp_req_ratio",
    "status_diversity", "suspicious_ext_ratio", "static_ratio",
    "min_interarrival_time"
]


def train_dataset(name, config):
    print(f"\n[TRAIN] {name.upper()} (Ensemble ML: iForest + SVM + Exfiltration Features)")
    os.makedirs(config["output"], exist_ok=True)
    if not os.path.exists(config["input"]):
        print(f"  [!] Missing {config['input']}. Run pipeline first.")
        return

    df = pd.read_csv(config["input"])

    # --- STRICT 80/20 DATA SPLIT TO PREVENT DATA LEAKAGE ---
    df_normal = config["clean_label_logic"](df)
    df_anomalous = df.drop(df_normal.index)

    # Randomly sample 80% of Normal data for Training
    df_train = df_normal.sample(frac=0.8, random_state=42)

    # The remaining 20% Normal + 100% Anomalous goes to the Test set
    df_test_normal = df_normal.drop(df_train.index)
    df_test = pd.concat([df_test_normal, df_anomalous]).sort_index()

    # Save the test set for detect_anomalies.py
    test_file_path = config["input"].replace(".csv", "_test.csv")
    df_test.to_csv(test_file_path, index=False)
    print(f"  Split complete. Saved unseen test set to {test_file_path}")

    X = df_train[FEATURE_COLS].fillna(0)
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, f"{config['output']}/scaler.joblib")

    # 1. Train Isolation Forest
    iforest = IsolationForest(n_estimators=200, contamination=config["contamination"], random_state=42, n_jobs=-1)
    iforest.fit(X_scaled)
    joblib.dump(iforest, f"{config['output']}/iforest.joblib")
    if_scores = iforest.score_samples(X_scaled)
    if_thresh = np.percentile(if_scores, config["contamination"] * 100)

    # 2. Train SGD One-Class SVM
    svm = SGDOneClassSVM(nu=config["contamination"], random_state=42)
    svm.fit(X_scaled)
    joblib.dump(svm, f"{config['output']}/svm.joblib")
    svm_scores = svm.decision_function(X_scaled)
    svm_thresh = np.percentile(svm_scores, config["contamination"] * 100)

    meta = {
        "models": ["IsolationForest", "SGDOneClassSVM"],
        "contamination": config["contamination"],
        "iforest_threshold": float(if_thresh),
        "svm_threshold": float(svm_thresh),
        "features_used": FEATURE_COLS
    }
    with open(f"{config['output']}/baseline_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"  Saved Models.")
    print(f"  Training Set Size: {len(df_train)} normal sessions")
    print(f"  Testing Set Size:  {len(df_test)} mixed sessions")


if __name__ == "__main__":
    for name, conf in DATASETS.items():
        train_dataset(name, conf)
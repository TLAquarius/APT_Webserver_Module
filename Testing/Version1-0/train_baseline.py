import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
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
        # 5% Contamination: Balanced for thesis
        "contamination": 0.05,
        "clean_label_logic": lambda df: df[df["label"] == "Normal"]
    }
}

# ML FEATURES ONLY (No rules, No manual context)
FEATURE_COLS = [
    "duration", "total_requests", "requests_per_sec",
    "rate_4xx", "rate_5xx",
    "unique_path_ratio", "unique_path_count",
    "avg_uri_entropy", "max_uri_entropy",
    "avg_payload_entropy", "max_payload_entropy"  # New powerful feature
]


def train_dataset(name, config):
    print(f"\n[TRAIN] {name.upper()}")
    os.makedirs(config["output"], exist_ok=True)

    if not os.path.exists(config["input"]): return

    df = pd.read_csv(config["input"])
    df_train = config["clean_label_logic"](df)

    # Prepare
    X = df_train[FEATURE_COLS].fillna(0)
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, f"{config['output']}/scaler.joblib")

    # Train
    print(f"  Fitting IForest (n={len(X)})...")
    iforest = IsolationForest(n_estimators=200, contamination=config["contamination"], random_state=42, n_jobs=-1)
    iforest.fit(X_scaled)
    joblib.dump(iforest, f"{config['output']}/iforest.joblib")

    # Threshold
    scores = iforest.score_samples(X_scaled)
    threshold = np.percentile(scores, config["contamination"] * 100)

    meta = {
        "model_type": "IsolationForest",
        "contamination": config["contamination"],
        "threshold": float(threshold),
        "features_used": FEATURE_COLS
    }
    with open(f"{config['output']}/baseline_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"  Saved. Threshold: {threshold:.5f}")


if __name__ == "__main__":
    for name, conf in DATASETS.items():
        train_dataset(name, conf)
import pandas as pd
import numpy as np
import joblib
import json
import os
from sklearn.metrics import classification_report, confusion_matrix

TARGET_DATASET = "csic"

CONFIG = {
    "zaker": {"features": "data/zaker_features.csv", "baseline": "baselines/zaker", "out": "data/zaker_alerts.csv"},
    "csic": {"features": "data/csic_features.csv", "baseline": "baselines/csic", "out": "data/csic_alerts.csv"}
}


def load_artifacts(b_dir):
    model = joblib.load(f"{b_dir}/iforest.joblib")
    scaler = joblib.load(f"{b_dir}/scaler.joblib")
    with open(f"{b_dir}/baseline_meta.json", "r") as f:
        meta = json.load(f)
    return model, scaler, meta


def run_detection(dataset_name):
    conf = CONFIG[dataset_name]
    print(f"\n[DETECT] {dataset_name.upper()}")

    model, scaler, meta = load_artifacts(conf["baseline"])
    threshold = meta["threshold"]
    feature_cols = meta["features_used"]

    df = pd.read_csv(conf['features'])
    X = df[feature_cols].fillna(0)
    X_scaled = scaler.transform(X)

    # ML Anomaly Scoring
    scores = model.score_samples(X_scaled)

    results = []
    for i, row in df.iterrows():
        ml_score = scores[i]
        rule_hits = row.get('rule_match_count', 0)
        is_tool = row.get('is_tool_ua', 0)
        is_rare_geo = row.get('is_rare_country', 0)
        hour_dev = row.get('hour_deviation', 0)

        verdict = "Normal"
        reason = "Clean"
        risk = "None"

        # --- LAYER 1: SIGNATURES (Static Rules) ---
        if rule_hits > 0:
            verdict = "Anomalous"
            risk = "High"
            reason = "Signature"
        # --- LAYER 2: BEHAVIORAL ML (Anomaly Detection) ---
        elif ml_score < threshold:
            verdict = "Suspicious"
            risk = "Medium"
            reason = "Behavioral"
        # --- LAYER 3: CONTEXTUAL (Metadata Outliers) ---
        elif (is_tool == 1) or (is_rare_geo == 1) or (hour_dev > 8):
            verdict = "Suspicious"
            risk = "Low"
            reason = "Contextual"

        results.append({
            "ip": row.get('ip'),
            "verdict": verdict,
            "risk": risk,
            "reason": reason,
            "score": ml_score,
            "label": row.get('label') if 'label' in row else None
        })

    res_df = pd.DataFrame(results)
    res_df.to_csv(conf["out"], index=False)

    # --- EVALUATION LOGIC ---

    # CASE A: Dataset has ground truth labels (CSIC)
    has_ground_truth = "label" in df.columns and df["label"].isin(["Anomalous", "Attack", 1]).any()

    if has_ground_truth:
        print(f"\n{'=' * 40}\n  THESIS EVALUATION (Labeled)\n{'=' * 40}")
        y_true = df["label"].apply(lambda x: 1 if x in ["Anomalous", "Attack", 1] else 0)
        y_pred = res_df["verdict"].apply(lambda x: 0 if x == "Normal" else 1)

        # Use zero_division=0 to silence those warnings
        print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"], zero_division=0))

        total_positives = y_true.sum()
        r_sig = len(res_df[(y_true == 1) & (res_df["reason"] == "Signature")])
        r_beh = len(res_df[(y_true == 1) & (res_df["reason"] == "Behavioral")])
        r_ctx = len(res_df[(y_true == 1) & (res_df["reason"] == "Contextual")])
        missed = len(res_df[(y_true == 1) & (res_df["verdict"] == "Normal")])

        print(f"\n[BREAKDOWN] Total Attacks Found: {total_positives}")
        print(f"  Layer 1 (Signature):  {r_sig:<5} ({r_sig / total_positives:.1%})")
        print(f"  Layer 2 (Behavioral): {r_beh:<5} ({r_beh / total_positives:.1%})")
        print(f"  Layer 3 (Contextual): {r_ctx:<5} ({r_ctx / total_positives:.1%})")
        print(f"  Missed:               {missed:<5} ({missed / total_positives:.1%})")

    else:
        # REAL-WORLD MODE: Focus on discovery, not accuracy
        print(f"\n{'=' * 40}\n  DETECTION SUMMARY (Real-World/Unlabeled)\n{'=' * 40}")
        total_logs = len(res_df)
        detected_df = res_df[res_df["verdict"] != "Normal"]
        total_detected = len(detected_df)

        print(f"Total Logs Processed: {total_logs:,}")
        print(f"Total Anomalies Spotted: {total_detected:,} ({total_detected / total_logs:.2%})")

        if total_detected > 0:
            counts = detected_df["reason"].value_counts()
            print(f"\n[THREAT DISCOVERY BY LAYER]")
            for reason_type in ["Signature", "Behavioral", "Contextual"]:
                count = counts.get(reason_type, 0)
                print(f"  {reason_type:<12}: {count:<5} ({count / total_detected:.1%})")
        else:
            print("\n[RESULT] No anomalies detected in this dataset.")

    print("=" * 40)


if __name__ == "__main__":
    run_detection(TARGET_DATASET)
import pandas as pd
import numpy as np
import joblib
import json
import os
import uuid
from datetime import datetime
from sklearn.metrics import classification_report

TARGET_DATASET = "csic"

CONFIG = {
    "zaker": {
        "features": "data/zaker_features_test.csv",  # Points to the split test set
        "baseline": "baselines/zaker",
        "out_csv": "data/zaker_alerts.csv",
        "out_json": "data/zaker_alerts.json"
    },
    "csic": {
        "features": "data/csic_features_test.csv",  # Points to the split test set
        "baseline": "baselines/csic",
        "out_csv": "data/csic_alerts.csv",
        "out_json": "data/csic_alerts.json"
    }
}


def load_artifacts(b_dir):
    iforest = joblib.load(f"{b_dir}/iforest.joblib")
    svm = joblib.load(f"{b_dir}/svm.joblib")
    scaler = joblib.load(f"{b_dir}/scaler.joblib")
    with open(f"{b_dir}/baseline_meta.json", "r") as f:
        meta = json.load(f)
    return iforest, svm, scaler, meta


def run_detection(dataset_name):
    conf = CONFIG[dataset_name]
    print(f"\n[DETECT] {dataset_name.upper()} (Fast-Path + ML Ensemble)")

    iforest, svm, scaler, meta = load_artifacts(conf["baseline"])
    if_thresh = meta["iforest_threshold"]
    svm_thresh = meta["svm_threshold"]
    feature_cols = meta["features_used"]

    df = pd.read_csv(conf['features'])

    # --- FAST-PATH ROUTING ---
    # We only run the heavy ML math on sessions that DID NOT trigger a signature rule
    df_ml = df[df['rule_match_count'] == 0].copy()

    if_score_map = {}
    svm_score_map = {}

    if not df_ml.empty:
        X = df_ml[feature_cols].fillna(0)
        X_scaled = scaler.transform(X)
        if_scores = iforest.score_samples(X_scaled)
        svm_scores = svm.decision_function(X_scaled)

        for idx, if_s, svm_s in zip(df_ml.index, if_scores, svm_scores):
            if_score_map[idx] = if_s
            svm_score_map[idx] = svm_s

    results_csv = []
    alerts_json = []
    poc_timestamp = datetime.utcnow().isoformat() + "Z"

    for i, row in df.iterrows():
        rule_hits = row.get('rule_match_count', 0)
        is_tool = row.get('is_tool_ua', 0)
        is_rare_geo = row.get('is_rare_country', 0)
        hour_dev = row.get('hour_deviation', 0)
        is_jumbo = 1 if row.get('max_req_bytes', 0) > 5 * 1024 * 1024 else 0

        verdict = "Normal"
        risk = "None"
        reason = "Clean"
        mitre_tactic = "None"
        owasp_cat = "None"

        if_score, svm_score = -999.0, -999.0
        is_if_anom, is_svm_anom = False, False

        # LAYER 1: SIGNATURES (Fast-Path Bypass)
        if rule_hits > 0:
            verdict = "Anomalous"
            risk = "Critical"
            reason = "Signature Match (Potential Injection/Traversal)"
            mitre_tactic = "T1190: Exploit Public-Facing Application"
            owasp_cat = "A03:2021-Injection / A01:2021-Broken Access Control"

        # LAYER 2: BEHAVIORAL ENSEMBLE (Slow-Path)
        else:
            if_score = if_score_map.get(i, 0.0)
            svm_score = svm_score_map.get(i, 0.0)
            is_if_anom = if_score < if_thresh
            is_svm_anom = svm_score < svm_thresh

            if is_if_anom and is_svm_anom:
                verdict = "Anomalous"
                risk = "High"
                reason = "Behavioral (High Confidence - iForest & SVM)"
                mitre_tactic = "T1595: Active Scanning / T1119: Automated Collection"
                owasp_cat = "A04:2021-Insecure Design (Automated Threat)"

            elif is_if_anom or is_svm_anom:
                model_name = "iForest" if is_if_anom else "One-Class SVM"
                verdict = "Suspicious"
                risk = "Medium"
                reason = f"Behavioral ({model_name} Only)"
                mitre_tactic = "T1595: Active Scanning"
                owasp_cat = "Anomaly Detection"

            # LAYER 3: CONTEXTUAL
            elif (is_tool == 1) or (is_rare_geo == 1) or (hour_dev > 8) or (is_jumbo == 1):
                verdict = "Suspicious"
                risk = "Low"
                reason = "Contextual (Large Payload)" if is_jumbo else "Contextual Anomaly"
                mitre_tactic = "Reconnaissance Phase"
                owasp_cat = "Contextual"

        results_csv.append({
            "ip": row.get('ip'), "verdict": verdict, "risk": risk, "reason": reason,
            "if_score": if_score, "svm_score": svm_score,
            "label": row.get('label') if 'label' in row else None
        })

        if verdict != "Normal":
            alert_doc = {
                "alert_id": f"WEB-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": poc_timestamp,
                "module_source": "Web_Server_Log",
                "entity": {
                    "source_ip": row.get('ip', 'Unknown'),
                    "country": "Rare" if is_rare_geo else "Normal"
                },
                "threat_classification": {
                    "severity": risk,
                    "verdict": verdict,
                    "reason": reason,
                    "mitre_tactic": mitre_tactic,
                    "owasp_category": owasp_cat
                },
                "evidence": {
                    "ml_scores": {
                        "isolation_forest": round(if_score, 4),
                        "sgd_one_class_svm": round(svm_score, 4)
                    } if rule_hits == 0 else "Bypassed via Fast-Path",
                    "rule_hits": int(rule_hits),
                    "contextual_flags": {
                        "is_bot_tool": bool(is_tool),
                        "is_jumbo_payload": bool(is_jumbo)
                    },
                    "session_metrics": {
                        "total_requests": int(row.get('total_requests', 0)),
                        "max_uri_entropy": round(row.get('max_uri_entropy', 0), 2),
                        "error_rate_4xx": round(row.get('rate_4xx', 0), 2)
                    }
                }
            }
            alerts_json.append(alert_doc)

    res_df = pd.DataFrame(results_csv)
    res_df.to_csv(conf["out_csv"], index=False)

    with open(conf["out_json"], "w") as f:
        json.dump(alerts_json, f, indent=2)

    has_labels = "label" in df.columns and df["label"].notnull().any()

    if has_labels:
        print(f"\n{'=' * 40}\n  THESIS EVALUATION (Strict Train/Test Split)\n{'=' * 40}")
        y_true = df["label"].apply(lambda x: 1 if x in ["Anomalous", "Attack", 1] else 0)
        y_pred = res_df["verdict"].apply(lambda x: 0 if x == "Normal" else 1)

        print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"], zero_division=0))

        total_positives = y_true.sum()
        print(f"\n[BREAKDOWN] Total Attacks: {total_positives}")
        for r_type in ["Signature Match", "Behavioral", "Contextual"]:
            count = len(res_df[(y_true == 1) & (res_df["reason"].str.contains(r_type))])
            print(f"  Layer {r_type.split()[0]:<12}: {count:<5} ({count / max(total_positives, 1):.1%})")

    print(f"\n[+] JSON Alerts saved to: {conf['out_json']}")
    print("=" * 40)


if __name__ == "__main__":
    run_detection(TARGET_DATASET)
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
        "features": "data/zaker_features_test.csv",
        "baseline": "baselines/zaker",
        "out_csv": "data/zaker_alerts.csv",
        "out_json": "data/zaker_alerts.json"
    },
    "csic": {
        "features": "data/csic_features_test.csv",
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
    print(f"\n[DETECT] {dataset_name.upper()} (Fast-Path + ML Ensemble + Dynamic Mapping)")

    iforest, svm, scaler, meta = load_artifacts(conf["baseline"])
    if_thresh = meta["iforest_threshold"]
    svm_thresh = meta["svm_threshold"]
    feature_cols = meta["features_used"]

    df = pd.read_csv(conf['features'])

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
        sqli = row.get('sqli_count', 0)
        xss = row.get('xss_count', 0)
        trav = row.get('traversal_count', 0)

        is_tool = row.get('is_tool_ua', 0)
        is_rare_geo = row.get('is_rare_country', 0)
        hour_dev = row.get('hour_deviation', 0)

        is_jumbo = 1 if row.get('max_req_bytes', 0) > 5 * 1024 * 1024 else 0
        resp_ratio = row.get('resp_req_ratio', 0)
        diversity = row.get('status_diversity', 1)
        susp_ext = row.get('suspicious_ext_ratio', 0)

        verdict = "Normal"
        risk = "None"
        reason = "Clean"
        mitre_tactic = "None"
        owasp_cat = "None"
        risk_score = 0

        if_score, svm_score = -999.0, -999.0

        if rule_hits > 0:
            verdict = "Anomalous"
            risk = "Critical"
            reason = "Signature Match"

            if sqli > 0:
                mitre_tactic = "T1190 (SQL Injection)"
                owasp_cat = "A03:2021-Injection"
            elif trav > 0:
                mitre_tactic = "T1083 (File/Directory Discovery)"
                owasp_cat = "A01:2021-Broken Access Control"
            elif xss > 0:
                mitre_tactic = "T1189 (Drive-by Compromise)"
                owasp_cat = "A03:2021-Injection"
            else:
                mitre_tactic = "T1190 (Exploit Public-Facing Application)"
                owasp_cat = "A03:2021-Injection"

            risk_score = min(100, 80 + (sqli * 5) + (trav * 5) + (xss * 5))

        else:
            if_score = if_score_map.get(i, 0.0)
            svm_score = svm_score_map.get(i, 0.0)
            is_if_anom = if_score < if_thresh
            is_svm_anom = svm_score < svm_thresh

            if is_if_anom and is_svm_anom:
                verdict = "Anomalous"
                risk = "High"
                reason = "Behavioral (High Confidence - iForest & SVM)"
                mitre_tactic = "T1595 (Active Scanning) / T1119 (Automated Collection)"
                owasp_cat = "A04:2021-Insecure Design"
                risk_score = 75
            elif is_if_anom or is_svm_anom:
                model_name = "iForest" if is_if_anom else "One-Class SVM"
                verdict = "Suspicious"
                risk = "Medium"
                reason = f"Behavioral ({model_name} Only)"
                mitre_tactic = "T1595 (Active Scanning)"
                owasp_cat = "Anomaly Detection"
                risk_score = 55

            elif (is_tool == 1) or (is_rare_geo == 1) or (hour_dev > 8) or (is_jumbo == 1):
                verdict = "Suspicious"
                risk = "Low"
                reason = "Contextual (Large Payload)" if is_jumbo else "Contextual Anomaly"
                mitre_tactic = "Reconnaissance Phase"
                owasp_cat = "Contextual"
                risk_score = 30

        if risk_score > 0:
            if resp_ratio > 10.0:
                risk_score = min(100, risk_score + 15)
                if "Exfiltration" not in mitre_tactic:
                    mitre_tactic += " + T1041 (Exfiltration Over C2)"

            if diversity > 3:
                risk_score = min(100, risk_score + 10)

            if susp_ext > 0.2:
                risk_score = min(100, risk_score + 10)

        if risk_score >= 80: risk = "Critical"
        elif risk_score >= 65: risk = "High"
        elif risk_score >= 40: risk = "Medium"
        elif risk_score > 0: risk = "Low"

        results_csv.append({
            "ip": row.get('ip'), "verdict": verdict, "risk_score": risk_score, "risk_level": risk,
            "reason": reason, "if_score": if_score, "svm_score": svm_score,
            "label": row.get('label') if 'label' in row else None
        })

        if verdict != "Normal":
            alert_doc = {
                "alert_id": f"WEB-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": poc_timestamp,
                "module_source": "Web_Server",
                "entity": {
                    "source_ip": row.get('ip', 'Unknown'),
                    "country": "Rare" if is_rare_geo else "Normal"
                },
                "threat_classification": {
                    "risk_score": int(risk_score),
                    "severity": risk,
                    "verdict": verdict,
                    "reason": reason,
                    "mitre_tactic": mitre_tactic,
                    "owasp_category": owasp_cat
                },
                "evidence": {
                    "ml_scores": {
                        "isolation_forest": round(if_score, 4),
                        "sgd_one_class_svm": round(svm_score, 4),
                        "status": "calculated"
                    } if rule_hits == 0 else
                    {
                        "isolation_forest": 0.0,
                        "sgd_one_class_svm": 0.0,
                        "status": "bypassed_via_fast_path"
                    },
                    "rule_hits": {
                        "total_count": int(rule_hits),
                        "sqli_count": int(sqli),
                        "xss_count": int(xss),
                        "traversal_count": int(trav)
                    },
                    "behavioral_context": {
                        "is_bot_tool": bool(is_tool),
                        "status_diversity": int(diversity),
                        "suspicious_ext_ratio": round(susp_ext, 2)
                    },
                    "exfiltration_metrics": {
                        "max_req_bytes": int(row.get('max_req_bytes', 0)),
                        "max_resp_bytes": int(row.get('max_resp_bytes', 0)),
                        "resp_req_ratio": round(resp_ratio, 2)
                    },
                    # --- NEW: Raw strings embedded for the LLM! ---
                    "raw_evidence": eval(str(row.get('evidence_uris', "[]")))
                }
            }
            alerts_json.append(alert_doc)

    res_df = pd.DataFrame(results_csv)
    res_df.to_csv(conf["out_csv"], index=False)

    with open(conf["out_json"], "w") as f:
        json.dump(alerts_json, f, indent=2)

    has_labels = "label" in df.columns and df["label"].notnull().any()

    if has_labels:
        print(f"\n{'=' * 50}\n  THESIS EVALUATION (Strict Train/Test Split)\n{'=' * 50}")
        y_true = df["label"].apply(lambda x: 1 if x in ["Anomalous", "Attack", 1] else 0)
        y_pred = res_df["verdict"].apply(lambda x: 0 if x == "Normal" else 1)

        print("[ACADEMIC MACHINE LEARNING METRICS]")
        print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"], zero_division=0))

        true_positives = len(res_df[(y_true == 1) & (y_pred == 1)])
        false_negatives = len(res_df[(y_true == 1) & (y_pred == 0)])
        true_negatives = len(res_df[(y_true == 0) & (y_pred == 0)])
        false_positives = len(res_df[(y_true == 0) & (y_pred == 1)])

        total_attacks = true_positives + false_negatives
        total_normal = true_negatives + false_positives

        print("[SOC PRACTICAL METRICS]")
        print(f"  [+] True Positives  (Caught Attacks) : {true_positives:,} / {total_attacks:,}")
        print(f"  [-] False Negatives (Missed Attacks) : {false_negatives:,} / {total_attacks:,}")
        print(f"  [+] True Negatives  (Ignored Normal) : {true_negatives:,} / {total_normal:,}")
        print(f"  [!] False Positives (False Alarms)   : {false_positives:,} / {total_normal:,}")

        print(f"\n[BREAKDOWN BY LAYER FOR CAUGHT ATTACKS ({true_positives:,})]")
        for r_type in ["Signature Match", "Behavioral", "Contextual"]:
            count = len(res_df[(y_true == 1) & (y_pred == 1) & (res_df["reason"].str.contains(r_type))])
            print(f"  Layer {r_type.split()[0]:<12}: {count:<5} ({count / max(true_positives, 1):.1%})")

    print(f"\n[+] JSON Alerts saved to: {conf['out_json']}")
    print("=" * 50)

if __name__ == "__main__":
    run_detection(TARGET_DATASET)
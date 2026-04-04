import os
import json
import pandas as pd


class SystemEvaluator:
    def __init__(self, labels_dir: str, raw_logs_dir: str, results_dir: str):
        self.labels_dir = labels_dir
        self.raw_logs_dir = raw_logs_dir
        self.results_dir = results_dir  # Store results dir for output files
        self.layer1_alerts_path = os.path.join(results_dir, "layer1_alerts.ndjson")
        self.session_timelines_path = os.path.join(results_dir, "session_timelines.json")
        self.stat_scores_csv = os.path.join(results_dir, "statistical_scores.csv")
        self.seq_scores_csv = os.path.join(results_dir, "sequential_scores.csv")
        self.incident_reports_path = os.path.join(results_dir, "incident_reports.ndjson")

        self.malicious_raw_texts = set()
        self.session_ground_truth = {}
        self.incident_ground_truth = {}
        self.total_mapped_malicious_lines = 0

    def _extract_ground_truth(self):
        print("[*] Extracting malicious ground truth from labels...")
        for root, dirs, files in os.walk(self.labels_dir):
            if 'apache2' in root:
                for file in files:
                    if 'access.log' in file or 'error.log' in file:
                        label_filepath = os.path.join(root, file)
                        rel_path = os.path.relpath(label_filepath, self.labels_dir)
                        raw_filepath = os.path.join(self.raw_logs_dir, rel_path)

                        if not os.path.exists(raw_filepath): continue

                        malicious_lines = set()
                        with open(label_filepath, 'r', encoding='utf-8', errors='ignore') as lf:
                            for line in lf:
                                try:
                                    malicious_lines.add(json.loads(line.strip())['line'])
                                except:
                                    pass

                        with open(raw_filepath, 'r', encoding='utf-8', errors='ignore') as rf:
                            for i, line in enumerate(rf, 1):
                                if i in malicious_lines:
                                    self.malicious_raw_texts.add(line.strip())

        print(f"[+] Found {len(self.malicious_raw_texts)} malicious raw logs.")
        print("[*] Mapping ground truth to Sessions and Incidents...")

        matched_lines_count = 0
        with open(self.session_timelines_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                session = json.loads(line)
                session_id = session.get('session_id')
                parent_id = session.get('parent_tracking_id')
                events = session.get('timeline', [])

                session_is_malicious = False
                for e in events:
                    if e.get('raw_message', '').strip() in self.malicious_raw_texts:
                        session_is_malicious = True
                        matched_lines_count += 1

                if session_id:
                    self.session_ground_truth[session_id] = session_is_malicious
                if parent_id:
                    if session_is_malicious or not self.incident_ground_truth.get(parent_id, False):
                        self.incident_ground_truth[parent_id] = session_is_malicious

        self.total_mapped_malicious_lines = matched_lines_count
        print(f"[+] Successfully mapped {matched_lines_count} malicious lines into the sessions.")

    def _print_metrics(self, y_true, y_pred, threshold_label):
        total = len(y_true)
        actual_attacks = sum(y_true)
        actual_normals = total - actual_attacks

        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt and yp)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and yp)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if not yt and not yp)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt and not yp)

        recall = (tp / actual_attacks * 100) if actual_attacks > 0 else 0.0
        fpr = (fp / actual_normals * 100) if actual_normals > 0 else 0.0
        precision = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0.0
        f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        accuracy = ((tp + tn) / total * 100) if total > 0 else 0.0

        print(
            f"{threshold_label:<16} | {recall:>6.2f}% (TP:{tp:<5} FN:{fn:<5}) | {fpr:>6.2f}% (FP:{fp:<5} TN:{tn:<5}) | {precision:>6.2f}%   | {f1_score:>6.2f}%   | {accuracy:>6.2f}%")

    def evaluate_layer1_waf(self):
        print("\n" + "=" * 105)
        print("ĐÁNH GIÁ MÔ HÌNH LỌC TĨNH (LAYER 1 WAF) - LINE-BY-LINE LEVEL")
        print("-" * 105)

        if not os.path.exists(self.layer1_alerts_path):
            print("File layer1_alerts.ndjson không tồn tại.")
            return

        y_true = []
        y_pred = []

        # 🟢 NEW: Lists to store samples for investigation
        missed_attacks = []
        false_positives = []

        with open(self.layer1_alerts_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                record = json.loads(line)
                raw_msg = record.get('raw_message', '').strip()

                is_actual = raw_msg in self.malicious_raw_texts
                is_predicted = record.get('layer1_flagged', False)

                y_true.append(is_actual)
                y_pred.append(is_predicted)

                # 🟢 DEBUG LOGIC
                if is_actual and not is_predicted:
                    # Attack existed but WAF missed it (False Negative)
                    missed_attacks.append(raw_msg)
                elif not is_actual and is_predicted:
                    # Log was benign but WAF flagged it (False Positive)
                    # We also save the alert reason to help you debug
                    reason = record.get('layer1_alerts', 'Unknown')
                    false_positives.append(f"[{reason}] {raw_msg}")

        # Save to files
        with open(os.path.join(self.results_dir, "l1_missed_attacks.txt"), "w", encoding="utf-8") as f1:
            f1.write("\n".join(list(set(missed_attacks))))

        with open(os.path.join(self.results_dir, "l1_false_positives.txt"), "w", encoding="utf-8") as f2:
            f2.write("\n".join(list(set(false_positives))))

        print(f"[!] Exported investigation logs to {self.results_dir}")
        print(
            f"{'Tiêu chí Alert':<16} | {'Recall (TP/FN)':<22} | {'FPR (Báo giả)':<22} | {'Precision':<11} | {'F1-Score':<9} | {'Accuracy':<10}")
        print("-" * 105)
        self._print_metrics(y_true, y_pred, "Flagged == True")

    # ... (Keep existing methods: evaluate_statistical_model, evaluate_sequential_model, evaluate_correlator_e2e) ...
    def evaluate_statistical_model(self):
        print("\n" + "=" * 105)
        print("ĐÁNH GIÁ MÔ HÌNH THỐNG KÊ (STATISTICAL LAYER) - SESSION LEVEL")
        print("-" * 105)
        df = pd.read_csv(self.stat_scores_csv)
        df['is_actual'] = df['session_id'].map(self.session_ground_truth).fillna(False)
        print(
            f"{'Ngưỡng (Thresh)':<16} | {'Recall (TP/FN)':<22} | {'FPR (Báo giả)':<22} | {'Precision':<11} | {'F1-Score':<9} | {'Accuracy':<10}")
        print("-" * 105)
        for thresh in [40, 50, 60, 70, 80, 90]:
            y_pred = (df['statistical_threat_score'] >= thresh).tolist()
            self._print_metrics(df['is_actual'].tolist(), y_pred, f"ML Score >= {thresh}")

    def evaluate_sequential_model(self):
        print("\n" + "=" * 105)
        print("ĐÁNH GIÁ MÔ HÌNH CHUỖI MARKOV (SEQUENTIAL LAYER) - SESSION LEVEL")
        print("-" * 105)
        df = pd.read_csv(self.seq_scores_csv)
        df['is_actual'] = df['session_id'].map(self.session_ground_truth).fillna(False)
        print(
            f"{'Ngưỡng (Thresh)':<16} | {'Recall (TP/FN)':<22} | {'FPR (Báo giả)':<22} | {'Precision':<11} | {'F1-Score':<9} | {'Accuracy':<10}")
        print("-" * 105)
        for thresh in [40, 50, 60, 70, 80, 90]:
            y_pred = (df['markov_threat_score'] >= thresh).tolist()
            self._print_metrics(df['is_actual'].tolist(), y_pred, f"ML Score >= {thresh}")

    def evaluate_correlator_e2e(self):
        print("\n" + "=" * 105)
        print("ĐÁNH GIÁ TỔNG THỂ HỆ THỐNG CORRELATOR (END-TO-END) - INCIDENT LEVEL")
        print("-" * 105)
        y_true, y_pred = [], []
        ablation_stats = {'waf_only': 0, 'ml_only': 0, 'both': 0}
        with open(self.incident_reports_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                incident = json.loads(line)
                parent_id = incident.get('incident_tracking_id')
                threat_level = incident.get('overall_threat_level')
                is_actual = self.incident_ground_truth.get(parent_id, False)
                is_predicted = threat_level in ["CRITICAL", "SUSPICIOUS"]
                y_true.append(is_actual)
                y_pred.append(is_predicted)
                if is_actual and is_predicted:
                    max_ml = max(incident.get('max_statistical_score', 0), incident.get('max_markov_score', 0))
                    has_waf = len(incident.get('layer1_alerts', [])) > 0
                    if has_waf and max_ml >= 50:
                        ablation_stats['both'] += 1
                    elif has_waf and max_ml < 50:
                        ablation_stats['waf_only'] += 1
                    elif not has_waf and max_ml >= 50:
                        ablation_stats['ml_only'] += 1
        print(
            f"{'Tiêu chí Alert':<16} | {'Recall (TP/FN)':<22} | {'FPR (Báo giả)':<22} | {'Precision':<11} | {'F1-Score':<9} | {'Accuracy':<10}")
        print("-" * 105)
        self._print_metrics(y_true, y_pred, "SUSPICIOUS+")

    def run_all(self):
        self._extract_ground_truth()
        if not self.malicious_raw_texts: return
        self.evaluate_layer1_waf()
        self.evaluate_statistical_model()
        self.evaluate_sequential_model()
        self.evaluate_correlator_e2e()


if __name__ == "__main__":
    LABELS_PATH = r"../../test_data/fox/labels"
    RAW_LOGS_PATH = r"../../test_data/fox/gather"
    PROFILE_RESULTS_DIR = r"./module_data/Default_Tenant/results"
    evaluator = SystemEvaluator(LABELS_PATH, RAW_LOGS_PATH, PROFILE_RESULTS_DIR)
    evaluator.run_all()




#
# import json
# from datetime import datetime
# from collections import Counter
#
#
# def parse_ts(ts_str):
#     return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
#
#
# def inspect_layer1(filepath):
#     print(f"\n" + "=" * 60)
#     print(f"🔍 DEEP INSPECTION: LAYER 1 STREAM")
#     print("=" * 60)
#
#     last_ts = None
#     line_count = 0
#     global_violations = 0
#
#     with open(filepath, 'r', encoding='utf-8') as f:
#         for line in f:
#             line_count += 1
#             if not line.strip(): continue
#             data = json.loads(line)
#             curr_ts = parse_ts(data['@timestamp'])
#
#             if last_ts and curr_ts < last_ts:
#                 global_violations += 1
#                 if global_violations <= 5:  # Only show first 5
#                     print(f"[!] Stream Disorder at line {line_count}: {curr_ts} < {last_ts}")
#             last_ts = curr_ts
#
#     if global_violations == 0:
#         print(f"[✅] PASS: Global stream is 100% chronological.")
#     else:
#         print(f"[❌] FAIL: Found {global_violations} stream violations. This will confuse the Sessionizer!")
#
#
# def inspect_incidents(filepath):
#     print(f"\n" + "=" * 60)
#     print(f"🔍 DEEP INSPECTION: INCIDENT REPORTS")
#     print("=" * 60)
#
#     incident_count = 0
#     internal_violations = 0
#     file_chronological = True
#     last_incident_start = None
#
#     with open(filepath, 'r', encoding='utf-8') as f:
#         for line in f:
#             incident_count += 1
#             incident = json.loads(line)
#             timeline = incident.get('timeline', [])
#             inc_id = incident.get('incident_tracking_id')
#
#             # 1. Check Internal Order (The most important part for ML)
#             last_event_ts = None
#             for i, event in enumerate(timeline):
#                 curr_ts = parse_ts(event['@timestamp'])
#                 if last_event_ts and curr_ts < last_event_ts:
#                     internal_violations += 1
#                     print(f"[❌] Internal Disorder in {inc_id} at event index {i}")
#                 last_event_ts = curr_ts
#
#             # 2. Check File Order (Just for information)
#             if timeline:
#                 start_ts = parse_ts(timeline[0]['@timestamp'])
#                 if last_incident_start and start_ts < last_incident_start:
#                     file_chronological = False
#                 last_incident_start = start_ts
#
#     print(f"[*] Processed {incident_count} incidents.")
#
#     if internal_violations == 0:
#         print(f"[✅] PASS: All incidents have 100% correct internal timelines.")
#     else:
#         print(f"[❌] FAIL: Found {internal_violations} internal disorders. Correlator sorting logic might be bugged.")
#
#     if not file_chronological:
#         print(f"[i] Info: File is NOT chronological (likely sorted by Threat Score). This is NORMAL.")
#     else:
#         print(f"[i] Info: File is chronological.")
#
#
# if __name__ == "__main__":
#     L1 = r"./module_data/Default_Tenant/results/layer1_alerts.ndjson"
#     INC = r"./module_data/Default_Tenant/results/incident_reports.ndjson"
#
#     inspect_layer1(L1)
#     inspect_incidents(INC)

# import pandas as pd
# import numpy as np
# import joblib
# import shap
# import os
# import warnings
#
# # Suppress SHAP warnings for cleaner output
# warnings.filterwarnings("ignore")
#
#
# def test_layer2_explainability(features_csv, model_dir):
#     print("=" * 80)
#     print("🧠 EXPLAINABLE AI (XAI) BENCHMARK: IQR vs SHAP (Layer 2 Ensemble)")
#     print("=" * 80)
#
#     # 1. Load Data and Models
#     try:
#         df = pd.read_csv(features_csv)
#         iso_forest = joblib.load(os.path.join(model_dir, 'isolation_forest.joblib'))
#         ocsvm = joblib.load(os.path.join(model_dir, 'one_class_svm.joblib'))
#         scaler = joblib.load(os.path.join(model_dir, 'scaler.joblib'))
#     except FileNotFoundError as e:
#         print(f"❌ Error loading files: {e}")
#         return
#
#     feature_cols = [
#         'is_external_ip', 'session_duration_sec', 'total_requests',
#         'req_per_min', 'min_interarrival_sec', 'avg_uri_depth',
#         'error_404_rate', 'error_403_rate', 'error_401_rate', 'error_50x_rate',
#         'post_rate', 'rare_method_rate', 'unique_path_ratio', 'static_asset_ratio',
#         'suspicious_ext_rate', 'status_diversity', 'unique_uas',
#         'avg_payload_bytes', 'max_resp_bytes', 'max_req_length',
#         'geo_country_freq', 'auth_attempt_rate', 'bytes_std_dev',
#         'evasion_attempt_rate'
#     ]
#
#     for col in feature_cols:
#         if col not in df.columns:
#             df[col] = 0.0
#
#     X_raw = df[feature_cols].fillna(0)
#     X_scaled = scaler.transform(X_raw)
#
#     # Calculate Ensemble Anomaly Score (Lower decision_function = more anomalous)
#     iso_scores = -iso_forest.decision_function(X_scaled)
#     svm_scores = -ocsvm.decision_function(X_scaled)
#     df['ensemble_anomaly_score'] = iso_scores + svm_scores
#
#     # 2. Select the Top 3 Worst Sessions (Attacks)
#     top_anomalies = df.sort_values(by='ensemble_anomaly_score', ascending=False).head(3)
#
#     # 3. Initialize Explainers
#     print("[*] Initializing SHAP TreeExplainer (Isolation Forest)...")
#     iso_explainer = shap.TreeExplainer(iso_forest)
#
#     print("[*] Initializing SHAP KernelExplainer (One-Class SVM)...")
#     # KernelExplainer needs a "background" dataset. We use a sample of 50 normal sessions.
#     background_data = shap.sample(X_scaled, 50)
#     # We wrap the SVM decision function so SHAP can understand it
#     svm_predict_func = lambda x: ocsvm.decision_function(x)
#     svm_explainer = shap.KernelExplainer(svm_predict_func, background_data)
#
#     print("\n" + "=" * 80)
#
#     for idx, row in top_anomalies.iterrows():
#         print(f"🚨 TARGET SESSION: {row['session_id']}")
#
#         # --- METHOD A: IQR (Data Deviation) ---
#         scaled_values = X_scaled[idx]
#         abs_scores = np.abs(scaled_values)
#         top_3_iqr_idx = np.argsort(abs_scores)[-3:][::-1]
#
#         iqr_reasons = []
#         for i in top_3_iqr_idx:
#             val = scaled_values[i]
#             if abs(val) > 2.0:
#                 iqr_reasons.append(f"{feature_cols[i]} ({val:+.1f} IQR)")
#
#         print(f"\n   🔹 [1] IQR Explanation (Physical Data Deviation):")
#         print(f"      ➤ {' | '.join(iqr_reasons) if iqr_reasons else 'No extreme deviations'}")
#
#         # --- METHOD B: SHAP for ISOLATION FOREST ---
#         row_scaled = X_scaled[idx].reshape(1, -1)
#         iso_shap_values = iso_explainer.shap_values(row_scaled)[0]
#         # Negative SHAP value pushes the model towards "Anomaly"
#         top_3_iso_idx = np.argsort(iso_shap_values)[:3]
#
#         iso_reasons = []
#         for i in top_3_iso_idx:
#             raw_val = X_raw.iloc[idx][feature_cols[i]]
#             impact = iso_shap_values[i]
#             iso_reasons.append(f"{feature_cols[i]} (Val:{raw_val:.2f}, Impact:{impact:.2f})")
#
#         print(f"   🔸 [2] SHAP - Isolation Forest (Tree Logic):")
#         print(f"      ➤ {' | '.join(iso_reasons)}")
#
#         # --- METHOD C: SHAP for ONE-CLASS SVM ---
#         svm_shap_values = svm_explainer.shap_values(row_scaled, silent=True)[0]
#         # Negative SHAP value in SVM decision_function pushes towards "Anomaly"
#         top_3_svm_idx = np.argsort(svm_shap_values)[:3]
#
#         svm_reasons = []
#         for i in top_3_svm_idx:
#             raw_val = X_raw.iloc[idx][feature_cols[i]]
#             impact = svm_shap_values[i]
#             svm_reasons.append(f"{feature_cols[i]} (Val:{raw_val:.2f}, Impact:{impact:.2f})")
#
#         print(f"   🔸 [3] SHAP - One-Class SVM (RBF Kernel Logic):")
#         print(f"      ➤ {' | '.join(svm_reasons)}")
#         print("-" * 80)
#
#
# if __name__ == "__main__":
#     FEATURES_CSV = r"./module_data/Default_Tenant/results/ml_features.csv"
#     MODEL_DIR = r"./module_data/Default_Tenant/models"
#     test_layer2_explainability(FEATURES_CSV, MODEL_DIR)
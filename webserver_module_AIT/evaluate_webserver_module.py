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
        print("🛡️ ĐÁNH GIÁ MÔ HÌNH LỌC TĨNH (LAYER 1 WAF) - LINE-BY-LINE LEVEL")
        print("-" * 105)

        if not os.path.exists(self.layer1_alerts_path):
            print("❌ File layer1_alerts.ndjson không tồn tại.")
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
        print("🎯 ĐÁNH GIÁ MÔ HÌNH THỐNG KÊ (STATISTICAL LAYER) - SESSION LEVEL")
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
        print("🎯 ĐÁNH GIÁ MÔ HÌNH CHUỖI MARKOV (SEQUENTIAL LAYER) - SESSION LEVEL")
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
        print("🚀 ĐÁNH GIÁ TỔNG THỂ HỆ THỐNG CORRELATOR (END-TO-END) - INCIDENT LEVEL")
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
    LABELS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\labels"
    RAW_LOGS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"
    PROFILE_RESULTS_DIR = r"./module_data/Default_Tenant/results"
    evaluator = SystemEvaluator(LABELS_PATH, RAW_LOGS_PATH, PROFILE_RESULTS_DIR)
    evaluator.run_all()
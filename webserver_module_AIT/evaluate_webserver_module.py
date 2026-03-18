import os
import json
import re


class AITEvaluator:
    def __init__(self, labels_dir, raw_logs_dir, incident_reports_path, output_dir):
        self.labels_dir = labels_dir
        self.raw_logs_dir = raw_logs_dir
        self.incident_reports_path = incident_reports_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _extract_uri_path(self, raw_line):
        match = re.search(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) (\S+) ', raw_line)
        if match: return match.group(1).split('?')[0]
        return None

    def _extract_ip(self, raw_line):
        if not raw_line.startswith('['):
            return raw_line.split()[0]
        else:
            match = re.search(r'\[client ([^:]+)', raw_line)
            if match: return match.group(1)
        return None

    def load_ground_truth(self):
        print(f"[*] Scanning AIT Labels Directory: {self.labels_dir}")
        gt_logs = []
        attacker_ips = set()

        for root, dirs, files in os.walk(self.labels_dir):
            if 'apache2' in root:
                for file in files:
                    if not ('access.log' in file or 'error.log' in file): continue
                    label_filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(label_filepath, self.labels_dir)
                    raw_log_filepath = os.path.join(self.raw_logs_dir, rel_path)

                    if not os.path.exists(raw_log_filepath): continue

                    malicious_lines = set()
                    with open(label_filepath, 'r', encoding='utf-8', errors='ignore') as lf:
                        for line in lf:
                            try:
                                malicious_lines.add(json.loads(line.strip())['line'])
                            except:
                                pass

                    with open(raw_log_filepath, 'r', encoding='utf-8', errors='ignore') as rf:
                        for line_number, raw_line in enumerate(rf, 1):
                            if line_number in malicious_lines:
                                clean_raw = raw_line.strip()
                                uri = self._extract_uri_path(clean_raw)
                                ip = self._extract_ip(clean_raw)
                                if ip: attacker_ips.add(ip)

                                gt_logs.append({
                                    "raw": clean_raw,
                                    "uri": uri,
                                    "ip": ip,
                                    "file": file,
                                    "line": line_number,
                                    "matched": False  # New flag to prevent double counting
                                })

        return gt_logs, attacker_ips

    def evaluate(self):
        print("[*] Starting Strict Dual-Level Attribution Evaluation...")
        gt_logs, attacker_ips = self.load_ground_truth()

        with open(self.incident_reports_path, 'r', encoding='utf-8') as f:
            system_sessions = [json.loads(line) for line in f if line.strip()]

        tp_sessions, fp_sessions, tn_sessions, fn_sessions = 0, 0, 0, 0
        caught_l1, caught_l2_only = 0, 0

        for session in system_sessions:
            session_ip = session.get('incident_tracking_id', '').split('_')[0]
            is_attacker_session = session_ip in attacker_ips

            l2_flagged = session.get('overall_threat_level') in ['CRITICAL', 'SUSPICIOUS']
            l1_flagged_any = any(e.get('layer1_flagged') for e in session.get('timeline', []))
            system_flagged = l2_flagged or l1_flagged_any

            session_has_attack = False

            # If this is the attacker, map their logs strictly to THIS session's flag status
            if is_attacker_session:
                for event in session.get('timeline', []):
                    raw_msg = event.get('raw_message', '').strip()
                    uri_path = event.get('uri_path')
                    is_bulk = event.get('event_type') == 'COMPRESSED_BULK_ACTION'
                    l1_hit = event.get('layer1_flagged')

                    # Find all unmatched ground truth logs that map to this event
                    for gt in gt_logs:
                        if gt['matched']: continue  # Skip if already counted

                        match_found = False
                        if is_bulk and gt['uri'] == uri_path:
                            match_found = True
                        elif not is_bulk and gt['raw'] == raw_msg:
                            match_found = True

                        if match_found:
                            session_has_attack = True
                            gt['matched'] = True

                            # Record attribution ONLY IF the session was actually flagged!
                            if system_flagged:
                                if l1_hit:
                                    caught_l1 += 1
                                else:
                                    caught_l2_only += 1

                            # Safely break so one raw log doesn't double-count
                            if not is_bulk:
                                break

            # Session-Level Confusion Matrix
            if system_flagged and session_has_attack:
                tp_sessions += 1
            elif system_flagged and not session_has_attack:
                fp_sessions += 1
            elif not system_flagged and session_has_attack:
                fn_sessions += 1
            elif not system_flagged and not session_has_attack:
                tn_sessions += 1

        # Calculate missed logs
        missed_logs = [gt for gt in gt_logs if not gt['matched'] or (gt['matched'] and fn_sessions > 0)]

        total_gt = len(gt_logs)
        total_caught = caught_l1 + caught_l2_only
        total_missed = total_gt - total_caught

        event_recall = (total_caught / total_gt) * 100 if total_gt > 0 else 0
        event_fnr = (total_missed / total_gt) * 100 if total_gt > 0 else 0

        l1_contribution = (caught_l1 / total_caught) * 100 if total_caught > 0 else 0
        l2_exclusive = (caught_l2_only / total_caught) * 100 if total_caught > 0 else 0

        total_sessions = tp_sessions + fp_sessions + tn_sessions + fn_sessions
        session_precision = (tp_sessions / (tp_sessions + fp_sessions)) * 100 if (tp_sessions + fp_sessions) > 0 else 0
        session_fpr = (fp_sessions / (fp_sessions + tn_sessions)) * 100 if (fp_sessions + tn_sessions) > 0 else 0

        print("\n" + "=" * 70)
        print("🎯 STRICT ACADEMIC EVALUATION METRICS")
        print("=" * 70)
        print("1️⃣ SESSION-LEVEL RATES (SOC Dashboard Accuracy)")
        print(f"   ➤ Total Sessions Analyzed  : {total_sessions}")
        print(f"   ➤ True Positives (TP)      : {tp_sessions}")
        print(f"   ➤ False Positives (FP)     : {fp_sessions}")
        print(f"   ➤ True Negatives (TN)      : {tn_sessions}")
        print(f"   ➤ False Negatives (FN)     : {fn_sessions}")
        print(f"   ----------------------------------")
        print(f"   [RATE] False Positive Rate : {session_fpr:.2f}%")
        print(f"   [RATE] Precision           : {session_precision:.2f}%")

        print("\n2️⃣ EVENT-LEVEL RATES (The True Catch Rate)")
        print(f"   ➤ Total Malicious Logs     : {total_gt}")
        print(f"   ➤ Total Logs Caught        : {total_caught}")
        print(f"   ➤ Total Logs Missed        : {total_missed}")
        print(f"   ----------------------------------")
        print(f"   [RATE] Recall (Catch Rate) : {event_recall:.2f}%")
        print(f"   [RATE] False Negative Rate : {event_fnr:.2f}%")

        print("\n3️⃣ VALUE ATTRIBUTION")
        print(f"   ➤ Layer 1 (WAF) Caught     : {l1_contribution:.1f}%")
        print(f"   ➤ Layer 2 EXCLUSIVE VALUE  : {l2_exclusive:.1f}%")
        print("=" * 70)


if __name__ == "__main__":
    LABELS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\labels"
    RAW_LOGS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"
    REPORTS_PATH = "../final_layer/incident_reports.ndjson"
    OUTPUT_DIR = "../evaluation_results"

    evaluator = AITEvaluator(LABELS_PATH, RAW_LOGS_PATH, REPORTS_PATH, OUTPUT_DIR)
    evaluator.evaluate()
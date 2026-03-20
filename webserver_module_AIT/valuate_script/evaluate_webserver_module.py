import os
import json


class UltimateE2EEvaluator:
    def __init__(self, labels_dir, raw_logs_dir, incident_reports_path):
        self.labels_dir = labels_dir
        self.raw_logs_dir = raw_logs_dir
        self.incident_reports_path = incident_reports_path

    def get_malicious_raw_logs(self):
        malicious_raw_texts = set()
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
                                if i in malicious_lines: malicious_raw_texts.add(line.strip())
        return malicious_raw_texts

    def evaluate(self):
        print("\n" + "=" * 80)
        print("🚀 ĐÁNH GIÁ TỔNG THỂ KIẾN TRÚC CORRELATOR (END-TO-END)")
        print("=" * 80)

        if not os.path.exists(self.incident_reports_path):
            print("❌ Không tìm thấy file incident_reports.ndjson.")
            return

        malicious_raw_texts = self.get_malicious_raw_logs()

        sessions_data = []
        total_raw_events = 0
        total_comp_events = 0

        with open(self.incident_reports_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                session = json.loads(line)

                total_raw_events += session.get('total_raw_events', 0)
                total_comp_events += session.get('total_compressed_events', 0)

                is_actual_attack = False
                waf_caught_actual_payload = False  # WAF bắt trúng chính xác dòng log APT
                has_any_waf_alert = False  # WAF bắt nhầm log rác trong cùng session

                for event in session.get('timeline', []):
                    if event.get('layer1_flagged'): has_any_waf_alert = True

                    if event.get('event_type') != 'COMPRESSED_BULK_ACTION':
                        raw_msg = event.get('raw_message', '').strip()
                        if raw_msg in malicious_raw_texts:
                            is_actual_attack = True
                            if event.get('layer1_flagged'):
                                waf_caught_actual_payload = True

                max_ml_score = max(session.get('max_statistical_score', 0), session.get('max_markov_score', 0))

                sessions_data.append({
                    'is_actual_attack': is_actual_attack,
                    'waf_caught_payload': waf_caught_actual_payload,
                    'has_any_waf_alert': has_any_waf_alert,
                    'max_ml_score': max_ml_score
                })

        total_sessions = len(sessions_data)
        actual_attacks = sum(1 for s in sessions_data if s['is_actual_attack'])
        actual_normals = total_sessions - actual_attacks
        compression_rate = (
                    (total_raw_events - total_comp_events) / total_raw_events * 100) if total_raw_events > 0 else 0

        print(f"📊 THỐNG KÊ ĐẦU VÀO (ENTITY/INCIDENT LEVEL):")
        print(f"    ➤ Tổng số Hồ sơ sự cố (Incidents) : {total_sessions}")
        print(f"    ➤ Hồ sơ Tấn công thực tế          : {actual_attacks}")
        print(f"    ➤ Hiệu suất nén log (Compression) : {compression_rate:.2f}% (Bảo toàn ngữ cảnh APT)")

        print("\n📈 KIỂM THỬ ĐÁNH GIÁ CHÉO (CORRELATION TRADE-OFF):")
        print("-" * 80)
        print(f"{'Ngưỡng ML (Threshold)':<20} | {'Recall (Bắt trúng)':<25} | {'FPR (Báo giả)':<15}")
        print("-" * 80)

        thresholds = [50, 60, 70, 80, 90]
        best_tp, best_fp = 0, 0
        ablation_stats = {}

        for thresh in thresholds:
            tp, fp, tn, fn = 0, 0, 0, 0
            waf_only, ml_only, both, incidental = 0, 0, 0, 0

            for s in sessions_data:
                # Correlator báo động nếu WAF quét ra L1 hoặc ML vượt ngưỡng
                is_predicted_attack = s['has_any_waf_alert'] or (s['max_ml_score'] >= thresh)

                if s['is_actual_attack'] and is_predicted_attack:
                    tp += 1
                    if s['waf_caught_payload'] and s['max_ml_score'] >= thresh:
                        both += 1
                    elif s['waf_caught_payload'] and s['max_ml_score'] < thresh:
                        waf_only += 1
                    elif not s['waf_caught_payload'] and s['max_ml_score'] >= thresh:
                        ml_only += 1
                    else:
                        incidental += 1  # WAF bắt trúng rác, ML không báo, ăn may bắt được session
                elif not s['is_actual_attack'] and is_predicted_attack:
                    fp += 1
                elif not s['is_actual_attack'] and not is_predicted_attack:
                    tn += 1
                elif s['is_actual_attack'] and not is_predicted_attack:
                    fn += 1

            recall = (tp / actual_attacks * 100) if actual_attacks > 0 else 0
            fpr = (fp / actual_normals * 100) if actual_normals > 0 else 0

            print(f"Chấp nhận ML >= {thresh:<5} | {recall:>6.2f}% (TP:{tp:<3} FN:{fn:<3}) | {fpr:>5.2f}% (FP:{fp:<3})")

            if thresh == 80:  # Lưu lại để in Ablation Study cho ngưỡng chuẩn
                ablation_stats = {'both': both, 'waf_only': waf_only, 'ml_only': ml_only, 'incidental': incidental,
                                  'tp': tp}

        print("-" * 80)
        print(f"\n🔍 PHÂN TÍCH ĐÓNG GÓP TẠI NGƯỠNG CHUẨN (THRESHOLD 80):")
        tp = ablation_stats['tp']
        if tp > 0:
            print(
                f"    ➤ Bắt được CẢ nhờ WAF và ML Hành vi : {ablation_stats['both']} ({ablation_stats['both'] / tp * 100:.1f}%)")
            print(
                f"    ➤ Chỉ bắt được nhờ WAF tĩnh (Tầng 1): {ablation_stats['waf_only']} ({ablation_stats['waf_only'] / tp * 100:.1f}%)")
            print(
                f"    ➤ Chỉ bắt được nhờ ML AI (Tầng 2+3) : {ablation_stats['ml_only']} ({ablation_stats['ml_only'] / tp * 100:.1f}%) [SỨC MẠNH LÕI]")
            print(
                f"    ➤ Trùng hợp ngẫu nhiên (Ăn may)     : {ablation_stats['incidental']} ({ablation_stats['incidental'] / tp * 100:.1f}%)")


if __name__ == "__main__":
    LABELS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\labels"
    RAW_LOGS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"
    PROFILE_RESULTS_DIR = r"./module_data/Default_Tenant/results"  # SỬA LẠI ĐÚNG PROFILE BẠN TEST NHÉ
    INCIDENT_REPORTS_PATH = os.path.join(PROFILE_RESULTS_DIR, "incident_reports.ndjson")

    evaluator = UltimateE2EEvaluator(LABELS_PATH, RAW_LOGS_PATH, INCIDENT_REPORTS_PATH)
    evaluator.evaluate()
import os
import json
import pandas as pd


class ExactSequentialEvaluator:
    def __init__(self, labels_dir, raw_logs_dir, session_timelines_path, seq_scores_csv):
        self.labels_dir = labels_dir
        self.raw_logs_dir = raw_logs_dir
        self.session_timelines_path = session_timelines_path
        self.seq_scores_csv = seq_scores_csv

    def get_malicious_raw_logs(self):
        """Trích xuất log độc hại nguyên thủy (Ground Truth) từ bộ dataset"""
        malicious_raw_texts = set()
        print(f"[*] Đang quét thư mục Labels: {self.labels_dir}")

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
                                    malicious_raw_texts.add(line.strip())

        print(f"[+] Đã trích xuất {len(malicious_raw_texts)} dòng log độc hại.")
        return malicious_raw_texts

    def map_ground_truth_to_sessions(self, malicious_raw_texts):
        """Map log độc hại vào Session Timeline"""
        session_ground_truth = {}
        with open(self.session_timelines_path, 'r', encoding='utf-8') as f:
            try:
                sessions_data = json.load(f)
                if isinstance(sessions_data, dict):
                    for session_id, events in sessions_data.items():
                        is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                        session_ground_truth[session_id] = is_malicious
                elif isinstance(sessions_data, list):
                    for session in sessions_data:
                        session_id = session.get('session_id')
                        events = session.get('timeline', [])
                        is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                        if session_id: session_ground_truth[session_id] = is_malicious
            except json.JSONDecodeError:
                f.seek(0)
                for line in f:
                    if not line.strip(): continue
                    session = json.loads(line)
                    session_id = session.get('session_id')
                    events = session.get('timeline', [])
                    is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                    if session_id: session_ground_truth[session_id] = is_malicious

        return session_ground_truth

    def evaluate(self):
        print("\n" + "=" * 60)
        print("🎯 BẮT ĐẦU ĐÁNH GIÁ MÔ HÌNH CHUỖI MARKOV (SEQUENTIAL MODEL)")
        print("=" * 60)

        if not os.path.exists(self.seq_scores_csv) or not os.path.exists(self.session_timelines_path):
            print("❌ Không tìm thấy file sequential_scores.csv. Hãy chạy pipeline trên WebApp trước!")
            return

        malicious_raw_texts = self.get_malicious_raw_logs()
        session_ground_truth = self.map_ground_truth_to_sessions(malicious_raw_texts)

        df_scores = pd.read_csv(self.seq_scores_csv)
        if 'session_id' not in df_scores.columns:
            print("❌ File sequential_scores.csv không có cột 'session_id'")
            return

        df_scores['is_actual_attack'] = df_scores['session_id'].map(session_ground_truth).fillna(False)

        total_sessions = len(df_scores)
        actual_attacks = df_scores['is_actual_attack'].sum()
        actual_normals = total_sessions - actual_attacks

        print(f"\n📊 THỐNG KÊ DỮ LIỆU ĐẦU VÀO MÔ HÌNH CHUỖI:")
        print(f"    ➤ Tổng số Session phân tích : {total_sessions}")
        print(f"    ➤ Session Tấn công (Actual) : {actual_attacks}")
        print(f"    ➤ Session Hợp lệ (Actual)   : {actual_normals}")

        print("\n📈 SỰ ĐÁNH ĐỔI (TRADE-OFF) QUA CÁC NGƯỠNG (THRESHOLDS):")
        print("-" * 75)
        print(f"{'Ngưỡng (Threshold)':<20} | {'Recall (Bắt trúng)':<25} | {'FPR (Báo giả)':<15}")
        print("-" * 75)

        thresholds_to_test = [40, 50, 60, 70, 80, 90]

        for thresh in thresholds_to_test:
            # Điểm Markov >= ngưỡng thì cảnh báo
            df_scores['is_predicted_attack'] = df_scores['markov_threat_score'] >= thresh

            tp = ((df_scores['is_actual_attack'] == True) & (df_scores['is_predicted_attack'] == True)).sum()
            fp = ((df_scores['is_actual_attack'] == False) & (df_scores['is_predicted_attack'] == True)).sum()
            tn = ((df_scores['is_actual_attack'] == False) & (df_scores['is_predicted_attack'] == False)).sum()
            fn = ((df_scores['is_actual_attack'] == True) & (df_scores['is_predicted_attack'] == False)).sum()

            recall = (tp / actual_attacks * 100) if actual_attacks > 0 else 0
            fpr = (fp / actual_normals * 100) if actual_normals > 0 else 0

            print(f"Điểm Markov >= {thresh:<6} | {recall:>6.2f}% (TP:{tp:<4} FN:{fn:<4}) | {fpr:>5.2f}% (FP:{fp:<4})")

        print("-" * 75)

import os
import json
import pandas as pd


class ExactStatisticalEvaluator:
    def __init__(self, labels_dir, raw_logs_dir, session_timelines_path, stat_scores_csv):
        self.labels_dir = labels_dir
        self.raw_logs_dir = raw_logs_dir
        self.session_timelines_path = session_timelines_path
        self.stat_scores_csv = stat_scores_csv

    def get_malicious_raw_logs(self):
        """
        BƯỚC 1: Đọc file labels, lấy số dòng (line), đối chiếu sang thư mục gather
        để trích xuất chính xác chuỗi raw_message độc hại.
        """
        malicious_raw_texts = set()
        print(f"[*] Đang quét thư mục Labels: {self.labels_dir}")

        for root, dirs, files in os.walk(self.labels_dir):
            if 'apache2' in root:
                for file in files:
                    if 'access.log' in file or 'error.log' in file:
                        label_filepath = os.path.join(root, file)
                        # Lấy đường dẫn tương đối để map sang thư mục gather
                        rel_path = os.path.relpath(label_filepath, self.labels_dir)
                        raw_filepath = os.path.join(self.raw_logs_dir, rel_path)

                        if not os.path.exists(raw_filepath):
                            continue

                        # Đọc các dòng bị đánh nhãn từ file JSON
                        malicious_lines = set()
                        with open(label_filepath, 'r', encoding='utf-8', errors='ignore') as lf:
                            for line in lf:
                                try:
                                    data = json.loads(line.strip())
                                    malicious_lines.add(data['line'])
                                except:
                                    pass

                        # Mở file log thô, trích xuất chính xác chuỗi text tại các dòng đó
                        with open(raw_filepath, 'r', encoding='utf-8', errors='ignore') as rf:
                            for i, line in enumerate(rf, 1):
                                if i in malicious_lines:
                                    malicious_raw_texts.add(line.strip())

        print(f"[+] Đã trích xuất thành công {len(malicious_raw_texts)} dòng log độc hại (Ground Truth).")
        return malicious_raw_texts

    def map_ground_truth_to_sessions(self, malicious_raw_texts):
        """
        BƯỚC 2: Kiểm tra xem Session nào chứa ít nhất 1 dòng log độc hại.
        """
        session_ground_truth = {}
        print(f"[*] Đang mapping Ground Truth vào cấu trúc Session...")

        with open(self.session_timelines_path, 'r', encoding='utf-8') as f:
            try:
                sessions_data = json.load(f)
                # Xử lý trường hợp file JSON là Dictionary {"session_id": [events...]}
                if isinstance(sessions_data, dict):
                    for session_id, events in sessions_data.items():
                        is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                        session_ground_truth[session_id] = is_malicious
                # Xử lý trường hợp file JSON là List [{session_id: "...", timeline: [...]}]
                elif isinstance(sessions_data, list):
                    for session in sessions_data:
                        session_id = session.get('session_id')
                        events = session.get('timeline', [])
                        is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                        if session_id:
                            session_ground_truth[session_id] = is_malicious
            except json.JSONDecodeError:
                # Xử lý trường hợp file là NDJSON (mỗi dòng là 1 JSON object)
                f.seek(0)
                for line in f:
                    if not line.strip(): continue
                    session = json.loads(line)
                    session_id = session.get('session_id')
                    events = session.get('timeline', [])
                    is_malicious = any(e.get('raw_message', '').strip() in malicious_raw_texts for e in events)
                    if session_id:
                        session_ground_truth[session_id] = is_malicious

        return session_ground_truth

    def evaluate(self):
        print("\n" + "=" * 60)
        print("🎯 BẮT ĐẦU ĐÁNH GIÁ MÔ HÌNH THỐNG KÊ (LAYER 2)")
        print("=" * 60)

        if not os.path.exists(self.stat_scores_csv) or not os.path.exists(self.session_timelines_path):
            print("❌ Không tìm thấy file kết quả. Hãy đảm bảo bạn đã chạy luồng phân tích trên giao diện Web!")
            return

        # 1. Trích xuất log thực sự độc hại
        malicious_raw_texts = self.get_malicious_raw_logs()
        if len(malicious_raw_texts) == 0:
            print("❌ Không tìm thấy log độc hại nào. Vui lòng kiểm tra lại LABELS_PATH và RAW_LOGS_PATH.")
            return

        # 2. Tìm xem session nào thực sự chứa log độc hại
        session_ground_truth = self.map_ground_truth_to_sessions(malicious_raw_texts)

        # 3. Load bảng điểm của ML
        df_scores = pd.read_csv(self.stat_scores_csv)
        if 'session_id' not in df_scores.columns:
            print("❌ File statistical_scores.csv không có cột 'session_id'")
            return

        # 4. Gắn nhãn Actual Attack vào bảng điểm
        df_scores['is_actual_attack'] = df_scores['session_id'].map(session_ground_truth).fillna(False)

        total_sessions = len(df_scores)
        actual_attacks = df_scores['is_actual_attack'].sum()
        actual_normals = total_sessions - actual_attacks

        print(f"\n📊 THỐNG KÊ DỮ LIỆU:")
        print(f"    ➤ Tổng số Session phân tích : {total_sessions}")
        print(f"    ➤ Session Tấn công (Chứa ít nhất 1 log xấu): {actual_attacks}")
        print(f"    ➤ Session Hợp lệ (Hoàn toàn sạch)          : {actual_normals}")
        print("\n📈 KIỂM THỬ QUA CÁC NGƯỠNG ĐIỂM (THRESHOLDS):")
        print("-" * 75)
        print(f"{'Ngưỡng (Threshold)':<20} | {'Recall (Bắt trúng)':<25} | {'FPR (Báo giả)':<15}")
        print("-" * 75)

        thresholds_to_test = [40, 50, 60, 70, 80, 90]

        for thresh in thresholds_to_test:
            # Nếu điểm ML >= ngưỡng thì hệ thống báo là Tấn công
            df_scores['is_predicted_attack'] = df_scores['statistical_threat_score'] >= thresh

            tp = ((df_scores['is_actual_attack'] == True) & (df_scores['is_predicted_attack'] == True)).sum()
            fp = ((df_scores['is_actual_attack'] == False) & (df_scores['is_predicted_attack'] == True)).sum()
            tn = ((df_scores['is_actual_attack'] == False) & (df_scores['is_predicted_attack'] == False)).sum()
            fn = ((df_scores['is_actual_attack'] == True) & (df_scores['is_predicted_attack'] == False)).sum()

            recall = (tp / actual_attacks * 100) if actual_attacks > 0 else 0
            fpr = (fp / actual_normals * 100) if actual_normals > 0 else 0

            print(f"Điểm ML >= {thresh:<9} | {recall:>6.2f}% (TP:{tp:<4} FN:{fn:<4}) | {fpr:>5.2f}% (FP:{fp:<4})")

        print("-" * 75)
        print("💡 HƯỚNG DẪN VIẾT BÁO CÁO:")
        print("Dựa vào bảng trên, hãy chọn ra ngưỡng (Threshold) có sự cân bằng tốt nhất (Recall cao, FPR thấp).")
        print("Ví dụ: Nếu Ngưỡng 60 cho Recall 85% và FPR 1.2%, hãy điền số này vào file chapter4.tex.")


if __name__ == "__main__":
    # ĐƯỜNG DẪN TỚI THƯ MỤC CỦA DATASET

    LABELS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\labels"
    RAW_LOGS_PATH = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\gather"

    # ĐƯỜNG DẪN TỚI FILE KẾT QUẢ CỦA MODULE (Đảm bảo đã chạy Pipeline trước)
    # Tùy thuộc vào việc bạn test trên profile nào (VD: Default_Tenant)
    PROFILE_RESULTS_DIR = r"./module_data/Default_Tenant/results"

    SESSION_TIMELINES_PATH = os.path.join(PROFILE_RESULTS_DIR, "session_timelines.json")
    STAT_SCORES_CSV = os.path.join(PROFILE_RESULTS_DIR, "statistical_scores.csv")

    evaluator = ExactStatisticalEvaluator(LABELS_PATH, RAW_LOGS_PATH, SESSION_TIMELINES_PATH, STAT_SCORES_CSV)
    evaluator.evaluate()

    SESSION_TIMELINES_PATH = os.path.join(PROFILE_RESULTS_DIR, "session_timelines.json")
    # Thay đổi sang file chấm điểm của thuật toán Chuỗi
    SEQ_SCORES_CSV = os.path.join(PROFILE_RESULTS_DIR, "sequential_scores.csv")

    evaluator = ExactSequentialEvaluator(LABELS_PATH, RAW_LOGS_PATH, SESSION_TIMELINES_PATH, SEQ_SCORES_CSV)
    evaluator.evaluate()
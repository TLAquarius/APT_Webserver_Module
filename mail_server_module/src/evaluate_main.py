import json
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, classification_report

# Import các vũ khí từ hệ thống SIEM một cách danh chính ngôn thuận
from log_parser import parse_log_line
from AI.feature_extractor import extract_features, get_feature_names
from AI.model_manager import AnomalyDetector

def evaluate_siem_performance(y_true, y_pred, model_name="Mô hình AI"):
    """Hàm in ra bảng điểm chi tiết (Confusion Matrix & F1-Score)"""
    print("\n" + "="*65)
    print(f"📊 BÁO CÁO ĐÁNH GIÁ: {model_name.upper()}")
    print("="*65)

    cm = confusion_matrix(y_true, y_pred)
    # Xử lý trường hợp ma trận thiếu chiều (nếu dữ liệu quá ít)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn, fp, fn, tp = cm[0][0], 0, 0, 0

    print("\n[1] MA TRẬN NHẦM LẪN (Confusion Matrix):")
    print(f"    ✅ True Negatives (Bình thường & Bỏ qua):     {tn} dòng")
    print(f"    🚨 False Positives (Báo động giả / Bắt nhầm): {fp} dòng")
    print(f"    ❌ False Negatives (Bỏ lọt tội phạm):         {fn} dòng")
    print(f"    🎯 True Positives (Bắt trúng Hacker):         {tp} dòng")

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    print("\n[2] CHỈ SỐ ĐÁNH GIÁ CỐT LÕI:")
    print(f"    - Precision (Độ chính xác khi báo động): {precision*100:.2f}%")
    print(f"    - Recall (Độ phủ / Tỉ lệ tóm gọn):       {recall*100:.2f}%")
    print(f"    - F1-Score (Điểm tổng hợp):              {f1*100:.2f}%")
    print("="*65 + "\n")


def load_ground_truth_labels(label_file_path):
    """Đọc file JSONL và trả về 1 danh sách (Set) chứa các Dòng là Hacker"""
    malicious_lines = set()
    with open(label_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                # Nếu mảng "labels" có chứa dữ liệu -> Đây là dòng của hacker
                if data.get("labels"):
                    malicious_lines.add(data["line"])
    return malicious_lines


def run_evaluation_pipeline(log_file_path, label_file_path):
    print(f"[*] Đang nạp đáp án từ: {label_file_path}")
    malicious_lines_set = load_ground_truth_labels(label_file_path)
    print(f"[+] Đã tìm thấy {len(malicious_lines_set)} dòng log chứa hành vi tấn công trong đáp án.")

    ai_detector = AnomalyDetector()
    feature_names = get_feature_names()
    
    y_true = []
    y_pred_ai = []
    buffer_data = []
    WARM_UP_SAMPLES = 500

    print(f"[*] Đang đọc và chấm điểm file: {log_file_path} ...")
    
    with open(log_file_path, 'r', encoding='utf-8') as f:
        # Dùng enumerate(f, 1) để lấy số thứ tự dòng hiện tại (bắt đầu từ 1)
        for line_number, line_text in enumerate(f, 1):
            
            # Bước 1: Ghi nhận ĐÁP ÁN (Y_TRUE)
            if line_number in malicious_lines_set:
                y_true.append(1) # Là Hacker
            else:
                y_true.append(0) # Bình thường

            # Bước 2: Dịch text thành Data (Lớp 0)
            log_data = parse_log_line(line_text)
            
            # Nếu Lớp 0 không đọc được (rác), mặc định AI coi là Bình thường (0)
            if not log_data:
                y_pred_ai.append(0)
                continue

            # Bước 3: Đưa qua AI (Lớp 3)
            features = extract_features(log_data)
            
            if not ai_detector.is_trained:
                buffer_data.append(features)
                y_pred_ai.append(0) # Trong lúc WARM-UP, AI chưa biết gì nên đánh 0
                
                if len(buffer_data) >= WARM_UP_SAMPLES:
                    ai_detector.train(buffer_data, feature_names)
                    buffer_data.clear()
            else:
                is_anomaly, _ = ai_detector.predict(features, feature_names)
                y_pred_ai.append(1 if is_anomaly else 0)

    # In Bảng điểm cuối cùng cho AI
    evaluate_siem_performance(y_true, y_pred_ai, "AI Isolation Forest (Lớp 3)")

if __name__ == "__main__":
    
    LOG_PATH = "data/mail.log"
    LABEL_PATH = "data/mail_labels.jsonl" 
    
    run_evaluation_pipeline(LOG_PATH, LABEL_PATH)
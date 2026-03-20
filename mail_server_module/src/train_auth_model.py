import os
import pandas as pd
import pickle
import json
from sklearn.ensemble import IsolationForest

# Cấu hình đường dẫn
INPUT_CSV = "data/auth_features_train_ready.csv"
MODEL_PATH = "models/auth_model.pkl"
WHITELIST_PATH = "models/auth_known_users.json"

print("=====================================================")
print("[*] KHỞI ĐỘNG LÒ LUYỆN AI: CHUYÊN GIA AUTH 8D")
print("=====================================================")

try:
    print(f"[*] Đang nạp Ma trận Dữ liệu từ: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)

    if df.empty:
        print("[!] Lỗi: File CSV không có dữ liệu!")
        exit()

    # 1. TẠO DANH SÁCH TRẮNG (Cho "Luật Cứng")
    # Lấy ra tất cả các user hợp lệ (bỏ qua giá trị 'unknown')
    known_users = df[df['user'] != 'unknown']['user'].dropna().unique().tolist()
    os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
    with open(WHITELIST_PATH, 'w', encoding='utf-8') as f:
        json.dump(known_users, f)
    print(f"[+] Đã trích xuất {len(known_users)} tài khoản hợp lệ vào Whitelist: {WHITELIST_PATH}")

    # 2. CHUẨN BỊ ỐNG NGHIỆM CHO AI (Tách 8 Cột Toán Học)
    features_8d = [
        'action_code', 'program_code', 'is_root_target', 'is_privilege_escalation', 
        'hour_of_day', 'is_off_hours', 'velocity', 'unique_users','session_risk_score'
    ]
    
    print(f"[*] Đang nạp 8 Chiều Không Gian: {features_8d}")
    X_train = df[features_8d]

    # 3. HUẤN LUYỆN BỘ NÃO (Isolation Forest)
    print("[🤖] AI đang tiến hành học các khuôn mẫu hành vi leo thang và rà quét...")
    
    # contamination=0.01: Giả định dữ liệu này khá sạch, chỉ 1% là bất thường thực sự
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)

    # 4. LƯU TRỮ CHUYÊN GIA
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"[✅] HOÀN TẤT! Đã xuất xưởng Chuyên gia Auth tại: {MODEL_PATH}")
    print("=====================================================")

except FileNotFoundError:
    print(f"[!] Lỗi: Không tìm thấy file {INPUT_CSV}. Bạn đã chạy normalize_auth_features.py chưa?")
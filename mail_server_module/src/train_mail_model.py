import os
import pandas as pd
import pickle
import json
from sklearn.ensemble import IsolationForest

# Cấu hình đường dẫn
INPUT_CSV = "data/mail_features_ready.csv"
MODEL_PATH = "models/mail_model.pkl"
WHITELIST_PATH = "models/known_users.json"

print("=====================================================")
print("[*] KHỞI ĐỘNG LÒ LUYỆN AI: CHUYÊN GIA MAIL 8D")
print("=====================================================")

try:
    print(f"[*] Đang nạp Ma trận Dữ liệu từ: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)

    if df.empty:
        print("[!] Lỗi: File CSV không có dữ liệu!")
        exit()

    # 1. TẠO DANH SÁCH TRẮNG (Cho "Luật Cứng")
    # Lấy ra tất cả các user đã xuất hiện trong quá khứ bình yên
    known_users = df['user'].dropna().unique().tolist()
    os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
    with open(WHITELIST_PATH, 'w', encoding='utf-8') as f:
        json.dump(known_users, f)
    print(f"[+] Đã trích xuất {len(known_users)} nhân viên hợp lệ vào Whitelist: {WHITELIST_PATH}")

    # 2. CHUẨN BỊ ỐNG NGHIỆM CHO AI (Tách 8 Cột Toán Học)
    features_10d = [
        'action_code', 'is_remote', 'attempts', 'duration_secs', 
        'bytes_in', 'bytes_out', 'velocity', 'unique_users',
        'hour_of_day', 'is_off_hours'
    ]
    
    print(f"[*] Đang tách 3 Cột định vị, giữ lại 8 Cột Đặc trưng: {features_10d}")
    X_train = df[features_10d]

    # 3. HUẤN LUYỆN BỘ NÃO (Isolation Forest)
    print("[🤖] AI đang tiến hành học các khuôn mẫu hành vi...")
    
    # contamination=0.01: Môi trường train rất sạch, chỉ cho phép sai số 1%
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)

    # 4. LƯU TRỮ CHUYÊN GIA
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"[✅] HOÀN TẤT! Đã xuất xưởng Chuyên gia Mail tại: {MODEL_PATH}")
    print("=====================================================")

except FileNotFoundError:
    print(f"[!] Lỗi: Không tìm thấy file {INPUT_CSV}. Bạn đã chạy normalize_features.py chưa?")
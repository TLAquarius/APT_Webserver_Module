import pandas as pd
import pickle
import json

TEST_CSV = "data/mail_test_features_ready.csv"
MODEL_PATH = "models/mail_model.pkl"
WHITELIST_PATH = "models/known_users.json"

print("=====================================================")
print("🕵️‍♂️ HỆ THỐNG ĐI SĂN APT (MAIL EXPERT 10D) ĐÃ KHỞI ĐỘNG")
print("=====================================================")

try:
    # 1. NẠP DỮ LIỆU & VŨ KHÍ
    print("[*] Đang nạp dữ liệu chiến trường...")
    df_test = pd.read_csv(TEST_CSV)
    
    print("[*] Đang triệu hồi Chuyên gia Mail 10D & Sổ tay Whitelist...")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
        
    with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
        known_users = set(json.load(f))

    # 2. CHẤM ĐIỂM (AI 10D + LUẬT CỨNG)
    features_10d = [
        'action_code', 'is_remote', 'attempts', 'duration_secs', 
        'bytes_in', 'bytes_out', 'velocity', 'unique_users',
        'hour_of_day', 'is_off_hours'
    ]
    print("[🤖] AI đang soi chiếu ma trận 10D (Đã mở nhãn quan Thời gian)...")
    df_test['ai_prediction'] = model.predict(df_test[features_10d])

    print("[🛡️] Đang kiểm tra chéo với Danh sách trắng...")
    def apply_strict_rules(row):
        pred = row['ai_prediction']
        if pd.notna(row['user']) and row['user'] not in known_users:
            return -1 # Trảm ngay kẻ lạ mặt
        return pred

    df_test['final_verdict'] = df_test.apply(apply_strict_rules, axis=1)

    # 3. THỐNG KÊ CHI TIẾT
    ai_flags = (df_test['ai_prediction'] == -1)
    whitelist_flags = df_test['user'].apply(lambda x: pd.notna(x) and x not in known_users)

    caught_by_ai = ai_flags.sum()
    caught_by_whitelist = whitelist_flags.sum()
    caught_by_both = (ai_flags & whitelist_flags).sum()
    caught_by_whitelist_only = caught_by_whitelist - caught_by_both

    anomalies = df_test[df_test['final_verdict'] == -1]

    print("\n=====================================================")
    print(f"🚨 TỔNG KẾT: PHÁT HIỆN {len(anomalies)} HÀNH VI TẤN CÔNG!")
    print("=====================================================")
    print(" 📊 BÁO CÁO NGUỒN PHÁT HIỆN:")
    print(f"    - Do AI 10D phát hiện (Sai lệch hành vi/thời gian): {caught_by_ai} dòng")
    print(f"    - Do Luật Cứng (Người lạ) trảm ĐỘC LẬP: {caught_by_whitelist_only} dòng")
    print(f"    - (Chú thích: Có {caught_by_both} dòng bị cả AI và Luật Cứng cùng chỉ điểm)")
    print("-----------------------------------------------------")
    
    # 4. HIỂN THỊ CẢNH BÁO & XUẤT FILE HACKER
    if not anomalies.empty:
        print("\n[!] TOP CÁC ĐỊA CHỈ IP BỊ TÓM GÁY:")
        ip_counts = anomalies['rip'].value_counts()
        for ip, count in ip_counts.items():
            print(f"   ☠️ IP: {ip} | Số log độc hại: {count}")
            
        print("\n[!] BẰNG CHỨNG PHẠM TỘI (5 log đầu tiên):")
        # In thêm cột hour_of_day để bạn thấy khung giờ Hacker hoạt động
        print(anomalies[['timestamp', 'rip', 'user', 'hour_of_day', 'velocity', 'unique_users', 'bytes_out']].head(5).to_string())
        
        # Xuất file
        EXPORT_HACKER_FILE = "data/detected_hackers.csv"
        export_cols = [
            'timestamp', 'rip', 'user', 'action_code', 
            'is_remote', 'attempts', 'velocity', 'unique_users', 'bytes_out',
            'hour_of_day', 'is_off_hours'
        ]
        anomalies_sorted = anomalies.sort_values('timestamp')
        anomalies_sorted[export_cols].to_csv(EXPORT_HACKER_FILE, index=False)
        print(f"\n[💾] XUẤT FILE THÀNH CÔNG: Đã lưu toàn bộ {len(anomalies)} dòng log của Hacker vào: {EXPORT_HACKER_FILE}")
        
    else:
        print("[+] Hệ thống an toàn. Không phát hiện bất thường.")

except FileNotFoundError as e:
    print(f"[!] Lỗi: Không tìm thấy file. Chi tiết: {e}")
except KeyError as e:
    print(f"[!] Lỗi Thiếu Cột: {e}. Bạn đã chạy file normalize_features.py cho Dữ liệu TEST chưa?")
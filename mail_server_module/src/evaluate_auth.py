import pandas as pd
import pickle
import json

# Ở đây ta dùng luôn file vừa chuẩn hóa làm chiến trường để xem AI bắt được gì trong đống log đó
TEST_CSV = "data/auth_features_ready.csv" 
MODEL_PATH = "models/auth_model.pkl"
WHITELIST_PATH = "models/auth_known_users.json"

print("=====================================================")
print("🕵️‍♂️ HỆ THỐNG ĐI SĂN APT (AUTH EXPERT 8D) ĐÃ KHỞI ĐỘNG")
print("=====================================================")

try:
    # 1. NẠP DỮ LIỆU & VŨ KHÍ
    print("[*] Đang nạp dữ liệu chiến trường Linux Auth...")
    df_test = pd.read_csv(TEST_CSV)
    
    print("[*] Đang triệu hồi Chuyên gia Auth & Sổ tay Whitelist...")
    with open(MODEL_PATH, 'rb') as f:
        model = pickle.load(f)
        
    with open(WHITELIST_PATH, 'r', encoding='utf-8') as f:
        known_users = set(json.load(f))

    # 2. CHẤM ĐIỂM BẰNG AI 8D
    features_8d = [
        'action_code', 'program_code', 'is_root_target', 'is_privilege_escalation', 
        'hour_of_day', 'is_off_hours', 'velocity', 'unique_users','session_risk_score'
    ]
    print("[🤖] AI đang rà quét ma trận không gian 8 Chiều...")
    df_test['ai_prediction'] = model.predict(df_test[features_8d])

    # 3. ÁP DỤNG LUẬT CỨNG (SIEM RULES)
    print("[🛡️] Đang kiểm tra chéo với Danh sách trắng và Luật Leo Thang...")
    def apply_auth_rules(row):
        pred = row['ai_prediction']
        
        # LUẬT 1: Kẻ lạ mặt xuất hiện -> Trảm
        # (Bỏ qua chữ 'unknown' vì đó là các dòng log không có thông tin user)
        if pd.notna(row['user']) and row['user'] != 'unknown' and row['user'] not in known_users:
            return -1 
            
        # LUẬT 2: Cảnh báo đỏ với quyền ROOT
        # Nếu AI thấy hơi nghi ngờ (nhưng chưa đến mức -1) mà đích đến lại là ROOT hoặc Sudo
        # Trong thực tế, các rule YAML sẽ tóm ngay lập tức các hành vi su/sudo bất thường
        if row['is_root_target'] == 1 and row['is_off_hours'] == 1:
            return -1 # Nửa đêm mò vào lấy quyền Root -> Trảm chắc chắn!

        return pred

    df_test['final_verdict'] = df_test.apply(apply_auth_rules, axis=1)

    # 4. THỐNG KÊ CHI TIẾT
    ai_flags = (df_test['ai_prediction'] == -1)
    whitelist_flags = df_test['user'].apply(lambda x: pd.notna(x) and x != 'unknown' and x not in known_users)

    caught_by_ai = ai_flags.sum()
    caught_by_whitelist = whitelist_flags.sum()
    caught_by_both = (ai_flags & whitelist_flags).sum()
    caught_by_whitelist_only = caught_by_whitelist - caught_by_both

    anomalies = df_test[df_test['final_verdict'] == -1]

    print("\n=====================================================")
    print(f"🚨 TỔNG KẾT: PHÁT HIỆN {len(anomalies)} HÀNH VI ĐĂNG NHẬP/CHUYỂN QUYỀN BẤT THƯỜNG!")
    print("=====================================================")
    print(" 📊 BÁO CÁO NGUỒN PHÁT HIỆN:")
    print(f"    - Do AI 8D phát hiện (Rà quét Brute-force/Bất thường): {caught_by_ai} dòng")
    print(f"    - Do Luật Cứng (Người lạ/Root đêm khuya) trảm ĐỘC LẬP: {caught_by_whitelist_only} dòng")
    print(f"    - (Chú thích: Có {caught_by_both} dòng bị cả AI và Luật Cứng cùng chỉ điểm)")
    print("-----------------------------------------------------")
    
    # 5. HIỂN THỊ CẢNH BÁO & XUẤT FILE HACKER
    if not anomalies.empty:
        print("\n[!] TOP CÁC TÀI KHOẢN ĐANG BỊ TẤN CÔNG / LỢI DỤNG:")
        user_counts = anomalies[anomalies['user'] != 'unknown']['user'].value_counts()
        for u, count in user_counts.items():
            print(f"   🎯 User: {u} | Số log độc hại: {count}")
            
        print("\n[!] BẰNG CHỨNG PHẠM TỘI (5 log đầu tiên):")
        # In các cột quan trọng nhất để điều tra
        print(anomalies[['timestamp', 'rip', 'user', 'program', 'action', 'velocity']].head(5).to_string())
        
        # Xuất file
        EXPORT_HACKER_FILE = "data/detected_auth_hackers.csv"
        export_cols = [
            'timestamp', 'rip', 'user', 'program', 'action', 
            'is_root_target', 'is_privilege_escalation', 'velocity', 'unique_users', 'hour_of_day'
        ]
        anomalies_sorted = anomalies.sort_values('timestamp')
        anomalies_sorted[export_cols].to_csv(EXPORT_HACKER_FILE, index=False)
        print(f"\n[💾] XUẤT FILE THÀNH CÔNG: Đã lưu toàn bộ {len(anomalies)} dòng log của Hacker vào: {EXPORT_HACKER_FILE}")
        
    else:
        print("[+] Hệ thống an toàn. Không phát hiện bất thường.")

except FileNotFoundError as e:
    print(f"[!] Lỗi: Không tìm thấy file. Chi tiết: {e}")
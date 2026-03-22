import pandas as pd
import numpy as np

INPUT_FILE = "data/mail_log_cleaned.csv"
OUTPUT_FILE = "data/mail_features_ready.csv"
# INPUT_FILE = "data/mail_test_cleaned.csv"
# OUTPUT_FILE = "data/mail_test_features_ready.csv"


print(f"[*] Đang nạp dữ liệu từ {INPUT_FILE}...")

try:
    df = pd.read_csv(INPUT_FILE, parse_dates=['timestamp'])
    
    # Sắp xếp dữ liệu theo thời gian tuyệt đối để tính toán không bị sai
    df = df.sort_values('timestamp').reset_index(drop=True)

    print("[*] Đang tiến hành chuẩn hóa 8 Chiều (Feature Engineering)...")

    # CHIỀU 1: action_code (1=Login, 2=Logged out, 3=Disconnected)
    action_mapping = {'Login': 1, 'Logged out': 2, 'Disconnected': 3}
    df['action_code'] = df['action'].map(action_mapping).fillna(0).astype(int)

    # CHIỀU 2: is_remote (0=Nội bộ, 1=Bên ngoài)
    # Nếu rip giống hệt lip -> 0, ngược lại -> 1. (Lưu ý xử lý NaN nếu có)
    df['is_remote'] = np.where((df['rip'] == df['lip']) & (df['rip'].notna()), 0, 1)

    # CHIỀU 3 & 4: attempts và duration_secs (Đã là số, giữ nguyên)
    # CHIỀU 5 & 6: bytes_in và bytes_out (Đã là số, giữ nguyên)

    # =================================================================
    # CHIỀU 7: velocity (Đếm số log của IP này trong 60 giây qua)
    # =================================================================
    print("  -> Đang tính toán Vận tốc (Cửa sổ 60s)...")
    df = df.sort_values(by=['rip', 'timestamp'])
    df = df.set_index('timestamp')
    # Dùng rolling window 60s đếm số lần xuất hiện của IP
    df['velocity'] = df.groupby('rip')['action_code'].rolling('60s').count().reset_index(level=0, drop=True)
    df = df.reset_index()

    # =================================================================
    # CHIỀU 8: unique_users (Số lượng tài khoản IP này ĐÃ chạm vào tính đến hiện tại)
    # =================================================================
    print("  -> Đang truy vết Hành vi Nhồi nhét tài khoản (Credential Stuffing)...")
    
    # Hàm đếm số user duy nhất theo thời gian thực (tích lũy)
    def cumulative_nunique(series):
        seen = set()
        res = []
        for val in series:
            if pd.notna(val):
                seen.add(val)
            res.append(len(seen))
        return res

    df['unique_users'] = df.groupby('rip')['user'].transform(cumulative_nunique)

    # Sắp xếp lại theo thời gian như cũ
    df = df.sort_values('timestamp').reset_index(drop=True)

    # =================================================================
    # CHIỀU 9 & 10: TRỊ BỆNH "MÙ THỜI GIAN" (Time-based Features)
    # =================================================================
    print("  -> Đang nhúng Đồng hồ sinh học vào Ma trận...")
    # Trích xuất Giờ (0-23)
    df['hour_of_day'] = df['timestamp'].dt.hour
    
    # Đánh dấu Ngoài giờ hành chính (Từ 22h đêm đến 5h sáng hôm sau)
    # Nếu rơi vào khung giờ này thì set là 1 (Bất thường tiềm năng), ngược lại là 0
    df['is_off_hours'] = df['hour_of_day'].apply(lambda x: 1 if (x >= 22 or x <= 5) else 0)
    
    # LỌC LẠI BỘ KHUNG CUỐI CÙNG (Chỉ giữ lại Số học + Các cột định vị)
    # Ta giữ lại timestamp, rip và user để sau này AI báo lỗi thì biết ai đang tấn công
    final_columns = [
        'timestamp', 'rip', 'user', # 3 Cột định vị (Không đưa vào AI học)
        'action_code', 'is_remote', 'attempts', 'duration_secs', 
        'bytes_in', 'bytes_out', 'velocity', 'unique_users',
        'hour_of_day', 'is_off_hours' # 10 Cột Ma trận 8=10D
    ]
    
    df_final = df[final_columns]

    print("\n[+] HOÀN TẤT! Hình hài của Ma trận 10D như sau:\n")
    print(df_final[['rip', 'action_code', 'velocity', 'unique_users', 'bytes_out']].head(10).to_string())

    # Xuất ra file để chuẩn bị đưa vào AI
    df_final.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] Đã lưu Ma trận hoàn chỉnh tại: {OUTPUT_FILE}")

except FileNotFoundError:
    print(f"[!] Không tìm thấy file {INPUT_FILE}. Vui lòng chạy file eda_mail_log.py trước!")
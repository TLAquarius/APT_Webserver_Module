import pandas as pd
import numpy as np

INPUT_FILE = "data/auth_log_train_cleaned.csv"
OUTPUT_FILE = "data/auth_features_train_ready.csv"

# INPUT_FILE = "data/auth_log_cleaned.csv"
# OUTPUT_FILE = "data/auth_features_ready.csv"

print("=====================================================")
print("⚙️ KHỞI ĐỘNG NHÀ MÁY LÀM GIÀU DỮ LIỆU: AUTH 8D")
print("=====================================================")

try:
    df = pd.read_csv(INPUT_FILE, parse_dates=['timestamp'])
    df = df.sort_values('timestamp').reset_index(drop=True)

    # Xử lý các hành động nội bộ (su, sudo) không có IP từ xa
    # Ta sẽ gán IP mặc định là 'localhost' để tính toán Velocity không bị lỗi
    df['rip'] = df['rip'].fillna('localhost')
    df['user'] = df['user'].fillna('unknown')

    print("[*] Đang mã hóa các trục không gian (Encoding)...")

    # CHIỀU 1: action_code
    action_mapping = {
        'Login Success': 1, 'Login Failed': -1, 'Disconnected': 2,
        'Session Opened': 3, 'Session Closed': 4,
        'Systemd Session Opened': 5,
        'Privilege Escalation (su)': 10, 'Sudo Command': 11
    }
    df['action_code'] = df['action'].map(action_mapping).fillna(0).astype(int)

    # CHIỀU 2: program_code
    program_mapping = {'sshd': 1, 'auth': 2, 'su': 3, 'sudo': 4, 'systemd': 5, 'systemd-logind': 5}
    df['program_code'] = df['program'].map(program_mapping).fillna(0).astype(int)

    # CHIỀU 3: is_root_target (Nhắm vào quyền tối cao)
    df['is_root_target'] = df['user'].apply(lambda x: 1 if x == 'root' else 0)

    # CHIỀU 4: is_privilege_escalation (Dấu hiệu leo thang theo file YAML)
    df['is_privilege_escalation'] = df['action'].apply(
        lambda x: 1 if x in ['Privilege Escalation (su)', 'Sudo Command'] else 0
    )

    # CHIỀU 5 & 6: Đồng hồ sinh học (Chống mù thời gian)
    print("[*] Đang nhúng Đồng hồ sinh học (Time-based Features)...")
    df['hour_of_day'] = df['timestamp'].dt.hour
    df['is_off_hours'] = df['hour_of_day'].apply(lambda x: 1 if (x >= 22 or x <= 5) else 0)

    # CHIỀU 7 & 8: Vận tốc và Truy vết Nhồi nhét (Sliding Window)
    print("[*] Đang tính toán Vận tốc và Mức độ phát tán (Sliding Window 60s)...")
    df = df.sort_values(by=['rip', 'timestamp']).set_index('timestamp')
    df['velocity'] = df.groupby('rip')['action_code'].rolling('60s').count().reset_index(level=0, drop=True)
    df = df.reset_index()

    # -------------------------------------------------------------------------
    # CHIỀU 9 (TỐI ƯU HÓA): THEO DÕI CHUỖI SỰ KIỆN THEO PHIÊN (Session-based Tracking)
    # -------------------------------------------------------------------------
    print("[*] Đang vá lỗ hổng Tàng hình (Chuyển sang theo dõi rủi ro theo Session)...")
    
    # Bước 1: Xác định điểm kết thúc của một phiên làm việc
    reset_actions = ['Disconnected', 'Session Closed']
    df['is_reset'] = df['action'].isin(reset_actions).astype(int)
    
    # Bước 2: Tạo ID Phiên (Session Block) cho từng IP. 
    # Mỗi lần gặp hành động "Reset", ID Phiên sẽ cộng dồn lên 1 để tạo thành block mới
    df['session_block'] = df.groupby('rip')['is_reset'].cumsum()
    
    # Bước 3: Tính điểm vi phạm của dòng hiện tại (Su/Sudo/Root)
    df['combo_score'] = df['is_privilege_escalation'] + df['is_root_target']
    
    # Bước 4: Cộng dồn vĩnh viễn (Cumulative Sum) điểm vi phạm TRONG CÙNG 1 PHIÊN của 1 IP
    df['session_risk_score'] = df.groupby(['rip', 'session_block'])['combo_score'].cumsum()

    def cumulative_nunique(series):
        seen = set()
        res = []
        for val in series:
            seen.add(val)
            res.append(len(seen))
        return res

    df['unique_users'] = df.groupby('rip')['user'].transform(cumulative_nunique)
    df = df.sort_values('timestamp').reset_index(drop=True)

    # CHỐT MA TRẬN CUỐI CÙNG
    final_columns = [
        'timestamp', 'rip', 'user', 'program', 'action', # 5 Cột định vị & hiển thị
        'action_code', 'program_code', 'is_root_target', 'is_privilege_escalation', 
        'hour_of_day', 'is_off_hours', 'velocity', 'unique_users','session_risk_score'
    ]
    
    df_final = df[final_columns]

    print("\n[+] HOÀN TẤT! Hình hài của Ma trận Auth 8D như sau:")
    print(df_final[['rip', 'user', 'action', 'velocity', 'is_privilege_escalation']].head(10).to_string())

    df_final.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[💾] Đã lưu Ma trận hoàn chỉnh tại: {OUTPUT_FILE}")

except FileNotFoundError:
    print(f"[!] Không tìm thấy file {INPUT_FILE}.")
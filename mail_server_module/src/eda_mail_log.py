import re
import pandas as pd
from collections import defaultdict

LOG_FILE = "data/mail.log"

# Regex bắt Timestamp và Message
BASE_REGEX = re.compile(r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+[^:]+:\s+(?P<message>.*)$")

# Regex bóc tách chi tiết từng kiểu
LOGIN_REGEX = re.compile(r"Login: user=<(.*?)>.*rip=([\d\.]+), lip=([\d\.]+)")
LOGOUT_REGEX = re.compile(r"imap\((.*?)\): Logged out in=(\d+) out=(\d+)")
FAILED_REGEX = re.compile(r"Disconnected \(auth failed, (\d+) attempts in (\d+) secs\): user=<(.*?)>.*rip=([\d\.]+), lip=([\d\.]+)")

parsed_data = []

# BỘ NHỚ ĐỆM (CACHE): Lưu trữ rip và lip của user để điền cho Kiểu 2 (Logout)
user_ip_cache = defaultdict(lambda: {'rip': None, 'lip': None})

print(f"[*] Đang bóc tách file {LOG_FILE} theo chuẩn 9 Cột...")

try:
    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            match = BASE_REGEX.search(line)
            if match:
                timestamp = match.group('timestamp')
                msg = match.group('message')
                
                # Khởi tạo Row với các giá trị mặc định theo đúng rule của bạn
                row = {
                    'timestamp': timestamp,
                    'action': 'Unknown',
                    'user': None,
                    'rip': None,
                    'lip': None,
                    'attempts': 0,        # Kiểu 1 & 2 set 0
                    'duration_secs': 0,   # Kiểu 1 & 2 set 0
                    'bytes_in': 0,        # Kiểu 1 & 3 set 0
                    'bytes_out': 0        # Kiểu 1 & 3 set 0
                }
                
                # KIỂU 1: Login Success
                if "Login: user=" in msg:
                    m = LOGIN_REGEX.search(msg)
                    if m:
                        row['action'] = "Login"
                        row['user'] = m.group(1)
                        row['rip'] = m.group(2)
                        row['lip'] = m.group(3)
                        # Cập nhật Cache để dùng cho lúc Logout
                        user_ip_cache[row['user']] = {'rip': row['rip'], 'lip': row['lip']}
                        parsed_data.append(row)
                        
                # KIỂU 3: Disconnected / Auth Failed
                elif "Disconnected (auth failed" in msg:
                    m = FAILED_REGEX.search(msg)
                    if m:
                        row['action'] = "Disconnected"
                        row['attempts'] = int(m.group(1))
                        row['duration_secs'] = int(m.group(2))
                        row['user'] = m.group(3)
                        row['rip'] = m.group(4)
                        row['lip'] = m.group(5)
                        # Cập nhật Cache (Vì Hacker có thể rà quét sai pass rồi mới đúng)
                        user_ip_cache[row['user']] = {'rip': row['rip'], 'lip': row['lip']}
                        parsed_data.append(row)

                # KIỂU 2: Logged out
                elif "Logged out" in msg:
                    m = LOGOUT_REGEX.search(msg)
                    if m:
                        row['action'] = "Logged out"
                        row['user'] = m.group(1)
                        row['bytes_in'] = int(m.group(2))
                        row['bytes_out'] = int(m.group(3))
                        # KÉO RIP VÀ LIP TỪ BỘ NHỚ CACHE RA!
                        cached_ip = user_ip_cache[row['user']]
                        row['rip'] = cached_ip['rip']
                        row['lip'] = cached_ip['lip']
                        parsed_data.append(row)

    # CHUYỂN THÀNH DATAFRAME
    df = pd.DataFrame(parsed_data)

    # Chuẩn hóa Timestamp
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
    df['timestamp'] = df['timestamp'].apply(lambda dt: dt.replace(year=2026) if pd.notnull(dt) else dt)

    print("[+] Hoàn tất! Cấu trúc DataFrame Vàng (9 Cột):\n")
    print(df.head(10).to_string())

    # Xuất file CSV để kiểm tra
    export_path = "data/mail_test_cleaned.csv"
    df.to_csv(export_path, index=False)
    print(f"\n[+] Đã xuất DataFrame ra file: {export_path}")

except FileNotFoundError:
    print(f"[!] Lỗi: Không tìm thấy file {LOG_FILE}")
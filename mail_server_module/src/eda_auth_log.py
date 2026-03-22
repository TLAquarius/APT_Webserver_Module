import re
import pandas as pd
from datetime import datetime

# Cấu hình đường dẫn
# LOG_FILE = "data/auth.log" # Đảm bảo bạn đã có file này trong thư mục data/
# OUTPUT_CSV = "data/auth_log_cleaned.csv"

LOG_FILE = "data/auth.log.1" # Đảm bảo bạn đã có file này trong thư mục data/
OUTPUT_CSV = "data/auth_log_train_cleaned.csv"


# Năm mặc định (vì syslog thường không ghi năm, ta giả định năm 2022 theo file YAML)
YEAR = "2022"

print("=====================================================")
print("🧹 MÁY XÚC DỮ LIỆU: CHUẨN HÓA AUTH LOG (HỆ HÀNH VI)")
print("=====================================================")

# 1. BỘ LỌC REGEX CHÍNH BÓC TÁCH HEADER
# Bắt các thành phần: Tháng, Ngày, Giờ, Hostname, Tên Process (PID), Message
# Lưu ý: Chấp nhận cả lỗi đánh máy ngày tháng (như "an 15" thay vì "Jan 15")
base_regex = re.compile(r'^(?P<month>[a-zA-Z]+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>[a-zA-Z0-9_-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$')

parsed_data = []
ignored_lines = 0

print(f"[*] Đang đọc và quét nội dung file: {LOG_FILE}...")

try:
    with open(LOG_FILE, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            if not line: continue
            
            match = base_regex.match(line)
            if not match:
                ignored_lines += 1
                continue
                
            log_dict = match.groupdict()
            program = log_dict['program']
            msg = log_dict['message']
            
            # --- BỘ LỌC RÁC (BỎ QUA CRON VÀ CÁC TIẾN TRÌNH KHÔNG QUAN TRỌNG) ---
            if program in ['CRON']:
                ignored_lines += 1
                continue
                
            # Khởi tạo các biến mặc định
            action = "Unknown"
            user = None
            ip = None
            
            # --- LUẬT BÓC TÁCH CHO SSHD (Đăng nhập từ xa) ---
            if program == 'sshd':
                if "Accepted" in msg:
                    action = "Login Success"
                    # Lấy user và IP từ chuỗi: Accepted password/publickey for phopkins from 10.35.35.202
                    m = re.search(r'for (?:invalid user )?(\S+) from (\S+)', msg)
                    if m: user, ip = m.groups()
                elif "Failed" in msg:
                    action = "Login Failed"
                    m = re.search(r'for (?:invalid user )?(\S+) from (\S+)', msg)
                    if m: user, ip = m.groups()
                elif "Disconnected from" in msg or "Received disconnect" in msg:
                    action = "Disconnected"
                    m = re.search(r'from (?:invalid user )?(\S+)', msg)
                    if m: ip = m.group(1)
                elif "session opened" in msg:
                    action = "Session Opened"
                    m = re.search(r'for user (\S+)', msg)
                    if m: user = m.group(1)
                elif "session closed" in msg:
                    action = "Session Closed"
                    m = re.search(r'for user (\S+)', msg)
                    if m: user = m.group(1)

            # --- LUẬT BÓC TÁCH CHO DOVECOT/AUTH (Mail Login via Auth) ---
            elif program == 'auth':
                if "authentication failure" in msg:
                    action = "Login Failed"
                    m = re.search(r'rhost=(\S+)\s+user=(\S+)', msg)
                    if m: ip, user = m.groups()
                    
            # --- LUẬT BÓC TÁCH CHO SU / SUDO / SYSTEMD (Leo thang đặc quyền) ---
            elif program == 'su':
                if "Successful su for" in msg:
                    action = "Privilege Escalation (su)"
                    m = re.search(r'for (\S+) by (\S+)', msg)
                    if m: user = m.group(1) # Target user
            elif program == 'sudo':
                if "COMMAND=" in msg:
                    action = "Sudo Command"
                    m = re.search(r'USER=(\S+)\s+;\s+COMMAND=(.*)', msg)
                    if m: user = m.group(1)
            elif 'systemd' in program:
                if "session opened" in msg or "New session" in msg:
                    action = "Systemd Session Opened"
                    m = re.search(r'user (\S+)', msg)
                    if m: user = m.group(1)

            # Lắp ráp Thời gian (Thêm năm 2022)
            # Sửa lỗi đánh máy 'an' thành 'Jan' nếu có
            month = log_dict['month']
            if month == 'an': month = 'Jan'
            
            datetime_str = f"{YEAR} {month} {log_dict['day']} {log_dict['time']}"
            try:
                timestamp = datetime.strptime(datetime_str, '%Y %b %d %H:%M:%S')
            except ValueError:
                continue

            # Chỉ lưu lại những log đã xác định được hành vi quan trọng
            if action != "Unknown":
                parsed_data.append({
                    'timestamp': timestamp,
                    'program': program,
                    'action': action,
                    'user': user,
                    'rip': ip
                })

    # Đổ vào Pandas DataFrame
    df = pd.DataFrame(parsed_data)
    
    print(f"\n[+] Tổng số dòng log đã quét: {len(df) + ignored_lines}")
    print(f"[+] Số dòng rác bị ném bỏ (CRON/Unknown): {ignored_lines}")
    print(f"[+] Số dòng có giá trị bảo mật giữ lại: {len(df)}")
    
    if not df.empty:
        print("\n[+] XEM THỬ 10 DÒNG DỮ LIỆU ĐÃ ĐƯỢC ÉP PHẲNG THÀNH CỘT:")
        print(df.head(10).to_string())

        # Xuất ra file
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"\n[💾] Đã lưu File cấu trúc tại: {OUTPUT_CSV}")
        print(" -> Bây giờ bạn đã có thể đưa nó vào khâu Chuẩn hóa (Normalize) để đúc Ma trận 8D/10D!")

except FileNotFoundError:
    print(f"[!] Lỗi: Không tìm thấy file {LOG_FILE}. Bạn nhớ đổi tên file auth gốc thành auth.log và để vào thư mục data/ nhé.")
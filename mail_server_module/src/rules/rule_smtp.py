from collections import deque
from datetime import timedelta

# Cấu hình ngưỡng
ENUM_THRESHOLD = 20    # 20 lần thử user sai / 1 phút
DOS_THRESHOLD = 100    # 100 connect / 1 phút

enum_attempts = {}
dos_attempts = {}

def check_smtp_enumeration(log_data):
    """Bắt quả tang SMTP Enumeration / Directory Harvest Attack (Dò tìm user tồn tại)"""
    if log_data.get('service') != 'postfix': return None
    
    ip = log_data.get('ip')
    reason = log_data.get('reason', '')
    
    if ip and reason == 'User unknown':
        if ip not in enum_attempts: enum_attempts[ip] = deque()
        enum_attempts[ip].append(log_data['timestamp'])
        
        time_limit = log_data['timestamp'] - timedelta(minutes=1)
        while enum_attempts[ip] and enum_attempts[ip][0] < time_limit:
            enum_attempts[ip].popleft()
            
        if len(enum_attempts[ip]) >= ENUM_THRESHOLD:
            enum_attempts[ip].clear()
            return {
                "alert_type": "SMTP Enumeration / DHA Attack",
                "severity": "HIGH",
                "source_ip": ip,
                "description": f"IP {ip} đang quét dò tìm các email tồn tại trong hệ thống (> {ENUM_THRESHOLD} lần/phút)."
            }
    return None

def check_relay_attempt(log_data):
    """Spam Relay Attempt: Mượn server mình để gửi thư rác đi nơi khác"""
    if log_data.get('service') == 'postfix' and log_data.get('reason') == 'Relay access denied':
        return {
            "alert_type": "Open Relay Spam Attempt",
            "severity": "MEDIUM",
            "source_ip": log_data.get('ip', 'Unknown'),
            "description": "Phát hiện kẻ lạ cố gắng lợi dụng Mail Server để phát tán Spam ra ngoài."
        }
    return None
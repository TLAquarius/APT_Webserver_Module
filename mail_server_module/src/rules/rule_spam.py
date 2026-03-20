from collections import deque
from datetime import timedelta

SPAM_THRESHOLD = 50 # Gửi 50 mail / 1 phút là bất thường

# Lưu vết: { "User": deque([time1, time2...]) }
outbound_mails = {}

def check_mass_outbound_spam(log_data):
    """Mass Outbound Spam: Tài khoản nhân viên bị hack và đang gửi hàng loạt thư rác"""
    # LƯU Ý: Để bắt chính xác Mass Spam, Lớp 0 cần đọc thêm log `postfix/qmgr` (ghi nhận việc gửi thư).
    # Khung code dưới đây thể hiện logic cửa sổ trượt cho Spam.
    action = log_data.get('action', '')
    user = log_data.get('user')
    
    if log_data.get('service') == 'postfix' and "queue active" in action and user != 'unknown':
        if user not in outbound_mails: outbound_mails[user] = deque()
        outbound_mails[user].append(log_data['timestamp'])
        
        time_limit = log_data['timestamp'] - timedelta(minutes=1)
        while outbound_mails[user] and outbound_mails[user][0] < time_limit:
            outbound_mails[user].popleft()
            
        if len(outbound_mails[user]) >= SPAM_THRESHOLD:
            outbound_mails[user].clear()
            return {
                "alert_type": "Mass Outbound Spam (Compromised Account)",
                "severity": "CRITICAL",
                "target_user": user,
                "description": f"Tài khoản {user} đang gửi đi lượng email khổng lồ (> {SPAM_THRESHOLD} mail/phút). Cần khóa tài khoản ngay lập tức!"
            }
    return None
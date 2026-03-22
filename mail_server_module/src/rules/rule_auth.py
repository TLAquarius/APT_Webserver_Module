from collections import deque
from datetime import timedelta

# Cấu hình ngưỡng linh hoạt (Dễ dàng thay đổi)
MAX_ATTEMPTS = 10
TIME_WINDOW_MINUTES = 5

# Biến toàn cục lưu trạng thái. 
# Cấu trúc mới: { "IP": deque([thoi_gian_1, thoi_gian_2, ...]) }
failed_attempts = {}

def check_brute_force(log_data):
    """
    Thuật toán Cửa sổ trượt (Sliding Window):
    Cảnh báo nếu 1 IP sai mật khẩu vượt ngưỡng TRONG VÒNG X PHÚT.
    """
    ip = log_data['ip']
    action = log_data['action']
    user = log_data['user']
    current_time = log_data['timestamp']

    if "Disconnected" in action or "auth failed" in action:
        # 1. Nếu IP này chưa từng sai, tạo một hàng đợi (deque) mới
        if ip not in failed_attempts:
            failed_attempts[ip] = deque()
        
        # 2. Ghi nhận thời gian của lần sai mật khẩu này
        failed_attempts[ip].append(current_time)
        
        # 3. TRƯỢT CỬA SỔ: Xóa bỏ các lần sai đã quá hạn (cũ hơn 5 phút)
        time_limit = current_time - timedelta(minutes=TIME_WINDOW_MINUTES)
        while failed_attempts[ip] and failed_attempts[ip][0] < time_limit:
            failed_attempts[ip].popleft() # Đẩy dữ liệu cũ ra khỏi hàng đợi
        
        # 4. Kiểm tra số lượng lỗi còn lại TRONG cửa sổ thời gian
        if len(failed_attempts[ip]) >= MAX_ATTEMPTS:
            # Reset hàng đợi để tránh xả cảnh báo rác (spam) liên tục cho cùng 1 đợt tấn công
            failed_attempts[ip].clear() 
            
            return {
                "alert_type": "Brute-Force (Sliding Window)",
                "severity": "HIGH",
                "source_ip": ip,
                "target_user": user,
                "description": f"IP {ip} sai mật khẩu {MAX_ATTEMPTS} lần chỉ trong vòng {TIME_WINDOW_MINUTES} phút!"
            }
            
    elif action == "Login":
        # Reset sạch sẽ nếu user nhớ ra mật khẩu và đăng nhập thành công
        if ip in failed_attempts:
            failed_attempts[ip].clear()
        
    return None # An toàn, không có gì bất thường


SPRAY_MAX_USERS = 5
VIP_USERS = ["root", "admin", "ceo@ascolotus.com"]

# Bộ nhớ cho Password Spraying: { "IP": set([user1, user2, ...]) }
spraying_attempts = {}

def check_password_spraying(log_data):
    """Luật: 1 IP thử đăng nhập sai trên nhiều User khác nhau"""
    ip = log_data['ip']
    action = log_data['action']
    user = log_data['user']

    if "Disconnected" in action or "auth failed" in action:
        if ip not in spraying_attempts:
            spraying_attempts[ip] = set()
            
        spraying_attempts[ip].add(user)
        
        # Nếu IP này thử dò tới user thứ 5 khác nhau -> Báo động!
        if len(spraying_attempts[ip]) >= SPRAY_MAX_USERS:
            spraying_attempts[ip].clear() # Reset để tránh spam
            return {
                "alert_type": "Password Spraying Attack",
                "severity": "CRITICAL",
                "source_ip": ip,
                "target_user": "Multiple Users",
                "description": f"IP {ip} đang rải thảm mật khẩu trên {SPRAY_MAX_USERS} tài khoản khác nhau!"
            }
    elif action == "Login" and ip in spraying_attempts:
        # Nếu đang rải thảm mà có 1 user thành công -> Xóa log rải thảm cũ (tuỳ chọn)
        pass 
        
    return None

def check_off_hours_login(log_data):
    """Luật: Đăng nhập thành công vào khung giờ 2h - 5h sáng"""
    action = log_data['action']
    user = log_data['user']
    current_time = log_data['timestamp']
    ip = log_data['ip']

    if action == "Login":
        hour = current_time.hour
        # Khung giờ đỏ: Từ 2h đến 5h sáng
        if 2 <= hour <= 5:
            return {
                "alert_type": "Off-hours Login",
                "severity": "MEDIUM",
                "source_ip": ip,
                "target_user": user,
                "description": f"User {user} đăng nhập thành công vào giờ bất thường ({hour}h sáng)."
            }
            
    return None
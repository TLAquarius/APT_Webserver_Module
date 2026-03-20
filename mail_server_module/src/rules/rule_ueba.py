import math
import requests
from datetime import datetime

# Bộ nhớ lưu trạng thái đăng nhập cuối cùng: 
# { "user": {"ip": "1.2.3.4", "time": datetime, "lat": 10.0, "lon": 106.0} }
last_login_info = {}

def get_lat_lon(ip):
    """Lấy tọa độ địa lý từ IP."""
    # Xử lý IP LAN (Nội bộ mạng doanh nghiệp)
    if ip.startswith("172.") or ip.startswith("192.") or ip.startswith("10."):
        return 21.0285, 105.8542 # Tọa độ giả định tại Hà Nội
    
    # Đối với IP Public, gọi API miễn phí để lấy tọa độ
    # (Trong báo cáo đồ án, bạn có thể ghi chú là thực tế sẽ dùng Database MaxMind GeoLite2 Offline để tốc độ nhanh hơn)
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response['status'] == 'success':
            return response['lat'], response['lon']
    except Exception:
        pass
    
    return None, None

def haversine_distance(lat1, lon1, lat2, lon2):
    """Công thức Haversine tính khoảng cách (km) giữa 2 tọa độ trên Trái Đất"""
    R = 6371.0 # Bán kính Trái Đất (km)
    dLat = math.radians(lat2 - lat1)
    dLon = math.radians(lon2 - lon1)
    a = math.sin(dLat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dLon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c

def check_impossible_travel(log_data):
    """LỚP 2: Phân tích hành vi (UEBA) - Tính toán Vận tốc Địa lý"""
    action = log_data.get('action')
    user = log_data.get('user')
    ip = log_data.get('ip')
    current_time = log_data.get('timestamp')

    if action == "Login" and user != "unknown" and ip:
        if user in last_login_info:
            last_info = last_login_info[user]
            last_ip = last_info['ip']
            
            # Chỉ tính toán nếu IP thay đổi
            if ip != last_ip:
                lat1, lon1 = last_info['lat'], last_info['lon']
                lat2, lon2 = get_lat_lon(ip)
                
                if lat1 and lat2:
                    distance = haversine_distance(lat1, lon1, lat2, lon2)
                    time_diff_hours = (current_time - last_info['time']).total_seconds() / 3600.0
                    
                    # Tránh lỗi chia cho 0 nếu 2 log xảy ra cùng 1 giây
                    if time_diff_hours > 0:
                        speed = distance / time_diff_hours
                        
                        # NGƯỠNG BÁO ĐỘNG: 1000 km/h
                        if speed > 1000:
                            # Cập nhật lại vị trí mới để không báo spam
                            last_login_info[user] = {"ip": ip, "time": current_time, "lat": lat2, "lon": lon2}
                            return {
                                "alert_type": "Impossible Travel (Geo-Velocity)",
                                "severity": "CRITICAL",
                                "source_ip": ip,
                                "target_user": user,
                                "description": f"Tài khoản {user} di chuyển {int(distance)}km trong {time_diff_hours:.2f} giờ. Vận tốc {int(speed)} km/h là không tưởng!"
                            }
        
        # Lưu lại trạng thái của lần đăng nhập thành công này
        lat, lon = get_lat_lon(ip)
        if lat and lon:
            last_login_info[user] = {"ip": ip, "time": current_time, "lat": lat, "lon": lon}
            
    return None


# Bộ nhớ lưu Lịch sử tất cả các IP đã từng đăng nhập của mỗi User
# Cấu trúc: { "user": set(["ip1", "ip2", ...])
historical_ips = {}

def check_new_ip_login(log_data):
    """
    LỚP 2: Phân tích hành vi (UEBA) - First-Time Access
    Phát hiện Đăng nhập thành công từ một Địa chỉ IP chưa từng thấy trước đây.
    """
    action = log_data.get('action')
    user = log_data.get('user')
    ip = log_data.get('ip')

    if action == "Login" and user != "unknown" and ip:
        # Nếu user này đã có trong hồ sơ
        if user in historical_ips:
            # Và IP này chưa từng nằm trong danh sách IP quen thuộc
            if ip not in historical_ips[user]:
                # Ghi nhận IP mới vào hồ sơ để không cảnh báo ở lần sau
                historical_ips[user].add(ip)
                return {
                    "alert_type": "First-Time IP Access (New Device/Location)",
                    "severity": "LOW", # Chỉ để Low hoặc Medium vì có thể nhân viên dùng máy mới thật
                    "source_ip": ip,
                    "target_user": user,
                    "description": f"Hành vi mới: Tài khoản {user} vừa đăng nhập thành công từ một IP ({ip}) chưa từng xuất hiện trong lịch sử."
                }
        else:
            # Lần đầu tiên hệ thống thấy user này -> Khởi tạo hồ sơ IP cho họ
            historical_ips[user] = set([ip])
            
    return None
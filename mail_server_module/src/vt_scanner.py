import requests
import time

# --- CẤU HÌNH API ---
# Thay thế bằng API Key thực tế của bạn
VT_API_KEY = "011a16b6a38a42b9284d25b2a3e1a51df8fbacb3348067b0389fbba69b66fb57" 

HEADERS = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
}

def check_ioc_virustotal(ioc_value, ioc_type="hash"):
    """
    Kiểm tra một IOC (Indicator of Compromise) trên VirusTotal.
    ioc_type có thể là 'url' hoặc 'hash'
    """
    print(f"[*] Đang truy vấn VirusTotal cho {ioc_type}: {ioc_value}")
    
    # Endpoint tìm kiếm chung của VT (chấp nhận cả Hash, Domain, URL, IP)
    search_url = f"https://www.virustotal.com/api/v3/search?query={ioc_value}"
    
    try:
        response = requests.get(search_url, headers=HEADERS)
        
        # Xử lý giới hạn API (Rate Limit)
        if response.status_code == 429:
            return {"status": "Error", "message": "Vượt quá giới hạn API (4 requests/phút). Hãy đợi..."}
            
        if response.status_code != 200:
            return {"status": "Error", "message": f"Lỗi HTTP {response.status_code}"}

        data = response.json()
        
        # Nếu không tìm thấy dữ liệu trên VT
        if not data.get('data'):
            return {"status": "Clean/Unknown", "malicious_score": 0, "message": "Chưa từng bị báo cáo trên VirusTotal"}
            
        # Lấy thông số phân tích từ các trình diệt virus
        stats = data['data'][0]['attributes']['last_analysis_stats']
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        total_engines = sum(stats.values())
        
        score = malicious + suspicious
        
        if score > 0:
            return {
                "status": "Malicious", 
                "malicious_score": score,
                "total_engines": total_engines,
                "message": f"CẢNH BÁO: {score}/{total_engines} engine đánh giá là độc hại!"
            }
        else:
            return {
                "status": "Clean", 
                "malicious_score": 0,
                "total_engines": total_engines,
                "message": f"An toàn (0/{total_engines} engine báo cáo)"
            }

    except Exception as e:
        return {"status": "Error", "message": str(e)}

# --- CHẠY THỬ NGHIỆM ĐỘC LẬP ---
if __name__ == "__main__":
    # Test 1: Quét một mã Hash của virus WannaCry nổi tiếng
    wannacry_hash = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"
    print("--- TEST HASH ---")
    result_hash = check_ioc_virustotal(wannacry_hash, "hash")
    print(result_hash)
    
    time.sleep(15) # Nghỉ 15 giây để tránh bị block API miễn phí
    
    # Test 2: Quét một URL lừa đảo (bạn có thể thay bằng URL sạch để xem khác biệt)
    phishing_url = "http://secure-login-paypal-update.com"
    print("\n--- TEST URL ---")
    result_url = check_ioc_virustotal(phishing_url, "url")
    print(result_url)